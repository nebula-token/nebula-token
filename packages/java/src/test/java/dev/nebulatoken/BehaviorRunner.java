package dev.nebulatoken;

import com.fasterxml.jackson.databind.JsonNode;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Runner for the normative behavioral suite, spec/behavior-vectors.json
 * ([N-47], [N-49]).
 *
 * <p>The scenarios are data. This file is the only language-specific part, which
 * is what stops the ten ports from drifting apart the way ten hand-written
 * suites did. Nothing here re-derives a case; if a behaviour is not in the
 * vectors it belongs in {@link EngineTest}, not here.
 */
final class BehaviorRunner {

    /**
     * Conditions this runtime satisfies. Java strings are UTF-16 code-unit
     * sequences and can hold an unpaired surrogate, so the invalid-Unicode
     * scenario applies here and is executed rather than skipped.
     */
    static final Set<String> SATISFIED_CONDITIONS = Set.of("runtime-admits-invalid-unicode-strings");

    /** 32 zero bytes, canonically encoded: well-formed, and never the real secret. */
    private static final String FORGED_VERIFIER = "A".repeat(Nebula.VERIFIER_CHARS);
    private static final String FORGED_SELECTOR = "A".repeat(Nebula.SELECTOR_CHARS);
    private static final String LONE_SURROGATE = "\uD800";

    private BehaviorRunner() {}

    record Skipped(String id, String condition) {}

    record RunOutcome(List<String> executed, List<Skipped> skipped) {}

    static JsonNode load() {
        return SpecVectors.load("behavior-vectors.json");
    }

    /** Execute every applicable scenario. Throws on the first divergence. */
    static RunOutcome run(JsonNode vectors) {
        List<String> executed = new ArrayList<>();
        List<Skipped> skipped = new ArrayList<>();

        for (JsonNode scenario : vectors.get("scenarios")) {
            String condition = scenario.has("condition") ? scenario.get("condition").asText() : null;
            if (condition != null && !SATISFIED_CONDITIONS.contains(condition)) {
                skipped.add(new Skipped(scenario.get("id").asText(), condition));
                continue;
            }
            runScenario(vectors, scenario);
            executed.add(scenario.get("id").asText());
        }
        return new RunOutcome(executed, skipped);
    }

    /**
     * Cognitive complexity is high and stays high (java:S3776).
     *
     * <p>This method is an interpreter for the step vocabulary published in
     * spec/behavior-vectors.json. Every {@code case} below is one {@code op} in
     * that file, in the order the file lists them, so the vocabulary and the
     * code that executes it can be diffed against each other by eye -- which is
     * the property that makes a conformance runner auditable at all.
     *
     * <p>Extracting one method per op was considered and rejected. The ops share
     * one mutable scenario state -- {@code engine}, {@code store},
     * {@code bindings}, {@code issuedSecrets}, {@code presentedDeviceIds},
     * {@code now} -- and {@code reconfigure} <em>reassigns</em> {@code engine},
     * which an extracted static method cannot do without a holder object. The
     * result would be a dozen methods each taking a context parameter, the same
     * total branching, and a dispatch table that no longer reads like the vector
     * format. That trades an honest measurement for a worse artefact.
     */
    @SuppressWarnings("java:S3776")
    static void runScenario(JsonNode vectors, JsonNode scenario) {
        JsonNode defaults = vectors.get("defaults");
        JsonNode override = scenario.get("config");

        AtomicLong now = new AtomicLong(setting(defaults, override, "now").asLong());
        long absoluteTtl = setting(defaults, override, "absoluteTtlSeconds").asLong();
        long idleTtl = setting(defaults, override, "idleTtlSeconds").asLong();
        long grace = setting(defaults, override, "reuseGraceSeconds").asLong();

        ControllableStore store = new ControllableStore();
        Map<String, Binding> bindings = new LinkedHashMap<>();
        List<String> issuedSecrets = new ArrayList<>();
        Set<String> presentedDeviceIds = new LinkedHashSet<>();

        NebulaEngine engine = build(vectors, store, now, absoluteTtl, idleTtl, grace,
                strings(setting(defaults, override, "peppers")),
                setting(defaults, override, "activeKid").asText());

        int index = -1;
        for (JsonNode step : scenario.get("steps")) {
            index++;
            JsonNode expect = step.get("expect");

            switch (step.get("op").asText()) {
                case "issue" -> {
                    String deviceId = deviceOf(step);
                    IssueResult res = engine.issue(step.get("userId").asText(), deviceId);
                    if (expect != null && expect.has("ok") && !expect.get("ok").asBoolean()) {
                        throw fail(scenario, index, "expected issue to fail");
                    }
                    checkSuccess(scenario, index, bindings, expect,
                            res.token(), res.generation(), res.familyId(),
                            res.expiresAt(), res.idleExpiresAt());
                    bind(bindings, step, res.token(), res.familyId(), res.expiresAt());
                    issuedSecrets.add(verifierPartOf(res.token()));
                    if (deviceId != null && !deviceId.isEmpty()) presentedDeviceIds.add(deviceId);
                }

                case "refresh" -> {
                    String deviceId = deviceOf(step);
                    RefreshResult res = engine.refresh(
                            resolveToken(scenario, index, bindings, step.get("token")), deviceId);
                    if (deviceId != null && !deviceId.isEmpty()) presentedDeviceIds.add(deviceId);

                    if (expectsSuccess(expect)) {
                        if (res instanceof RefreshResult.Failure f) {
                            throw fail(scenario, index, "expected success, got " + f.error());
                        }
                        RefreshResult.Success ok = (RefreshResult.Success) res;
                        checkSuccess(scenario, index, bindings, expect,
                                ok.token(), ok.generation(), ok.familyId(),
                                ok.expiresAt(), ok.idleExpiresAt());
                        bind(bindings, step, ok.token(), ok.familyId(), ok.expiresAt());
                        issuedSecrets.add(verifierPartOf(ok.token()));
                    } else {
                        String want = expect.get("error").asText();
                        if (!(res instanceof RefreshResult.Failure f)) {
                            throw fail(scenario, index, "expected " + want + ", got success");
                        }
                        if (!f.error().name().equals(want)) {
                            throw fail(scenario, index, "expected " + want + ", got " + f.error());
                        }
                        checkAttribution(scenario, index, expect, f.userId(), f.familyId());
                    }
                }

                case "revokeToken" -> {
                    RevokeResult res = engine.revokeToken(
                            resolveToken(scenario, index, bindings, step.get("token")));
                    if (expect != null && expect.has("ok") && !expect.get("ok").asBoolean()) {
                        String want = expect.get("error").asText();
                        if (!(res instanceof RevokeResult.Failure f)) {
                            throw fail(scenario, index, "expected " + want + ", got success");
                        }
                        if (!f.error().name().equals(want)) {
                            throw fail(scenario, index, "expected " + want + ", got " + f.error());
                        }
                        // [N-39] governs every failure result, revokeToken's included.
                        checkAttribution(scenario, index, expect, f.userId(), f.familyId());
                    } else {
                        if (res instanceof RevokeResult.Failure f) {
                            throw fail(scenario, index, "expected success, got " + f.error());
                        }
                        checkRevoked(scenario, index, expect, ((RevokeResult.Success) res).revoked());
                    }
                }

                case "revokeFamilyOf" -> {
                    Binding of = bindings.get(step.get("of").asText());
                    if (of == null) throw fail(scenario, index, "unknown binding " + step.get("of").asText());
                    checkRevoked(scenario, index, expect, engine.revokeFamily(of.familyId()));
                }

                case "revokeUser" ->
                        checkRevoked(scenario, index, expect,
                                engine.revokeAllForUser(step.get("userId").asText()));

                case "advance" -> now.addAndGet(step.get("seconds").asLong());

                // A new engine over the SAME store: pepper rotation is a config
                // change, not a data migration.
                case "reconfigure" -> engine = build(vectors, store, now, absoluteTtl, idleTtl, grace,
                        strings(step.get("peppers")), step.get("activeKid").asText());

                case "failNextCas" -> store.failNextCas(step.get("method").asText());

                case "expectStatusCounts" -> {
                    Map<String, Integer> actual = new LinkedHashMap<>();
                    for (TokenStatus status : TokenStatus.values()) {
                        actual.put(status.name().toLowerCase(java.util.Locale.ROOT), 0);
                    }
                    for (TokenRecord row : store.inner.all()) {
                        String key = row.status().name().toLowerCase(java.util.Locale.ROOT);
                        actual.merge(key, 1, Integer::sum);
                    }
                    JsonNode counts = step.get("counts");
                    var names = counts.fieldNames();
                    while (names.hasNext()) {
                        String status = names.next();
                        int want = counts.get(status).asInt();
                        if (!Integer.valueOf(want).equals(actual.get(status))) {
                            throw fail(scenario, index, "expected " + want + " " + status
                                    + ", got " + actual.get(status) + " " + actual);
                        }
                    }
                }

                case "expectNoRawSecrets" -> {
                    String dump = store.inner.all().toString();
                    for (String secret : issuedSecrets) {
                        if (dump.contains(secret)) {
                            throw fail(scenario, index, "a raw verifier reached the store ([N-14])");
                        }
                    }
                    for (String deviceId : presentedDeviceIds) {
                        if (dump.contains(deviceId)) {
                            throw fail(scenario, index, "a raw device identifier reached the store ([N-14])");
                        }
                    }
                }

                default -> throw fail(scenario, index, "unknown op \"" + step.get("op").asText() + "\"");
            }
        }
    }

    // --- step helpers -------------------------------------------------------

    private record Binding(String token, String familyId, long expiresAt) {}

    /** A step with no {@code expect}, or one naming neither ok nor error, expects success. */
    private static boolean expectsSuccess(JsonNode expect) {
        if (expect == null) return true;
        if (expect.has("ok")) return expect.get("ok").asBoolean();
        return !expect.has("error");
    }

    /**
     * Nine parameters (java:S107), and each one is a field of the vector step or
     * of the result being checked against it. Bundling them into a carrier type
     * would add a class whose only job is to be unpacked one line later, and
     * would hide which vector fields this check actually reads.
     */
    @SuppressWarnings("java:S107")
    private static void checkSuccess(JsonNode scenario, int index, Map<String, Binding> bindings,
                                     JsonNode expect, String token, int generation, String familyId,
                                     long expiresAt, long idleExpiresAt) {
        if (expect == null) return;
        if (expect.has("generation") && expect.get("generation").asInt() != generation) {
            throw fail(scenario, index,
                    "expected generation " + expect.get("generation").asInt() + ", got " + generation);
        }
        if (expect.has("kid")) {
            String kid = token.split("\\.", -1)[1];
            if (!expect.get("kid").asText().equals(kid)) {
                throw fail(scenario, index, "expected kid " + expect.get("kid").asText() + ", got " + kid);
            }
        }
        if (expect.has("sameFamilyAs")) {
            Binding other = bindings.get(expect.get("sameFamilyAs").asText());
            if (other == null || !other.familyId().equals(familyId)) {
                throw fail(scenario, index, "familyId changed across rotation");
            }
        }
        if (expect.has("sameExpiresAtAs")) {
            Binding other = bindings.get(expect.get("sameExpiresAtAs").asText());
            if (other == null || other.expiresAt() != expiresAt) {
                throw fail(scenario, index, "absolute deadline moved: "
                        + (other == null ? "?" : other.expiresAt()) + " -> " + expiresAt);
            }
        }
        if (expect.path("idleEqualsExpires").asBoolean() && idleExpiresAt != expiresAt) {
            throw fail(scenario, index,
                    "idleExpiresAt " + idleExpiresAt + " should be clamped to " + expiresAt);
        }
    }

    /**
     * The tri-state [N-39] attribution expectation. {@code true} demands the
     * field, {@code false} demands its <em>absence</em> -- the exclusion list
     * (MALFORMED, UNKNOWN_KID, NOT_FOUND) is a requirement too, and the
     * truthy-only check this replaced could never observe it. A key the vector
     * omits asserts nothing.
     *
     * <p>Both failure records always declare the two components, so "absent"
     * reads as {@code null} here -- that is how the engine signals "no record
     * was resolved" on the refresh path and the revokeToken path alike.
     */
    private static void checkAttribution(JsonNode scenario, int index, JsonNode expect,
                                         String userId, String familyId) {
        if (expect == null) return;
        if (expect.has("hasUserId")) {
            boolean want = expect.get("hasUserId").asBoolean();
            if ((userId != null) != want) {
                throw fail(scenario, index,
                        "expected userId " + (want ? "present" : "absent") + " ([N-39])");
            }
        }
        if (expect.has("hasFamilyId")) {
            boolean want = expect.get("hasFamilyId").asBoolean();
            if ((familyId != null) != want) {
                throw fail(scenario, index,
                        "expected familyId " + (want ? "present" : "absent") + " ([N-39])");
            }
        }
    }

    private static void checkRevoked(JsonNode scenario, int index, JsonNode expect, int revoked) {
        if (expect != null && expect.has("revoked") && expect.get("revoked").asInt() != revoked) {
            throw fail(scenario, index,
                    "expected " + expect.get("revoked").asInt() + " revoked, got " + revoked);
        }
    }

    private static void bind(Map<String, Binding> bindings, JsonNode step,
                             String token, String familyId, long expiresAt) {
        if (step.has("bind")) {
            bindings.put(step.get("bind").asText(), new Binding(token, familyId, expiresAt));
        }
    }

    private static String resolveToken(JsonNode scenario, int index,
                                       Map<String, Binding> bindings, JsonNode ref) {
        if (ref == null) throw fail(scenario, index, "step has no token reference");
        if (ref.has("literal")) return ref.get("literal").asText();
        if (!ref.has("ref")) throw fail(scenario, index, "step has no token reference");

        Binding bound = bindings.get(ref.get("ref").asText());
        if (bound == null) throw fail(scenario, index, "unknown binding \"" + ref.get("ref").asText() + "\"");
        if (!ref.has("forge")) return bound.token();

        String[] parts = bound.token().split("\\.", -1);
        switch (ref.get("forge").asText()) {
            case "verifier" -> parts[3] = FORGED_VERIFIER;
            case "unknownKid" -> parts[1] = "zz";
            case "unknownSelector" -> parts[2] = FORGED_SELECTOR;
            default -> throw fail(scenario, index, "unknown forge \"" + ref.get("forge").asText() + "\"");
        }
        return String.join(".", parts);
    }

    /**
     * A JSON document cannot carry a lone surrogate, so the vectors name the
     * kind and the runner constructs it ([N-12]).
     */
    private static String deviceOf(JsonNode step) {
        if (step.has("deviceIdKind")) {
            String kind = step.get("deviceIdKind").asText();
            if ("lone-surrogate".equals(kind)) return LONE_SURROGATE;
            throw new IllegalArgumentException("unknown deviceIdKind \"" + kind + "\"");
        }
        return step.has("deviceId") ? step.get("deviceId").asText() : null;
    }

    private static String verifierPartOf(String token) {
        return token.split("\\.", -1)[3];
    }

    /**
     * Eight parameters (java:S107): the eight configuration settings a scenario
     * may override, one per parameter. They are exactly the {@code defaults}
     * keys of spec/behavior-vectors.json, so the signature is the vector schema.
     */
    @SuppressWarnings("java:S107")
    private static NebulaEngine build(JsonNode vectors, RefreshTokenStore store, AtomicLong now,
                                      long absoluteTtl, long idleTtl, long grace,
                                      List<String> kids, String activeKid) {
        Map<String, String> peppers = new LinkedHashMap<>();
        for (String kid : kids) peppers.put(kid, vectors.get("peppers").get(kid).asText());

        NebulaEngine.Config cfg = new NebulaEngine.Config();
        cfg.peppers = peppers;
        cfg.activeKid = activeKid;
        cfg.store = store;
        cfg.absoluteTtlSeconds = absoluteTtl;
        cfg.idleTtlSeconds = idleTtl;
        cfg.reuseGraceSeconds = grace;
        cfg.clock = now::get;
        return new NebulaEngine(cfg);
    }

    private static JsonNode setting(JsonNode defaults, JsonNode override, String name) {
        if (override != null && override.has(name)) return override.get(name);
        return defaults.get(name);
    }

    private static List<String> strings(JsonNode array) {
        List<String> out = new ArrayList<>();
        array.forEach(node -> out.add(node.asText()));
        return out;
    }

    private static AssertionError fail(JsonNode scenario, int index, String message) {
        List<String> requirements = strings(scenario.get("requirements"));
        return new AssertionError("[" + scenario.get("id").asText() + "] step " + index
                + " (" + String.join(", ", requirements) + "): " + message);
    }

    // --- store ---------------------------------------------------------------

    /**
     * Wraps the reference store so a scenario can force one compare-and-set to
     * lose, which is how the CONFLICT scenarios reproduce a concurrent refresh
     * deterministically ([N-17], [N-18]).
     */
    static final class ControllableStore implements RefreshTokenStore {

        final MemoryRefreshTokenStore inner = new MemoryRefreshTokenStore();
        private final Set<String> failNext = ConcurrentHashMap.newKeySet();

        void failNextCas(String method) {
            if (!Arrays.asList("markRotated", "revokeIfActive").contains(method)) {
                throw new IllegalArgumentException("not a compare-and-set: " + method);
            }
            failNext.add(method);
        }

        @Override
        public TokenRecord findBySelector(String selector) {
            return inner.findBySelector(selector);
        }

        @Override
        public void insert(TokenRecord row) {
            inner.insert(row);
        }

        @Override
        public boolean markRotated(String selector, TokenStatus fromStatus, long rotatedAt,
                                   String replacedBySelector) {
            if (failNext.remove("markRotated")) return false;
            return inner.markRotated(selector, fromStatus, rotatedAt, replacedBySelector);
        }

        @Override
        public boolean revokeIfActive(String selector) {
            if (failNext.remove("revokeIfActive")) return false;
            return inner.revokeIfActive(selector);
        }

        @Override
        public int revokeFamily(String familyId) {
            return inner.revokeFamily(familyId);
        }

        @Override
        public int revokeUser(String userId) {
            return inner.revokeUser(userId);
        }
    }
}
