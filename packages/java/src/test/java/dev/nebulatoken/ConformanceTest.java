package dev.nebulatoken;

import com.fasterxml.jackson.databind.JsonNode;
import org.junit.jupiter.api.Test;

import java.util.Base64;
import java.util.LinkedHashSet;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Shared conformance vectors -- spec/test-vectors.json ([N-47]).
 *
 * <p>Every section asserts that the number of cases it executed equals the
 * number published in the {@code counts} block, and that the section was not
 * empty: silently iterating zero cases is a conformance failure, not a pass
 * ([N-48]).
 */
class ConformanceTest {

    private static final JsonNode VECTORS = SpecVectors.load("test-vectors.json");

    @Test
    void specVersionMatchesThePublishedVectors() {
        assertEquals(VECTORS.get("spec_version").asInt(), Nebula.SPEC_VERSION);
    }

    @Test
    void constantsMatchTheSpecification() {
        JsonNode published = VECTORS.get("constants");
        assertNotNull(published, "the constants section must be present");
        Set<String> compared = new LinkedHashSet<>();

        compareText(published, compared, "prefix", Nebula.PREFIX);
        compareLong(published, compared, "selector_bytes", Nebula.SELECTOR_BYTES);
        compareLong(published, compared, "verifier_bytes", Nebula.VERIFIER_BYTES);
        compareLong(published, compared, "selector_chars", Nebula.SELECTOR_CHARS);
        compareLong(published, compared, "verifier_chars", Nebula.VERIFIER_CHARS);
        compareLong(published, compared, "max_kid_length", Nebula.MAX_KID_LENGTH);
        compareLong(published, compared, "max_token_length", Nebula.MAX_TOKEN_LENGTH);
        compareLong(published, compared, "min_pepper_length", Nebula.MIN_PEPPER_LENGTH);
        compareLong(published, compared, "default_absolute_ttl_seconds", Nebula.DEFAULT_ABSOLUTE_TTL);
        compareLong(published, compared, "default_idle_ttl_seconds", Nebula.DEFAULT_IDLE_TTL);
        compareLong(published, compared, "default_reuse_grace_seconds", Nebula.DEFAULT_REUSE_GRACE);

        // [N-4]/[N-48]: every constant the spec publishes is exposed and was
        // compared here -- not only the ones we happened to remember.
        Set<String> names = new LinkedHashSet<>();
        published.fieldNames().forEachRemaining(names::add);
        assertEquals(names, compared, "a published constant was never asserted");
    }

    @Test
    void verifierHashingVectors() {
        JsonNode section = VECTORS.get("verifier_hashing");
        int executed = 0;
        for (JsonNode v : section) {
            byte[] verifier = Base64.getUrlDecoder().decode(v.get("verifier_b64url").asText());
            assertEquals(v.get("expected_hmac_sha256_hex").asText(),
                    Nebula.hashVerifier(v.get("pepper").asText(), verifier),
                    v.get("id").asText() + ": " + v.get("note").asText());
            executed++;
        }
        assertExecuted(executed, "verifier_hashing");
    }

    @Test
    void deviceHashingVectors() {
        JsonNode section = VECTORS.get("device_hashing");
        int executed = 0;
        for (JsonNode v : section) {
            assertEquals(v.get("expected_hmac_sha256_hex").asText(),
                    Nebula.hashDeviceId(v.get("pepper").asText(), v.get("device_id").asText()),
                    v.get("id").asText() + ": " + v.get("note").asText());
            executed++;
        }
        assertExecuted(executed, "device_hashing");
    }

    @Test
    void parsingVectors() {
        JsonNode section = VECTORS.get("parsing");
        int executed = 0;
        for (JsonNode v : section) {
            String label = v.get("id").asText() + ": " + v.get("note").asText();
            Nebula.ParsedToken parsed = Nebula.parseToken(v.get("token").asText());
            if (v.get("valid").asBoolean()) {
                assertNotNull(parsed, label + " should parse");
                assertEquals(v.get("kid").asText(), parsed.kid(), label);
                assertEquals(v.get("selector").asText(), parsed.selector(), label);
                assertEquals(Nebula.VERIFIER_BYTES, parsed.verifier().length, label);
            } else {
                assertNull(parsed, label + " should be MALFORMED");
            }
            executed++;
        }
        assertExecuted(executed, "parsing");
    }

    /** [N-8]: parsing is total. Nothing below may raise. */
    @Test
    void parsingIsTotal() {
        String[] hostile = {
                null,
                "",
                " ",
                ".",
                "...",
                "\uD800",                                    // lone high surrogate
                "nbl.k1.\uD800\uD800\uD800.\uD800",
                "nbl.k1." + " ".repeat(22) + "." + "A".repeat(43),
                "nbl." + "k".repeat(10_000),
                ".".repeat(100_000),
                // Three NUL bytes, written as escapes: as literal control
                // characters they are invisible in every editor and a
                // "helpful" whitespace trim would silently delete the case.
                "nbl.k1.AAECAwQFBgcICQoLDA0ODw.\0\0\0",
        };
        for (String input : hostile) {
            assertNull(Nebula.parseToken(input),
                    "hostile input must be MALFORMED, not accepted: " + describe(input));
        }
    }

    /** The only token-shaped thing the engine mints must round-trip ([N-33], §2). */
    @Test
    void mintedTokensParse() {
        MemoryRefreshTokenStore store = new MemoryRefreshTokenStore();
        NebulaEngine.Config cfg = new NebulaEngine.Config();
        cfg.peppers = java.util.Map.of("k1", "test-pepper-0123456789abcdef0123456789abcdef");
        cfg.activeKid = "k1";
        cfg.store = store;
        NebulaEngine engine = new NebulaEngine(cfg);

        Set<String> seen = new LinkedHashSet<>();
        for (int i = 0; i < 200; i++) {
            String token = engine.issue("u1").token();
            assertTrue(seen.add(token), "the CSPRNG must not repeat a token");
            Nebula.ParsedToken parsed = Nebula.parseToken(token);
            assertNotNull(parsed);
            assertEquals("k1", parsed.kid());
            assertEquals(Nebula.SELECTOR_CHARS, parsed.selector().length());
        }
    }

    // --- helpers ------------------------------------------------------------

    private static void assertExecuted(int executed, String section) {
        assertFalse(executed == 0, "section " + section + " is absent or empty ([N-48])");
        assertEquals(VECTORS.get("counts").get(section).asInt(), executed,
                "executed count must equal the published count for " + section + " ([N-48])");
    }

    private static void compareText(JsonNode published, Set<String> compared, String name, String actual) {
        assertTrue(published.has(name), name + " missing from the published constants");
        assertEquals(published.get(name).asText(), actual, name);
        compared.add(name);
    }

    private static void compareLong(JsonNode published, Set<String> compared, String name, long actual) {
        assertTrue(published.has(name), name + " missing from the published constants");
        assertEquals(published.get(name).asLong(), actual, name);
        compared.add(name);
    }

    private static String describe(String input) {
        if (input == null) return "null";
        return input.length() > 40 ? input.substring(0, 40) + "... (" + input.length() + " chars)" : input;
    }
}
