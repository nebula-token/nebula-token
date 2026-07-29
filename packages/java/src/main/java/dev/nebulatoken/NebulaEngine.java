package dev.nebulatoken;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.function.LongSupplier;

/**
 * The NEBULA engine -- SPECIFICATION.md &sect;5 and &sect;6.
 *
 * <p>Immutable after construction and safe to share across threads; as
 * thread-safe as the {@link RefreshTokenStore} behind it. The API is
 * synchronous by design: on JDK 21 a blocking store call inside a virtual
 * thread parks the carrier rather than occupying it, so there is nothing to buy
 * by returning futures.
 *
 * <p>Protocol outcomes come back as {@link RefreshResult} / {@link RevokeResult}
 * values; store failures propagate as unchecked exceptions and fail closed
 * ([N-20]). See the package documentation.
 */
public final class NebulaEngine {

    /**
     * Engine configuration (&sect;5). Fill in the fields and hand it to the
     * constructor, which validates and <b>copies</b> everything it needs
     * ([N-24]) -- mutating this object afterwards cannot change engine
     * behaviour.
     */
    public static final class Config {

        /**
         * Map kid -&gt; pepper secret. Each kid must match the {@code kid}
         * production of &sect;2 and each secret must have a UTF-8 encoding --
         * no unpaired surrogate ([N-11]) -- and be at least
         * {@link Nebula#MIN_PEPPER_LENGTH} <em>bytes of that encoding</em>.
         *
         * <p>A pepper is a cryptographic key, not a passphrase: generate it with
         * {@code openssl rand -base64 48} and hold it in an environment
         * variable, secret manager or KMS. The minimum length is a floor against
         * obvious misconfiguration, not a sufficient condition for security
         * ([N-23]).
         */
        public Map<String, String> peppers = new LinkedHashMap<>();

        /** kid used for newly minted tokens. Must be present in {@link #peppers}. */
        public String activeKid;

        /** Where records live. Required. */
        public RefreshTokenStore store;

        /** Must be &gt; 0. */
        public long absoluteTtlSeconds = Nebula.DEFAULT_ABSOLUTE_TTL;

        /** Must be &gt; 0. */
        public long idleTtlSeconds = Nebula.DEFAULT_IDLE_TTL;

        /**
         * Must be &ge; 0. Read [N-30] before raising it above the default of 0:
         * for this many seconds after a rotation, an adversary holding the
         * rotated predecessor who acts before the legitimate client is served a
         * valid token, the legitimate client is evicted with
         * {@link ErrorCode#REVOKED}, and no {@link ErrorCode#REUSE_DETECTED}
         * event is raised. It is a reliability-versus-detectability trade-off,
         * not a free knob.
         */
        public long reuseGraceSeconds = Nebula.DEFAULT_REUSE_GRACE;

        /** Injectable clock, unix seconds ([N-3]). */
        public LongSupplier clock = () -> Instant.now().getEpochSecond();
    }

    /** Platform CSPRNG ([N-43]). Thread-safe; failure to obtain randomness propagates. */
    private static final SecureRandom RANDOM = new SecureRandom();

    private final Map<String, String> peppers;
    private final String activeKid;
    private final RefreshTokenStore store;
    private final long absoluteTtl;
    private final long idleTtl;
    private final long reuseGrace;
    private final LongSupplier clock;

    public NebulaEngine(Config config) {
        if (config == null) throw new NebulaConfigException("config must not be null");
        if (config.store == null) throw new NebulaConfigException("store must not be null");
        if (config.peppers == null) throw new NebulaConfigException("peppers must not be null");

        // [N-24] copy FIRST, then validate the copy. Validating the caller's map
        // and keeping a reference to it would let a caller -- or a racing thread
        // -- swap in a one-byte secret after the checks passed.
        Map<String, String> copied = new LinkedHashMap<>(config.peppers);
        for (Map.Entry<String, String> e : copied.entrySet()) {
            String kid = e.getKey();
            if (kid == null || kid.isEmpty() || !Nebula.isB64Url(kid)
                    || Nebula.utf8Length(kid) > Nebula.MAX_KID_LENGTH) {
                throw new NebulaConfigException("kid \"" + kid + "\" must be 1-"
                        + Nebula.MAX_KID_LENGTH + " characters from [A-Za-z0-9_-]");
            }
            String secret = e.getValue();
            // [N-11] the HMAC key is the pepper encoded as UTF-8, and a Java
            // String is a UTF-16 code-unit sequence, so a secret holding an
            // unpaired surrogate -- which arrives trivially from a JSON secrets
            // file or a lenient UTF-16 decode -- has no UTF-8 encoding and is
            // not a usable key. String.getBytes(UTF_8) would silently
            // substitute '?', Node substitutes U+FFFD and Python refuses: three
            // different keys for the same configured value. §5 resolves it by
            // failing construction everywhere. The message never quotes the
            // secret ([N-14]).
            if (secret == null || !Nebula.isWellFormedUnicode(secret)) {
                throw new NebulaConfigException("pepper \"" + kid + "\" must be a string with a"
                        + " UTF-8 encoding (no unpaired surrogate)");
            }
            // [N-1] bytes of that encoding, not characters: 16 CJK characters
            // look long and are 48 bytes; 31 ASCII characters look long and are
            // 31. Measured on the encoded form the HMAC is actually keyed with,
            // so the floor and the key can never disagree.
            if (secret.getBytes(StandardCharsets.UTF_8).length < Nebula.MIN_PEPPER_LENGTH) {
                throw new NebulaConfigException("pepper \"" + kid + "\" must be at least "
                        + Nebula.MIN_PEPPER_LENGTH + " bytes"); // never echo the secret ([N-46])
            }
        }
        if (config.activeKid == null || !copied.containsKey(config.activeKid)) {
            throw new NebulaConfigException(
                    "activeKid \"" + config.activeKid + "\" not present in peppers");
        }
        if (config.absoluteTtlSeconds <= 0) {
            throw new NebulaConfigException("absoluteTtlSeconds must be positive");
        }
        if (config.idleTtlSeconds <= 0) {
            throw new NebulaConfigException("idleTtlSeconds must be positive");
        }
        if (config.reuseGraceSeconds < 0) {
            throw new NebulaConfigException("reuseGraceSeconds must be non-negative");
        }
        if (config.clock == null) throw new NebulaConfigException("clock must not be null");

        this.peppers = Map.copyOf(copied);
        this.activeKid = config.activeKid;
        this.store = config.store;
        this.absoluteTtl = config.absoluteTtlSeconds;
        this.idleTtl = config.idleTtlSeconds;
        this.reuseGrace = config.reuseGraceSeconds;
        this.clock = config.clock;
    }

    /** Issue the first token of a new family ([N-25]), unbound. Call at login. */
    public IssueResult issue(String userId) {
        return issue(userId, null);
    }

    /**
     * Issue the first token of a new family ([N-25]). Call at login.
     *
     * @param deviceId sender-binding identifier, or {@code null} for an unbound
     *     family. {@code null} and {@code ""} are different bindings: an empty
     *     string is a real device identifier that hashes like any other, and a
     *     later refresh presenting no identifier at all will fail against it.
     * @throws NebulaConfigException if {@code deviceId} is not valid Unicode.
     *     Here the value came from the application, so the defect surfaces at
     *     the call site rather than minting a binding nothing can satisfy
     *     ([N-12]).
     * @throws RuntimeException if the store fails; no token is returned for
     *     state that was not written ([N-20]).
     */
    public IssueResult issue(String userId, String deviceId) {
        if (deviceId != null && !Nebula.isWellFormedUnicode(deviceId)) {
            throw new NebulaConfigException("deviceId is not valid Unicode (unpaired surrogate)");
        }
        long now = clock.getAsLong();
        String familyId = randomHex(16);
        long familyExpiresAt = now + absoluteTtl;
        String deviceIdHash = deviceId != null ? Nebula.hashDeviceId(activePepper(), deviceId) : null;

        Minted minted = mint(userId, familyId, 0, deviceIdHash, familyExpiresAt, now);
        store.insert(minted.tokenRecord());

        return new IssueResult(minted.token(), userId, familyId, 0,
                familyExpiresAt, minted.tokenRecord().idleExpiresAt());
    }

    /** Exchange a refresh token for its successor ([N-26]), with no sender binding. */
    public RefreshResult refresh(String token) {
        return refresh(token, null);
    }

    /**
     * Exchange a refresh token for its successor ([N-26]).
     *
     * <p>The ten checks below run in the order the specification fixes, and the
     * first failure is returned. That order is observable and normative
     * ([N-28]): in particular the verifier proof precedes reuse handling, so a
     * rotated record presented with a wrong verifier reports
     * {@link ErrorCode#VERIFIER_MISMATCH} and revokes nothing -- otherwise
     * knowledge of a selector alone would let anyone destroy a session.
     *
     * @param deviceId the identifier presented by the client, or {@code null}.
     *     Attacker-controlled, so an invalid-Unicode value is a binding failure
     *     here, never an exception ([N-12]).
     */
    // java:S3776 cognitive complexity 16 against a threshold of 15. The two
    // parts worth extracting are already extracted -- handleReuse (step 5) and
    // rotate (step 10) -- which is the same split the TypeScript reference uses.
    // What remains is the [N-26] table itself: ten checks, in a normative and
    // observable order, each returning the first failure. Folding any of them
    // into a helper would move a step out of the list that the specification
    // numbers, and the numbering in the comments below is how a reader confirms
    // the order is right. The measurement is accurate; the shape is the point.
    @SuppressWarnings("java:S3776")
    public RefreshResult refresh(String token, String deviceId) {
        Nebula.ParsedToken parsed = Nebula.parseToken(token);                       // 1
        if (parsed == null) return RefreshResult.Failure.of(ErrorCode.MALFORMED);

        if (!peppers.containsKey(parsed.kid())) {                                   // 2
            return RefreshResult.Failure.of(ErrorCode.UNKNOWN_KID);
        }

        TokenRecord stored = store.findBySelector(parsed.selector());               // 3
        if (stored == null) return RefreshResult.Failure.of(ErrorCode.NOT_FOUND);

        // 4. Verifier proof, against the pepper of the RECORD's kid ([N-27]).
        String recordPepper = peppers.get(stored.kid());
        if (recordPepper == null) return RefreshResult.Failure.of(ErrorCode.UNKNOWN_KID);
        String presented = Nebula.hashVerifier(recordPepper, parsed.verifier());
        if (!Nebula.constantTimeEqualHex(presented, stored.verifierHash())) {
            return RefreshResult.Failure.of(ErrorCode.VERIFIER_MISMATCH, stored);   // no revocation ([N-28])
        }

        long now = clock.getAsLong();

        if (stored.status() == TokenStatus.ROTATED) {                               // 5
            return handleReuse(stored, recordPepper, deviceId, now);
        }
        if (stored.status() == TokenStatus.REVOKED) {                               // 6
            return RefreshResult.Failure.of(ErrorCode.REVOKED, stored);
        }

        if (now >= stored.familyExpiresAt()) {                                      // 7
            store.revokeFamily(stored.familyId());
            return RefreshResult.Failure.of(ErrorCode.EXPIRED_ABSOLUTE, stored);
        }
        if (now >= stored.idleExpiresAt()) {                                        // 8
            store.revokeFamily(stored.familyId());
            return RefreshResult.Failure.of(ErrorCode.EXPIRED_IDLE, stored);
        }

        if (stored.deviceIdHash() != null && !deviceMatches(stored, recordPepper, deviceId)) { // 9
            store.revokeFamily(stored.familyId());
            return RefreshResult.Failure.of(ErrorCode.DEVICE_MISMATCH, stored);
        }

        return rotate(stored, deviceId, now, TokenStatus.ACTIVE, now);              // 10
    }

    /**
     * Revoke the family a token belongs to ([N-36]).
     *
     * <p>Authenticated: steps 1-4 of {@link #refresh} run unchanged, because
     * &sect;3 designates the selector as a <em>public</em> lookup key -- it is
     * safe to index, it appears in logs, and it is recoverable from a database
     * dump that this specification otherwise renders inert. If revocation
     * accepted a selector alone, anyone who read one could terminate that
     * session. Administrative paths that legitimately have no token use
     * {@link #revokeFamily} and {@link #revokeAllForUser} instead ([N-37]).
     *
     * <p>Succeeds whatever the record's status, so a client can still log out
     * with a token that was already rotated or revoked.
     *
     * <p>Takes no device identifier and performs no sender-binding check
     * ([N-36] specifies steps 1-4 of [N-26] and no sender-binding step): logout
     * must keep working for a client that can no longer produce its device
     * identifier -- a cleared cookie, a reinstalled app, a stolen laptop being
     * disowned from another machine. A binding check here would turn "kill this
     * session" into "prove you are still the device holding it", which is the
     * opposite of the intent, and the operation is already authenticated by the
     * verifier proof below.
     *
     * @param token the refresh token presented by the client
     * @return the outcome, which may be a {@link RevokeResult.Failure}
     */
    public RevokeResult revokeToken(String token) {
        Nebula.ParsedToken parsed = Nebula.parseToken(token);
        if (parsed == null) return RevokeResult.Failure.of(ErrorCode.MALFORMED);
        if (!peppers.containsKey(parsed.kid())) return RevokeResult.Failure.of(ErrorCode.UNKNOWN_KID);

        TokenRecord stored = store.findBySelector(parsed.selector());
        if (stored == null) return RevokeResult.Failure.of(ErrorCode.NOT_FOUND);

        String recordPepper = peppers.get(stored.kid());
        if (recordPepper == null) return RevokeResult.Failure.of(ErrorCode.UNKNOWN_KID);
        String presented = Nebula.hashVerifier(recordPepper, parsed.verifier());
        if (!Nebula.constantTimeEqualHex(presented, stored.verifierHash())) {
            return RevokeResult.Failure.of(ErrorCode.VERIFIER_MISMATCH, stored);
        }

        int revoked = store.revokeFamily(stored.familyId());
        return new RevokeResult.Success(stored.userId(), stored.familyId(), revoked);
    }

    /**
     * Revoke a whole family by its server-side identifier ([N-37]). Requires no
     * token; the caller is responsible for authorising it. Idempotent.
     *
     * @return how many records were revoked
     */
    public int revokeFamily(String familyId) {
        return store.revokeFamily(familyId);
    }

    /**
     * Revoke every session of a user ([N-37]) -- password change, "log out all
     * devices", compromise response. Idempotent.
     *
     * @return how many records were revoked
     */
    public int revokeAllForUser(String userId) {
        return store.revokeUser(userId);
    }

    // --- Private -----------------------------------------------------------

    private RefreshResult handleReuse(TokenRecord stored, String recordPepper,
                                      String deviceId, long now) {
        // [N-30] preconditions 1-4 and 6. Condition 6 (now < familyExpiresAt) is
        // what stops a grace retry from minting a token past the family's
        // absolute deadline; condition 5 is the successor check just below.
        boolean withinGrace = reuseGrace > 0
                && stored.rotatedAt() != null
                && now - stored.rotatedAt() <= reuseGrace
                && stored.replacedBySelector() != null
                && now < stored.familyExpiresAt();

        if (withinGrace) {
            TokenRecord successor = store.findBySelector(stored.replacedBySelector());
            if (successor != null && successor.status() == TokenStatus.ACTIVE) {    // condition 5

                // Binding is checked before anything is written ([N-30] step 1).
                if (stored.deviceIdHash() != null && !deviceMatches(stored, recordPepper, deviceId)) {
                    store.revokeFamily(stored.familyId());
                    return RefreshResult.Failure.of(ErrorCode.DEVICE_MISMATCH, stored);
                }

                // Compare-and-set: exactly one concurrent retry may consume the
                // unused successor. The loser mints nothing ([N-30] step 2).
                if (!store.revokeIfActive(successor.selector())) {
                    return RefreshResult.Failure.of(ErrorCode.CONFLICT, stored);
                }

                // Original rotatedAt preserved: the window is anchored to the
                // first rotation and cannot be walked forward ([N-30] step 3).
                return rotate(stored, deviceId, now, TokenStatus.ROTATED, stored.rotatedAt());
            }
        }

        // Any other presentation of a rotated record is a theft signal.
        store.revokeFamily(stored.familyId());
        return RefreshResult.Failure.of(ErrorCode.REUSE_DETECTED, stored);
    }

    private RefreshResult rotate(TokenRecord stored, String deviceId, long now,
                                 TokenStatus fromStatus, long rotatedAt) {
        // Re-hash with the ACTIVE pepper, migrating the binding forward across a
        // pepper rotation ([N-33] step 4). Reachable with a non-null
        // deviceIdHash only after the binding check above succeeded, so deviceId
        // is known to be valid Unicode here.
        String deviceIdHash = (stored.deviceIdHash() != null && deviceId != null)
                ? Nebula.hashDeviceId(activePepper(), deviceId)
                : stored.deviceIdHash();

        Minted minted = mint(stored.userId(), stored.familyId(), stored.generation() + 1,
                deviceIdHash, stored.familyExpiresAt(), now);

        store.insert(minted.tokenRecord());

        boolean applied = store.markRotated(stored.selector(), fromStatus, rotatedAt,
                minted.tokenRecord().selector());
        if (!applied) {
            // [N-34] step 5: a concurrent refresh won the compare-and-set. Clean
            // up the successor we just inserted and report a retryable conflict.
            // Never a token, and nothing else is revoked ([N-35]).
            store.revokeIfActive(minted.tokenRecord().selector());
            return RefreshResult.Failure.of(ErrorCode.CONFLICT, stored);
        }

        return new RefreshResult.Success(minted.token(), stored.userId(), stored.familyId(),
                minted.tokenRecord().generation(), minted.tokenRecord().familyExpiresAt(),
                minted.tokenRecord().idleExpiresAt());
    }

    private record Minted(String token, TokenRecord tokenRecord) {}

    /** Mint a token and its record ([N-33]). */
    private Minted mint(String userId, String familyId, int generation,
                        String deviceIdHash, long familyExpiresAt, long now) {
        byte[] selectorBytes = new byte[Nebula.SELECTOR_BYTES];
        byte[] verifier = new byte[Nebula.VERIFIER_BYTES];
        RANDOM.nextBytes(selectorBytes);
        RANDOM.nextBytes(verifier);
        String selector = Nebula.b64url(selectorBytes);

        TokenRecord tokenRecord = new TokenRecord(
                selector,
                Nebula.hashVerifier(activePepper(), verifier),
                activeKid,
                familyId,
                generation,
                userId,
                deviceIdHash,
                now,
                familyExpiresAt,
                Math.min(now + idleTtl, familyExpiresAt),
                TokenStatus.ACTIVE,
                null,
                null);

        String token = Nebula.PREFIX + "." + activeKid + "." + selector + "." + Nebula.b64url(verifier);
        return new Minted(token, tokenRecord);
    }

    /**
     * Sender binding ([N-32]) against the pepper of the RECORD's kid, not the
     * active one -- the stored hash was computed under the former.
     */
    private boolean deviceMatches(TokenRecord stored, String recordPepper, String deviceId) {
        if (deviceId == null || stored.deviceIdHash() == null) return false;
        // [N-12] on the attacker-reachable path an invalid device identifier is
        // a binding failure, never an exception.
        if (!Nebula.isWellFormedUnicode(deviceId)) return false;
        return Nebula.constantTimeEqualHex(Nebula.hashDeviceId(recordPepper, deviceId),
                stored.deviceIdHash());
    }

    private String activePepper() {
        return peppers.get(activeKid);
    }

    private static String randomHex(int n) {
        byte[] buf = new byte[n];
        RANDOM.nextBytes(buf);
        return Nebula.hex(buf); // lowercase ([N-13])
    }
}
