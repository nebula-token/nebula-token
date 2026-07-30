package dev.nebulatoken;

import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.BrokenBarrierException;
import java.util.concurrent.CyclicBarrier;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicLong;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Language-specific tests: properties that cannot be expressed as portable
 * behavior vectors -- real thread concurrency, a store that throws, byte-versus
 * -character lengths, and the configuration surface.
 *
 * <p>All cross-language behaviour lives in spec/behavior-vectors.json and is
 * exercised by {@link BehaviorVectorsTest}. Nothing here duplicates it.
 */
class EngineTest {

    private static final String PEPPER = "pepper-one-0123456789abcdef0123456789ab";
    private static final String HASH = "a".repeat(64);
    private static final long T0 = 1_700_000_000L;

    private static NebulaEngine.Config config(RefreshTokenStore store, AtomicLong now) {
        NebulaEngine.Config cfg = new NebulaEngine.Config();
        cfg.peppers = Map.of("k1", PEPPER);
        cfg.activeKid = "k1";
        cfg.store = store;
        cfg.clock = now::get;
        return cfg;
    }

    // --- Constant-time comparison ([N-31]) ----------------------------------

    @Test
    void constantTimeEqualHexRejectsAnythingThatIsNot64LowercaseHexCharacters() {
        assertTrue(Nebula.constantTimeEqualHex(HASH, HASH));
        assertFalse(Nebula.constantTimeEqualHex(HASH, "b".repeat(64)));

        // Every case below would compare EQUAL under a lenient hex decode that
        // stops at the first invalid character, or under HexFormat.parseHex,
        // which accepts upper case and throws on the rest.
        assertFalse(Nebula.constantTimeEqualHex(HASH, HASH.toUpperCase(java.util.Locale.ROOT)),
                "case must not be folded");
        assertFalse(Nebula.constantTimeEqualHex(HASH, HASH + "   "), "space-padded CHAR column");
        assertFalse(Nebula.constantTimeEqualHex(HASH, HASH.substring(0, 60) + "    "),
                "space-padded to width after truncation");
        assertFalse(Nebula.constantTimeEqualHex(HASH, HASH + "\n"), "trailing newline");
        assertFalse(Nebula.constantTimeEqualHex(HASH.substring(0, 63), HASH.substring(0, 63)),
                "truncated column is never equal, not even to itself");
        assertFalse(Nebula.constantTimeEqualHex("abc", "abc"), "short operands");
        assertFalse(Nebula.constantTimeEqualHex("", ""), "empty is never equal");
    }

    @Test
    void constantTimeEqualHexNeverThrows() {
        String[] hostile = {null, "", " ", "zz", " ".repeat(64), "\uD800".repeat(64), HASH + HASH};
        for (String a : hostile) {
            assertFalse(Nebula.constantTimeEqualHex(a, HASH), "operand " + (a == null ? "null" : "?"));
            assertFalse(Nebula.constantTimeEqualHex(HASH, a));
            assertFalse(Nebula.constantTimeEqualHex(a, a));
        }
    }

    @Test
    void aStoredHashCorruptedAfterTheFactFailsClosedInsteadOfVerifying() {
        MemoryRefreshTokenStore store = new MemoryRefreshTokenStore();
        NebulaEngine engine = new NebulaEngine(config(store, new AtomicLong(T0)));
        String token = engine.issue("u1").token();

        // The same row, but an ETL job upper-cased the hash column.
        TokenRecord row = store.all().get(0);
        String corruptedSelector = "x".repeat(Nebula.SELECTOR_CHARS);
        store.insert(new TokenRecord(corruptedSelector,
                row.verifierHash().toUpperCase(java.util.Locale.ROOT), row.kid(), row.familyId(),
                row.generation(), row.userId(), row.deviceIdHash(), row.createdAt(),
                row.familyExpiresAt(), row.idleExpiresAt(), TokenStatus.ACTIVE, null, null));

        String[] parts = token.split("\\.", -1);
        RefreshResult res = engine.refresh(
                parts[0] + "." + parts[1] + "." + corruptedSelector + "." + parts[3]);

        assertEquals(ErrorCode.VERIFIER_MISMATCH,
                assertInstanceOf(RefreshResult.Failure.class, res).error());
    }

    // --- Concurrency ([N-17], [N-34], [N-35]) -------------------------------

    /**
     * Forces the genuine race the compare-and-set exists for: every racer reads
     * the same {@code active} row before any of them writes. Without the barrier
     * the threads would serialise by luck and the test would prove nothing.
     */
    private static final class BarrierStore implements RefreshTokenStore {
        private final RefreshTokenStore inner;
        private final CyclicBarrier gate;

        BarrierStore(RefreshTokenStore inner, CyclicBarrier gate) {
            this.inner = inner;
            this.gate = gate;
        }

        @Override
        public TokenRecord findBySelector(String selector) {
            TokenRecord stored = inner.findBySelector(selector);
            try {
                gate.await(10, TimeUnit.SECONDS);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new IllegalStateException(e);
            } catch (BrokenBarrierException | TimeoutException e) {
                throw new IllegalStateException(e);
            }
            return stored;
        }

        @Override
        public void insert(TokenRecord row) {
            inner.insert(row);
        }

        @Override
        public boolean markRotated(String s, TokenStatus from, long at, String next) {
            return inner.markRotated(s, from, at, next);
        }

        @Override
        public boolean revokeIfActive(String selector) {
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

    private static void raceRefreshes(int racers) throws Exception {
        MemoryRefreshTokenStore store = new MemoryRefreshTokenStore();
        AtomicLong now = new AtomicLong(T0);
        String token = new NebulaEngine(config(store, now)).issue("u1").token();

        NebulaEngine engine = new NebulaEngine(
                config(new BarrierStore(store, new CyclicBarrier(racers)), now));

        ExecutorService pool = Executors.newFixedThreadPool(racers);
        List<Future<RefreshResult>> futures = new ArrayList<>();
        try {
            for (int i = 0; i < racers; i++) futures.add(pool.submit(() -> engine.refresh(token)));
        } finally {
            pool.shutdown();
        }
        assertTrue(pool.awaitTermination(30, TimeUnit.SECONDS), "racers did not finish");

        int successes = 0;
        for (Future<RefreshResult> future : futures) {
            RefreshResult res = future.get();
            if (res instanceof RefreshResult.Success) {
                successes++;
            } else {
                // [N-35]: the losers are told to retry, not that they were robbed.
                assertEquals(ErrorCode.CONFLICT,
                        assertInstanceOf(RefreshResult.Failure.class, res).error());
            }
        }

        assertEquals(1, successes, "exactly one refresh may win the compare-and-set");
        assertEquals(1, store.all().stream().filter(r -> r.status() == TokenStatus.ACTIVE).count(),
                "the family must not fork into two live lineages");
        // Predecessor + one successor per racer; the losers' successors were
        // cleaned up rather than left dangling as active rows ([N-34] step 5).
        assertEquals(1 + racers, store.all().size());
        assertEquals(racers - 1L,
                store.all().stream().filter(r -> r.status() == TokenStatus.REVOKED).count());
    }

    @Test
    void twoConcurrentRefreshesOfTheSameTokenNeverForkTheFamily() throws Exception {
        raceRefreshes(2);
    }

    @Test
    void aBurstOfConcurrentRefreshesStillLeavesExactlyOneActiveRecord() throws Exception {
        raceRefreshes(16);
    }

    // --- Store failures fail closed ([N-20]) --------------------------------

    /** A store whose infrastructure is down reports it by throwing, never by a value. */
    private static final class ExplodingStore implements RefreshTokenStore {
        final MemoryRefreshTokenStore inner = new MemoryRefreshTokenStore();
        private final String failOn;

        ExplodingStore(String failOn) {
            this.failOn = failOn;
        }

        private void guard(String method) {
            if (method.equals(failOn)) throw new IllegalStateException("database is on fire");
        }

        @Override
        public TokenRecord findBySelector(String selector) {
            guard("findBySelector");
            return inner.findBySelector(selector);
        }

        @Override
        public void insert(TokenRecord row) {
            guard("insert");
            inner.insert(row);
        }

        @Override
        public boolean markRotated(String s, TokenStatus from, long at, String next) {
            guard("markRotated");
            return inner.markRotated(s, from, at, next);
        }

        @Override
        public boolean revokeIfActive(String selector) {
            guard("revokeIfActive");
            return inner.revokeIfActive(selector);
        }

        @Override
        public int revokeFamily(String familyId) {
            guard("revokeFamily");
            return inner.revokeFamily(familyId);
        }

        @Override
        public int revokeUser(String userId) {
            guard("revokeUser");
            return inner.revokeUser(userId);
        }
    }

    @Test
    void aFailingInsertMustNotHandBackATokenForStateThatWasNeverWritten() {
        NebulaEngine engine = new NebulaEngine(
                config(new ExplodingStore("insert"), new AtomicLong(T0)));
        assertThrows(IllegalStateException.class, () -> engine.issue("u1"));
    }

    @Test
    void aFailingRevokeFamilyMustNotBeReportedAsASuccessfulRevocation() {
        ExplodingStore store = new ExplodingStore("revokeFamily");
        NebulaEngine engine = new NebulaEngine(config(store, new AtomicLong(T0)));
        String token = engine.issue("u1").token();
        assertTrue(engine.refresh(token).ok());

        // The replay must attempt a family revocation. The exception propagates
        // rather than being swallowed into a confident REUSE_DETECTED, which
        // would tell the operator a family was burned when it was not.
        assertThrows(IllegalStateException.class, () -> engine.refresh(token));
    }

    @Test
    void aFailingCompareAndSetMustNotBeMistakenForALostRace() {
        ExplodingStore store = new ExplodingStore("markRotated");
        NebulaEngine engine = new NebulaEngine(config(store, new AtomicLong(T0)));
        String token = engine.issue("u1").token();
        // A thrown markRotated is not CONFLICT: CONFLICT is a statement about
        // the data, and nothing here knows what the data says ([N-20]).
        assertThrows(IllegalStateException.class, () -> engine.refresh(token));
    }

    @Test
    void aFailingLookupIsNotNotFound() {
        ExplodingStore store = new ExplodingStore("findBySelector");
        NebulaEngine engine = new NebulaEngine(config(store, new AtomicLong(T0)));
        String token = new NebulaEngine(config(store.inner, new AtomicLong(T0))).issue("u1").token();
        assertThrows(IllegalStateException.class, () -> engine.refresh(token));
        assertThrows(IllegalStateException.class, () -> engine.revokeToken(token));
    }

    // --- Configuration (§5, [N-23], [N-24]) ---------------------------------

    @Test
    void constructorValidation() {
        MemoryRefreshTokenStore store = new MemoryRefreshTokenStore();

        assertThrows(NebulaConfigException.class, () -> {
            NebulaEngine.Config cfg = config(store, new AtomicLong(T0));
            cfg.peppers = Map.of("k1", "short");
            new NebulaEngine(cfg);
        }, "pepper below the floor");

        assertThrows(NebulaConfigException.class, () -> {
            NebulaEngine.Config cfg = config(store, new AtomicLong(T0));
            cfg.activeKid = "nope";
            new NebulaEngine(cfg);
        }, "activeKid absent from peppers");

        assertThrows(NebulaConfigException.class, () -> {
            NebulaEngine.Config cfg = config(store, new AtomicLong(T0));
            cfg.peppers = Map.of("k.1", PEPPER);
            cfg.activeKid = "k.1";
            new NebulaEngine(cfg);
        }, "a '.' in the kid would make the token unparseable");

        assertThrows(NebulaConfigException.class, () -> {
            NebulaEngine.Config cfg = config(store, new AtomicLong(T0));
            cfg.peppers = Map.of("", PEPPER);
            cfg.activeKid = "";
            new NebulaEngine(cfg);
        }, "empty kid");

        assertThrows(NebulaConfigException.class, () -> {
            NebulaEngine.Config cfg = config(store, new AtomicLong(T0));
            cfg.peppers = Map.of("k".repeat(Nebula.MAX_KID_LENGTH + 1), PEPPER);
            cfg.activeKid = "k".repeat(Nebula.MAX_KID_LENGTH + 1);
            new NebulaEngine(cfg);
        }, "kid beyond MAX_KID_LENGTH");

        assertThrows(NebulaConfigException.class, () -> {
            NebulaEngine.Config cfg = config(store, new AtomicLong(T0));
            cfg.absoluteTtlSeconds = 0;
            new NebulaEngine(cfg);
        });

        assertThrows(NebulaConfigException.class, () -> {
            NebulaEngine.Config cfg = config(store, new AtomicLong(T0));
            cfg.idleTtlSeconds = -5;
            new NebulaEngine(cfg);
        });

        assertThrows(NebulaConfigException.class, () -> {
            NebulaEngine.Config cfg = config(store, new AtomicLong(T0));
            cfg.reuseGraceSeconds = -1;
            new NebulaEngine(cfg);
        });

        assertThrows(NebulaConfigException.class, () -> {
            NebulaEngine.Config cfg = config(store, new AtomicLong(T0));
            cfg.store = null;
            new NebulaEngine(cfg);
        });

        // [N-11] a pepper with no UTF-8 encoding is not a usable HMAC key.
        // Each of these is well over the byte floor, so only the encoding rule
        // can reject it -- and it must, because String.getBytes(UTF_8) would
        // silently substitute '?' here while Node substitutes U+FFFD, giving
        // one configured value two different HMAC keys.
        for (String illFormed : new String[] {
                "\uD800".repeat(40),
                "\uDC00" + PEPPER,
                PEPPER + "\uD800"}) {
            assertThrows(NebulaConfigException.class, () -> {
                NebulaEngine.Config cfg = config(store, new AtomicLong(T0));
                cfg.peppers = Map.of("k1", illFormed);
                new NebulaEngine(cfg);
            }, "a pepper with no UTF-8 encoding must fail construction");
        }
    }

    @Test
    void minPepperLengthCountsBytesNotCharacters() {
        MemoryRefreshTokenStore store = new MemoryRefreshTokenStore();

        // U+65E5: 16 characters, 48 UTF-8 bytes. A character-counting check
        // would reject this perfectly adequate key ([N-1]).
        String wide = "日".repeat(16);
        assertEquals(16, wide.length());
        NebulaEngine.Config wideCfg = config(store, new AtomicLong(T0));
        wideCfg.peppers = Map.of("k1", wide);
        assertNotNull(new NebulaEngine(wideCfg), "48 bytes is above the floor");

        NebulaEngine.Config narrowCfg = config(store, new AtomicLong(T0));
        narrowCfg.peppers = Map.of("k1", "a".repeat(Nebula.MIN_PEPPER_LENGTH - 1));
        assertThrows(NebulaConfigException.class, () -> new NebulaEngine(narrowCfg),
                "31 ASCII characters are 31 bytes, one short");
    }

    @Test
    void thePepperMapIsCopiedSoMutatingTheCallersMapCannotWeakenTheEngine() {
        MemoryRefreshTokenStore store = new MemoryRefreshTokenStore();
        Map<String, String> peppers = new HashMap<>();
        peppers.put("k1", PEPPER);

        NebulaEngine.Config cfg = config(store, new AtomicLong(T0));
        cfg.peppers = peppers;
        NebulaEngine engine = new NebulaEngine(cfg);

        peppers.put("k1", "x"); // would otherwise key the HMAC with a one-byte secret
        peppers.clear();
        cfg.activeKid = "k2";   // and repoint the active kid at nothing

        String token = engine.issue("u1").token();
        assertEquals(Nebula.hashVerifier(PEPPER, Nebula.parseToken(token).verifier()),
                store.all().get(0).verifierHash(), "[N-24]");
        assertTrue(engine.refresh(token).ok());
    }

    // --- Device identifiers ([N-11], [N-12], [N-14]) ------------------------

    @Test
    void issueRejectsADeviceIdThatIsNotValidUnicodeAtTheCallSite() {
        NebulaEngine engine = new NebulaEngine(
                config(new MemoryRefreshTokenStore(), new AtomicLong(T0)));
        // [N-12]: at issue the value comes from the application, so this is a
        // caller error, not a protocol outcome.
        assertThrows(NebulaConfigException.class, () -> engine.issue("u1", "\uD800"));
    }

    @Test
    void hashDeviceIdAppliesNoNormalisationTrimmingOrCaseFolding() {
        assertNotEquals(Nebula.hashDeviceId(PEPPER, "Café"),   // NFC
                Nebula.hashDeviceId(PEPPER, "Café"),           // NFD
                "NFC and NFD must not be conflated ([N-11])");
        assertNotEquals(Nebula.hashDeviceId(PEPPER, "x"), Nebula.hashDeviceId(PEPPER, " x"));
        assertNotEquals(Nebula.hashDeviceId(PEPPER, "x"), Nebula.hashDeviceId(PEPPER, "X"));
        assertNotEquals(Nebula.hashDeviceId(PEPPER, ""), Nebula.hashDeviceId(PEPPER, " "));
    }

    @Test
    void absentAndEmptyDeviceIdentifiersAreDifferentBindings() {
        MemoryRefreshTokenStore store = new MemoryRefreshTokenStore();
        NebulaEngine engine = new NebulaEngine(config(store, new AtomicLong(T0)));

        assertNull(store.findBySelector(
                        Nebula.parseToken(engine.issue("u1", null).token()).selector()).deviceIdHash(),
                "absent means unbound");
        assertNotNull(store.findBySelector(
                        Nebula.parseToken(engine.issue("u1", "").token()).selector()).deviceIdHash(),
                "the empty string is a real binding ([N-25])");
    }

    @Test
    void noRawSecretAppearsInAnythingTheEngineStores() {
        MemoryRefreshTokenStore store = new MemoryRefreshTokenStore();
        NebulaEngine engine = new NebulaEngine(config(store, new AtomicLong(T0)));
        String token = engine.issue("u1", "devA").token();

        String dump = store.all().toString();
        assertFalse(dump.contains(token.split("\\.", -1)[3]), "raw verifier");
        assertFalse(dump.contains("devA"), "raw device identifier");
        assertFalse(dump.contains(PEPPER), "pepper");

        TokenRecord row = store.all().get(0);
        assertTrue(row.verifierHash().matches("[0-9a-f]{64}"), "lowercase hex only ([N-13])");
        assertTrue(row.deviceIdHash().matches("[0-9a-f]{64}"));
        assertTrue(row.familyId().matches("[0-9a-f]{32}"));

        // The parsed token carries the raw verifier; its toString must not.
        assertFalse(Nebula.parseToken(token).toString().contains(token.split("\\.", -1)[3]),
                "[N-14] forbids the verifier in any toString");
    }

    /**
     * [N-14]/[N-46]: the results the engine hands back carry the wire token,
     * which embeds the raw verifier. A record's compiler-generated
     * {@code toString} prints every component, and that is what
     * {@code log.info("issued {}", result)} and every string concatenation
     * reach for -- so the credential lands in the log file of anyone who logs a
     * result. Both types therefore redact it.
     */
    @Test
    void noResultTypeRendersTheRawTokenInItsDebugRepresentation() {
        NebulaEngine engine = new NebulaEngine(
                config(new MemoryRefreshTokenStore(), new AtomicLong(T0)));

        IssueResult issued = engine.issue("u1");
        String issuedVerifier = issued.token().split("\\.", -1)[3];
        assertFalse(issued.toString().contains(issuedVerifier),
                "IssueResult.toString leaks the verifier: " + issued);
        assertFalse(issued.toString().contains(issued.token()), "IssueResult.toString leaks the token");
        assertTrue(issued.toString().contains(issued.familyId()),
                "the non-secret fields must still be renderable for debugging");

        RefreshResult.Success ok =
                assertInstanceOf(RefreshResult.Success.class, engine.refresh(issued.token()));
        String rotatedVerifier = ok.token().split("\\.", -1)[3];
        assertFalse(ok.toString().contains(rotatedVerifier),
                "RefreshResult.Success.toString leaks the verifier: " + ok);
        assertFalse(ok.toString().contains(ok.token()), "RefreshResult.Success.toString leaks the token");
        assertTrue(ok.toString().contains(ok.familyId()),
                "the non-secret fields must still be renderable for debugging");

        // Implicit concatenation is the realistic leak, not an explicit call.
        assertFalse(("issued " + issued + " then " + ok).contains(issuedVerifier), "[N-14]");

        // A failure carries no token, so its generated toString is already safe.
        RefreshResult.Failure replay =
                assertInstanceOf(RefreshResult.Failure.class, engine.refresh(issued.token()));
        assertFalse(replay.toString().contains(issuedVerifier), "[N-14]");
    }

    // --- Result shape ([N-2], [N-39]) ---------------------------------------

    @Test
    void timestampsAreUnixSecondsDerivedFromTheInjectedClock() {
        AtomicLong now = new AtomicLong(T0);
        NebulaEngine.Config cfg = config(new MemoryRefreshTokenStore(), now);
        cfg.absoluteTtlSeconds = 100;
        cfg.idleTtlSeconds = 40;
        NebulaEngine engine = new NebulaEngine(cfg);

        IssueResult issued = engine.issue("u1");
        assertEquals(T0 + 100, issued.expiresAt());
        assertEquals(T0 + 40, issued.idleExpiresAt());
        assertEquals(0, issued.generation());
        assertEquals("u1", issued.userId());

        now.addAndGet(30);
        RefreshResult.Success refreshed =
                assertInstanceOf(RefreshResult.Success.class, engine.refresh(issued.token()));
        assertEquals(T0 + 100, refreshed.expiresAt(), "the absolute deadline never moves");
        assertEquals(T0 + 70, refreshed.idleExpiresAt(), "the sliding deadline renews");

        now.addAndGet(30);
        RefreshResult.Success clamped =
                assertInstanceOf(RefreshResult.Success.class, engine.refresh(refreshed.token()));
        assertEquals(T0 + 100, clamped.idleExpiresAt(), "idle is clamped to the ceiling");
    }

    @Test
    void failuresCarryUserIdAndFamilyIdOnceARecordIsResolved() {
        NebulaEngine engine = new NebulaEngine(
                config(new MemoryRefreshTokenStore(), new AtomicLong(T0)));
        IssueResult issued = engine.issue("u1");
        engine.refresh(issued.token());

        RefreshResult.Failure replay =
                assertInstanceOf(RefreshResult.Failure.class, engine.refresh(issued.token()));
        assertEquals(ErrorCode.REUSE_DETECTED, replay.error());
        assertEquals("u1", replay.userId());
        assertEquals(issued.familyId(), replay.familyId());

        // Before a record is resolved there is nothing to attribute ([N-39]).
        RefreshResult.Failure malformed =
                assertInstanceOf(RefreshResult.Failure.class, engine.refresh("garbage"));
        assertNull(malformed.userId());
        assertNull(malformed.familyId());
    }

    // --- Store hygiene -------------------------------------------------------

    @Test
    void theInMemoryStoreRefusesADuplicateSelectorRatherThanOverwritingARecord() {
        MemoryRefreshTokenStore store = new MemoryRefreshTokenStore();
        TokenRecord row = new TokenRecord("A".repeat(22), HASH, "k1", "f", 0, "u1", null,
                0, 1, 1, TokenStatus.ACTIVE, null, null);
        store.insert(row);
        assertThrows(IllegalStateException.class, () -> store.insert(row));
    }

    @Test
    void deleteExpiredOnlyRemovesRecordsPastTheFamilyDeadline() {
        MemoryRefreshTokenStore store = new MemoryRefreshTokenStore();
        AtomicLong now = new AtomicLong(T0);
        NebulaEngine.Config cfg = config(store, now);
        cfg.absoluteTtlSeconds = 100;
        cfg.idleTtlSeconds = 100;
        NebulaEngine engine = new NebulaEngine(cfg);

        engine.refresh(engine.issue("u1").token());
        // [N-15]: rotated rows are what reuse detection reads. Dropping them one
        // second early turns every replay into NOT_FOUND.
        assertEquals(0, store.deleteExpired(T0 + 99));
        assertEquals(2, store.all().size());
        assertEquals(2, store.deleteExpired(T0 + 100));
    }
}
