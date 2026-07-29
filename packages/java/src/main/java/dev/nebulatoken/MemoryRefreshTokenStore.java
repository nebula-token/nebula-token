package dev.nebulatoken;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Reference in-memory store ([N-21]).
 *
 * <p><b>NOT FOR PRODUCTION.</b> State is per-process and lost on restart, so
 * reuse detection does not survive a deploy and does not work behind more than
 * one instance -- the two situations in which you most want it. Implement
 * {@link RefreshTokenStore} over your database instead; see
 * {@code examples/JdbcRefreshTokenStore.java} and {@code docs/STORE.md}.
 *
 * <p>Safe for concurrent use. {@link TokenRecord} is immutable and every
 * mutation goes through {@link ConcurrentHashMap#compute} on a single key, so
 * the compare-and-set methods really are atomic rather than
 * read-then-write-and-hope -- which is what makes this store usable as the
 * oracle for the concurrency tests.
 */
public final class MemoryRefreshTokenStore implements RefreshTokenStore {

    private final Map<String, TokenRecord> rows = new ConcurrentHashMap<>();

    @Override
    public TokenRecord findBySelector(String selector) {
        return selector == null ? null : rows.get(selector);
    }

    @Override
    public void insert(TokenRecord row) {
        if (rows.putIfAbsent(row.selector(), row) != null) {
            // A selector collision means the CSPRNG repeated 16 bytes, or a
            // caller re-inserted a record. Both are infrastructure-class faults:
            // throw rather than silently overwriting a live session ([N-20]).
            throw new IllegalStateException("[NEBULA] duplicate selector " + row.selector());
        }
    }

    @Override
    public boolean markRotated(String selector, TokenStatus fromStatus, long rotatedAt,
                               String replacedBySelector) {
        AtomicBoolean applied = new AtomicBoolean(false);
        rows.computeIfPresent(selector, (key, current) -> {
            if (current.status() != fromStatus) return current; // CAS lost ([N-17])
            applied.set(true);
            return current.rotated(rotatedAt, replacedBySelector);
        });
        return applied.get();
    }

    @Override
    public boolean revokeIfActive(String selector) {
        AtomicBoolean applied = new AtomicBoolean(false);
        rows.computeIfPresent(selector, (key, current) -> {
            if (current.status() != TokenStatus.ACTIVE) return current; // CAS lost ([N-18])
            applied.set(true);
            return current.revoked();
        });
        return applied.get();
    }

    @Override
    public int revokeFamily(String familyId) {
        return revokeWhere(row -> row.familyId().equals(familyId));
    }

    @Override
    public int revokeUser(String userId) {
        return revokeWhere(row -> row.userId().equals(userId));
    }

    /** Test helper: every record currently stored. Not part of the store contract. */
    public List<TokenRecord> all() {
        return new ArrayList<>(rows.values());
    }

    /**
     * Test helper: drop records whose family deadline has passed. Records MUST
     * NOT be dropped before {@code familyExpiresAt} ([N-15]).
     */
    public int deleteExpired(long now) {
        int n = 0;
        for (Map.Entry<String, TokenRecord> entry : rows.entrySet()) {
            if (now >= entry.getValue().familyExpiresAt() && rows.remove(entry.getKey(), entry.getValue())) {
                n++;
            }
        }
        return n;
    }

    /**
     * Already-revoked rows are not counted, which is what makes revocation
     * idempotent in the sense [N-19] requires: the second call changes nothing
     * and reports 0.
     */
    private int revokeWhere(java.util.function.Predicate<TokenRecord> match) {
        int n = 0;
        for (String selector : rows.keySet()) {
            AtomicBoolean changed = new AtomicBoolean(false);
            rows.computeIfPresent(selector, (key, current) -> {
                if (current.status() == TokenStatus.REVOKED || !match.test(current)) return current;
                changed.set(true);
                return current.revoked();
            });
            if (changed.get()) n++;
        }
        return n;
    }
}
