package dev.nebulatoken;

/**
 * The server-side record -- one row per issued token ([N-10]).
 *
 * <p>Immutable, so a store may hand the same instance to several threads and
 * the engine can never mutate what the store holds. The two state transitions a
 * store needs are {@link #rotated} and {@link #revoked}, which return new
 * instances.
 *
 * <p>Nothing here is a raw secret: {@code verifierHash} and {@code deviceIdHash}
 * are keyed digests, so the generated {@code toString} is safe to log ([N-14]).
 * The token itself and the raw device identifier never reach this type.
 *
 * @param selector           primary key; the only token-derived value that may be indexed ([N-45])
 * @param verifierHash       lowercase hex HMAC-SHA-256(pepper[kid], verifier bytes)
 * @param kid                pepper id used for BOTH hashes on this row
 * @param familyId           lowercase hex of 16 CSPRNG bytes, fixed at login
 * @param generation         0 at issue, +1 per rotation
 * @param userId             owner
 * @param deviceIdHash       lowercase hex HMAC-SHA-256(pepper[kid], "device:" + deviceId), or null when unbound
 * @param createdAt          issue time of this record, unix seconds ([N-2])
 * @param familyExpiresAt    absolute deadline, fixed at login; MUST never be extended
 * @param idleExpiresAt      sliding deadline: min(now + idleTtl, familyExpiresAt)
 * @param status             active / rotated / revoked
 * @param rotatedAt          set on first rotation; a grace retry MUST keep the original value ([N-30])
 * @param replacedBySelector selector of the successor record
 */
public record TokenRecord(
        String selector,
        String verifierHash,
        String kid,
        String familyId,
        int generation,
        String userId,
        String deviceIdHash,
        long createdAt,
        long familyExpiresAt,
        long idleExpiresAt,
        TokenStatus status,
        Long rotatedAt,
        String replacedBySelector) {

    /** This record, rotated. Used by stores implementing the [N-17] compare-and-set. */
    public TokenRecord rotated(long newRotatedAt, String successorSelector) {
        return new TokenRecord(selector, verifierHash, kid, familyId, generation, userId,
                deviceIdHash, createdAt, familyExpiresAt, idleExpiresAt,
                TokenStatus.ROTATED, newRotatedAt, successorSelector);
    }

    /**
     * This record, revoked. {@code rotatedAt} and {@code replacedBySelector} are
     * carried over untouched -- revocation must not erase the rotation lineage
     * that reuse detection reads ([N-15]).
     */
    public TokenRecord revoked() {
        return new TokenRecord(selector, verifierHash, kid, familyId, generation, userId,
                deviceIdHash, createdAt, familyExpiresAt, idleExpiresAt,
                TokenStatus.REVOKED, rotatedAt, replacedBySelector);
    }
}
