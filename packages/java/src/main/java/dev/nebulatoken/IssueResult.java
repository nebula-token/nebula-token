package dev.nebulatoken;

/**
 * The outcome of {@link NebulaEngine#issue} ([N-25]).
 *
 * <p>{@code issue} either produces this or throws: there is no failure variant,
 * because every way it can go wrong is either a caller mistake
 * ({@link NebulaConfigException}) or an infrastructure failure, and both belong
 * on the native error channel ([N-20]).
 *
 * @param token          the wire token; hand it to the client, never persist or log it ([N-14])
 * @param userId         owner
 * @param familyId       server-side session identifier, stable across every rotation
 * @param generation     always 0 for a freshly issued family
 * @param expiresAt      the family's fixed absolute deadline, unix seconds ([N-2])
 * @param idleExpiresAt  this token's sliding idle deadline, unix seconds ([N-2])
 */
public record IssueResult(
        String token,
        String userId,
        String familyId,
        int generation,
        long expiresAt,
        long idleExpiresAt) {

    /**
     * [N-14]/[N-46]: {@code token} embeds the raw verifier, so the
     * compiler-generated record {@code toString} would print a live credential
     * into every {@code log.info("issued {}", result)}, every string
     * concatenation and every exception message that captures this result --
     * the exact leak [N-14] forbids. The value is still available from
     * {@link #token()}; only the debug rendering is redacted.
     */
    @Override
    public String toString() {
        return "IssueResult[token=<redacted>, userId=" + userId
                + ", familyId=" + familyId
                + ", generation=" + generation
                + ", expiresAt=" + expiresAt
                + ", idleExpiresAt=" + idleExpiresAt + "]";
    }
}
