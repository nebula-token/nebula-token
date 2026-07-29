package dev.nebulatoken;

/**
 * The outcome of {@link NebulaEngine#refresh} -- a closed sum type, returned as
 * a value and never thrown ([N-29]).
 *
 * <p>Sealed, so on JDK 21 and later a {@code switch} over it is checked
 * exhaustive by the compiler:
 *
 * <pre>{@code
 * String access = switch (engine.refresh(presented, deviceId)) {
 *     case RefreshResult.Success s -> mintAccessToken(s);
 *     case RefreshResult.Failure f -> deny(f.error());
 * };
 * }</pre>
 *
 * On JDK 17 the same shape works with {@code instanceof} patterns. Note that the
 * exhaustiveness is over this type, not over {@link ErrorCode}, which is
 * explicitly open to future additions ([N-40]).
 */
public sealed interface RefreshResult permits RefreshResult.Success, RefreshResult.Failure {

    /** Convenience discriminator for call sites that do not pattern-match. */
    boolean ok();

    /**
     * The presented token was exchanged for its successor.
     *
     * @param token          the NEW wire token; the presented one is now dead
     * @param userId         owner
     * @param familyId       unchanged across the rotation
     * @param generation     predecessor's generation + 1
     * @param expiresAt      the family's fixed absolute deadline, unix seconds ([N-2])
     * @param idleExpiresAt  the successor's sliding idle deadline, unix seconds ([N-2])
     */
    record Success(
            String token,
            String userId,
            String familyId,
            int generation,
            long expiresAt,
            long idleExpiresAt) implements RefreshResult {

        @Override
        public boolean ok() {
            return true;
        }

        /**
         * Redacted for the same reason as {@link IssueResult#toString()}
         * ([N-14]/[N-46]): {@code token} embeds the raw verifier, and the
         * compiler-generated record {@code toString} is what a logging call or
         * a string concatenation reaches for. {@link #token()} still returns
         * it.
         */
        @Override
        public String toString() {
            return "Success[token=<redacted>, userId=" + userId
                    + ", familyId=" + familyId
                    + ", generation=" + generation
                    + ", expiresAt=" + expiresAt
                    + ", idleExpiresAt=" + idleExpiresAt + "]";
        }
    }

    /**
     * The presented token was refused. No access token may be issued.
     *
     * <p>{@code userId} and {@code familyId} are populated whenever the engine
     * resolved a record -- every code except {@link ErrorCode#MALFORMED},
     * {@link ErrorCode#UNKNOWN_KID} and {@link ErrorCode#NOT_FOUND} -- and are
     * {@code null} otherwise. That is what lets a REUSE_DETECTED or
     * DEVICE_MISMATCH event be attributed to a session in your monitoring
     * without a second lookup of a token you were told never to log ([N-39]).
     */
    record Failure(ErrorCode error, String userId, String familyId) implements RefreshResult {

        /** A refusal reached before any record was resolved ([N-39]). */
        static Failure of(ErrorCode error) {
            return new Failure(error, null, null);
        }

        /** A refusal attributable to a resolved record ([N-39]). */
        static Failure of(ErrorCode error, TokenRecord stored) {
            return new Failure(error, stored.userId(), stored.familyId());
        }

        @Override
        public boolean ok() {
            return false;
        }
    }
}
