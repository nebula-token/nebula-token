package dev.nebulatoken;

/**
 * The outcome of {@link NebulaEngine#revokeToken} -- a closed sum type, returned
 * as a value and never thrown ([N-29]).
 *
 * <p>Revocation by token is an <em>authenticated</em> operation ([N-36]): it
 * proves the verifier exactly as {@code refresh} does, so the failure variants
 * are the first four of &sect;6.2. It succeeds whatever the record's status, so
 * a client can log out with a token that has already been rotated or revoked.
 */
public sealed interface RevokeResult permits RevokeResult.Success, RevokeResult.Failure {

    /** Convenience discriminator for call sites that do not pattern-match. */
    boolean ok();

    /**
     * The family was revoked.
     *
     * @param revoked how many records this call changed; 0 means the family was
     *                already fully revoked, which is a success ([N-19])
     */
    record Success(String userId, String familyId, int revoked) implements RevokeResult {

        @Override
        public boolean ok() {
            return true;
        }
    }

    /**
     * Nothing was revoked.
     *
     * <p>As in {@link RefreshResult.Failure}, {@code userId} and
     * {@code familyId} are populated whenever a record was resolved -- here that
     * means {@link ErrorCode#VERIFIER_MISMATCH}, the one refusal that arrives
     * after the lookup -- and are {@code null} otherwise ([N-39]).
     */
    record Failure(ErrorCode error, String userId, String familyId) implements RevokeResult {

        static Failure of(ErrorCode error) {
            return new Failure(error, null, null);
        }

        static Failure of(ErrorCode error, TokenRecord stored) {
            return new Failure(error, stored.userId(), stored.familyId());
        }

        @Override
        public boolean ok() {
            return false;
        }
    }
}
