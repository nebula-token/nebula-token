package dev.nebulatoken;

/**
 * The storage contract ([N-16]) -- exactly six capabilities, implemented over
 * PostgreSQL, Redis, DynamoDB or whatever you already run. See
 * {@code examples/JdbcRefreshTokenStore.java} for a SQL template and
 * {@code docs/STORE.md} for the schema.
 *
 * <p><b>Failure channel ([N-20]).</b> The return values below carry protocol
 * outcomes only. An infrastructure failure -- unreachable database, timeout,
 * constraint violation -- MUST be thrown as an unchecked exception. It MUST NOT
 * be converted into a {@code false}, a {@code 0} or a {@code null}: those are
 * statements about the data, and reporting one for a call that never reached
 * the database is how an engine ends up returning a token for state that was
 * never written, or reporting a revocation that did not happen.
 *
 * <p><b>Retention ([N-15]).</b> Rows MUST survive, with {@code status} and
 * {@code replacedBySelector} intact, until at least their
 * {@code familyExpiresAt}. A Redis TTL applied at rotation, or a nightly
 * {@code DELETE WHERE status <> 'active'}, disables reuse detection entirely.
 *
 * <p>Implementations SHOULD be safe for concurrent use, and SHOULD run the
 * rotation write pair (insert of the successor, then {@code markRotated} of the
 * predecessor) in one transaction ([N-22]).
 */
public interface RefreshTokenStore {

    /** @return the record for this selector, or {@code null} if there is none. */
    TokenRecord findBySelector(String selector);

    /** Persist a newly minted record. */
    void insert(TokenRecord row);

    /**
     * Compare-and-set ([N-17]). Apply the rotation write <b>if and only if</b>
     * the stored record's current status equals {@code fromStatus}, and report
     * whether it was applied.
     *
     * <p>In SQL:
     * <pre>{@code
     * UPDATE refresh_tokens
     *    SET status='rotated', rotated_at=?, replaced_by_selector=?
     *  WHERE selector=? AND status=?
     * }</pre>
     * returning {@code affectedRows == 1}.
     *
     * <p>Returning {@code true} unconditionally is non-conforming, and not in a
     * theoretical way: it re-opens the race in which two concurrent refreshes
     * both observe {@code active}, both mint a successor, and the family forks
     * into two independently valid lineages -- which is exactly the state reuse
     * detection exists to make impossible. Two browser tabs are enough.
     *
     * @return whether the write was applied
     */
    boolean markRotated(String selector, TokenStatus fromStatus, long rotatedAt, String replacedBySelector);

    /**
     * Compare-and-set ([N-18]): set {@code status = revoked} if and only if the
     * current status is {@code active}, and report whether it did.
     *
     * @return whether the write was applied
     */
    boolean revokeIfActive(String selector);

    /**
     * Revoke every record of the family. Idempotent ([N-19]).
     *
     * @return how many records this call changed
     */
    int revokeFamily(String familyId);

    /**
     * Revoke every record of the user. Idempotent ([N-19]).
     *
     * @return how many records this call changed
     */
    int revokeUser(String userId);
}
