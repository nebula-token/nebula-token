<?php

declare(strict_types=1);

namespace NebulaToken;

/**
 * Storage contract ([N-16]) — six methods, implement over PDO / Redis / etc.
 * Synchronous, matching the PHP-FPM request lifecycle.
 *
 * **Two failure channels ([N-20]).** Protocol outcomes are the return values
 * below. Infrastructure failures — the store unreachable, a timeout, a
 * constraint violation — MUST be thrown (PDOException, RuntimeException, …),
 * MUST NOT be converted into a `false`/`0` return, and MUST NOT be swallowed.
 * An exception propagates out of the engine untouched, so the caller fails
 * closed: no token is returned for state that was not written, and no
 * revocation is reported that did not happen.
 */
interface RefreshTokenStore
{
    public function findBySelector(string $selector): ?TokenRecord;

    public function insert(TokenRecord $record): void;

    /**
     * Compare-and-set ([N-17]). Apply the rotation write **only if** the stored
     * record's status is still `$fromStatus`, and report whether it applied.
     *
     * SQL: `UPDATE … SET status='rotated', rotated_at=?, replaced_by_selector=?
     *       WHERE selector=? AND status=?` → `rowCount() === 1`.
     *
     * Returning `true` unconditionally is non-conforming: it re-opens the race
     * in which two concurrent refreshes both mint a successor and fork the
     * family into two independently valid lineages.
     */
    public function markRotated(
        string $selector,
        TokenStatus $fromStatus,
        int $rotatedAt,
        string $replacedBySelector,
    ): bool;

    /** Compare-and-set ([N-18]): revoke only if still `active`; report whether it did. */
    public function revokeIfActive(string $selector): bool;

    /** Revoke every record of the family. Returns how many changed; idempotent ([N-19]). */
    public function revokeFamily(string $familyId): int;

    /** Revoke every record of the user. Returns how many changed; idempotent ([N-19]). */
    public function revokeUser(string $userId): int;
}
