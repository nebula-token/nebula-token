<?php

declare(strict_types=1);

namespace NebulaToken\Examples;

use NebulaToken\RefreshTokenStore;
use NebulaToken\TokenRecord;
use NebulaToken\TokenStatus;
use PDO;

/**
 * Production-style SQL store for NEBULA — PDO example (PostgreSQL/MySQL/SQLite).
 *
 * Best practices demonstrated: prepared statements only; lookups keyed on the
 * non-secret selector ([N-45]); the two compare-and-set writes expressed as
 * conditional UPDATEs whose affected-row count is the return value ([N-17],
 * [N-18]); rotated/revoked rows kept until the family's absolute deadline
 * because they are what powers reuse detection ([N-15]); deleteExpired() for
 * periodic GC.
 *
 * ERRMODE_EXCEPTION is set deliberately: a store failure must reach the caller
 * as an exception, never as a `false` that the engine would read as a lost race
 * ([N-20]).
 *
 * Wrap each refresh request in one transaction at the call site
 * ($pdo->beginTransaction() → $engine->refresh() → commit) so that insert +
 * markRotated are atomic ([N-22]); the engine's compensation in [N-34] step 5
 * covers the case where they are not.
 *
 * Schema: docs/STORE.md. This file lives in examples/ and is not autoloaded by
 * the published package.
 */
final class PdoRefreshTokenStore implements RefreshTokenStore
{
    private const COLS = 'selector, verifier_hash, kid, family_id, generation, user_id, '
        . 'device_id_hash, created_at, family_expires_at, idle_expires_at, status, '
        . 'rotated_at, replaced_by_selector';

    public function __construct(private readonly PDO $pdo)
    {
        $this->pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    }

    public function findBySelector(string $selector): ?TokenRecord
    {
        $st = $this->pdo->prepare('SELECT ' . self::COLS . ' FROM refresh_tokens WHERE selector = ?');
        $st->execute([$selector]);
        $row = $st->fetch(PDO::FETCH_ASSOC);
        if ($row === false) {
            return null;
        }

        return new TokenRecord(
            selector: $row['selector'],
            verifierHash: $row['verifier_hash'],
            kid: $row['kid'],
            familyId: $row['family_id'],
            generation: (int) $row['generation'],
            userId: $row['user_id'],
            deviceIdHash: $row['device_id_hash'],
            createdAt: (int) $row['created_at'],
            familyExpiresAt: (int) $row['family_expires_at'],
            idleExpiresAt: (int) $row['idle_expires_at'],
            status: TokenStatus::from($row['status']),
            rotatedAt: $row['rotated_at'] === null ? null : (int) $row['rotated_at'],
            replacedBySelector: $row['replaced_by_selector'],
        );
    }

    public function insert(TokenRecord $r): void
    {
        $st = $this->pdo->prepare(
            'INSERT INTO refresh_tokens (' . self::COLS . ') VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)'
        );
        $st->execute([
            $r->selector, $r->verifierHash, $r->kid, $r->familyId, $r->generation, $r->userId,
            $r->deviceIdHash, $r->createdAt, $r->familyExpiresAt, $r->idleExpiresAt,
            $r->status->value, $r->rotatedAt, $r->replacedBySelector,
        ]);
    }

    /**
     * Compare-and-set ([N-17]): the `AND status = ?` clause is the whole point.
     * Without it two concurrent refreshes both write, and the family forks into
     * two independently valid lineages.
     */
    public function markRotated(
        string $selector,
        TokenStatus $fromStatus,
        int $rotatedAt,
        string $replacedBySelector,
    ): bool {
        $st = $this->pdo->prepare(
            "UPDATE refresh_tokens SET status='rotated', rotated_at=?, replaced_by_selector=? "
            . 'WHERE selector=? AND status=?'
        );
        $st->execute([$rotatedAt, $replacedBySelector, $selector, $fromStatus->value]);

        return $st->rowCount() === 1;
    }

    /** Compare-and-set ([N-18]). */
    public function revokeIfActive(string $selector): bool
    {
        $st = $this->pdo->prepare(
            "UPDATE refresh_tokens SET status='revoked' WHERE selector=? AND status='active'"
        );
        $st->execute([$selector]);

        return $st->rowCount() === 1;
    }

    public function revokeFamily(string $familyId): int
    {
        return $this->revokeWhere('family_id', $familyId);
    }

    public function revokeUser(string $userId): int
    {
        return $this->revokeWhere('user_id', $userId);
    }

    /** Operational helper: GC families past their absolute deadline ([N-15]). */
    public function deleteExpired(int $now): int
    {
        $st = $this->pdo->prepare('DELETE FROM refresh_tokens WHERE family_expires_at <= ?');
        $st->execute([$now]);

        return $st->rowCount();
    }

    /**
     * [N-19] wants the number of records *changed*, which is also what makes
     * the operation idempotent. The `status <> 'revoked'` predicate is what
     * keeps the count honest on MySQL, whose rowCount() reports matched rows
     * when PDO::MYSQL_ATTR_FOUND_ROWS is enabled.
     */
    private function revokeWhere(string $column, string $value): int
    {
        $st = $this->pdo->prepare(
            "UPDATE refresh_tokens SET status='revoked' WHERE $column=? AND status <> 'revoked'"
        );
        $st->execute([$value]);

        return $st->rowCount();
    }
}
