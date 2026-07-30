<?php

declare(strict_types=1);

namespace NebulaToken;

/**
 * Reference store ([N-21]).
 *
 * A PHP request has a single thread of execution and none of the methods below
 * yields, so each compare-and-set is atomic with respect to the others within
 * one process.
 *
 * NOT FOR PRODUCTION: state lives in one PHP process and dies with the request,
 * so reuse detection does not survive the response, let alone a second FPM
 * worker. Implement {@see RefreshTokenStore} over your database instead — see
 * examples/PdoRefreshTokenStore.php and docs/STORE.md.
 */
final class MemoryRefreshTokenStore implements RefreshTokenStore
{
    /** @var array<string, TokenRecord> */
    private array $rows = [];

    public function findBySelector(string $selector): ?TokenRecord
    {
        return $this->rows[$selector] ?? null;
    }

    public function insert(TokenRecord $record): void
    {
        if (isset($this->rows[$record->selector])) {
            // A duplicate selector means the CSPRNG repeated itself or a caller
            // re-inserted a row: refuse rather than overwrite live state.
            // A dedicated type, not a bare RuntimeException: this is the [N-20]
            // native error channel, and a caller that wants to distinguish a
            // store refusal from any other runtime fault must be able to.
            throw new NebulaStoreException('duplicate selector');
        }
        $this->rows[$record->selector] = $record;
    }

    public function markRotated(
        string $selector,
        TokenStatus $fromStatus,
        int $rotatedAt,
        string $replacedBySelector,
    ): bool {
        $row = $this->rows[$selector] ?? null;
        if ($row === null || $row->status !== $fromStatus) {
            return false;
        }
        $this->rows[$selector] = $row->asRotated($rotatedAt, $replacedBySelector);

        return true;
    }

    public function revokeIfActive(string $selector): bool
    {
        $row = $this->rows[$selector] ?? null;
        if ($row === null || $row->status !== TokenStatus::Active) {
            return false;
        }
        $this->rows[$selector] = $row->asRevoked();

        return true;
    }

    public function revokeFamily(string $familyId): int
    {
        return $this->revokeWhere(static fn (TokenRecord $r): bool => $r->familyId === $familyId);
    }

    public function revokeUser(string $userId): int
    {
        return $this->revokeWhere(static fn (TokenRecord $r): bool => $r->userId === $userId);
    }

    /**
     * Test helper: every record currently stored. Not part of the store contract.
     *
     * @return list<TokenRecord>
     */
    public function all(): array
    {
        return array_values($this->rows);
    }

    /**
     * Test helper: drop records whose family deadline has passed ([N-15]).
     * Rotated and revoked rows before that point are what reuse detection reads.
     */
    public function deleteExpired(int $now): int
    {
        $n = 0;
        foreach ($this->rows as $selector => $row) {
            if ($now >= $row->familyExpiresAt) {
                unset($this->rows[$selector]);
                $n++;
            }
        }

        return $n;
    }

    /** @param callable(TokenRecord): bool $matches */
    private function revokeWhere(callable $matches): int
    {
        $n = 0;
        foreach ($this->rows as $selector => $row) {
            // Already-revoked rows are not counted: [N-19] asks for the number
            // of records changed, which is what makes the operation idempotent.
            if ($matches($row) && $row->status !== TokenStatus::Revoked) {
                $this->rows[$selector] = $row->asRevoked();
                $n++;
            }
        }

        return $n;
    }
}
