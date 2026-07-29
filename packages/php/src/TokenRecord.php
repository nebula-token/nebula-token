<?php

declare(strict_types=1);

namespace NebulaToken;

/**
 * Server-side record — one row per issued token ([N-10]).
 *
 * Immutable: a store hands out snapshots and applies its own writes, so no
 * caller can mutate a row it was merely shown. The lifecycle transitions are
 * the two `with*` helpers below.
 */
final readonly class TokenRecord
{
    /**
     * @param string      $verifierHash Lowercase hex HMAC — never the raw verifier ([N-14]).
     * @param string|null $deviceIdHash Lowercase hex HMAC, or null when unbound.
     * @param int         $createdAt    Unix seconds ([N-2]).
     */
    public function __construct(
        public string $selector,
        public string $verifierHash,
        public string $kid,
        public string $familyId,
        public int $generation,
        public string $userId,
        public ?string $deviceIdHash,
        public int $createdAt,
        public int $familyExpiresAt,
        public int $idleExpiresAt,
        public TokenStatus $status = TokenStatus::Active,
        public ?int $rotatedAt = null,
        public ?string $replacedBySelector = null,
    ) {
    }

    /** The `rotated` transition. On a grace retry `$rotatedAt` keeps its original value ([N-10]). */
    public function asRotated(int $rotatedAt, string $replacedBySelector): self
    {
        return new self(
            $this->selector, $this->verifierHash, $this->kid, $this->familyId,
            $this->generation, $this->userId, $this->deviceIdHash, $this->createdAt,
            $this->familyExpiresAt, $this->idleExpiresAt, TokenStatus::Rotated,
            $rotatedAt, $replacedBySelector,
        );
    }

    /** The `revoked` transition: status only — `replacedBySelector` is retained ([N-15]). */
    public function asRevoked(): self
    {
        return new self(
            $this->selector, $this->verifierHash, $this->kid, $this->familyId,
            $this->generation, $this->userId, $this->deviceIdHash, $this->createdAt,
            $this->familyExpiresAt, $this->idleExpiresAt, TokenStatus::Revoked,
            $this->rotatedAt, $this->replacedBySelector,
        );
    }
}
