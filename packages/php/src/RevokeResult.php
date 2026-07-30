<?php

declare(strict_types=1);

namespace NebulaToken;

/**
 * Result of NebulaEngine::revokeToken() ([N-36]).
 *
 * Revocation by token is authenticated, so it reports the same failure codes as
 * the first four steps of a refresh; `revoked` is the number of records the
 * store changed.
 *
 * `userId` and `familyId` are populated on a failure too, whenever the engine
 * resolved a record, exactly as in {@see RefreshResult} ([N-39]).
 */
final readonly class RevokeResult
{
    private function __construct(
        public bool $ok,
        public ?string $userId,
        public ?string $familyId,
        public int $revoked,
        public ?ErrorCode $error,
    ) {
    }

    public static function success(string $userId, string $familyId, int $revoked): self
    {
        return new self(true, $userId, $familyId, $revoked, null);
    }

    /**
     * @param TokenRecord|null $record The affected record, when the engine got far
     *                                 enough to resolve one. [N-39] governs every
     *                                 failure result, not `refresh` alone: a
     *                                 VERIFIER_MISMATCH here is raised after the
     *                                 lookup, so it is attributable, while
     *                                 MALFORMED, UNKNOWN_KID and NOT_FOUND never
     *                                 carry identifiers.
     */
    public static function failure(ErrorCode $error, ?TokenRecord $record = null): self
    {
        return new self(false, $record?->userId, $record?->familyId, 0, $error);
    }
}
