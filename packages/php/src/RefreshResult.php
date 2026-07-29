<?php

declare(strict_types=1);

namespace NebulaToken;

/**
 * Discriminated result of NebulaEngine::refresh() ([N-26]).
 *
 * Failures are values, never exceptions ([N-29]); infrastructure failures use
 * the native error channel instead ([N-20]).
 */
final readonly class RefreshResult
{
    /**
     * @param string|null $userId   Populated on failure too, whenever a record was resolved ([N-39]).
     * @param string|null $familyId Populated on failure too, whenever a record was resolved ([N-39]).
     * @param int|null    $generation    Successor generation, success only.
     * @param int|null    $expiresAt     Unix seconds ([N-2]), success only.
     * @param int|null    $idleExpiresAt Unix seconds ([N-2]), success only.
     */
    private function __construct(
        public bool $ok,
        public ?string $token,
        public ?string $userId,
        public ?string $familyId,
        public ?int $generation,
        public ?int $expiresAt,
        public ?int $idleExpiresAt,
        public ?ErrorCode $error,
    ) {
    }

    public static function success(TokenRecord $successor, string $token): self
    {
        return new self(
            true,
            $token,
            $successor->userId,
            $successor->familyId,
            $successor->generation,
            $successor->familyExpiresAt,
            $successor->idleExpiresAt,
            null,
        );
    }

    /**
     * @param TokenRecord|null $record The affected record, when the engine got far
     *                                 enough to resolve one. Every code except
     *                                 MALFORMED, UNKNOWN_KID and NOT_FOUND carries
     *                                 one, so a REUSE_DETECTED or DEVICE_MISMATCH
     *                                 event can be attributed to a user and a
     *                                 family without a second lookup of a token you
     *                                 were told never to log ([N-39]).
     */
    public static function failure(ErrorCode $error, ?TokenRecord $record = null): self
    {
        return new self(false, null, $record?->userId, $record?->familyId, null, null, null, $error);
    }

    /**
     * [N-14]: on success the token embeds the raw verifier, so the default
     * rendering of this object would put the whole secret into `var_dump()`, a
     * `dd()` and every framework debug page.
     *
     * @return array<string, string|int|bool|null>
     */
    public function __debugInfo(): array
    {
        return [
            'ok' => $this->ok,
            'token' => $this->token === null ? null : '[redacted]',
            'userId' => $this->userId,
            'familyId' => $this->familyId,
            'generation' => $this->generation,
            'expiresAt' => $this->expiresAt,
            'idleExpiresAt' => $this->idleExpiresAt,
            'error' => $this->error?->value,
        ];
    }
}
