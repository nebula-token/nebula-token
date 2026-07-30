<?php

declare(strict_types=1);

namespace NebulaToken;

/** Result of NebulaEngine::issue() ([N-25]). */
final readonly class IssueResult
{
    /**
     * @param int $expiresAt     Unix seconds ([N-2]) — the family's fixed absolute deadline.
     * @param int $idleExpiresAt Unix seconds ([N-2]) — this token's sliding idle deadline.
     */
    public function __construct(
        public string $token,
        public string $userId,
        public string $familyId,
        public int $generation,
        public int $expiresAt,
        public int $idleExpiresAt,
    ) {
    }

    /**
     * [N-14]: the token embeds the raw verifier, so the default rendering of
     * this object would put the whole secret into `var_dump()`, a `dd()` and
     * every framework debug page. Redacting here is the only place that can
     * stop it, because the caller never opts in.
     *
     * @return array<string, string|int>
     */
    public function __debugInfo(): array
    {
        return [
            'token' => '[redacted]',
            'userId' => $this->userId,
            'familyId' => $this->familyId,
            'generation' => $this->generation,
            'expiresAt' => $this->expiresAt,
            'idleExpiresAt' => $this->idleExpiresAt,
        ];
    }
}
