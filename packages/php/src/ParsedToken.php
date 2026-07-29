<?php

declare(strict_types=1);

namespace NebulaToken;

/** The three fields of a well-formed wire token (§2). */
final readonly class ParsedToken
{
    /**
     * @param string $verifier The raw 32 secret bytes — never persist or log
     *                         them ([N-14]).
     */
    public function __construct(
        public string $kid,
        public string $selector,
        public string $verifier,
    ) {
    }

    /**
     * [N-14]: the raw verifier must not appear in a debug representation.
     * var_dump() and friends honour this; deliberately, there is no __toString.
     *
     * @return array<string, string>
     */
    public function __debugInfo(): array
    {
        return ['kid' => $this->kid, 'selector' => $this->selector, 'verifier' => '[redacted]'];
    }
}
