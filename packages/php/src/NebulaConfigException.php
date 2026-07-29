<?php

declare(strict_types=1);

namespace NebulaToken;

use InvalidArgumentException;

/**
 * A caller mistake: invalid engine configuration (§5), or a device identifier
 * supplied to issue() that is not valid UTF-8 ([N-12]).
 *
 * This is the native error channel of [N-20], never a protocol outcome: no
 * §7 error code is ever raised. It extends InvalidArgumentException so that
 * existing `catch (InvalidArgumentException)` handlers keep working.
 */
final class NebulaConfigException extends InvalidArgumentException
{
    public function __construct(string $message)
    {
        parent::__construct('[NEBULA] ' . $message);
    }
}
