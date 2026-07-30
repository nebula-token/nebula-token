<?php

declare(strict_types=1);

namespace NebulaToken;

/** Record status (§3). */
enum TokenStatus: string
{
    case Active = 'active';
    case Rotated = 'rotated';
    case Revoked = 'revoked';
}
