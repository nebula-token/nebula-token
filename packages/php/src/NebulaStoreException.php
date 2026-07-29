<?php

declare(strict_types=1);

namespace NebulaToken;

use RuntimeException;

/**
 * A store could not carry out a write it was asked to carry out.
 *
 * This is the native error channel of [N-20], never a protocol outcome: a
 * `false`, a `0` or a `null` is a statement about the data, and returning one
 * for a call that never reached the database is how an engine ends up handing
 * back a token for state it did not write, or reporting a revocation that did
 * not happen. An exception is how the engine fails closed.
 *
 * The reference in-memory store raises it for a duplicate selector. Your own
 * store implementation is welcome to raise it too, but is not required to: the
 * contract in {@see RefreshTokenStore} is that infrastructure failures *throw*,
 * not that they throw this class. A PDOException propagating untouched is
 * equally conforming — see examples/PdoRefreshTokenStore.php.
 *
 * It extends RuntimeException so that existing `catch (RuntimeException)`
 * handlers, and the two failure channels described in docs/STORE.md, keep
 * working unchanged.
 */
final class NebulaStoreException extends RuntimeException
{
    public function __construct(string $message)
    {
        parent::__construct('[NEBULA] ' . $message);
    }
}
