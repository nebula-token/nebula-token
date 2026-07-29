---
name: nebula-token-php
description: Integrate NEBULA opaque rotating refresh tokens in a PHP backend. Use when adding login sessions, refresh-token rotation, reuse detection, token revocation, or when replacing hand-rolled or JWT-based refresh tokens. Covers engine setup, endpoints, production store, and security rules.
---

# Integrating nebula-token (PHP)

NEBULA is an implementation profile of RFC 9700 (OAuth 2.0 Security BCP) for
refresh tokens: opaque tokens (`nbl.{kid}.{selector}.{verifier}` — pure
entropy, no claims), rotation on every use, reuse detection with family
revocation, hashed storage, optional device binding. Package: `nebula-token/nebula-token`.
Normative behavior: `SPECIFICATION.md` in the repository root.

## Install

```
composer require nebula-token/nebula-token
```

## Core integration

```php
use NebulaToken\{NebulaEngine, MemoryRefreshTokenStore, ErrorCode};

$engine = new NebulaEngine(
    peppers: ['k1' => getenv('NEBULA_PEPPER_K1')],   // >= 32 BYTES, from env
    activeKid: 'k1',
    store: new MemoryRefreshTokenStore(),            // dev only — PDO store in prod
    // reuseGraceSeconds defaults to 0 (strict); raising it costs detectability.
);

// Login endpoint
$issued = $engine->issue($userId, $deviceId);        // $issued->token

// Refresh endpoint
$result = $engine->refresh($presentedToken, $deviceId);
if ($result->ok) {
    // $result->token is the NEW refresh token; the presented one is now dead
} else {
    match ($result->error) {
        ErrorCode::ReuseDetected, ErrorCode::DeviceMismatch =>
            // security event: the family is already revoked — alert, force re-login
            $this->alert($result->userId, $result->familyId),
        ErrorCode::Conflict =>
            // a concurrent refresh won the compare-and-set: nothing was rotated,
            // retry the refresh once with the same token
            $this->retryOnce(),
        default => $this->requireLogin(),
    };
}

// Logout / compromise
$revoked = $engine->revokeToken($token); // authenticated: proves the verifier
if (!$revoked->ok) {
    // it REFUSED (Malformed / UnknownKid / NotFound / VerifierMismatch) and
    // nothing was revoked — do not report the user as logged out ([N-36])
}
$engine->revokeFamily($familyId);      // administrative, by server-side id → int
$engine->revokeAllForUser($userId);    // administrative, by server-side id → int
```

The API is synchronous — a natural fit for PHP-FPM request lifecycles.

## Integration checklist

1. **Pepper**: generate with `openssl rand -base64 48`; store in env/KMS, never in code or DB. It is a cryptographic key, not a passphrase: the 32-byte floor is a guard against misconfiguration, not a target. Key it as `k1` now so future rotation (add `k2`, switch `activeKid`) is zero-downtime.
2. **Store**: for production implement the six-method `RefreshTokenStore` contract over your database. `markRotated` and `revokeIfActive` are **compare-and-set**: their conditional `UPDATE … WHERE selector=? AND status=?` must return `rowCount() === 1`, never a hardcoded `true`, or two concurrent refreshes fork the family. Start from `examples/PdoRefreshTokenStore.php` (schema in `docs/STORE.md`). The in-memory store is **not for production** ([N-21]): its state is per-process and lost on restart, so reuse detection does not survive a deploy and does not work behind more than one instance.
3. **Login endpoint**: authenticate credentials → `issue` → set the token in an `httpOnly; Secure; SameSite=Strict` cookie scoped to the refresh path. Never return it in a JSON body read by browser JS, never localStorage.
4. **Refresh endpoint**: read cookie → `refresh` → on success set the NEW token in the cookie and mint a short-lived access token (5–15 min). Wrap the call in one DB transaction so insert + markRotated commit atomically.
5. **Error handling**: `$result->error` is an `ErrorCode`; failures also carry `->userId` and `->familyId` once a record was resolved — every code except `Malformed`, `UnknownKid` and `NotFound` — so a security event needs no second lookup of a token you were told never to log ([N-39]). Every failure means "no access token issued". `ErrorCode::Conflict` (`CONFLICT`) is transient: retry the refresh once ([N-35]). Treat the enum as **open** — always give `match` a `default` arm, since a future minor version may add a code. Never return the code to the client; log it and answer `401` with no detail.
6. **Store failures**: anything the store throws propagates out of the engine. Let it: that is what fails closed. Never catch it and continue as if the write happened.
7. **Logout**: `revokeToken` (one session, requires the token itself) / `revokeFamily` / `revokeAllForUser` (password change, compromise — the caller authorises them). They do not return the same shape, and the difference is load-bearing: `revokeToken` returns a `RevokeResult` that **can refuse** (`Malformed`, `UnknownKid`, `NotFound`, `VerifierMismatch`) ([N-36]) — check `->ok` and read the count from `->revoked`; calling it and answering `204` reports a logout that never happened and leaves the session alive. The two administrative calls take no token, cannot refuse, and return the `int` count directly.
8. **Device binding (optional)**: pass a stable device identifier at issue AND every refresh. `null` (unbound) and `''` (bound to the empty string) are different things. Strong on native apps (Keychain/Keystore-held ID); weaker on web where the ID travels with the token.
9. **GC**: run the store's `deleteExpired` helper periodically; keep rotated/revoked rows until the family's absolute deadline — they are what makes reuse detection work.

## Security rules (non-negotiable)

- Never log a full token, the verifier, the pepper or the raw device identifier, and never put them in an error value ([N-14]/[N-46]); the selector is public and may be logged as a correlation id.
- Never store or transmit the raw verifier or raw deviceId server-side — the engine already guarantees the store only sees hashes; don't work around it.
- Treat store errors as refresh failures (fail closed).
- Default TTLs (30d absolute / 7d idle) suit consumer apps; for high-assurance (NIST AAL2), configure ~12h absolute / 30min idle.
- `reuseGraceSeconds` **defaults to 0 (strict), and that is the recommendation** ([N-30]). A non-zero window buys retry tolerance for clients that sent a refresh and never got the response, and it costs detectability: for that many seconds after a rotation, a thief holding the rotated predecessor who acts before the legitimate client is **served a valid token**, the legitimate client is evicted with `REVOKED`, and **no `REUSE_DETECTED` is raised**. Keep it as small as your clients need, and if you enable it, alert on the `REVOKED` rate.

## Common mistakes to avoid

- Reusing the presented refresh token after a successful refresh — it is dead; always persist the returned one.
- Retrying a failed refresh with the same token in client retry loops — outside the grace window this burns the family (by design). `CONFLICT` is the one code that is meant to be retried.
- Implementing `markRotated` as an unconditional `UPDATE` — it re-opens the race the compare-and-set exists to close.
- Deleting rotated/revoked rows early (a Redis TTL at rotation, a nightly `DELETE WHERE status <> 'active'`) — it silently turns every replay into `NOT_FOUND` and disables reuse detection.
- Putting user data or expiry claims "inside" the token — NEBULA tokens are opaque by design; claims belong in the short-lived access token.
