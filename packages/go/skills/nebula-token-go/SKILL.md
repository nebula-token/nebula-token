---
name: nebula-token-go
description: Integrate NEBULA opaque rotating refresh tokens in a Go backend. Use when adding login sessions, refresh-token rotation, reuse detection, token revocation, or when replacing hand-rolled or JWT-based refresh tokens. Covers engine setup, endpoints, production store, and security rules.
---

# Integrating nebula-token (Go)

NEBULA is an implementation profile of RFC 9700 (OAuth 2.0 Security BCP) for
refresh tokens: opaque tokens (`nbl.{kid}.{selector}.{verifier}` — pure
entropy, no claims), rotation on every use, reuse detection with family
revocation, hashed storage, optional device binding. Package:
`github.com/nebula-token/nebula-token/packages/go`, imported as `nebulatoken`
— the package clause is not the last path element (the short name `nebula`
belongs to an unrelated overlay network), so always write the qualifier.
Normative behavior: `SPECIFICATION.md` in the repository root.

## Install

```
go get github.com/nebula-token/nebula-token/packages/go
```

```go
import nebulatoken "github.com/nebula-token/nebula-token/packages/go"
```

A submodule of the NEBULA monorepo: its versions are the directory-prefixed
tags `packages/go/vX.Y.Z`, not bare `vX.Y.Z` tags.

## Core integration

```go
engine, err := nebulatoken.NewEngine(nebulatoken.Config{
    Peppers:   map[string]string{"k1": os.Getenv("NEBULA_PEPPER_K1")}, // >= 32 BYTES
    ActiveKid: "k1",
    Store:     nebulatoken.NewMemoryRefreshTokenStore(), // dev only — SQL store in prod
    // ReuseGraceSeconds defaults to 0 (strict); raising it costs detectability.
})

// Login endpoint. deviceID is optional: nil = unbound, Device("") = bound to
// the empty identifier. They are different bindings.
issued, err := engine.Issue(ctx, userID, nebulatoken.Device(deviceID))

// Refresh endpoint
res, err := engine.Refresh(ctx, presentedToken, nebulatoken.Device(deviceID))
switch {
case err != nil:
    // Store failure: fail closed, issue no access token.
case res.OK:
    // res.Token is the NEW refresh token; the presented one is now dead.
case res.Error == nebulatoken.CodeConflict:
    // A concurrent refresh won the compare-and-set. Retry once.
case res.Error == nebulatoken.CodeReuseDetected, res.Error == nebulatoken.CodeDeviceMismatch:
    // Security event: family already revoked — alert, force re-login.
    // res.UserID / res.FamilyID identify the session; no second lookup ([N-39]).
default:
    // Every other code, including an unrecognised one, is a refusal.
}

// Logout / compromise. RevokeToken returns BOTH channels: err is the store,
// revoke is the protocol outcome, and it can refuse.
revoke, err := engine.RevokeToken(ctx, presentedToken)      // proves the verifier first
if err == nil && !revoke.OK {
    // REFUSED (revoke.Error): nothing was revoked, so this is not a logout ([N-36])
}
n, err := engine.RevokeFamily(ctx, familyID)                // administrative → count
n, err = engine.RevokeAllForUser(ctx, userID)               // administrative → count
```

Every method returns `error` for store failures — treat a store error as a
refresh failure (fail closed). Protocol outcomes are never returned as `error`.

## Integration checklist

1. **Pepper**: generate with `openssl rand -base64 48`; store in env/KMS, never in code or DB. Key it as `k1` now so a future rotation (add `k2`, switch `ActiveKid`) is zero-downtime. The 32-byte floor is measured in bytes, not characters.
2. **Store**: for production implement the six-method `RefreshTokenStore` over your database. Start from `examples/sqlstore/sqlstore.go` (schema in `docs/STORE.md`). `MarkRotated` and `RevokeIfActive` are compare-and-sets: the status predicate belongs in the `WHERE` clause and the answer is `RowsAffected`. Returning `true` unconditionally forks families under concurrency. The in-memory store is **not for production** ([N-21]): its state is per-process and lost on restart, so reuse detection does not survive a deploy and does not work behind more than one instance.
3. **Login endpoint**: authenticate credentials → `Issue` → set the token in an `httpOnly; Secure; SameSite=Strict` cookie scoped to the refresh path. Never return it in a JSON body read by browser JS, never localStorage.
4. **Refresh endpoint**: read cookie → `Refresh` → on success set the NEW token in the cookie and mint a short-lived access token (5–15 min). Wrap the call in one `*sql.Tx` so the insert and the mark-rotated commit atomically.
5. **Error handling**: `res.Error` carries the code (`nebulatoken.CodeReuseDetected`, …). Every failure means "no access token issued", and failures carry `res.UserID` / `res.FamilyID` whenever a record was resolved — every code except `MALFORMED`, `UNKNOWN_KID` and `NOT_FOUND` — so a security event needs no second lookup of a token you were told never to log ([N-39]). `REUSE_DETECTED` and `DEVICE_MISMATCH` additionally mean the family is already revoked — log a security event and alert. `CONFLICT` is transient: retry once ([N-35]). Always keep a `default` branch: the code set is open.
6. **Logout**: `RevokeToken` (one session, authenticated by the token itself) / `RevokeAllForUser` (password change, compromise). `RevokeFamily` and `RevokeAllForUser` take no token — authorise them yourself. The shapes differ, and the difference is load-bearing: `RevokeToken` returns `(*RevokeResult, error)` and the result **can refuse** (`MALFORMED`, `UNKNOWN_KID`, `NOT_FOUND`, `VERIFIER_MISMATCH`) ([N-36]) — check `revoke.OK` as well as `err`, and read the count from `revoke.Revoked`; checking only `err` reports a logout that never happened and leaves the session alive. The two administrative calls return `(int, error)` — the count directly, with no protocol refusal.
7. **Device binding (optional)**: pass a stable device identifier at issue AND at every refresh. Strong on native apps (Keychain/Keystore-held ID); weaker on web, where the ID travels with the token.
8. **GC**: run the store's `DeleteExpired` helper periodically; keep rotated and revoked rows until the family's absolute deadline — they are what powers reuse detection.

## Security rules (non-negotiable)

- Never log a full token, the verifier, the pepper or the raw device identifier, and never put them in an error value ([N-14]/[N-46]); the selector is public and may be logged as a correlation id.
- Never store or transmit the raw verifier or raw device identifier — the engine already guarantees the store only sees hashes; do not work around it.
- Treat store errors as refresh failures (fail closed).
- Default TTLs (30d absolute / 7d idle) suit consumer apps; for high-assurance (NIST AAL2), configure ~12h absolute / 30min idle.
- `ReuseGraceSeconds` **defaults to 0 (strict), and that is the recommendation** ([N-30]). A non-zero window buys retry tolerance for clients that sent a refresh and never got the response, and it costs detectability: for that many seconds after a rotation, a thief holding the rotated predecessor who acts before the legitimate client is **served a valid token**, the legitimate client is evicted with `REVOKED`, and **no `REUSE_DETECTED` is raised**. Keep it as small as your clients need, and if you enable it, alert on the `REVOKED` rate.
- Collapse every failure to one generic response (e.g. `401` with no detail) at the transport boundary and log the specific code server-side.

## Common mistakes to avoid

- Reusing the presented refresh token after a successful refresh — it is dead; always persist the returned one.
- Retrying a failed refresh with the same token in client retry loops — outside the grace window this burns the family (by design).
- Writing `MarkRotated` as an unconditional `UPDATE` and discarding the row count — this silently reintroduces the fork the compare-and-set exists to prevent.
- Putting user data or expiry claims "inside" the token — NEBULA tokens are opaque by design; claims belong in the short-lived access token.
- Calling refresh from multiple concurrent requests with the same token — exactly one wins, the rest get `CONFLICT` and should retry once. Serialize refreshes client-side rather than relying on that.
- Deleting rotated/revoked rows early (a Redis TTL at rotation, a nightly `DELETE WHERE status <> 'active'`) — it silently turns every replay into `NOT_FOUND` and disables reuse detection.
