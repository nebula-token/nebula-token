---
name: nebula-token-csharp
description: Integrate NEBULA opaque rotating refresh tokens in a C# / .NET backend. Use when adding login sessions, refresh-token rotation, reuse detection, token revocation, or when replacing hand-rolled or JWT-based refresh tokens. Covers engine setup, endpoints, production store, and security rules.
---

# Integrating nebula-token (C# / .NET)

NEBULA is an implementation profile of RFC 9700 (OAuth 2.0 Security BCP) for
refresh tokens: opaque tokens (`nbl.{kid}.{selector}.{verifier}` — pure
entropy, no claims), rotation on every use, reuse detection with family
revocation, hashed storage, optional device binding. Package: `NebulaToken (NuGet)`.
Normative behavior: `SPECIFICATION.md` in the repository root.

## Install

```
dotnet add package NebulaToken
```

## Core integration

The API is asynchronous throughout: every store method returns a `Task` and takes a
`CancellationToken`. Targets `net10.0`.

```csharp
using NebulaToken;   // NebulaEngine, MemoryRefreshTokenStore, ErrorCode, RevokeResult

var engine = new NebulaEngine(new NebulaEngine.Config
{
    Peppers = new Dictionary<string, string>
        { ["k1"] = Environment.GetEnvironmentVariable("NEBULA_PEPPER_K1")! }, // >= 32 bytes
    ActiveKid = "k1",
    Store = new MemoryRefreshTokenStore(),   // dev only - ADO.NET store in prod
    // ReuseGraceSeconds defaults to 0 (strict); raising it costs detectability.
});

// Login endpoint
var issued = await engine.IssueAsync(userId, deviceId); // issued.Token; null deviceId = unbound

// Refresh endpoint
var result = await engine.RefreshAsync(presentedToken, deviceId);
if (result.Ok)
{
    // result.Token is the NEW refresh token; the presented one is now dead
}
else if (result.Error is ErrorCode.Conflict)
{
    // a concurrent refresh won the compare-and-set: nothing rotated, retry once
}
else if (result.Error is ErrorCode.ReuseDetected or ErrorCode.DeviceMismatch)
{
    // security event: family already revoked - alert, force re-login.
    // result.UserId / result.FamilyId identify the session; no second lookup ([N-39])
}
else
{
    // require login
}

// Logout / compromise
var revoked = await engine.RevokeTokenAsync(token); // proves the verifier
if (!revoked.Ok)
{
    // it REFUSED (Malformed / UnknownKid / NotFound / VerifierMismatch) and
    // nothing was revoked - do not report the user as logged out ([N-36])
}
await engine.RevokeFamilyAsync(familyId);    // administrative -> int count
await engine.RevokeAllForUserAsync(userId);  // administrative -> int count
```

`ErrorCode` is documented as open: a future minor version may add a member, so keep a
default arm in every `switch` and treat an unrecognised code as a refusal.

## Integration checklist

1. **Pepper**: generate with `openssl rand -base64 48`; store in env/KMS, never in code or DB. Key it as `k1` now so future rotation (add `k2`, switch `ActiveKid`) is zero-downtime.
2. **Store**: for production implement the six-method contract (IRefreshTokenStore interface) over your database. `MarkRotatedAsync` and `RevokeIfActiveAsync` are compare-and-set: they must apply the write only if the current status matches, and report whether it applied - returning `true` unconditionally forks the family under concurrency. Start from the ready-made template in `examples/AdoNetRefreshTokenStore.cs` (schema in `docs/STORE.md`). The in-memory store is **not for production** ([N-21]): its state is per-process and lost on restart, so reuse detection does not survive a deploy and does not work behind more than one instance.
3. **Login endpoint**: authenticate credentials → `IssueAsync` → set the token in an `httpOnly; Secure; SameSite=Strict` cookie scoped to the refresh path. Never return it in a JSON body read by browser JS, never localStorage.
4. **Refresh endpoint**: read cookie → `RefreshAsync` → on success set the NEW token in the cookie and mint a short-lived access token (5–15 min). Wrap the call in one DB transaction so `InsertAsync` + `MarkRotatedAsync` commit atomically.
5. **Error handling**: `result.Error` (ErrorCode enum: `ErrorCode.ReuseDetected`, ...). Every failure means "no access token issued", and failures carry `result.UserId` / `result.FamilyId` whenever a record was resolved — every code except `Malformed`, `UnknownKid` and `NotFound` — so a security event needs no second lookup of a token you were told never to log ([N-39]). `REUSE_DETECTED` and `DEVICE_MISMATCH` additionally mean the family is already revoked — log a security event and alert. `CONFLICT` is transient (a concurrent refresh won the compare-and-set; nothing was rotated) — retry once ([N-35]). The enum is open: keep a default arm and treat an unrecognised code as a refusal.
6. **Logout**: `RevokeTokenAsync` (one session, proves the verifier) / `RevokeFamilyAsync` and `RevokeAllForUserAsync` (administrative: password change, compromise). They do not return the same shape: `RevokeTokenAsync` returns a `RevokeResult` — check `.Ok`, read the count from `.Revoked` — because it can refuse (`Malformed`, `UnknownKid`, `NotFound`, `VerifierMismatch`); the two administrative calls take no token, cannot refuse, and return the `int` count directly.
7. **Device binding (optional)**: pass a stable device identifier at issue AND every refresh. Strong on native apps (Keychain/Keystore-held ID); weaker on web where the ID travels with the token.
8. **GC**: run the store's `DeleteExpiredAsync` helper periodically; keep rotated/revoked rows until the family's absolute deadline — they power reuse detection.

## Security rules (non-negotiable)

- Never log a full token, the verifier, the pepper or the raw device identifier, and never put them in an error value ([N-14]/[N-46]); the selector is public and may be logged as a correlation id.
- Never store or transmit the raw verifier or raw deviceId server-side — the engine already guarantees the store only sees hashes; don't work around it.
- Let store errors propagate; never catch one and turn it into an `ErrorCode`. A refresh whose store call failed must fail closed: no token, and no revocation reported that did not happen.
- Default TTLs (30d absolute / 7d idle) suit consumer apps; for high-assurance (NIST AAL2), configure ~12h absolute / 30min idle.
- `ReuseGraceSeconds` **defaults to 0 (strict), and that is the recommendation** ([N-30]). A non-zero window buys retry tolerance for clients that sent a refresh and never got the response, and it costs detectability: for that many seconds after a rotation, a thief holding the rotated predecessor who acts before the legitimate client is **served a valid token**, the legitimate client is evicted with `REVOKED`, and **no `REUSE_DETECTED` is raised**. Keep it as small as your clients need, and if you enable it, alert on the `REVOKED` rate.

## Common mistakes to avoid

- Reusing the presented refresh token after a successful refresh — it is dead; always persist the returned one.
- Retrying a failed refresh with the same token in client retry loops — outside the grace window this burns the family (by design).
- Putting user data or expiry claims "inside" the token — NEBULA tokens are opaque by design; claims belong in the short-lived access token.
- Calling refresh from multiple concurrent requests with the same token — exactly one wins, the rest get `CONFLICT` and should retry once. Serialize refreshes client-side rather than relying on that, and do not raise `ReuseGraceSeconds` to paper over it: the window costs detectability, and the compare-and-set already prevents the fork.
- Blocking on the async API with `.Result` or `.GetAwaiter().GetResult()` — that is the deadlock the async contract exists to avoid.
