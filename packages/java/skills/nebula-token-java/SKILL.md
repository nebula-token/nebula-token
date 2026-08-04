---
name: nebula-token-java
description: Integrate NEBULA opaque rotating refresh tokens in a Java / Kotlin / Scala (JVM) backend. Use when adding login sessions, refresh-token rotation, reuse detection, token revocation, or when replacing hand-rolled or JWT-based refresh tokens. Covers engine setup, endpoints, production store, and security rules.
---

# Integrating nebula-token (Java / Kotlin / Scala (JVM))

NEBULA is an implementation profile of RFC 9700 (OAuth 2.0 Security BCP) for
refresh tokens: opaque tokens (`nbl.{kid}.{selector}.{verifier}` — pure
entropy, no claims), rotation on every use, reuse detection with family
revocation, hashed storage, optional device binding. Package: `dev.nebulatoken:nebula-token`.
Normative behavior: `SPECIFICATION.md` in the repository root.

## Install

```
Maven/Gradle: dev.nebulatoken:nebula-token:1.0.2
```

## Core integration

```java
import dev.nebulatoken.*;   // NebulaEngine, IssueResult, RefreshResult, RevokeResult, ErrorCode

NebulaEngine.Config cfg = new NebulaEngine.Config();
cfg.peppers = Map.of("k1", System.getenv("NEBULA_PEPPER_K1")); // >= 32 BYTES
cfg.activeKid = "k1";
cfg.store = new MemoryRefreshTokenStore();                     // dev only — JDBC store in prod
// cfg.reuseGraceSeconds defaults to 0 (strict); raising it costs detectability.
NebulaEngine engine = new NebulaEngine(cfg);

// Login endpoint
IssueResult issued = engine.issue(userId, deviceId); // deviceId null = unbound, "" = a real binding

// Refresh endpoint. RefreshResult is sealed: this switch is exhaustive on JDK 21+.
switch (engine.refresh(presentedToken, deviceId)) {
    case RefreshResult.Success s -> {
        // s.token() is the NEW refresh token; the presented one is now dead
    }
    case RefreshResult.Failure f -> {
        switch (f.error()) {
            case REUSE_DETECTED, DEVICE_MISMATCH ->
                alert(f.userId(), f.familyId());  // family already revoked — force re-login
            case CONFLICT -> retryOnce();         // a concurrent refresh won; transient
            default -> requireLogin();            // and treat any UNKNOWN code the same way
        }
    }
}

// Logout / compromise
RevokeResult revoked = engine.revokeToken(token); // proves the verifier, works post-rotation
if (!revoked.ok()) {
    // it REFUSED (MALFORMED / UNKNOWN_KID / NOT_FOUND / VERIFIER_MISMATCH) and
    // nothing was revoked — do not report the user as logged out ([N-36])
}
engine.revokeFamily(familyId);      // administrative, no token needed → int count
engine.revokeAllForUser(userId);    // administrative, no token needed → int count
```

The API is synchronous and thread-safe if the store is. On JDK 21 run it on virtual threads: a
blocking store call parks the carrier rather than occupying it, so there is nothing to gain from
wrapping it in a future.

## Integration checklist

1. **Pepper**: generate with `openssl rand -base64 48`; store in env/KMS, never in code or DB. Key it as `k1` now so future rotation (add `k2`, switch `activeKid`) is zero-downtime.
2. **Store**: for production implement the six-method contract (RefreshTokenStore interface) over your database. Start from the ready-made template in `examples/JdbcRefreshTokenStore.java` (schema in `docs/STORE.md`). Two rules decide whether it is correct: `markRotated` and `revokeIfActive` must be real compare-and-sets (`... WHERE selector=? AND status=?`, returning whether a row changed), and a database error must be **thrown**, never returned as `false`/`0`. The in-memory store is **not for production** ([N-21]): its state is per-process and lost on restart, so reuse detection does not survive a deploy and does not work behind more than one instance.
3. **Login endpoint**: authenticate credentials → `issue` → set the token in an `httpOnly; Secure; SameSite=Strict` cookie scoped to the refresh path. Never return it in a JSON body read by browser JS, never localStorage.
4. **Refresh endpoint**: read cookie → `refresh` → on success set the NEW token in the cookie and mint a short-lived access token (5–15 min). Wrap the call in one DB transaction so insert + markRotated commit atomically.
5. **Error handling**: `RefreshResult.Failure.error()` (ErrorCode enum). Every failure means "no access token issued"; a `default` arm must deny, because the enum is documented open to future codes. `Failure.userId()` / `Failure.familyId()` are populated whenever a record was resolved — every code except `MALFORMED`, `UNKNOWN_KID` and `NOT_FOUND` — so a security event needs no second lookup of a token you were told never to log ([N-39]). `REUSE_DETECTED` and `DEVICE_MISMATCH` additionally mean the family is already revoked — log a security event and alert. `CONFLICT` is transient: retry once ([N-35]).
6. **Logout**: `revokeToken` (one session, proves the verifier — a selector alone must never terminate a session) / `revokeFamily` and `revokeAllForUser` for administrative paths you have already authorised. They do not return the same shape, and the difference is load-bearing: `revokeToken` returns a sealed `RevokeResult` that **can refuse** (`MALFORMED`, `UNKNOWN_KID`, `NOT_FOUND`, `VERIFIER_MISMATCH`) ([N-36]) — check `ok()`, or pattern-match `Success`/`Failure`, and read the count from `Success.revoked()`; calling it and returning `204` reports a logout that never happened and leaves the session alive. The two administrative calls take no token, cannot refuse, and return the `int` count directly.
7. **Device binding (optional)**: pass a stable device identifier at issue AND every refresh. Strong on native apps (Keychain/Keystore-held ID); weaker on web where the ID travels with the token.
8. **GC**: run the store's `deleteExpired` helper periodically; keep rotated/revoked rows until the family's absolute deadline — they power reuse detection.

## Security rules (non-negotiable)

- Never log a full token, the verifier, the pepper or the raw device identifier, and never put them in an error value ([N-14]/[N-46]); the selector is public and may be logged as a correlation id.
- Never store or transmit the raw verifier or raw deviceId server-side — the engine already guarantees the store only sees hashes; don't work around it.
- Treat a thrown store error as a refresh failure (fail closed). Never catch it and continue: the engine deliberately does not convert it into an ErrorCode, because "the database did not answer" is not a statement about the token.
- Default TTLs (30d absolute / 7d idle) suit consumer apps; for high-assurance (NIST AAL2), configure ~12h absolute / 30min idle.
- `reuseGraceSeconds` **defaults to 0 (strict), and that is the recommendation** ([N-30]). A non-zero window buys retry tolerance for clients that sent a refresh and never got the response, and it costs detectability: for that many seconds after a rotation, a thief holding the rotated predecessor who acts before the legitimate client is **served a valid token**, the legitimate client is evicted with `REVOKED`, and **no `REUSE_DETECTED` is raised**. Keep it as small as your clients need, and if you enable it, alert on the `REVOKED` rate.

## Common mistakes to avoid

- Reusing the presented refresh token after a successful refresh — it is dead; always persist the returned one.
- Retrying a failed refresh with the same token in client retry loops — outside the grace window this burns the family (by design).
- Putting user data or expiry claims "inside" the token — NEBULA tokens are opaque by design; claims belong in the short-lived access token.
- Calling refresh from multiple concurrent requests with the same token — exactly one wins, the others get `CONFLICT` and should retry once. Serialize refreshes client-side rather than relying on that.
- Implementing `markRotated` as an unconditional `UPDATE` — it is a compare-and-set, and without the `AND status=?` two concurrent refreshes fork the family into two live lineages, which is precisely what reuse detection cannot see.
