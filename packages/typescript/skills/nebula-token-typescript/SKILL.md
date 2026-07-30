---
name: nebula-token-typescript
description: Integrate NEBULA opaque rotating refresh tokens in a TypeScript backend running on Node.js. Use when adding login sessions, refresh-token rotation, reuse detection, token revocation, or when replacing hand-rolled or JWT-based refresh tokens. Covers engine setup, endpoints, production store, and security rules.
---

# Integrating nebula-token (TypeScript)

NEBULA is an implementation profile of RFC 9700 (OAuth 2.0 Security BCP) for
refresh tokens: opaque tokens (`nbl.{kid}.{selector}.{verifier}` — pure
entropy, no claims), rotation on every use, reuse detection with family
revocation, hashed storage, optional device binding. Package: `nebula-token`.
Normative behavior: `SPECIFICATION.md` in the repository root.

## Install

```
npm install nebula-token
```

## Core integration

```ts
import { NebulaEngine, MemoryRefreshTokenStore } from 'nebula-token';

const engine = new NebulaEngine({
  peppers: { k1: process.env.NEBULA_PEPPER_K1! },  // >= 32 BYTES, from env/KMS
  activeKid: 'k1',
  store: new MemoryRefreshTokenStore(),            // dev only — SQL store in prod
  // reuseGraceSeconds defaults to 0 (strict); raising it costs detectability.
});

// Login endpoint
const issued = await engine.issue(userId, deviceId);  // issued.token, .expiresAt, …

// Refresh endpoint
const result = await engine.refresh(presentedToken, deviceId);
if (result.ok) {
  // result.token is the NEW refresh token; the presented one is now dead
} else if (result.error === 'CONFLICT') {
  // a concurrent refresh won the compare-and-set: nothing was rotated, retry once
} else if (result.error === 'REUSE_DETECTED' || result.error === 'DEVICE_MISMATCH') {
  // security event: family already revoked — alert, force re-login.
  // result.userId / result.familyId identify the session; no second lookup ([N-39])
} else {
  // require login — including any code you do not recognise
}

// Logout / compromise
const revoked = await engine.revokeToken(presentedToken); // proves the verifier
if (!revoked.ok) {
  // it REFUSED (MALFORMED / UNKNOWN_KID / NOT_FOUND / VERIFIER_MISMATCH) and
  // nothing was revoked — do not report the user as logged out ([N-36])
}
await engine.revokeFamily(familyId);      // administrative, by server-side id → count
await engine.revokeAllForUser(userId);    // administrative, by server-side id → count
```

All engine methods are async — always `await` them. Protocol outcomes are
returned as values; a store failure rejects the promise instead, so it can never
be mistaken for a verdict — let it propagate and fail closed.

## Integration checklist

1. **Pepper**: generate with `openssl rand -base64 48`; store in env/KMS, never in code or DB. Key it as `k1` now so future rotation (add `k2`, switch `activeKid`) is zero-downtime.
2. **Store**: for production implement the six-method contract (`RefreshTokenStore`) over your database. `markRotated` and `revokeIfActive` are **compare-and-set**: `UPDATE … WHERE selector=$1 AND status=$2`, returning `rowCount === 1`. Returning `true` unconditionally lets two concurrent refreshes fork the family. `revokeFamily` / `revokeUser` return the number of rows they changed. Start from the ready-made template in `examples/postgres-store.ts` (schema in `docs/STORE.md`). The in-memory store is **not for production** ([N-21]): its state is per-process and lost on restart, so reuse detection does not survive a deploy and does not work behind more than one instance.
3. **Login endpoint**: authenticate credentials → `issue` → set the token in an `httpOnly; Secure; SameSite=Strict` cookie scoped to the refresh path. Never return it in a JSON body read by browser JS, never localStorage.
4. **Refresh endpoint**: read cookie → `refresh` → on success set the NEW token in the cookie and mint a short-lived access token (5–15 min). Wrap the call in one DB transaction so insert + markRotated commit atomically.
5. **Error handling**: `result.error` (string union). Every failure means "no access token issued", and failures carry `result.userId` / `result.familyId` whenever a record was resolved — every code except `MALFORMED`, `UNKNOWN_KID` and `NOT_FOUND` — so a security event needs no second lookup of a token you were told never to log ([N-39]). `REUSE_DETECTED` and `DEVICE_MISMATCH` additionally mean the family is already revoked — log a security event and alert. `CONFLICT` is transient: retry the refresh once ([N-35]). Treat the union as **open** — a future minor version may add a code, so an unrecognised value is a refusal, not a bug in your `switch`.
6. **Store errors**: a rejected promise is the native error channel and never a protocol outcome. Let it propagate to a 5xx; never catch one and continue as if the write happened, or report a revocation that did not occur.
7. **Logout**: `revokeToken` (one session — it proves the verifier, so a leaked selector cannot terminate a session) / `revokeFamily` and `revokeAllForUser` (administrative: password change, compromise — you authorise them). The two shapes differ, and the difference is load-bearing: `revokeToken` returns a `RevokeResult` that **can refuse** — `MALFORMED`, `UNKNOWN_KID`, `NOT_FOUND`, `VERIFIER_MISMATCH` ([N-36]) — so check `.ok` and read the count from `.revoked`; awaiting it and returning `204` reports a logout that never happened and leaves the session alive. The administrative calls take no token, cannot refuse, and return the `number` directly.
8. **Device binding (optional)**: pass a stable device identifier at issue AND every refresh. `undefined` is unbound; `''` is a real binding, and they are different things. Strong on native apps (Keychain/Keystore-held ID); weaker on web where the ID travels with the token.
9. **GC**: delete records whose family has passed its absolute deadline (`deleteExpired` on the in-memory store shows the predicate); keep rotated/revoked rows until then — they power reuse detection.

## Security rules (non-negotiable)

- Never log a full token, the verifier, the pepper, or the raw deviceId, and never put them in an error value ([N-14]/[N-46]). The selector may be logged as a correlation id.
- Never store or transmit the raw verifier or raw deviceId server-side — the engine already guarantees the store only sees hashes; don't work around it.
- Treat store errors as refresh failures (fail closed).
- Default TTLs (30d absolute / 7d idle) suit consumer apps; for high-assurance (NIST AAL2), configure ~12h absolute / 30min idle.
- `reuseGraceSeconds` **defaults to 0 (strict), and that is the recommendation** ([N-30]). A non-zero window buys retry tolerance for clients that sent a refresh and never got the response, and it costs detectability: for that many seconds after a rotation, a thief holding the rotated predecessor who acts before the legitimate client is **served a valid token**, the legitimate client is evicted with `REVOKED`, and **no `REUSE_DETECTED` is raised**. Keep it as small as your clients need, and if you enable it, alert on the `REVOKED` rate.

## Common mistakes to avoid

- Reusing the presented refresh token after a successful refresh — it is dead; always persist the returned one.
- Retrying a failed refresh with the same token in client retry loops — outside the grace window this burns the family (by design).
- Putting user data or expiry claims "inside" the token — NEBULA tokens are opaque by design; claims belong in the short-lived access token.
- Calling refresh from multiple concurrent requests with the same token — exactly one wins, the rest get `CONFLICT` and should retry once. Serialize refreshes client-side rather than relying on that.
- Implementing `markRotated` as an unconditional `UPDATE` and discarding the row count — it re-opens the race the compare-and-set exists to close, forking one family into two live lineages that reuse detection cannot see.
- Deleting rotated/revoked rows early (a Redis TTL at rotation, a nightly `DELETE WHERE status <> 'active'`) — it silently turns every replay into `NOT_FOUND` and disables reuse detection.
