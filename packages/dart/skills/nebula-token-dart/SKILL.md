---
name: nebula-token-dart
description: Integrate NEBULA opaque rotating refresh tokens in a Dart backend. Use when adding login sessions, refresh-token rotation, reuse detection, token revocation, or when replacing hand-rolled or JWT-based refresh tokens. Covers engine setup, endpoints, production store, and security rules.
---

# Integrating nebula-token (Dart)

NEBULA is an implementation profile of RFC 9700 (OAuth 2.0 Security BCP) for
refresh tokens: opaque tokens (`nbl.{kid}.{selector}.{verifier}` — pure
entropy, no claims), rotation on every use, reuse detection with family
revocation, hashed storage, optional device binding. Package: `nebula_token (pub.dev)`.
Normative behavior: `SPECIFICATION.md` in the repository root.

## Install

```
dart pub add nebula_token
```

## Core integration

```dart
import 'dart:io';                                // Platform.environment
import 'package:nebula_token/nebula_token.dart';

final engine = NebulaEngine(
  peppers: {'k1': Platform.environment['NEBULA_PEPPER_K1']!}, // >= 32 bytes
  activeKid: 'k1',
  store: MemoryRefreshTokenStore(),        // dev only — SQL store in prod
  // reuseGraceSeconds defaults to 0 (strict); raising it costs detectability.
);

// Login endpoint
final issued = await engine.issue(userId, deviceId);
setRefreshCookie(issued.token); // also .expiresAt, .idleExpiresAt (unix seconds)

// Refresh endpoint. Every arm needs a real body: cases with an empty body share
// the next one's, so a switch of bare comments silently does nothing.
final result = await engine.refresh(presentedToken, deviceId);
switch (result) {
  case RefreshSuccess(:final token):
    // `token` is the NEW refresh token; the presented one is now dead
    setRefreshCookie(token);
  case RefreshFailure(
      error: NebulaError.reuseDetected || NebulaError.deviceMismatch,
      userId: final failedUserId,
      familyId: final failedFamilyId,
    ):
    // security event: family already revoked — alert, force re-login.
    // The failure carries the attribution, so no second lookup ([N-39]).
    alertSecurity(failedUserId, failedFamilyId);
  case RefreshFailure(error: NebulaError.conflict):
    // a concurrent refresh won the race; retry ONCE, then require login
    retryOnce();
  case RefreshFailure():
    // require login — including any code you do not recognise
    requireLogin();
}

// Logout / compromise. revokeToken takes the token the client presented.
final revoked = await engine.revokeToken(presentedToken); // proves the verifier
if (!revoked.ok) {
  // it REFUSED (MALFORMED / UNKNOWN_KID / NOT_FOUND / VERIFIER_MISMATCH) and
  // nothing was revoked — do not report the user as logged out ([N-36])
}
await engine.revokeFamily(familyId);      // administrative, by identifier → int
await engine.revokeAllForUser(userId);    // administrative, by identifier → int
```

The API is asynchronous (`Future`-returning) because the store contract is: no
Dart database driver offers a blocking API, and `waitFor` was removed in Dart 3.
In shelf / dart_frog handlers, `await` it directly.

## Integration checklist

1. **Pepper**: generate with `openssl rand -base64 48`; store in env/KMS, never in code or DB. Key it as `k1` now so future rotation (add `k2`, switch `activeKid`) is zero-downtime.
2. **Store**: for production implement the six-method contract (RefreshTokenStore abstract interface) over your database. Start from the ready-made template in `example/sql_store_example.dart` (schema in `docs/STORE.md`). `markRotated` and `revokeIfActive` are compare-and-sets: the status predicate belongs in the WHERE clause and the affected-row count is the return value — returning `true` unconditionally lets two concurrent refreshes fork the family. `revokeFamily`/`revokeUser` return how many rows they changed. The in-memory store is **not for production** ([N-21]): its state is per-process and lost on restart, so reuse detection does not survive a deploy and does not work behind more than one instance.
3. **Login endpoint**: authenticate credentials → `issue` → set the token in an `httpOnly; Secure; SameSite=Strict` cookie scoped to the refresh path. Never return it in a JSON body read by browser JS, never localStorage.
4. **Refresh endpoint**: read cookie → `refresh` → on success set the NEW token in the cookie and mint a short-lived access token (5–15 min). Wrap the call in one DB transaction so insert + markRotated commit atomically.
5. **Error handling**: `RefreshFailure.error` (NebulaError enum; `.code` gives the spec name). Every failure means "no access token issued", and `RefreshFailure.userId` / `.familyId` are populated whenever a record was resolved — every code except `MALFORMED`, `UNKNOWN_KID` and `NOT_FOUND` — so a security event needs no second lookup of a token you were told never to log ([N-39]). `REUSE_DETECTED` and `DEVICE_MISMATCH` additionally mean the family is already revoked — log a security event and alert. `CONFLICT` is transient and retryable exactly once ([N-35]). Treat the enum as open: always keep a catch-all branch, since a future minor version may add a code. Collapse every failure to one generic 401 at the transport boundary; log the code server-side.
6. **Logout**: `revokeToken` (one session; authenticated — it proves the verifier, so a leaked selector cannot terminate a session) / `revokeFamily` and `revokeAllForUser` (administrative: password change, compromise; you authorise them). They do not return the same shape, and the difference is load-bearing: `revokeToken` returns a sealed `RevokeResult` that **can refuse** (`MALFORMED`, `UNKNOWN_KID`, `NOT_FOUND`, `VERIFIER_MISMATCH`) ([N-36]) — check `.ok`, or switch on `RevokeSuccess`/`RevokeFailure`, and read the count from `RevokeSuccess.revoked`; awaiting it and answering `204` reports a logout that never happened and leaves the session alive. The two administrative calls take no token, cannot refuse, and return the `int` count directly.
7. **Device binding (optional)**: pass a stable device identifier at issue AND every refresh. Strong on native apps (Keychain/Keystore-held ID); weaker on web where the ID travels with the token.
8. **GC**: run the store's `deleteExpired` helper periodically; keep rotated/revoked rows until the family's absolute deadline — they power reuse detection.

## Security rules (non-negotiable)

- Never log a full token, the verifier, the pepper or the raw device identifier, and never put them in an error value ([N-14]/[N-46]); the selector is public and may be logged as a correlation id.
- Never store or transmit the raw verifier or raw deviceId server-side — the engine already guarantees the store only sees hashes; don't work around it.
- Treat store errors as refresh failures (fail closed).
- Default TTLs (30d absolute / 7d idle) suit consumer apps; for high-assurance (NIST AAL2), configure ~12h absolute / 30min idle.
- `reuseGraceSeconds` **defaults to 0 (strict), and that is the recommendation** ([N-30]). A non-zero window buys retry tolerance for clients that sent a refresh and never got the response, and it costs detectability: for that many seconds after a rotation, a thief holding the rotated predecessor who acts before the legitimate client is **served a valid token**, the legitimate client is evicted with `REVOKED`, and **no `REUSE_DETECTED` is raised**. Keep it as small as your clients need, and if you enable it, alert on the `REVOKED` rate.

## Common mistakes to avoid

- Reusing the presented refresh token after a successful refresh — it is dead; always persist the returned one.
- Retrying a failed refresh with the same token in client retry loops — outside the grace window this burns the family (by design).
- Putting user data or expiry claims "inside" the token — NEBULA tokens are opaque by design; claims belong in the short-lived access token.
- Calling refresh from multiple concurrent requests with the same token — exactly one wins, the rest get `CONFLICT` and should retry once. Serialize refreshes client-side rather than relying on that, and do not raise `reuseGraceSeconds` to paper over it: the window costs detectability, and the compare-and-set already prevents the fork.
- Swallowing store errors into a `RefreshFailure` — infrastructure failures use Dart's error channel and must propagate, or you will report revocations that never happened.
