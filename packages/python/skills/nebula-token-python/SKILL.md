---
name: nebula-token-python
description: Integrate NEBULA opaque rotating refresh tokens in a Python backend. Use when adding login sessions, refresh-token rotation, reuse detection, token revocation, or when replacing hand-rolled or JWT-based refresh tokens. Covers engine setup, endpoints, production store, and security rules.
---

# Integrating nebula-token (Python)

NEBULA is an implementation profile of RFC 9700 (OAuth 2.0 Security BCP) for
refresh tokens: opaque tokens (`nbl.{kid}.{selector}.{verifier}` — pure
entropy, no claims), rotation on every use, reuse detection with family
revocation, hashed storage, optional device binding. Package: `nebula-token`.
Normative behavior: `SPECIFICATION.md` in the repository root.

## Install

```
pip install nebula-token
```

## Core integration

```python
import os

from nebula_token import NebulaEngine, MemoryRefreshTokenStore

engine = NebulaEngine(
    peppers={"k1": os.environ["NEBULA_PEPPER_K1"]},  # >= 32 BYTES, from env/KMS
    active_kid="k1",
    store=MemoryRefreshTokenStore(),                 # dev only — SQL store in prod
    reuse_grace_seconds=0,                           # raise only if you must
)

# Login endpoint
issued = engine.issue(user_id, device_id)            # issued.token, .expires_at, …

# Refresh endpoint
result = engine.refresh(presented_token, device_id)
if result.ok:
    pass  # result.token is the NEW refresh token; the presented one is now dead
elif result.error in ("REUSE_DETECTED", "DEVICE_MISMATCH"):
    pass  # security event: family already revoked — alert, force re-login.
          # result.user_id / result.family_id identify the session ([N-39])
elif result.error == "CONFLICT":
    pass  # a concurrent refresh won; retry once, then require login
else:
    pass  # require login — including any code you do not recognise

# Logout / compromise
revoked = engine.revoke_token(token)    # authenticated: proves the verifier
if not revoked.ok:
    pass  # it REFUSED and nothing was revoked — do not report a logout ([N-36])
engine.revoke_family(family_id)         # administrative, no token needed -> int
engine.revoke_all_for_user(user_id)     # administrative, no token needed -> int
```

## Synchrony

The API is **synchronous**, and so is the store contract. Under asyncio
(FastAPI, Starlette, aiohttp) call the engine off the event loop:

```python
result = await asyncio.to_thread(engine.refresh, presented_token, device_id)
```

Do NOT hand the engine a store whose methods are `async def`. Nothing awaits
them: `insert` would return an un-awaited coroutine, the row would never be
written, and the engine would still return a token — the exact failure the
compare-and-set in the contract exists to prevent. Use a blocking driver (or a
blocking wrapper around your async driver) inside the threadpool instead.

## Integration checklist

1. **Pepper**: generate with `openssl rand -base64 48`; store in env/KMS, never in code or DB. `MIN_PEPPER_LENGTH` counts **bytes**, not characters. Key it as `k1` now so future rotation (add `k2`, switch `active_kid`) is zero-downtime.
2. **Store**: for production implement the six-method contract (`RefreshTokenStore` Protocol) over your database. `mark_rotated` and `revoke_if_active` are compare-and-set: `UPDATE … WHERE selector=? AND status=?`, returning `rowcount == 1`. Returning `True` unconditionally forks the family under concurrency. `revoke_family` / `revoke_user` return the number of rows they changed. Start from `examples/sqlite_store.py` (schema in `docs/STORE.md`). The in-memory store is **not for production** ([N-21]): its state is per-process and lost on restart, so reuse detection does not survive a deploy and does not work behind more than one instance.
3. **Login endpoint**: authenticate credentials → `issue` → set the token in an `httpOnly; Secure; SameSite=Strict` cookie scoped to the refresh path. Never return it in a JSON body read by browser JS, never localStorage.
4. **Refresh endpoint**: read cookie → `refresh` → on success set the NEW token in the cookie and mint a short-lived access token (5–15 min). Wrap the call in one DB transaction so insert + mark_rotated commit atomically.
5. **Error handling**: `result.error` is a string code. Every failure means "no access token issued", and failures carry `result.user_id` / `result.family_id` whenever a record was resolved — every code except `MALFORMED`, `UNKNOWN_KID` and `NOT_FOUND` — so a security event needs no second lookup of a token you were told never to log ([N-39]). `REUSE_DETECTED` and `DEVICE_MISMATCH` additionally mean the family is already revoked — log a security event and alert. `CONFLICT` is transient: retry once ([N-35]). Treat an unrecognised code as a refusal; the set is open.
6. **Store errors**: let them raise. They are the native error channel, never a protocol outcome — catching one and returning "refresh failed" is fine at the HTTP boundary, but never convert one into a successful result or a reported revocation.
7. **Logout**: `revoke_token` (one session, requires the token itself) / `revoke_all_for_user` (password change, compromise). `revoke_token` deliberately refuses a selector without its verifier — otherwise anyone who read a log line could terminate that session. That refusal is a **return value, not an exception**: you get a `RevokeOk` or a `RevokeError` (`MALFORMED`, `UNKNOWN_KID`, `NOT_FOUND`, `VERIFIER_MISMATCH`), so check `.ok` and read the count from `.revoked` ([N-36]). Calling it and answering `204` reports a logout that never happened and leaves the session alive. `revoke_family` and `revoke_all_for_user` take no token, cannot refuse, and return the `int` count directly.
8. **Device binding (optional)**: pass a stable device identifier at issue AND every refresh. `device_id=""` is a real binding, distinct from `None`. Strong on native apps (Keychain/Keystore-held ID); weaker on web where the ID travels with the token.
9. **GC**: run the store's `delete_expired` helper periodically; keep rotated/revoked rows until the family's absolute deadline — they power reuse detection.

## Security rules (non-negotiable)

- Never log a full token, the verifier, the pepper or the raw device identifier, and never put them in an error value ([N-14]/[N-46]); the selector is public and may be logged as a correlation id. `TokenRecord`, `ParsedToken`, `IssueResult` and `RefreshOk` all redact the secret from their `__repr__`, so a captured traceback stays safe — do not add your own dump of `vars(record)` or `asdict(result)`.
- Never store or transmit the raw verifier or raw device id server-side — the engine already guarantees the store only sees hashes; don't work around it.
- Treat store errors as refresh failures (fail closed).
- Default TTLs (30d absolute / 7d idle) suit consumer apps; for high-assurance (NIST AAL2), configure ~12h absolute / 30min idle.
- `reuse_grace_seconds` **defaults to 0 (strict), and that is the recommendation** ([N-30]). A non-zero window buys retry tolerance for clients that sent a refresh and never got the response, and it costs detectability: for that many seconds after a rotation, a thief holding the rotated predecessor who acts before the legitimate client is **served a valid token**, the legitimate client is evicted with `REVOKED`, and **no `REUSE_DETECTED` is raised**. Keep it as small as your clients need, and if you enable it, alert on the `REVOKED` rate.

## Common mistakes to avoid

- Reusing the presented refresh token after a successful refresh — it is dead; always persist the returned one.
- Retrying a failed refresh with the same token in client retry loops — outside the grace window this burns the family (by design).
- Putting user data or expiry claims "inside" the token — NEBULA tokens are opaque by design; claims belong in the short-lived access token.
- Calling refresh from multiple concurrent requests with the same token — one wins, the rest get `CONFLICT`. Serialize refreshes client-side, or retry once.
- Writing an async store (see **Synchrony**) — un-awaited coroutines hand out tokens for records that were never written.
