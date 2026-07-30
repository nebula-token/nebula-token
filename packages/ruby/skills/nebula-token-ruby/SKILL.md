---
name: nebula-token-ruby
description: Integrate NEBULA opaque rotating refresh tokens in a Ruby backend. Use when adding login sessions, refresh-token rotation, reuse detection, token revocation, or when replacing hand-rolled or JWT-based refresh tokens. Covers engine setup, endpoints, production store, and security rules.
---

# Integrating nebula-token (Ruby)

NEBULA is an implementation profile of RFC 9700 (OAuth 2.0 Security BCP) for
refresh tokens: opaque tokens (`nbl.{kid}.{selector}.{verifier}` — pure
entropy, no claims), rotation on every use, reuse detection with family
revocation, hashed storage, optional device binding. Package: `nebula-token (RubyGems)`.
Normative behavior: `SPECIFICATION.md` in the repository root.

## Install

```
gem install nebula-token
```

## Core integration

```ruby
require 'nebula_token'   # 'nebula-token' also works; both load the same module

engine = NebulaToken::Engine.new(
  peppers: { 'k1' => ENV.fetch('NEBULA_PEPPER_K1') },  # >= 32 BYTES, from env
  active_kid: 'k1',
  store: NebulaToken::MemoryRefreshTokenStore.new      # dev only — pg store in prod
  # reuse_grace_seconds defaults to 0 (strict); raising it costs detectability.
)

# Login endpoint
issued = engine.issue(user_id, device_id)              # issued.token, .expires_at, …

# Refresh endpoint
result = engine.refresh(presented_token, device_id)
if result.ok?
  # result.token is the NEW refresh token; the presented one is now dead
elsif result.error == 'CONFLICT'
  # a concurrent refresh won the compare-and-set: nothing rotated, retry once
elsif %w[REUSE_DETECTED DEVICE_MISMATCH].include?(result.error)
  # security event: family already revoked — alert, force re-login
  # result.user_id / result.family_id identify the session, no second lookup
else
  # require login
end

# Logout / compromise
revoked = engine.revoke_token(token) # authenticated: proves the verifier
unless revoked.ok?
  # it REFUSED and nothing was revoked — do not report a logout ([N-36])
end
engine.revoke_family(family_id)     # administrative -> Integer
engine.revoke_all_for_user(user_id) # administrative -> Integer
```

The API is synchronous — a natural fit for Rails/Rack request lifecycles.

## Integration checklist

1. **Pepper**: generate with `openssl rand -base64 48`; store in env/KMS, never in code or DB. Key it as `k1` now so future rotation (add `k2`, switch `active_kid`) is zero-downtime.
2. **Store**: for production implement the six-method contract of `NebulaToken::RefreshTokenStore` (duck-typed) over your database: `find_by_selector`, `insert`, `mark_rotated`, `revoke_if_active`, `revoke_family`, `revoke_user`. `mark_rotated` and `revoke_if_active` are compare-and-set — apply the write only if the current status still matches, and return whether it applied; returning `true` unconditionally lets two concurrent refreshes fork the family. Start from `examples/pg_store.rb` (schema in `docs/STORE.md`). The in-memory store is **not for production** ([N-21]): its state is per-process and lost on restart, so reuse detection does not survive a deploy and does not work behind more than one instance.
3. **Login endpoint**: authenticate credentials → `issue` → set the token in an `httpOnly; Secure; SameSite=Strict` cookie scoped to the refresh path. Never return it in a JSON body read by browser JS, never localStorage.
4. **Refresh endpoint**: read cookie → `refresh` → on success set the NEW token in the cookie and mint a short-lived access token (5–15 min). Wrap the call in one DB transaction so insert + mark_rotated commit atomically.
5. **Error handling**: `result.error` (string). Every failure means "no access token issued", and failures carry `result.user_id` / `result.family_id` whenever a record was resolved — every code except `MALFORMED`, `UNKNOWN_KID` and `NOT_FOUND` — so a security event needs no second lookup of a token you were told never to log ([N-39]). The code set is open — always give the `case` an `else` that denies. `CONFLICT` is transient: retry once ([N-35]). `REUSE_DETECTED` and `DEVICE_MISMATCH` additionally mean the family is already revoked — log a security event and alert.
6. **Logout**: `revoke_token` (one session, requires the token itself) / `revoke_family`, `revoke_all_for_user` (administrative: password change, compromise). They do not return the same shape, and the difference is load-bearing: `revoke_token` returns a `RevokeResult` that **can refuse** (`MALFORMED`, `UNKNOWN_KID`, `NOT_FOUND`, `VERIFIER_MISMATCH`) ([N-36]) — check `.ok?` and read the count from `.revoked`; calling it and answering `204` reports a logout that never happened and leaves the session alive. The two administrative calls take no token, cannot refuse, and return the `Integer` count directly.
7. **Device binding (optional)**: pass a stable device identifier at issue AND every refresh. Strong on native apps (Keychain/Keystore-held ID); weaker on web where the ID travels with the token.
8. **GC**: run the store's `delete_expired` helper periodically; keep rotated/revoked rows until the family's absolute deadline — they power reuse detection.

## Security rules (non-negotiable)

- Never log a full token, the verifier, the pepper or the raw device identifier, and never put them in an error value ([N-14]/[N-46]); the selector is public and may be logged as a correlation id. `IssueResult`, `RefreshResult`, `ParsedToken`, `TokenRecord` and `Engine` redact the credential (and the peppers) in `inspect`/`to_s`, so `p result` and `p engine` are safe — but string-building the token yourself is not.
- Never store or transmit the raw verifier or raw deviceId server-side — the engine already guarantees the store only sees hashes; don't work around it.
- Let store errors propagate (fail closed). Never rescue a store exception and turn it into a "session expired": that would report revocations that never happened.
- Default TTLs (30d absolute / 7d idle) suit consumer apps; for high-assurance (NIST AAL2), configure ~12h absolute / 30min idle.
- `reuse_grace_seconds` **defaults to 0 (strict), and that is the recommendation** ([N-30]). A non-zero window buys retry tolerance for clients that sent a refresh and never got the response, and it costs detectability: for that many seconds after a rotation, a thief holding the rotated predecessor who acts before the legitimate client is **served a valid token**, the legitimate client is evicted with `REVOKED`, and **no `REUSE_DETECTED` is raised**. Keep it as small as your clients need, and if you enable it, alert on the `REVOKED` rate.

## Common mistakes to avoid

- Reusing the presented refresh token after a successful refresh — it is dead; always persist the returned one.
- Retrying a failed refresh with the same token in client retry loops — outside the grace window this burns the family (by design).
- Putting user data or expiry claims "inside" the token — NEBULA tokens are opaque by design; claims belong in the short-lived access token.
- Calling refresh from multiple concurrent requests with the same token — exactly one wins, the rest get `CONFLICT` and should retry once, never a forked family. Serialize refreshes client-side rather than relying on that, and do not raise `reuse_grace_seconds` to paper over it: the window costs detectability, and the compare-and-set already prevents the fork.
- Writing a store whose `mark_rotated` ignores `from_status`, or whose `revoke_family` returns a constant instead of the number of rows it changed.
- Deleting rotated/revoked rows before the family's absolute deadline — that silently converts every replay from `REUSE_DETECTED` into `NOT_FOUND`.
