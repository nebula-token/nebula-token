---
name: nebula-token-rust
description: Integrate NEBULA opaque rotating refresh tokens in a Rust backend. Use when adding login sessions, refresh-token rotation, reuse detection, token revocation, or when replacing hand-rolled or JWT-based refresh tokens. Covers engine setup, endpoints, production store, and security rules.
---

# Integrating nebula-token (Rust)

NEBULA is an implementation profile of RFC 9700 (OAuth 2.0 Security BCP) for
refresh tokens: opaque tokens (`nbl.{kid}.{selector}.{verifier}` — pure
entropy, no claims), rotation on every use, reuse detection with family
revocation, hashed storage, optional device binding. Package: `nebula-token (crates.io)`.
Normative behavior: `SPECIFICATION.md` in the repository root.

## Install

```
cargo add nebula-token
```

## Core integration

```rust
use nebula_token::{Config, ErrorCode, MemoryRefreshTokenStore, NebulaEngine};
use std::collections::HashMap;
use std::sync::Arc;

let peppers = HashMap::from([("k1".to_string(), std::env::var("NEBULA_PEPPER_K1")?)]);
// reuse_grace_seconds defaults to 0 (strict); raising it costs detectability.
let cfg = Config::new(peppers, "k1", MemoryRefreshTokenStore::new()); // dev store
// Build once at startup and share: every engine method takes &self.
let engine = Arc::new(NebulaEngine::new(cfg)?);

// Login endpoint
let issued = engine.issue(user_id, Some(device_id))?; // issued.token

// Refresh endpoint
match engine.refresh(&presented_token, Some(device_id))? {
    Ok(next) => { /* next.token is the NEW refresh token; the presented one is dead */ }
    Err(f) => match f.code {
        ErrorCode::Conflict => { /* a concurrent refresh won; retry once */ }
        ErrorCode::ReuseDetected | ErrorCode::DeviceMismatch => {
            /* security event: family already revoked — alert, force re-login */
        }
        _ => { /* require login */ }
    },
}

// Logout / compromise. revoke_token is doubly wrapped: `?` unwraps the store
// Result, and the INNER Result is the protocol outcome — it is #[must_use], so
// discarding it both warns and hides a refused logout.
match engine.revoke_token(&token)? {         // authenticated: proves the verifier
    Ok(done) => { /* done.revoked records were revoked */ }
    Err(f) => { /* REFUSED (f.code): nothing was revoked — not a logout ([N-36]) */ }
}
engine.revoke_all_for_user(user_id)?;    // administrative → u64 count
engine.revoke_family(&family_id)?;       // administrative → u64 count
```

The API is synchronous and shareable: `NebulaEngine<S>` is `Send + Sync`
whenever `S` is, so it lives in `Arc` inside axum/actix application state.

## Two failure channels

The outer `Result` is infrastructure (store down, timeout): propagate it with
`?` and return 5xx — never convert it into an auth outcome. The inner value is
the protocol outcome, `Err(Failure)` carrying `Failure::code` plus the
`user_id`/`family_id` of the affected session where one was resolved.
`ErrorCode` is `#[non_exhaustive]`: always keep a wildcard arm, and treat any
unrecognised code as a refusal.

## Integration checklist

1. **Pepper**: generate with `openssl rand -base64 48`; store in env/KMS, never in code or DB. Minimum 32 **bytes**. Key it as `k1` now so a future rotation (add `k2`, switch `active_kid`) is zero-downtime.
2. **Store**: for production implement the six-method `RefreshTokenStore` over your database, taking `&self`. `mark_rotated` and `revoke_if_active` must be compare-and-sets (`… WHERE selector=$1 AND status=$2`, returning the affected-row count) — returning `true` unconditionally forks token families under concurrency. Start from `examples/sql_store.rs` (schema in `docs/STORE.md`). The in-memory store is **not for production** ([N-21]): its state is per-process and lost on restart, so reuse detection does not survive a deploy and does not work behind more than one instance.
3. **Login endpoint**: authenticate credentials → `issue` → set the token in an `httpOnly; Secure; SameSite=Strict` cookie scoped to the refresh path. Never return it in a JSON body read by browser JS, never localStorage.
4. **Refresh endpoint**: read cookie → `refresh` → on success set the NEW token in the cookie and mint a short-lived access token (5–15 min). Wrap the call in one DB transaction so the successor insert and the predecessor's compare-and-set commit atomically.
5. **Error handling**: every failure means "no access token issued", and `Failure::user_id` / `Failure::family_id` are populated whenever a record was resolved — every code except `Malformed`, `UnknownKid` and `NotFound` — so a security event needs no second lookup of a token you were told never to log ([N-39]). `ReuseDetected` and `DeviceMismatch` additionally mean the family is already revoked — log a security event and alert. `Conflict` (spec code `CONFLICT`) is transient: retry the refresh once ([N-35]).
6. **Logout**: `revoke_token` (one session, requires the token) / `revoke_all_for_user` and `revoke_family` (password change, compromise; authorise them yourself). The shapes differ, and the difference is load-bearing: `revoke_token` returns `Result<RevokeResult, S::Error>` where `RevokeResult` is itself `Result<RevokeOk, Failure>`, so it **can refuse** (`Malformed`, `UnknownKid`, `NotFound`, `VerifierMismatch`) ([N-36]) — match the inner result and read the count from `RevokeOk::revoked`. Writing `engine.revoke_token(&token)?;` as a statement discards a `#[must_use]` value: it warns, and it reports a logout that never happened. The two administrative calls take no token, cannot refuse, and yield the `u64` count directly.
7. **Device binding (optional)**: pass a stable device identifier at issue AND every refresh. `Some("")` is a real binding, distinct from `None`. Strong on native apps (Keychain/Keystore-held ID); weaker on web where the ID travels with the token.
8. **GC**: run the store's `delete_expired` helper periodically; keep rotated/revoked rows until the family's absolute deadline — they power reuse detection.

## Security rules (non-negotiable)

- Never log a full token, the verifier, the pepper or the raw device identifier, and never put them in an error value ([N-14]/[N-46]); the selector is public and may be logged as a correlation id.
- Never store or transmit the raw verifier or raw deviceId server-side — the engine already guarantees the store only sees hashes; don't work around it.
- Treat store errors as refresh failures (fail closed): never `unwrap_or_default()` the outer `Result`.
- Default TTLs (30d absolute / 7d idle) suit consumer apps; for high-assurance (NIST AAL2), configure ~12h absolute / 30min idle.
- `reuse_grace_seconds` **defaults to 0 (strict), and that is the recommendation** ([N-30]). A non-zero window buys retry tolerance for clients that sent a refresh and never got the response, and it costs detectability: for that many seconds after a rotation, a thief holding the rotated predecessor who acts before the legitimate client is **served a valid token**, the legitimate client is evicted with `REVOKED`, and **no `REUSE_DETECTED` is raised**. Keep it as small as your clients need, and if you enable it, alert on the `REVOKED` rate.

## Common mistakes to avoid

- Reusing the presented refresh token after a successful refresh — it is dead; always persist the returned one.
- Retrying a failed refresh with the same token in client retry loops — outside the grace window this burns the family (by design).
- Putting user data or expiry claims "inside" the token — NEBULA tokens are opaque by design; claims belong in the short-lived access token.
- Implementing `mark_rotated` as a plain `UPDATE … WHERE selector=$1` — this silently disables the concurrency protection.
- Deleting rotated rows early (a Redis TTL at rotation, a nightly `DELETE WHERE status <> 'active'`) — that turns every replay into `NotFound` and disables reuse detection.
