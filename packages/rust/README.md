# nebula-token (Rust)

Rust implementation of [NEBULA](../../SPECIFICATION.md) — opaque rotating refresh tokens (RFC 9700 model). Implements spec version 1.

```toml
[dependencies]
nebula-token = "1"
```

```rust
use nebula_token::{Config, ErrorCode, MemoryRefreshTokenStore, NebulaEngine};
use std::collections::HashMap;
use std::sync::Arc;

let peppers = HashMap::from([("k1".into(), std::env::var("NEBULA_PEPPER_K1")?)]);
// Every method takes &self, so one engine serves every request handler.
let engine = Arc::new(NebulaEngine::new(Config::new(peppers, "k1", MemoryRefreshTokenStore::new()))?);

let issued = engine.issue("usr_1", Some(device_id))?;

match engine.refresh(&issued.token, Some(device_id))? {
    Ok(next) => { /* store next.token client-side; the presented one is dead */ }
    Err(failure) => match failure.code {
        ErrorCode::Conflict => { /* transient: retry once */ }
        ErrorCode::ReuseDetected | ErrorCode::DeviceMismatch => { /* security event; family already revoked */ }
        _ => { /* require a new login */ }
    },
}
```

## Two failure channels

Every engine method returns `Result<_, S::Error>`:

- the **outer** `Result` is the infrastructure channel — the store being unreachable, a timeout, a constraint violation. It is never downgraded into a protocol outcome, so `?` fails closed ([N-20]).
- the **inner** value is the protocol outcome: `Ok(RefreshOk)` or `Err(Failure)`, where `Failure::code` is one of the ten spec codes and carries `user_id`/`family_id` whenever a record was resolved ([N-39]).

`ErrorCode` is `#[non_exhaustive]` ([N-40]): match with a wildcard arm and treat an unrecognised code as a refusal.

## Store

Implement `RefreshTokenStore` over your database. `mark_rotated` and `revoke_if_active` MUST be compare-and-sets — the status belongs in the `WHERE` clause and the affected-row count is the return value ([N-17], [N-18]). `examples/sql_store.rs` is a complete driver-agnostic template; the schema is in [`docs/STORE.md`](../../docs/STORE.md).

`MemoryRefreshTokenStore` is thread-safe and for development and tests only: its state is per-process, so reuse detection would not survive a deploy or work behind more than one instance.

## Requirements

Rust 1.85 or newer.

## Tests

```
cargo test            # conformance vectors, behavior vectors, Rust-specific suite
cargo clippy --all-targets -- -D warnings
```

`tests/conformance.rs` and `tests/behavior.rs` read the shared vectors from `spec/` at the repository root; they are never copied into this package.

**Agent skill:** [`skills/nebula-token-rust/SKILL.md`](skills/nebula-token-rust/SKILL.md) teaches an AI coding assistant to integrate this package correctly. Install it with the standard agent-skill installer:

```sh
npx skills add nebula-token/nebula-token --skill nebula-token-rust
```

That lands in the project's `.claude/skills/`, checked in and shared with your team; add `-g` for your personal `~/.claude/skills/` instead. In Claude Code it is equally a plugin — `/plugin marketplace add nebula-token/nebula-token`, then `/plugin install nebula-token-rust@nebula-token`. Neither route copies anything: both read this directory in place, through [`.claude-plugin/marketplace.json`](../../.claude-plugin/marketplace.json).

As a fallback the skill also ships inside the published artefact, in the same installable shape — after `cargo add nebula-token` the directory is at `~/.cargo/registry/src/*/nebula-token-X.Y.Z/skills/nebula-token-rust/`, and copying that directory into `~/.claude/skills/` is the whole installation. All ten skills and every install route are in [`skills/README.md`](../../skills/README.md).
