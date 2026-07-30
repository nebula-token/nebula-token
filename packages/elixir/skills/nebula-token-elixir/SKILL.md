---
name: nebula-token-elixir
description: Integrate NEBULA opaque rotating refresh tokens in a Elixir backend. Use when adding login sessions, refresh-token rotation, reuse detection, token revocation, or when replacing hand-rolled or JWT-based refresh tokens. Covers engine setup, endpoints, production store, and security rules.
---

# Integrating nebula-token (Elixir)

NEBULA is an implementation profile of RFC 9700 (OAuth 2.0 Security BCP) for
refresh tokens: opaque tokens (`nbl.{kid}.{selector}.{verifier}` — pure
entropy, no claims), rotation on every use, reuse detection with family
revocation, hashed storage, optional device binding. Package: `nebula_token (Hex)`.
Normative behavior: `SPECIFICATION.md` in the repository root.

## Install

```
{:nebula_token, "~> 1.0"}
```

Requires **Elixir ≥ 1.18 and Erlang/OTP ≥ 25** — the constant-time comparison
([N-31]) is `:crypto.hash_equals/2`, which OTP added in 25. The build fails on
anything older rather than raising on every refresh at runtime.

## Core integration

```elixir
{:ok, store} = NebulaToken.MemoryStore.start_link()   # dev only — SQL store in prod

engine = NebulaToken.Engine.new(
  peppers: %{"k1" => System.fetch_env!("NEBULA_PEPPER_K1")},  # >= 32 BYTES
  active_kid: "k1",
  store_mod: NebulaToken.MemoryStore,   # <- the module; REQUIRED in production
  store: store,                         # <- the handle it receives
  reuse_grace_seconds: 0
)

# Login endpoint
issued = NebulaToken.Engine.issue(engine, user_id, device_id)
# %NebulaToken.TokenResult{token:, user_id:, family_id:, generation:, expires_at:, idle_expires_at:}
# a struct, so inspect/1 redacts the token ([N-14]); issued.token still returns it
# not Jason-encodable: Map.from_struct(issued) before json(conn, ...)

# Refresh endpoint
case NebulaToken.Engine.refresh(engine, presented_token, device_id) do
  {:ok, result} ->
    {:ok, result.token}   # result.token replaces the presented one, which is now dead

  {:error, %NebulaToken.Failure{code: code} = f}
  when code in [:REUSE_DETECTED, :DEVICE_MISMATCH] ->
    alert(f.user_id, f.family_id)   # family already revoked; attribution comes free ([N-39])

  {:error, %NebulaToken.Failure{code: :CONFLICT}} ->
    :retry_once           # a concurrent refresh won the CAS; nothing was rotated

  {:error, %NebulaToken.Failure{}} ->
    :require_login        # catch-all is mandatory: the code set is open ([N-40])
end

# Logout / compromise. revoke_token answers a tagged tuple, not :ok — an
# unmatched refusal is a logout that never happened ([N-36]).
case NebulaToken.Engine.revoke_token(engine, token) do  # proves the verifier
  {:ok, %{revoked: n}} -> n            # n records revoked
  {:error, %NebulaToken.Failure{}} -> :refused  # nothing was revoked
end

NebulaToken.Engine.revoke_family(engine, family_id)      # administrative -> integer
NebulaToken.Engine.revoke_all_for_user(engine, user_id)  # administrative -> integer
```

The engine is a plain immutable struct — build it once (e.g. in your Phoenix
context or application supervisor) and pass it around; the store owns the state.

## `:store_mod` — the option that decides whether you have a real store

`:store_mod` names the module implementing the `NebulaToken.Store` behaviour and
**defaults to `NebulaToken.MemoryStore`**. Passing only `:store` therefore does
not fail: it silently wires every call to the in-memory store, so sessions die
on deploy and reuse detection stops working across nodes. Always set both:

```elixir
store_mod: MyApp.RefreshTokenStore,
store: MyApp.Repo
```

Contract ([N-16]) — six callbacks, first argument is your `:store` handle:

```elixir
find_by_selector(store, selector)                                   :: {:ok, Record.t() | nil} | {:error, term}
insert(store, record)                                               :: :ok                     | {:error, term}
mark_rotated(store, selector, from_status, rotated_at, replaced_by) :: {:ok, boolean}          | {:error, term}
revoke_if_active(store, selector)                                   :: {:ok, boolean}          | {:error, term}
revoke_family(store, family_id)                                     :: {:ok, non_neg_integer}  | {:error, term}
revoke_user(store, user_id)                                         :: {:ok, non_neg_integer}  | {:error, term}
```

`mark_rotated/5` and `revoke_if_active/2` are compare-and-sets: apply the write
only if the current status still matches, and report whether it applied
(`WHERE selector = $1 AND status = $2`, then `num_rows == 1`). Returning
`{:ok, true}` unconditionally forks families under concurrency.

## Integration checklist

1. **Pepper**: generate with `openssl rand -base64 48`; store in env/KMS, never in code or DB. At least 32 **bytes** — the floor is measured in bytes, not characters. Key it as `k1` now so future rotation (add `k2`, switch `active_kid`) is zero-downtime.
2. **Store**: for production implement the six callbacks over your database and pass `:store_mod`. Start from `examples/postgrex_store.ex` (schema in `docs/STORE.md`). The in-memory store is **not for production** ([N-21]): its state is per-process and lost on restart, so reuse detection does not survive a deploy and does not work behind more than one instance.
3. **Login endpoint**: authenticate credentials → `issue` → set the token in an `httpOnly; Secure; SameSite=Strict` cookie scoped to the refresh path. Never return it in a JSON body read by browser JS, never localStorage.
4. **Refresh endpoint**: read cookie → `refresh` → on success set the NEW token in the cookie and mint a short-lived access token (5–15 min). Wrap the call in one DB transaction so insert + `mark_rotated` commit atomically.
5. **Error handling**: match on `%NebulaToken.Failure{code: code}` with atoms matching the spec names, and always keep a catch-all clause. Every failure means "no access token issued". `:REUSE_DETECTED` and `:DEVICE_MISMATCH` additionally mean the family is already revoked — log a security event and alert; the failure struct carries `user_id` and `family_id` whenever a record was resolved — every code except `:MALFORMED`, `:UNKNOWN_KID` and `:NOT_FOUND` — so you need no second lookup of a token you were told never to log ([N-39]). `:CONFLICT` is transient: retry once ([N-35]).
6. **Store errors**: a store callback answering `{:error, reason}` raises `NebulaToken.StoreError`. Let it propagate to a 5xx — never rescue it into "session invalid", and never rescue it into a success.
7. **Logout**: `revoke_token/2` (one session, proves the verifier) / `revoke_all_for_user/2` (password change, compromise). `revoke_family/2` for admin paths that already know the family. They do not return the same shape, and the difference is load-bearing: `revoke_token/2` answers `{:ok, %{user_id:, family_id:, revoked:}}` or `{:error, %NebulaToken.Failure{}}` — it **can refuse** (`:MALFORMED`, `:UNKNOWN_KID`, `:NOT_FOUND`, `:VERIFIER_MISMATCH`) ([N-36]), so match both clauses; calling it for its side effect and answering `204` reports a logout that never happened and leaves the session alive. `revoke_family/2` and `revoke_all_for_user/2` take no token, cannot refuse, and return a bare `integer` count.
8. **Device binding (optional)**: pass a stable device identifier at issue AND every refresh. `nil` means unbound; `""` is a real binding. Strong on native apps (Keychain/Keystore-held ID); weaker on web where the ID travels with the token.
9. **GC**: run the store's `delete_expired` helper periodically; keep rotated/revoked rows until the family's absolute deadline — they power reuse detection.

## Security rules (non-negotiable)

- Never log a full token, the verifier, the pepper or the raw device identifier, and never put them in an error value ([N-14]/[N-46]); the selector is public and may be logged as a correlation id. `inspect/1` on the engine already hides the peppers.
- Never store or transmit the raw verifier or raw device id server-side — the engine guarantees the store only sees hashes; don't work around it.
- Treat store errors as refresh failures (fail closed). `NebulaToken.StoreError` is the mechanism; do not convert it into a `%Failure{}`.
- Default TTLs (30d absolute / 7d idle) suit consumer apps; for high-assurance (NIST AAL2), configure ~12h absolute / 30min idle.
- `reuse_grace_seconds` **defaults to 0 (strict), and that is the recommendation** ([N-30]). A non-zero window buys retry tolerance for clients that sent a refresh and never got the response, and it costs detectability: for that many seconds after a rotation, a thief holding the rotated predecessor who acts before the legitimate client is **served a valid token**, the legitimate client is evicted with `:REVOKED`, and **no `:REUSE_DETECTED` is raised**. Keep it as small as your clients need, and if you enable it, alert on the `:REVOKED` rate.

## Common mistakes to avoid

- Omitting `:store_mod` and believing you configured a production store.
- Reusing the presented refresh token after a successful refresh — it is dead; always persist the returned one.
- Retrying a failed refresh with the same token in client retry loops — outside the grace window this burns the family (by design).
- Matching only the ten known error codes without a catch-all clause — the code set is documented as open.
- Putting user data or expiry claims "inside" the token — NEBULA tokens are opaque by design; claims belong in the short-lived access token.
- Implementing `mark_rotated/5` without the `AND status = $2` clause: it compiles, passes a single-threaded test, and forks families in production.
