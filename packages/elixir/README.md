# nebula_token (Elixir)

Elixir implementation of [NEBULA](../../SPECIFICATION.md) — opaque rotating refresh tokens (RFC 9700 model). `:crypto` + stdlib only, no runtime dependencies. Implements `spec_version = 1`.

**Requires Elixir ≥ 1.18 and Erlang/OTP ≥ 25.** The constant-time comparison the specification mandates ([N-31]) is `:crypto.hash_equals/2`, added in OTP 25, and it backs *both* the verifier proof and the sender binding. On an older OTP `issue/3` would work while every `refresh/3` raised `UndefinedFunctionError`, so `mix.exs` refuses to build there rather than letting the defect reach production.

```elixir
{:nebula_token, "~> 1.0"}
```

## Usage

```elixir
{:ok, store} = NebulaToken.MemoryStore.start_link()   # dev/test only — see "Stores"

engine =
  NebulaToken.Engine.new(
    peppers: %{"k1" => System.fetch_env!("NEBULA_PEPPER_K1")},
    active_kid: "k1",
    store_mod: NebulaToken.MemoryStore,
    store: store,
    reuse_grace_seconds: 0
  )

# Login
issued = NebulaToken.Engine.issue(engine, "usr_1", device_id)
# => %NebulaToken.TokenResult{token: ..., user_id: ..., family_id: ..., generation: 0,
#      expires_at: <unix seconds>, idle_expires_at: <unix seconds>}
# inspect/1 on it hides the token ([N-14]); issued.token still returns it.
# Being a struct is what makes that redaction possible, and it means the value
# is not Jason-encodable: use Map.from_struct(issued) before json(conn, ...),
# or build the response body field by field.

# Refresh
case NebulaToken.Engine.refresh(engine, presented_token, device_id) do
  {:ok, result} ->
    # the presented token is now dead — persist result.token
    {:ok, result.token}

  {:error, %NebulaToken.Failure{code: code} = failure}
  when code in [:REUSE_DETECTED, :DEVICE_MISMATCH] ->
    # security event: the family is already revoked. failure.user_id and
    # failure.family_id identify the session without a second lookup ([N-39]).
    alert(failure)

  {:error, %NebulaToken.Failure{code: :CONFLICT}} ->
    :retry_once            # a concurrent refresh won; nothing was rotated

  {:error, %NebulaToken.Failure{}} ->
    :require_login         # keep a catch-all: the code set is open ([N-40])
end

# Logout / incident response
{:ok, _} = NebulaToken.Engine.revoke_token(engine, token) # authenticated; it can refuse
NebulaToken.Engine.revoke_family(engine, family_id)     # administrative
NebulaToken.Engine.revoke_all_for_user(engine, user_id) # administrative
```

`revoke_token/2` proves the verifier before revoking anything ([N-36]): the selector is a *public* lookup key, so accepting one alone would be an unauthenticated denial of service. It takes no device identifier and performs no sender-binding check. It returns `{:ok, %{user_id: ..., family_id: ..., revoked: n}}` or `{:error, %NebulaToken.Failure{}}`; the two administrative functions take a server-side identifier and return the count `n` directly.

## Stores — `:store_mod` is not optional in production

The engine talks to storage through two options that travel together:

| Option | Meaning |
|---|---|
| `:store_mod` | The module implementing the `NebulaToken.Store` behaviour. **Defaults to `NebulaToken.MemoryStore`.** |
| `:store` | The handle passed back to that module as its first argument — an `Agent` pid, a `Postgrex` pool name, an `Ecto.Repo`, a tuple of those. |

Omitting `:store_mod` does not fail: it silently routes every call to the in-memory store, which loses every session on restart and cannot detect reuse across nodes. Production configurations must set it.

```elixir
engine =
  NebulaToken.Engine.new(
    peppers: %{"k1" => pepper},
    active_kid: "k1",
    store_mod: MyApp.RefreshTokenStore,
    store: MyApp.Repo
  )
```

The contract is six callbacks ([N-16]); a ready-made SQL template is in [`examples/postgrex_store.ex`](examples/postgrex_store.ex) and the schema in [`docs/STORE.md`](../../docs/STORE.md).

```elixir
find_by_selector(store, selector)                                        :: {:ok, Record.t() | nil} | {:error, term}
insert(store, record)                                                    :: :ok                     | {:error, term}
mark_rotated(store, selector, from_status, rotated_at, replaced_by)      :: {:ok, boolean}          | {:error, term}
revoke_if_active(store, selector)                                        :: {:ok, boolean}          | {:error, term}
revoke_family(store, family_id)                                          :: {:ok, non_neg_integer}  | {:error, term}
revoke_user(store, user_id)                                              :: {:ok, non_neg_integer}  | {:error, term}
```

`mark_rotated/5` and `revoke_if_active/2` are **compare-and-set** ([N-17], [N-18]): they must apply their write only if the current status still matches, and report whether it applied. Returning `{:ok, true}` unconditionally re-opens the race in which two concurrent refreshes each mint a successor and fork the family.

## Two failure channels ([N-20])

* **Protocol outcomes are values.** `{:error, %NebulaToken.Failure{code: ...}}` — one of the ten codes of [N-38]. Never raised.
* **Infrastructure failures raise.** A store callback that answers `{:error, reason}` — unreachable database, timeout, constraint violation — becomes a `NebulaToken.StoreError`. It is never laundered into a protocol outcome, so an operation whose store call failed cannot return a token for state that was not written, nor report a revocation that did not happen.

Invalid configuration and a device identifier that is not valid UTF-8 at `issue/3` raise `ArgumentError` ([N-12]).

## Tests

```
mix deps.get && mix test
```

The suite is three files and nothing is hand-derived from the prose:

* `test/conformance_test.exs` — every case in `spec/test-vectors.json`, asserting the executed count equals the published count ([N-48]);
* `test/behavior_test.exs` — every scenario in `spec/behavior-vectors.json`, one ExUnit test each, plus one test that runs the whole file and asserts the count it *actually executed* against the published `counts` block, reporting by id any conditional scenario this runtime skips ([N-48]);
* `test/engine_test.exs` — what the vectors cannot express: the constant-time guard, real concurrency, store-failure fail-closed behaviour, configuration validation, and secret hygiene.

Both vector files are resolved by walking up to the repository root, never copied into the package.

`runtime-admits-invalid-unicode-strings` is not satisfied here — `String.t()` on the BEAM is a UTF-8 binary and cannot hold an unpaired surrogate — so `device-05` is reported as skipped. The [N-12] requirement behind it is still proven in `engine_test.exs`, against the WTF-8 byte sequence `<<0xED, 0xA0, 0x80>>`.

**Agent skill:** [`skills/nebula-token-elixir/SKILL.md`](skills/nebula-token-elixir/SKILL.md) teaches an AI coding assistant to integrate this package correctly. Install it with the standard agent-skill installer:

```sh
npx skills add nebula-token/nebula-token --skill nebula-token-elixir
```

That lands in the project's `.claude/skills/`, checked in and shared with your team; add `-g` for your personal `~/.claude/skills/` instead. In Claude Code it is equally a plugin — `/plugin marketplace add nebula-token/nebula-token`, then `/plugin install nebula-token-elixir@nebula-token`. Neither route copies anything: both read this directory in place, through [`.claude-plugin/marketplace.json`](../../.claude-plugin/marketplace.json).

As a fallback the skill also ships inside the published artefact, in the same installable shape — after `mix deps.get` the directory is at `deps/nebula_token/skills/nebula-token-elixir/`, and copying that directory into `~/.claude/skills/` is the whole installation. All ten skills and every install route are in [`skills/README.md`](../../skills/README.md).
