# nebula-token

Python reference implementation of [NEBULA](../../SPECIFICATION.md) — opaque rotating refresh tokens (RFC 9700 model). Standard library only, Python ≥ 3.11. Implements `spec_version = 1`.

```
pip install nebula-token
```

```python
import os
from nebula_token import NebulaEngine, MemoryRefreshTokenStore

engine = NebulaEngine(
    peppers={"k1": os.environ["NEBULA_PEPPER_K1"]},  # >= 32 BYTES, from env/KMS
    active_kid="k1",
    store=MemoryRefreshTokenStore(),  # dev only — implement RefreshTokenStore for production
    reuse_grace_seconds=0,            # see [N-30] before raising this
)

issued = engine.issue("usr_1", device_id)
# issued.token, .user_id, .family_id, .generation, .expires_at, .idle_expires_at

result = engine.refresh(issued.token, device_id)
if result.ok:
    ...            # persist result.token client-side; the presented token is dead
else:
    result.error   # "REUSE_DETECTED", "CONFLICT", … — treat an unknown code as a refusal
```

## API

| Call | Returns |
|---|---|
| `issue(user_id, device_id=None)` | `IssueResult` — raises `NebulaConfigError` for an invalid `device_id` |
| `refresh(token, device_id=None)` | `RefreshOk` \| `RefreshError` (never raises for protocol outcomes) |
| `revoke_token(token)` | `RevokeOk` \| `RevokeError` — **authenticated**: proves the verifier, then revokes the family and reports `revoked`. Takes no device identifier ([N-36]) |
| `revoke_family(family_id)` | `int` revoked — administrative, no token required |
| `revoke_all_for_user(user_id)` | `int` revoked — administrative, no token required |

Timestamps are integer Unix seconds everywhere. `device_id=None` (unbound) and
`device_id=""` (bound to the empty string) are different values.

Failure results carry `user_id` and `family_id` whenever the engine resolved a
record — every code except `MALFORMED`, `UNKNOWN_KID` and `NOT_FOUND` — so a
security event can be attributed without a second lookup.

`NebulaErrorCode` is a closed `Literal` for type checking but an **open** set at
runtime: a future minor version may add a code, so treat an unrecognised value as
a refusal rather than assuming your `if/elif` chain is exhaustive.

## Stores

`RefreshTokenStore` is a six-method `Protocol`; `mark_rotated` and
`revoke_if_active` are compare-and-set and must return whether they applied —
returning `True` unconditionally re-opens the race that forks a token family.
`examples/sqlite_store.py` is a runnable template; the schema is in
[docs/STORE.md](../../docs/STORE.md).

**The contract is synchronous.** Blocking drivers are the Python norm, and an
engine that never awaits cannot silently discard a coroutine. Under asyncio, call
the engine off the event loop:

```python
result = await asyncio.to_thread(engine.refresh, token, device_id)
```

Do **not** give the engine a store whose methods are `async def`: nothing awaits
them, so `insert` would return an un-awaited coroutine and the engine would hand
out a token for a record that was never written.

Infrastructure failures (store unreachable, timeout, constraint violation) must
raise; the exception propagates out of the engine and is never converted into a
protocol outcome, so callers fail closed.

`MemoryRefreshTokenStore` is mutex-guarded and safe across threads, but is
per-process and lost on restart — development and tests only.

## Tests

```
cd packages/python
pip install pytest
pytest -q
```

`pyproject.toml` puts the source tree and `tests/` on `sys.path`
(`tool.pytest.ini_options.pythonpath`), so no install step is needed. The suites
read the normative artifacts from `spec/` in the repository root, located by
walking up from the test file:

- `tests/test_conformance.py` — `spec/test-vectors.json` (46 cases)
- `tests/test_behavior.py` + `tests/behavior_runner.py` — `spec/behavior-vectors.json` (38 scenarios)
- `tests/test_engine.py` — what the vectors cannot express: the constant-time
  guard, concurrency, store failures, configuration, and secret hygiene

Type checking: `pip install mypy && mypy --strict` (configured in `pyproject.toml`).

See the [repository README](../../README.md) and [SPECIFICATION.md](../../SPECIFICATION.md).

**Agent skill:** [`skills/nebula-token-python/SKILL.md`](skills/nebula-token-python/SKILL.md) teaches an AI coding assistant to integrate this package correctly. Install it with the standard agent-skill installer:

```sh
npx skills add nebula-token/nebula-token --skill nebula-token-python
```

That lands in the project's `.claude/skills/`, checked in and shared with your team; add `-g` for your personal `~/.claude/skills/` instead. In Claude Code it is equally a plugin — `/plugin marketplace add nebula-token/nebula-token`, then `/plugin install nebula-token-python@nebula-token`. Neither route copies anything: both read this directory in place, through [`.claude-plugin/marketplace.json`](../../.claude-plugin/marketplace.json).

As a fallback the skill also ships inside the published artefact, in the same installable shape — after `pip install nebula-token` the directory is at `<site-packages>/nebula_token/skills/nebula-token-python/`, and copying that directory into `~/.claude/skills/` is the whole installation. All ten skills and every install route are in [`skills/README.md`](../../skills/README.md).
