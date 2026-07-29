# nebula-token (Ruby)

Ruby implementation of [NEBULA](../../SPECIFICATION.md) — opaque rotating refresh tokens (RFC 9700 model). Standard library only (`openssl`, `securerandom`), no gem dependencies, Ruby ≥ 3.3.

```
gem install nebula-token
```

```ruby
require 'nebula_token' # or 'nebula-token'

engine = NebulaToken::Engine.new(
  peppers: { 'k1' => ENV.fetch('NEBULA_PEPPER_K1') }, # >= 32 BYTES
  active_kid: 'k1',
  store: NebulaToken::MemoryRefreshTokenStore.new,    # dev only — see examples/pg_store.rb
  reuse_grace_seconds: 0             # strict; see [N-30] before raising this
)

issued = engine.issue('usr_1', device_id)   # .token .user_id .family_id .generation
                                            # .expires_at .idle_expires_at (unix seconds)

result = engine.refresh(issued.token, device_id)
if result.ok?
  result.token                              # the NEW token; the presented one is dead
else
  result.error                              # 'REUSE_DETECTED', 'CONFLICT', …
end
```

`refresh` never raises for a protocol outcome — failures are values ([N-29]) — and a store
error is never converted into one: it propagates, so the caller fails closed ([N-20]).
`'CONFLICT'` means a concurrent refresh won the compare-and-set; nothing was rotated and the
client may retry once ([N-35]). Treat the code set as open: give every `case result.error`
an `else` branch that denies access ([N-40]).

Revocation:

```ruby
engine.revoke_token(token)          # authenticated: proves the verifier; -> .ok? .revoked
engine.revoke_family(family_id)     # administrative -> Integer
engine.revoke_all_for_user(user_id) # administrative -> Integer
```

Store: implement the six methods of [`NebulaToken::RefreshTokenStore`](lib/nebula_token.rb)
over your database — `find_by_selector`, `insert`, `mark_rotated`, `revoke_if_active`,
`revoke_family`, `revoke_user`. The two compare-and-set methods must apply their write only
when the current status still matches ([N-17], [N-18]); start from
[`examples/pg_store.rb`](examples/pg_store.rb), schema in [`docs/STORE.md`](../../docs/STORE.md).

Test (no bundler, no dependencies):

```
ruby -Ilib test/conformance_test.rb   # spec/test-vectors.json
ruby -Ilib test/behavior_test.rb      # spec/behavior-vectors.json
ruby -Ilib test/engine_test.rb        # Ruby-specific properties
```

**Agent skill:** [`skills/nebula-token-ruby/SKILL.md`](skills/nebula-token-ruby/SKILL.md) teaches an AI coding assistant to integrate this package correctly. Install it with the standard agent-skill installer:

```sh
npx skills add nebula-token/nebula-token --skill nebula-token-ruby
```

That lands in the project's `.claude/skills/`, checked in and shared with your team; add `-g` for your personal `~/.claude/skills/` instead. In Claude Code it is equally a plugin — `/plugin marketplace add nebula-token/nebula-token`, then `/plugin install nebula-token-ruby@nebula-token`. Neither route copies anything: both read this directory in place, through [`.claude-plugin/marketplace.json`](../../.claude-plugin/marketplace.json).

As a fallback the skill also ships inside the published artefact, in the same installable shape — after `gem install nebula-token` the directory is at `<gem dir>/gems/nebula-token-X.Y.Z/skills/nebula-token-ruby/`, and copying that directory into `~/.claude/skills/` is the whole installation. All ten skills and every install route are in [`skills/README.md`](../../skills/README.md).
