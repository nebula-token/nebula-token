# nebulatoken (Go)

Go implementation of [NEBULA](../../SPECIFICATION.md) — opaque rotating refresh tokens (RFC 9700 model). Standard library only, Go ≥ 1.25. Implements `spec_version = 1`.

```
go get github.com/nebula-token/nebula-token/packages/go
```

The package is named `nebulatoken`, not `nebula`: the short name collides with [slackhq/nebula](https://github.com/slackhq/nebula), an unrelated overlay network, and a mistaken import in an authentication path is expensive.

**Import path ends in `go`, package clause is `nebulatoken`** — legal, and deliberate, but not guessable. Always write the qualifier:

```go
import nebulatoken "github.com/nebula-token/nebula-token/packages/go"
```

This is a Go **submodule** of the NEBULA monorepo, so its versions are the directory-prefixed tags `packages/go/vX.Y.Z`; `go get …@v1.0.3` resolves against those, and a bare `v1.0.1` tag is not a version of this module ([`VERSIONING.md`](../../VERSIONING.md) §5).

```go
import (
    "context"

    nebulatoken "github.com/nebula-token/nebula-token/packages/go"
)

engine, err := nebulatoken.NewEngine(nebulatoken.Config{
    Peppers:   map[string]string{"k1": os.Getenv("NEBULA_PEPPER_K1")}, // >= 32 bytes
    ActiveKid: "k1",
    Store:     nebulatoken.NewMemoryRefreshTokenStore(), // dev only — implement RefreshTokenStore for production
})

// Login. The third argument is optional sender binding: nil binds nothing,
// nebulatoken.Device("") binds the empty identifier — they are different.
issued, err := engine.Issue(ctx, "usr_1", nebulatoken.Device(deviceID))

// Refresh.
res, err := engine.Refresh(ctx, presented, nebulatoken.Device(deviceID))
switch {
case err != nil:
    // Infrastructure failure: fail closed, issue nothing.
case res.OK:
    // res.Token is the NEW refresh token; the presented one is dead.
case res.Error == nebulatoken.CodeConflict:
    // A concurrent refresh won. Retryable exactly once.
case res.Error == nebulatoken.CodeReuseDetected, res.Error == nebulatoken.CodeDeviceMismatch:
    // Security event: the family is already revoked. Alert, force re-login.
default:
    // Any other code — including one this build does not know — is a refusal.
}

// Logout and incident response.
revoked, err := engine.RevokeToken(ctx, presented) // authenticated: proves the verifier
n, err := engine.RevokeFamily(ctx, familyID)
n, err = engine.RevokeAllForUser(ctx, "usr_1")
```

Two failure channels: protocol outcomes are values (`res.Error`), infrastructure failures are the returned `error` and must never be swallowed.

Test: `go test -race ./...` — the suite runs the shared vectors in `../../spec/`.

**Agent skill:** [`skills/nebula-token-go/SKILL.md`](skills/nebula-token-go/SKILL.md) teaches an AI coding assistant to integrate this package correctly. Install it with the standard agent-skill installer:

```sh
npx skills add nebula-token/nebula-token --skill nebula-token-go
```

That lands in the project's `.claude/skills/`, checked in and shared with your team; add `-g` for your personal `~/.claude/skills/` instead. In Claude Code it is equally a plugin — `/plugin marketplace add nebula-token/nebula-token`, then `/plugin install nebula-token-go@nebula-token`. Neither route copies anything: both read this directory in place, through [`.claude-plugin/marketplace.json`](../../.claude-plugin/marketplace.json).

As a fallback the skill also ships inside the published artefact, in the same installable shape — after `go get` the directory is at `$(go env GOMODCACHE)/github.com/nebula-token/nebula-token/packages/go@vX.Y.Z/skills/nebula-token-go/`, and copying that directory into `~/.claude/skills/` is the whole installation. All ten skills and every install route are in [`skills/README.md`](../../skills/README.md).
