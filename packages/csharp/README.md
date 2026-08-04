# NebulaToken (C#)

C# implementation of [NEBULA](../../SPECIFICATION.md) — opaque rotating refresh tokens
(RFC 9700 model). BCL only, no third-party dependencies. Targets `net10.0`.
Implements `spec_version = 1`.

```
dotnet add package NebulaToken
```

The API is **asynchronous**: every store method returns a `Task` and takes a
`CancellationToken`, because a blocking contract would force `GetAwaiter().GetResult()`
inside every real ADO.NET or EF Core store and starve the thread pool under ASP.NET.

```csharp
var engine = new NebulaEngine(new NebulaEngine.Config
{
    Peppers = new Dictionary<string, string>
    {
        ["k1"] = Environment.GetEnvironmentVariable("NEBULA_PEPPER_K1")!, // >= 32 bytes
    },
    ActiveKid = "k1",
    Store = new MemoryRefreshTokenStore(), // dev only — implement IRefreshTokenStore for production
    ReuseGraceSeconds = 0,         // strict; see [N-30] before raising this
});

// Login
var issued = await engine.IssueAsync("usr_1", deviceId);

// Refresh
var result = await engine.RefreshAsync(issued.Token, deviceId);
if (result.Ok)
{
    // result.Token is the NEW refresh token; the presented one is now dead
}
else if (result.Error is ErrorCode.Conflict)
{
    // a concurrent refresh won: retry once ([N-35])
}
else if (result.Error is ErrorCode.ReuseDetected or ErrorCode.DeviceMismatch)
{
    // security event: the family is already revoked — alert and force re-login
}

// Logout / incident response
var revoked = await engine.RevokeTokenAsync(token);  // authenticated: proves the verifier
if (!revoked.Ok) { /* it REFUSED — do not answer 204 ([N-36]) */ }
await engine.RevokeFamilyAsync(familyId);      // administrative
await engine.RevokeAllForUserAsync("usr_1");   // administrative
```

`ErrorCode` is documented as **open** ([N-40]): a future minor version may add a member,
so always include a default arm in a `switch` and treat an unrecognised code as a refusal.

## Tests

```
dotnet test
```

The suite is three files and adds no behaviour of its own:

| File | What it runs |
|---|---|
| `tests/NebulaToken.Tests/ConformanceTests.cs` | every case in `spec/test-vectors.json`, asserting the executed count equals the published `counts` block ([N-48]) |
| `tests/NebulaToken.Tests/BehaviorVectorsTests.cs` | every scenario in `spec/behavior-vectors.json`, one xUnit case per scenario |
| `tests/NebulaToken.Tests/EngineTests.cs` | what the vectors cannot express: the constant-time guard, the genuine rotation race, store-failure fail-closed behaviour, configuration validation, and secret hygiene |

The vector files are located by walking up to the repository root; they are never copied
into the package.

**Agent skill:** [`skills/nebula-token-csharp/SKILL.md`](skills/nebula-token-csharp/SKILL.md) teaches an AI coding assistant to integrate this package correctly. Install it with the standard agent-skill installer:

```sh
npx skills add nebula-token/nebula-token --skill nebula-token-csharp
```

That lands in the project's `.claude/skills/`, checked in and shared with your team; add `-g` for your personal `~/.claude/skills/` instead. In Claude Code it is equally a plugin — `/plugin marketplace add nebula-token/nebula-token`, then `/plugin install nebula-token-csharp@nebula-token`. Neither route copies anything: both read this directory in place, through [`.claude-plugin/marketplace.json`](../../.claude-plugin/marketplace.json).

As a fallback the skill also ships inside the published artefact, in the same installable shape — inside the extracted `.nupkg` the directory is `skills/nebula-token-csharp/`, and copying that directory into `~/.claude/skills/` is the whole installation. All ten skills and every install route are in [`skills/README.md`](../../skills/README.md).
