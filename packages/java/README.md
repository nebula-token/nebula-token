# nebula-token (Java)

Java implementation of [NEBULA](../../SPECIFICATION.md) — opaque rotating refresh tokens (RFC 9700 model). JDK standard library only, no runtime dependencies (JDK ≥ 17). Implements `spec_version = 1`.

```xml
<dependency>
  <groupId>dev.nebulatoken</groupId>
  <artifactId>nebula-token</artifactId>
  <version>1.0.2</version>
</dependency>
```

```groovy
implementation 'dev.nebulatoken:nebula-token:1.0.2'
```

```java
NebulaEngine.Config cfg = new NebulaEngine.Config();
cfg.peppers = Map.of("k1", System.getenv("NEBULA_PEPPER_K1")); // >= 32 BYTES
cfg.activeKid = "k1";
cfg.store = new MemoryRefreshTokenStore();  // dev only — implement RefreshTokenStore in production
NebulaEngine engine = new NebulaEngine(cfg);

// Login. deviceId is optional; null = unbound, "" is a real binding.
IssueResult issued = engine.issue("usr_1", deviceId);

// Refresh. The result type is sealed, so this switch is exhaustive on JDK 21+.
switch (engine.refresh(presented, deviceId)) {
    case RefreshResult.Success s -> setCookie(s.token());  // the presented token is now dead
    case RefreshResult.Failure f -> deny(f.error());       // f.userId()/f.familyId() for monitoring
}

// Logout and incident response.
var revoked = engine.revokeToken(presented);  // authenticated: proves the verifier
if (!revoked.ok()) { /* it REFUSED — do not answer 204 ([N-36]) */ }
engine.revokeFamily(familyId);      // administrative, no token needed
engine.revokeAllForUser("usr_1");   // returns how many records were revoked
```

## Two failure channels

Protocol outcomes are **return values** — `RefreshResult.Failure` carrying an `ErrorCode`, never thrown.
Infrastructure failures (store unreachable, timeout, constraint violation) are **unchecked exceptions**
thrown by your store and propagated unchanged, so an operation that could not read or write fails
closed rather than returning a token or claiming a revocation that never happened.
See `package-info.java` and [N-20].

`NebulaConfigException` is the third, narrower case: a caller mistake, surfaced at the call site.

## Conformance

`mvn test` runs three suites against the shared artifacts in `spec/`, resolved by walking up to the
repository root:

| File | What it runs |
|---|---|
| `ConformanceTest` | every case in `spec/test-vectors.json`, asserting the executed count equals the published count |
| `BehaviorVectorsTest` | every scenario in `spec/behavior-vectors.json`, one JUnit test each |
| `EngineTest` | what the vectors cannot express: real-thread concurrency, a store that throws, byte-vs-character lengths, config validation |

The suites are not published: the jar carries `dev/nebulatoken/**` plus the licence, this README
and `skills/nebula-token-java/SKILL.md` under `META-INF/`, and nothing else. Conformance is
verified from a repository checkout, which is where the shared `spec/` artifacts live.

**Agent skill:** [`skills/nebula-token-java/SKILL.md`](skills/nebula-token-java/SKILL.md) teaches an AI coding assistant to integrate this package correctly. Install it with the standard agent-skill installer:

```sh
npx skills add nebula-token/nebula-token --skill nebula-token-java
```

That lands in the project's `.claude/skills/`, checked in and shared with your team; add `-g` for your personal `~/.claude/skills/` instead. In Claude Code it is equally a plugin — `/plugin marketplace add nebula-token/nebula-token`, then `/plugin install nebula-token-java@nebula-token`. Neither route copies anything: both read this directory in place, through [`.claude-plugin/marketplace.json`](../../.claude-plugin/marketplace.json).

As a fallback the skill also ships inside the published artefact, in the same installable shape — inside the jar the directory is `META-INF/skills/nebula-token-java/`, and copying that directory into `~/.claude/skills/` is the whole installation. All ten skills and every install route are in [`skills/README.md`](../../skills/README.md).

## License

**Apache License 2.0** ([`LICENSE`](LICENSE)). SPDX: `Apache-2.0`. The full text ships inside
both the main jar and the sources jar as `META-INF/LICENSE`.
