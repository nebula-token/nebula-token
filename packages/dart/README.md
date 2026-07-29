# nebula_token (Dart)

Dart implementation of [NEBULA](../../SPECIFICATION.md) — opaque rotating refresh tokens (RFC 9700 model). Implements spec version 1. Dart ≥ 3.9, single dependency (`crypto`).

```
dart pub add nebula_token
```

```dart
import 'package:nebula_token/nebula_token.dart';

final engine = NebulaEngine(
  peppers: {'k1': Platform.environment['NEBULA_PEPPER_K1']!}, // >= 32 bytes
  activeKid: 'k1',
  store: MemoryRefreshTokenStore(), // implement RefreshTokenStore for production
  reuseGraceSeconds: 0,            // strict; see [N-30] before raising this
);

final issued = await engine.issue('usr_1', deviceId);

final result = await engine.refresh(issued.token, deviceId);
switch (result) {
  case RefreshSuccess(:final token):
    // store `token` client-side; the presented one is now dead
  case RefreshFailure(:final error):
    // no access token; see error.code for the spec name
}
```

The API is asynchronous: the store contract is `Future`-returning, because every
server-side Dart driver is (`package:postgres` has no blocking API, and `waitFor`
was removed in Dart 3). `example/sql_store_example.dart` is a ready-made
driver-agnostic store.

Test: `dart test` — runs the shared conformance vectors and the normative
behavioral suite from [`spec/`](../../spec), plus Dart-specific tests for
concurrency, fail-closed store errors and the constant-time guard.

**Agent skill:** [`skills/nebula-token-dart/SKILL.md`](skills/nebula-token-dart/SKILL.md) teaches an AI coding assistant to integrate this package correctly. Install it with the standard agent-skill installer:

```sh
npx skills add nebula-token/nebula-token --skill nebula-token-dart
```

That lands in the project's `.claude/skills/`, checked in and shared with your team; add `-g` for your personal `~/.claude/skills/` instead. In Claude Code it is equally a plugin — `/plugin marketplace add nebula-token/nebula-token`, then `/plugin install nebula-token-dart@nebula-token`. Neither route copies anything: both read this directory in place, through [`.claude-plugin/marketplace.json`](../../.claude-plugin/marketplace.json).

As a fallback the skill also ships inside the published artefact, in the same installable shape — after `dart pub get` the directory is at `<pub cache>/hosted/pub.dev/nebula_token-X.Y.Z/skills/nebula-token-dart/`, and copying that directory into `~/.claude/skills/` is the whole installation. All ten skills and every install route are in [`skills/README.md`](../../skills/README.md).
