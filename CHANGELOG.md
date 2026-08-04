# Changelog

All notable changes to this project are documented in this file.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
and this project adheres to [Semantic Versioning](https://semver.org/).

## [1.0.2] - 2026-08-04

`spec_version` remains **1** and no conforming behaviour changes. One erratum is
published, and `spec/test-vectors.json` gains two cases for a rule that was
already normative; everything else either brings one implementation back into
line with the other nine, or corrects a document.

### Specification
- **Erratum E-1** ([`spec/ERRATA.md`](spec/ERRATA.md)) — the first published for
  `spec_version = 1`. [N-11] said the `deviceIdHash` message is "the UTF-8
  encoding of the string", which is unambiguous in nine of the ten runtimes and
  not in the tenth: a Ruby `String` carries a declared encoding alongside its
  bytes, and "the string" can be read as either. [N-11] now states that where
  those bytes are *already* a valid UTF-8 encoding they **are** the input —
  acceptance is not decided on the declared encoding, and the value is not
  transcoded from it, which the requirement's existing sentence already forbade
  as "any other text encoding". Nine implementations read it that way from the
  start and are unchanged; see E-1 for why this is a clarification and not a
  behavioural change.
- `spec/test-vectors.json`: cases `dh-08` and `dh-09` pin it, carrying a new
  OPTIONAL `device_id_bytes` field — the UTF-8 encoding of the case's
  `device_id`, as lowercase hex. A runner whose strings are bytes feeds those
  bytes; one whose strings are Unicode decodes them; both must produce the
  case's single expected hash. `dh-09` additionally carries a
  supplementary-plane character, which is a surrogate *pair* in the UTF-16
  string types of JavaScript, Java, C# and Dart and was previously unexercised.
  `counts.device_hashing` 7 → 9 and all ten runners execute them ([N-48]).

### Fixed
- `packages/ruby`: the engine tested the compare-and-set return value directly,
  and in Ruby `0` is truthy. A store that reports the affected-row count — which
  `docs/STORE.md` §4 told adapters to return, naming `cmd_tuples` on a
  `PG::Result` by hand — made a **lost** compare-and-set read as applied: two
  concurrent refreshes each minted a successor and the family forked into two
  independently valid lineages, with reuse detection silently off for it. That
  is the failure [N-17] exists to close. Counts are now normalised, anything
  outside the contract fails closed as "not applied", and `docs/STORE.md` now
  says to derive a boolean from the count rather than to return the count. The
  other nine ports are unaffected: seven are statically typed to `bool`, `0` is
  falsy in Python, and Elixir raises on a non-boolean. A portable vector cannot
  express "a store returned the wrong type", so the regression lives in
  `packages/ruby/test/engine_test.rb`.
- `packages/ruby`: a device identifier was accepted or refused on the String's
  **encoding tag** rather than on its bytes, so the same bytes that every other
  port accepts were refused when tagged `ASCII-8BIT` — as they arrive from
  `String#b`, `File.binread` or a socket read. In `refresh` that refusal is a
  sender-binding failure, so Ruby revoked the family where the other nine
  rotated normally. Binary-tagged strings are now decided on the bytes, exactly
  as `pepper_bytes` already did; [N-12]'s treatment of invalid Unicode is
  unchanged. Erratum E-1 above records the clarification to [N-11], and the
  shared cases `dh-08`/`dh-09` now pin it for every implementation.
- `packages/go`: `Engine` and `Config` had no `String`, and `fmt` reads
  unexported fields by reflection, so a single `%+v` on any struct embedding an
  engine printed every configured pepper ([N-46]). Both now render the kid
  *names* and redact the secrets, under `%v`, `%+v` and `%#v`.
- `packages/php`: `#[\SensitiveParameter]` on the pepper map and on the token
  and device-identifier arguments, so an exception trace stops carrying them —
  `zend.exception_ignore_args` is `0` in `php.ini-development`, and a
  constructor failure otherwise put the whole map in every frame. Measured on
  8.3, `__debugInfo()` already covers `var_dump()` **and** `print_r()`;
  `var_export()` is the one residual path and is now documented in place and
  pinned by a test, because the obvious workaround is worse than the gap — a
  closure-held map makes `print_r()` and `var_dump()` start leaking, since both
  expand a Closure's `[static]` bindings.
- `packages/php/skills`: the `CONFLICT` sample instructed a server-side retry
  "with the same token". The winner has already rotated that token, so the
  retry is a replay and burns the family at the default grace of 0 — the exact
  thing `docs/INTEGRATION.md` warns against. [N-35]'s retry is the *client's*.
- `packages/python/examples/sqlite_store.py`: `sqlite3` defaults to
  `isolation_level = ''`, which opens an implicit transaction and never commits.
  Used without the optional `tx()` wrapper the example handed back a live token
  for a row no other connection could see and that was rolled back on close, and
  reported revocations that never landed ([N-20]). The connection is now in
  autocommit mode; `tx()` still groups a refresh for [N-22].
- `packages/typescript/package-lock.json` carried `1.0.0` in both root entries.
  `npm ci` validates neither against `package.json`, so nothing reported it.
- Seven changelogs linked `## [1.0.0]` at a release tag that was withdrawn during
  the 1.0.1 transition and has returned 404 ever since; `.lycheeignore` was
  masking it. They link the commit now, and all three expired ignore blocks —
  the two release URLs and the nine registry pages — are pruned.

### Changed
- `scripts/version.mjs` covers six more sites: both root entries of the
  TypeScript lockfile and the four install snippets that ship inside a published
  artefact (the Java README's Maven and Gradle coordinates, the Java skill, the
  Go README). Those four had to be corrected by hand for 1.0.1 and nothing
  stopped them recurring. Sixteen sites now, not ten.
- `docs/THREAT_MODEL.md` T3 described forgery given a record as "a second
  preimage under HMAC-SHA-256". The reduction is to pepper secrecy — existential
  forgery against a MAC under an unknown key — as the paper states.
- `CONTRIBUTING.md` "Adding an implementation" gains steps 11–14. Following the
  previous ten produced a tree that fails `npm run check`: three gates enumerate
  `packages/` themselves, and a new manifest was invisible to the version gate.
- `docs/paper/nebula.tex`: corrected the attribution of the selector/verifier
  split (Jaspan argues theft detection, not timing; the split-token rationale is
  Paragon Initiative's, now cited), the claim that RFC 9700 requires revoking a
  token lineage (it requires revoking the active token; family revocation is
  NEBULA's own strengthening), "compare-and-set on every state transition" (two
  of six), and the claim that [N-3] and [N-38] are asserted by every conformance
  runner (they are exercised by the behavioural suite; [N-4] is the one the
  conformance runners assert). Five smaller precision fixes.

## [1.0.1] - 2026-07-30

Release automation only. `SPECIFICATION.md`, both vector files and all ten
implementations are byte-identical to `1.0.0`.

### Fixed
- `release.yml`: the credential-existence guard on the crates.io, Maven Central,
  NuGet and Hex jobs ran before `actions/checkout` under a job-level
  `working-directory`, so the runner could not start a shell in a directory that
  did not exist yet. `1.0.0` published to npm and PyPI and then stopped at
  registry 3 of 10. Neither registry permits republishing a version number that
  has already been used — not even after an unpublish — so the remaining eight
  registries receive `1.0.1` and `1.0.0` is deprecated on the two that have it.
- `release.yml`: the npm job now clears the empty `_authToken` line that
  `actions/setup-node` writes when `NODE_AUTH_TOKEN` is unset. An empty token is
  a credential, not the absence of one, so npm skipped the OIDC exchange
  entirely and failed with a misleading `E404` against a package that exists.
- `packages/java/pom.xml`: `central-publishing-maven-plugin` 0.5.0 → 0.11.0. The
  bundle uploaded and validated correctly and the build then failed
  deserialising the reply — Sonatype added a usage-limit `warnings` field that
  0.5.0's response model rejects as an unknown property. The change is
  server-side, so pinning the old plugin was not the conservative option.
- `packages/java/README.md`, the Java agent skill and `packages/go/README.md`
  pinned `1.0.0` in their install snippets. Maven Central and the Go module
  proxy never received `1.0.0`, so those coordinates resolve to nothing; they
  name `1.0.1`, the first version those two ecosystems actually carry.

## [1.0.0] - 2026-07-30

### Added
- NEBULA specification v1 (`SPECIFICATION.md`) and shared conformance test vectors.
- Reference implementations: TypeScript, Python, Go, Rust, Java (plain JDK
  bytecode, callable from any JVM language; tested from Java only), PHP, C#,
  Dart, Ruby, Elixir.
- Production-style SQL store templates (`packages/*/examples/`) and per-language
  agent skills (`packages/<lang>/skills/nebula-token-<lang>/SKILL.md`) for
  AI-assisted integration. Every published artefact carries its skill as the
  directory a client installs — no repackaging — and each release attaches all
  ten as one archive.
- Opaque selector/verifier tokens, rotation, reuse detection with optional grace
  window, family revocation, sender (device) binding, dual expiry clocks,
  pepper rotation via `kid`.

[1.0.2]: https://github.com/nebula-token/nebula-token/releases/tag/v1.0.2
[1.0.1]: https://github.com/nebula-token/nebula-token/releases/tag/v1.0.1
[1.0.0]: https://github.com/nebula-token/nebula-token/commit/cb66b3dd897dc968bff8b211f001b94de7531b09
