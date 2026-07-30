# Changelog

All notable changes to this project are documented in this file.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
and this project adheres to [Semantic Versioning](https://semver.org/).

## [1.0.1-rc.2] - 2026-07-30

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

[1.0.1-rc.2]: https://github.com/nebula-token/nebula-token/releases/tag/v1.0.1-rc.2
[1.0.0]: https://github.com/nebula-token/nebula-token/releases/tag/v1.0.0
