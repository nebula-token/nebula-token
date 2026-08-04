# Changelog

All notable changes to this project are documented in this file.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
and this project adheres to [Semantic Versioning](https://semver.org/).

## [1.0.2] - 2026-08-04

No change to this package's behaviour, API or wire format. It is republished so
that all ten packages carry one version, as `VERSIONING.md` section 2 requires.

### Changed
- The root `README.md` now states the `spec_version` this package implements
  ([N-52]); it was the only thing `VERSIONING.md` section 3 asked for that this
  package did not say.
- `package-lock.json` carried `1.0.0` in both root entries while
  `package.json` said `1.0.1`. `npm ci` validates neither against the other, so
  nothing reported it; `scripts/version.mjs` now covers both.
- The conformance runner executes the two new `device_hashing` cases (erratum
  E-1). Tests are not published, so this reaches no consumer.

## [1.0.1] - 2026-07-30

Release automation only; no change to this package's behaviour, API or wire
format. Published because `1.0.0` reached only npm and PyPI before the release
workflow failed, and neither permits republishing a used version number.

## [1.0.0] - 2026-07-30

### Added
- NEBULA specification v1 (`SPECIFICATION.md`) and shared conformance test vectors.
- Reference implementations: TypeScript, Python, Go, Rust, Java (plain JDK
  bytecode, callable from any JVM language; tested from Java only), PHP, C#,
  Dart, Ruby, Elixir.
- Production-style SQL store templates (`packages/*/examples/`) and per-language
  agent skills (`packages/<lang>/skills/nebula-token-<lang>/SKILL.md`) for
  AI-assisted integration.
- Opaque selector/verifier tokens, rotation, reuse detection with optional grace
  window, family revocation, sender (device) binding, dual expiry clocks,
  pepper rotation via `kid`.

[1.0.2]: https://github.com/nebula-token/nebula-token/releases/tag/v1.0.2
[1.0.1]: https://github.com/nebula-token/nebula-token/releases/tag/v1.0.1
[1.0.0]: https://github.com/nebula-token/nebula-token/commit/cb66b3dd897dc968bff8b211f001b94de7531b09
