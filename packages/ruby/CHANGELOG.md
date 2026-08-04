# Changelog

All notable changes to this project are documented in this file.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
and this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Fixed
- The engine tested the compare-and-set return value directly, and in Ruby `0`
  is truthy. A store reporting the affected-row count — which `docs/STORE.md`
  told adapters to return — made a **lost** compare-and-set read as applied, so
  two concurrent refreshes each minted a successor and the family forked into
  two independently valid lineages with reuse detection off for it ([N-17],
  [N-18], [N-34] step 5). Counts are normalised now and anything outside the
  contract fails closed as "not applied".
- A device identifier was decided on the String's encoding tag rather than on
  its bytes, so bytes that every other port accepts were refused when tagged
  `ASCII-8BIT` — from `String#b`, `File.binread` or a socket read. In `refresh`
  that is a sender-binding failure, so the whole family was revoked where the
  other nine rotate normally ([N-11], [N-32]). [N-12]'s treatment of invalid
  Unicode is unchanged.

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

[1.0.1]: https://github.com/nebula-token/nebula-token/releases/tag/v1.0.1
[1.0.0]: https://github.com/nebula-token/nebula-token/commit/cb66b3dd897dc968bff8b211f001b94de7531b09
