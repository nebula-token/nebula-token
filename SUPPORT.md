# Support

Where to ask what, and what to expect back.

---

## Start here

| Your question | Where it goes |
|---|---|
| "How do I wire this into my API?" | [`docs/INTEGRATION.md`](docs/INTEGRATION.md) — endpoints, cookie attributes, the ten error codes, migration from a non-rotating or JWT setup |
| "How do I implement the store?" | [`docs/STORE.md`](docs/STORE.md), plus the DDL in [`spec/schema/`](spec/schema) |
| "What should I monitor? How do I rotate a pepper?" | [`docs/OPERATIONS.md`](docs/OPERATIONS.md) |
| "What exactly does the spec require here?" | [`SPECIFICATION.md`](SPECIFICATION.md) — every requirement is numbered `[N-*]`; quote the number |
| "Does it defend against X?" | [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md), including the traceability table and the residual risks it refuses to claim |
| "Does it satisfy ASVS / 800-63B control Y?" | [`docs/COMPLIANCE.md`](docs/COMPLIANCE.md) |
| "Will upgrading break me?" | [`COMPATIBILITY.md`](COMPATIBILITY.md) and [`VERSIONING.md`](VERSIONING.md) |
| **A usage question the docs did not answer** | **GitHub Discussions → Q&A** |
| **A bug** | **GitHub Issues**, using the bug template |
| **A spec ambiguity or a disagreement between two implementations** | **GitHub Issues**, titled with the `[N-*]` id. This is a defect even when no implementation is "wrong" — [`COMPATIBILITY.md`](COMPATIBILITY.md) §8 |
| **A vulnerability** | **[`SECURITY.md`](SECURITY.md)** — private reporting, never a public issue, pull request or discussion |
| A proposal to change behaviour | An issue first, per [`GOVERNANCE.md`](GOVERNANCE.md). A pull request that changes behaviour without a spec change cannot be merged, however good it is |
| A new language port | [`CONTRIBUTING.md`](CONTRIBUTING.md) for the code, [`GOVERNANCE.md`](GOVERNANCE.md) for how it gets listed |

Please do not open an issue to ask a usage question — Discussions keeps the
issue tracker meaningful, and a question answered in Discussions is findable by
the next person who has it.

## What makes a good bug report

The tracker is shared by ten implementations, so the first three lines decide how
fast anyone can help:

1. **Language and package version**, plus the `SPEC_VERSION` the package reports.
2. **The requirement id** you believe is violated, if you know it. "`refresh`
   returns `NOT_FOUND` where [N-26] step 5 requires `REUSE_DETECTED`" is a report
   somebody can act on before lunch.
3. **A reproduction** — ideally as a behaviour-vector-shaped scenario: the
   operations, the clock, and the expected versus actual outcome. If you can
   express it as a new case for [`spec/behavior-vectors.json`](spec/behavior-vectors.json),
   you have written both the bug report and its fix's test.

Never paste a real token, verifier, pepper or raw device identifier into an issue.
If you need to show token material, mint a throwaway one with a throwaway pepper.

## What to expect

| | |
|---|---|
| Vulnerability reports | Acknowledged within **72 hours**; see [`SECURITY.md`](SECURITY.md) for the full timeline |
| Everything else | Best effort. This is a volunteer project with no support contract and no SLA |
| Behaviour changes | Slow by design. The spec changes first, then ten implementations, then a release ([`GOVERNANCE.md`](GOVERNANCE.md)) |
| Commercial support | None is offered. There is no paid tier, no hosted service and no consulting arm |

If a question sits unanswered for two weeks, bumping it is welcome and not rude.

## Supported runtimes

A runtime is supported when CI exercises it ([`COMPATIBILITY.md`](COMPATIBILITY.md)
§7). This is not a snapshot that drifts: the table is generated from
[`.github/runtime-matrix.json`](.github/runtime-matrix.json) — the same file that
expands into the CI job matrices — and `scripts/check-runtime-matrix.mjs` fails
the build unless the lowest version tested is *exactly* the floor each package
manifest declares. A manifest promising a runtime nobody tests, and CI testing a
runtime no manifest promises, are both build failures.

<!-- BEGIN GENERATED: runtime-matrix -->

| Runtime | Package | Declared floor | Exercised by CI |
|---|---|---|---|
| Node.js | `packages/typescript` | 22 | 22, 24, 26 |
| Python | `packages/python` | 3.11 | 3.11, 3.12, 3.13, 3.14 |
| Go | `packages/go` | 1.25 | 1.25, 1.26, stable |
| Rust | `packages/rust` | 1.85 | 1.85, stable |
| Java | `packages/java` | 17 | 17, 21, 25 |
| PHP | `packages/php` | 8.3 | 8.3, 8.4, 8.5 |
| .NET | `packages/csharp` | net10.0 | net10.0 (SDK 10.0.x) |
| Dart | `packages/dart` | 3.9.0 | 3.9.0, stable |
| Ruby | `packages/ruby` | 3.3 | 3.3, 3.4, 4.0 |
| Elixir | `packages/elixir` | 1.18 / OTP 25 | 1.18 / OTP 25, 1.19 / OTP 27, 1.20 / OTP 28 |

<sub>Generated from `.github/runtime-matrix.json` by `scripts/check-runtime-matrix.mjs`. "Declared floor" is read from each package manifest; CI fails if the two disagree.</sub>

<!-- END GENERATED: runtime-matrix -->

`stable` tracks the ecosystem's current release, so a newly published compiler
cannot break users before we notice; the numeric entry beside it is the floor,
and the floor is the contractual one. Elixir is tested as `elixir / OTP` pairs
rather than as a cross product, because the package's OTP floor is set by
`:crypto.hash_equals/2` ([N-31]) and `mix.exs` refuses to build below it.

To change the table, edit `.github/runtime-matrix.json` **and** the package
manifest in the same commit, then run
`node scripts/check-runtime-matrix.mjs --write`. Editing the block above by hand
does nothing; it is overwritten.

Dropping a runtime that has reached its own end of life is a **minor** change,
announced one release in advance. Raising a minimum for any other reason is a
major change.

## Things this project will not help with

Said plainly so nobody wastes an afternoon waiting:

- **Writing your store adapter.** The contract is documented and the schemas are
  published; the adapter is yours, and a bug in it is out of scope for
  [`SECURITY.md`](SECURITY.md) too.
- **General authentication design.** Password hashing, MFA, account recovery,
  OAuth flows — all outside this library, and there are better places to ask.
- **"Is my deployment compliant?"** [`docs/COMPLIANCE.md`](docs/COMPLIANCE.md)
  maps the controls honestly; only your assessor can answer the question.
- **Private support requests by email.** The security address is for
  vulnerabilities. Everything else belongs in the open, where the answer helps
  more than one person.

## The two addresses, and what they are not

Two addresses appear in this project's metadata. Neither is a support channel.

| Address | What it is for |
|---|---|
| `security@nebulatoken.dev` | Vulnerability reports only — see [`SECURITY.md`](SECURITY.md) |
| `hello@nebulatoken.dev` | The contact of record: package manifests, `CITATION.cff`, the paper, and Code of Conduct reports ([`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md)) |

A usage question sent to either gets redirected to Discussions rather than
answered privately — not out of unhelpfulness, but because a question answered
in the open is findable by the next person who has it.
