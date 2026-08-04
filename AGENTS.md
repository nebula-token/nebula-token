# AGENTS.md

NEBULA is one specification with ten reference implementations that must agree
exactly, on every input, in every language. This file carries the rules an agent
breaks by default; everything else is linked, never restated. `CLAUDE.md`
imports it, so there is no second copy.

## The rule that outranks everything else here

**Behaviour never changes without the specification changing first.**

The most damaging contribution this project can receive is a helpful one: *"I
found a bug in the Python port and fixed it."* Ten implementations that agree are
the entire product, so a local improvement is a divergence, however good.

Behaviour is defined in [`SPECIFICATION.md`](SPECIFICATION.md) as numbered
requirements [N-1]..[N-53], and pinned by two published vector files. A
behavioural change lands in this order, and never in reverse:

```
SPECIFICATION.md → spec/*.json → all ten implementations → docs
                                 (TypeScript first)        (docs/THREAT_MODEL.md, CHANGELOG.md)
```

Behaviour is anything another implementation or an adopter can observe: an
accept/reject decision, a hash, an error code, a record state, a timestamp.
Renaming a private helper is not behaviour. Changing when it is called is.

At the keyboard that means:

- **One implementation disagrees with the other nine** → a bug in that one. Fix
  it, and propose the vector that would have caught it. Say in the pull request
  that the vectors missed it; that is the more interesting half of the report.
- **All ten agree and you believe all ten are wrong** → a specification defect.
  Open an issue citing the [N-*] id. Do not touch code.
- **A refactor that is "more idiomatic"** → idiom wins for names and shapes;
  uniformity wins for behaviour, always. Never make one language behave
  differently because its ecosystem would phrase it differently.
- **A behavioural change lands in all ten packages or in none**, TypeScript
  first — it is the reference implementation and the other nine follow its test
  layout ([`GOVERNANCE.md`](GOVERNANCE.md)). Never leave a partial one behind.
- `spec_version = 1` is frozen ([N-50]): no existing requirement changes meaning,
  no error code is removed or redefined, no wire form added or withdrawn. Ids are
  appended, never renumbered — tests and third-party reports cite them.

If a request cannot be satisfied without changing behaviour, stop and say so.

## Never

- **Never take a security problem public.** Not an issue, not a pull request,
  not a discussion, not a commit message that describes it. Follow
  [`SECURITY.md`](SECURITY.md): the fix branches from the affected release tag
  in a private fork. A public fix *is* the disclosure.
- **Never introduce cryptography.** HMAC-SHA-256, CSPRNG output, constant-time
  comparison. Nothing else, in any language, ever.
- **Never add a runtime dependency.** The packages are dependency-free by design
  (Rust and Dart are the two documented exceptions). Test-only dependencies are
  normal; a runtime one needs a justification, and it will be questioned.
- **Never let secret material escape.** The token, the verifier, the pepper and
  the raw device identifier must never reach a log, an error value, an exception
  message, or a debug/`repr`/`toString` ([N-14], [N-46]). The selector may be
  logged as a correlation id.
- **Never report success you cannot prove.** Fail closed. Errors are values;
  infrastructure failures are exceptions ([N-20], [N-29]). Backwards, that makes a
  store failure look like a successful revocation — the worst failure mode here.
- **Never copy, port or vendor the vectors.** Every runner loads
  [`spec/test-vectors.json`](spec/test-vectors.json) and
  [`spec/behavior-vectors.json`](spec/behavior-vectors.json) from the repository
  root, as files.
- **Never hand-edit a generated file.** They are listed below.
- **Never `git clean -xfd`, and never delete an ignored path.** `website/` is
  gitignored, untracked, and exists in no other repository, whatever a comment
  says. It is the one thing here that git cannot give back.
- **Never `git push`, `git tag`, or publish.** Commit locally when asked; a
  human reviews and pushes. Releases follow [`RELEASING.md`](RELEASING.md) — one
  tag, ten registries, and the conformance suite must have run in the same CI
  invocation.

## Running the checks

There is no root `package.json`. The gates live in `scripts/`, and one command
runs them:

```bash
cd scripts && npm ci && npm run check
```

That chains eleven gates — versions, vectors, licences, skills, marketplace,
runtime matrix, this file, links, pinned actions, examples, and the Docker
harness in `--check` mode, which needs no daemon. Run it before proposing any
change; it is what CI runs.

Most machines are missing four of the ten toolchains. Run those in Docker rather
than skipping them:

```bash
node scripts/docker-test.mjs            # all ten, official images, digest-pinned at the floors
node scripts/docker-test.mjs go ruby    # one language, or several
```

The repository is mounted read-only, and `--check` holds every service equal to
the CI job of the same name or requires the difference to be explained in
`docker/compose.yml` — where each `# not-in-ci:` line already carries its reason.
See [`docker/README.md`](docker/README.md).

## Per-package commands

<!-- BEGIN GENERATED: package-commands -->

| Package | Run from | Floor | Build and test |
|---|---|---|---|
| TypeScript | `packages/typescript` | 22 | `npm ci && npm run build && npm test` |
| Python | `packages/python` | 3.11 | `pip install -e . && pip install pytest && pytest -q` |
| Go | `packages/go` | 1.25 | `go build ./... && go vet ./... && go test -race -count=1 ./...` |
| Rust | `packages/rust` | 1.85 | `cargo test && cargo build --examples && cargo clippy --all-targets -- -D warnings` |
| Java | `packages/java` | 17 | `mvn -B -ntp verify` |
| PHP | *the repository root* | 8.3 | `composer install --no-progress --no-interaction --prefer-dist && vendor/bin/phpunit -c packages/php/phpunit.xml` |
| .NET | `packages/csharp` | net10.0 | `dotnet restore && dotnet build -c Release --no-restore && dotnet test -c Release --no-build` |
| Dart | `packages/dart` | 3.9.0 | `dart pub get && dart analyze --fatal-infos && dart test` |
| Ruby | `packages/ruby` | 3.3 | `for f in test/*_test.rb; do ruby -Ilib "$f"; done` |
| Elixir | `packages/elixir` | 1.18 / OTP 25 | `mix deps.get && mix test` |

<sub>Floors come from `.github/runtime-matrix.json`; each row's directory and commands are asserted against the CI job of the same name in `.github/workflows/ci.yml` by `scripts/check-agents-md.mjs`. One row shows more than CI runs, so that the command works on one machine: Ruby's loop — see below.</sub>

<!-- END GENERATED: package-commands -->

What the table cannot carry: **PHP runs from the repository root**, because the
only `composer.json` is the root one — Packagist reads a manifest from a
repository root only, and a second one under `packages/php` would let the suite
pass against a file nobody publishes. Ruby has no `Gemfile` and no `rake` task;
that loop is the whole suite. Clippy runs on stable only in CI.

**.NET targets one framework, `net10.0`, and needs only SDK 10.** Multi-targeting
cost a dual-SDK requirement everywhere, so every command carried a
`-p:TargetFrameworks=` override. Those are gone, and so is `-f`: on a **solution**
it is a global property that splits the library into two project instances and
races them into `MSB4018 … GenerateDepsFile … cannot access the file`. Add a second
framework and both return, to `docker/compose.yml`, `scripts/check-agents-md.mjs`
and the CI setup step together — and **`NETSDK1045` advises "target .NET 8.0 or
lower"; do not.** Editing `TargetFramework` down drops the only supported runtime.

## Adding a test

Do not write a test. **Add a vector**, and bump the `counts` block in the same
commit: every runner asserts the number of cases it executed equals the published
count ([N-48]), so a vector added without the count is one nobody has to run.

- A primitive, an encoding, or a parse case → [`spec/test-vectors.json`](spec/test-vectors.json).
- A state machine or a clock → [`spec/behavior-vectors.json`](spec/behavior-vectors.json).
- Then regenerate traceability (below), and implement in all ten.

Every package has the same three test files: a conformance runner, a behaviour
runner, and one hand-written `engine` file. That last is for what a portable
vector cannot express: concurrency, the constant-time guard, store-failure
fail-closed behaviour, configuration validation, and each runtime's own hygiene
— that no debug rendering carries a live credential ([N-14], [N-46]), that
timestamps are integers, that the error type is open ([N-40]). Anything a
vector *can* express belongs in a vector. A behaviour scenario may be
conditional only on a key in the vectors' `runner.conditions`, and skips are
reported by id.

## Generated files

| Artefact | Regenerate with | Enforced by |
|---|---|---|
| [`spec/traceability.json`](spec/traceability.json) | `node scripts/build-traceability.mjs` | `scripts/validate-vectors.mjs` fails when it is stale |
| the runtime table in [`SUPPORT.md`](SUPPORT.md) | `node scripts/check-runtime-matrix.mjs --write` | `scripts/check-runtime-matrix.mjs` |
| the command table above | `node scripts/check-agents-md.mjs --write` | `scripts/check-agents-md.mjs` |
| the CI job matrices | nothing — they expand at run time from [`.github/runtime-matrix.json`](.github/runtime-matrix.json) | never type a version list into [`.github/workflows/ci.yml`](.github/workflows/ci.yml) |

Adding a runtime, or raising a floor, edits `.github/runtime-matrix.json` **and**
the package manifest in the same commit. Either one alone fails the build.

## Traps

- `packages/go/go.mod` and the root `composer.json` carry **no** version field —
  Go and Packagist read the git tag, and one here would silently override it.
  `scripts/version.mjs check` covers ten version sites and nine dated ones —
  seven changelogs, `CITATION.cff`, the pom timestamp — on number and date.
- Seven manifests are **allow-lists**: the `LICENSE` and the skill directory are
  absent from the artefact unless the file-inclusion list names them. **Two are
  deny-lists**, where a new path **ships unless excluded**: PHP, whose dist
  Composer builds with `git archive` from the root `.gitattributes`
  `export-ignore` rules, and Dart's `.pubignore`. `packages/go` has neither and
  ships its whole directory. A new path edits both deny-lists, same commit.
- The skills are a closed set: exactly ten `SKILL.md`, each at
  `packages/<language>/skills/nebula-token-<language>/SKILL.md` with an entry in
  [`.claude-plugin/marketplace.json`](.claude-plugin/marketplace.json). A stray
  one anywhere else fails the build.
- Do not add a formatter config casually. `gofmt`, `rustfmt` and `dart format`
  are unconditional; the other seven run only where that package committed a
  config file, and adding one turns CI loose on a package that never opted in.
- Commit style is [Conventional Commits](https://www.conventionalcommits.org/),
  scoped by package: `fix(ruby): return MALFORMED for non-UTF-8 input`. **Do not
  infer it from `git log`** — the history predates the rule. Branches are free.

## Where the answers live

| Question | Document |
|---|---|
| What exactly is required? | [`SPECIFICATION.md`](SPECIFICATION.md) — cite the [N-*] id |
| How does a change get made, and by whom? | [`CONTRIBUTING.md`](CONTRIBUTING.md), [`GOVERNANCE.md`](GOVERNANCE.md) |
| Adding an eleventh language | [`CONTRIBUTING.md`](CONTRIBUTING.md), "Adding an implementation" — fourteen numbered steps, all of them required |
| What may break, and when | [`COMPATIBILITY.md`](COMPATIBILITY.md), [`VERSIONING.md`](VERSIONING.md) |
| Reporting or fixing a vulnerability | [`SECURITY.md`](SECURITY.md) |
| Publishing | [`RELEASING.md`](RELEASING.md) |
| Supported runtimes, and where to ask | [`SUPPORT.md`](SUPPORT.md) |

Those documents are deliberately not summarised here: this file exists for what
an agent gets wrong *before* it has read them.
