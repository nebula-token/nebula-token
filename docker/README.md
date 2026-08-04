# The conformance harness

Ten languages, one command, no local toolchains.

```bash
node scripts/docker-test.mjs
```

That runs every implementation's conformance suite — both shared vector files, in
all ten languages — inside the official upstream image for each language, and
prints a PASS/FAIL table. Nothing needs to be installed on your machine except
Docker.

**This is the supported way to reproduce NEBULA's conformance claim without
installing ten toolchains.** The claim the project makes is not "the code looks
right": it is that ten independent implementations agree, and that the agreement
is pinned by [`spec/test-vectors.json`](../spec/test-vectors.json) and
[`spec/behavior-vectors.json`](../spec/behavior-vectors.json) rather than by
prose. Anyone should be able to check that for themselves — a contributor
touching one language, a reviewer, a security auditor, or someone writing an
eleventh port who wants to know what "conforming" means in practice.

## Why this exists

Before this directory, checking the central claim of the repository required node,
python, go, rust, java + maven, php + composer, the .NET SDK, dart, ruby and
elixir on one machine, at the right versions. Nobody has that, and an
implementation nobody local can run is an implementation that drifts: the vectors
are shared, but the only thing actually executing them is CI, and CI only runs on
a push.

A harness in Docker changes that:

- a reviewer can run the language a pull request touches, before approving it;
- a porter can run all ten and see the shape of a conformance run;
- an auditor can reproduce the claim on a clean machine, from a tag, with no
  trust in this project's CI at all;
- the languages a given machine cannot install become as runnable as the ones it
  can.

## Usage

```bash
node scripts/docker-test.mjs                 # all ten suites, then a PASS/FAIL table
node scripts/docker-test.mjs go              # one language
node scripts/docker-test.mjs go ruby elixir  # several
node scripts/docker-test.mjs --list          # what the harness covers
node scripts/docker-test.mjs --check         # validate the harness itself, no daemon needed
```

The exit code is non-zero if any language failed, so it drops into a script or a
git hook unchanged. The runner is dependency-free — node and the Docker CLI,
nothing from npm — and it fails with an explicit diagnosis, rather than a stack
trace, when the daemon is not running: that is the most common way this command
fails and Docker's own message for it names a socket path and reads like a
misconfiguration.

### A shell in one of the images, for debugging

```bash
docker compose -f docker/compose.yml run --rm ruby bash
# then, inside:
sh /repo/docker/stage.sh ruby && cd /work/packages/ruby
ruby -Ilib test/conformance_test.rb
```

The trailing `bash` replaces the service's command with a shell; everything else —
the read-only mount, the tmpfs, the cache volume, the working directory — is
identical to what the failing run had. The staging step is what every service's
command does first, and it is required: `/repo` is read-only, so there is nothing
to build in until it has run.

## What it runs

One service per language, each running the same commands
[`.github/workflows/ci.yml`](../.github/workflows/ci.yml) runs for that language:

| Service | Image (pinned by digest) | Toolchain | Declared floor |
|---|---|---|---|
| `typescript` | `node:22` | Node 22.23.1 | `engines.node` >= 22 |
| `python` | `python:3.11` | Python 3.11.15 | `requires-python` >= 3.11 |
| `go` | `golang:1.25` | Go 1.25.12 | `go` directive 1.25 |
| `rust` | `rust:1.85` | Rust 1.85.1 | `rust-version` 1.85 (MSRV) |
| `java` | `maven:3.9-eclipse-temurin-17` | Temurin jdk-17.0.19+10 | `maven.compiler.release` 17 |
| `php` | `php:8.3-cli` | PHP 8.3.32 | `require.php` >= 8.3 |
| `csharp` | `mcr.microsoft.com/dotnet/sdk:10.0` | SDK 10.0.302 | `net10.0` |
| `dart` | `dart:3.9.0-sdk` | Dart 3.9.0 | `environment.sdk` >= 3.9.0 |
| `ruby` | `ruby:3.3` | Ruby 3.3.12 | `required_ruby_version` >= 3.3 |
| `elixir` | `elixir:1.18-otp-25` | Elixir 1.18.4, OTP 25.3.2.21 | `elixir ~> 1.18`, OTP 25 |

**Scope: the conformance suites — install, build, test.** Formatting, linting,
packaging checks and the example-template compile steps stay in CI. They are
single-toolchain checks that say nothing about whether ten implementations agree,
and running them here too would double the harness's runtime for no extra
evidence.

## The rules the harness follows

**Ten official images, never one image with ten toolchains.** A mega-image would
have to be built, hosted, updated and trusted by this project. Ten official
upstream images are smaller individually, are cached by your daemon, are rebuilt
by their maintainers when a CVE lands, and cost this project nothing to maintain.

**Every image is pinned by digest, with its tag in a trailing comment.** This is
the discipline [`ci.yml`](../.github/workflows/ci.yml) applies to every action and
container image, enforced there by
[`scripts/check-actions-pinned.mjs`](../scripts/check-actions-pinned.mjs). A tag
is mutable: `ruby:3.3` is a different image this month than last, and a
conformance result that cannot be reproduced is not a result. A digest is
immutable, so a run today and a run in two years execute the same bytes. The
comment is not decoration — it is the only way a human or Dependabot can tell
what version a digest is.

These digests are deliberately **not** tracked by Dependabot
([`.github/dependabot.yml`](../.github/dependabot.yml) has no `docker` ecosystem).
An automated bump here would move a floor, which is a MINOR change under
[`VERSIONING.md`](../VERSIONING.md) and has to happen in
`.github/runtime-matrix.json` and the package manifest first. To refresh a digest
by hand — after a floor moves, or to pick up an upstream rebuild of the same
version:

```bash
docker buildx imagetools inspect ruby:3.3 --format '{{.Manifest.Digest}}'
```

Paste that digest, and put the version the image reports (`ruby --version`) in the
comment beside it.

**Every image is the declared floor, not the newest release.** The versions above
are the lowest ones [`.github/runtime-matrix.json`](../.github/runtime-matrix.json)
tests, which `scripts/check-runtime-matrix.mjs` holds equal to the floor each
package manifest claims. A harness pinned to `latest` would prove that the code
works on versions nobody promised, while the version users are told is supported
went untested. `node scripts/docker-test.mjs --check` fails if a floor moves in
`runtime-matrix.json` and an image here does not move with it.

**The repository is mounted read-only.** A conformance run must not be able to
modify the tree it is judging, and no container may leave build output in your
working copy. The mount is `../:/repo:ro`, and everything a toolchain needs to
write goes to a `/work` tmpfs instead — staged there by
[`stage.sh`](stage.sh), which also refuses to copy your local build output, so a
run reproduces a clean checkout rather than your last local build. That tmpfs is
mounted `exec`: Docker's default is `noexec`, and a staged tree is executed from
as well as written to (`node_modules/.bin`, `vendor/bin/phpunit`), so without it
`npm ci` fails `EACCES` and PHPUnit exits 126 in an image where both are fine.

**What is mounted is the repository root, not the package.** Every conformance
runner in all ten languages finds the vectors by walking up from its own source
file until it sees `spec/test-vectors.json`. Mount `packages/go` alone and all
ten fail — not with a conformance error, with "vectors not found".

**Divergence from CI is checked, not trusted.** Each command in
[`compose.yml`](compose.yml) must appear verbatim in a step of `ci.yml`, or carry
a `# not-in-ci:` comment giving the reason. `--check` fails otherwise. There are
a handful of honest exceptions and each one says so in place: the staging step
(CI's checkout is writable, `/repo` is not), composer and `unzip` in the PHP
service (the official php image ships neither, so the harness does what
`setup-php` does for CI, from a checksum-pinned phar), the PHP service's `cd
/work` (its composer project root is the repository root, because Packagist
reads `composer.json` from a repository root only — CI's steps are already there
by default), Hex in the Elixir service
(the official elixir image does not ship it), and the Ruby service's guard line.
The `.NET` service used to be the largest exception here and is now none at all:
while the package multi-targeted `net8.0` and `net10.0`, every .NET command
needed a `-p:TargetFrameworks=` override, because one official image carries one
SDK and SDK 8 cannot even restore a project that names `net10.0`. The package
targets `net10.0` alone now, so those overrides are gone and so is the `-f` that
outlived them — on a solution it splits the library into two project instances
and races them into `MSB4018`. The service runs the same three commands as CI,
verbatim.

## Caches, volumes and disk

Build output lives in a per-run `/work` tmpfs and dies with the container.
Downloaded dependencies live in one named volume per language, so a second run is
fast and a poisoned cache can be dropped one language at a time:

```bash
docker volume rm nebula-conformance_nebula-cache-rust
docker compose -f docker/compose.yml down --volumes   # drop all of them
```

A first run pulls ten images and downloads each ecosystem's test dependencies, so
expect it to be slow and to want a few gigabytes; after that the images and the
caches are local. The suites run one at a time on purpose: ten toolchains
competing for cores makes a timing-sensitive failure — the Go race detector, for
instance — harder to read, and the harness is for evidence, not speed.

## When it does not work

**"the Docker daemon is not reachable"** — the runner says exactly this, and what
to do about it, per platform. It means the CLI is installed and the engine is
not running. Nothing here needs a daemon to be *validated*, so
`node scripts/docker-test.mjs --check` still works.

**Permission denied on `/repo` on an SELinux host** (Fedora, RHEL, CentOS) —
SELinux blocks container access to unlabelled bind mounts. The usual fix is to
relabel the mount, which writes to your working tree's metadata; prefer
`--security-opt label=disable` on the run instead, or run the harness from a
checkout you are happy to have relabelled.

**A language passes here and fails in CI, or the reverse** — that is a real
finding, and the most valuable thing this harness can produce. It means the
result depends on something other than the vectors: a toolchain patch version, a
locale, a filesystem, an ordering. Please report it with both outputs
([`../CONTRIBUTING.md`](../CONTRIBUTING.md)).

## In CI

`ci.yml`'s `docker-harness` job runs `--check` on every push — the harness must
not rot into certifying the wrong commands — and executes a representative
subset of the services on any pull request that touches this directory or
`scripts/docker-test.mjs`, plus the full ten on a weekly schedule. It
deliberately does not run all ten in Docker on every push: that would run every
suite twice per push for one bit of extra information.
