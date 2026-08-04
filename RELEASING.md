# Releasing

Ten artefacts, ten registries, one behaviour. This document is the checklist; the
automation that enforces it is in `.github/workflows/release.yml`.

Releases are cut by a maintainer ([`GOVERNANCE.md`](GOVERNANCE.md)). Nothing here
is optional — the failure mode of a partially published release is an ecosystem
where `nebula-token` means different things in different languages.

---

## The version surface

`scripts/version.mjs` is the single tool that reads and writes versions. It knows
about all the places a version appears, because there are sixteen of them —
eight package manifests, the Maven `<scm><tag>` that Central serves verbatim,
`sonar.projectVersion`, both root entries of the TypeScript lockfile, and the
four install snippets that ship inside a published artefact — and a human will
miss one. The last five were each missed once: the lockfile drifted to a
released tag unnoticed, and the four snippets had to be corrected by hand in
1.0.1 after Maven Central and the Go proxy never received 1.0.0.

| File | Field |
|---|---|
| `packages/typescript/package.json` | `version` |
| `packages/python/pyproject.toml` | `project.version` |
| `packages/rust/Cargo.toml` | `package.version` |
| `packages/java/pom.xml` | `project.version` |
| `packages/csharp/src/NebulaToken/NebulaToken.csproj` | `Version` |
| `packages/dart/pubspec.yaml` | `version` |
| `packages/ruby/nebula-token.gemspec` | `spec.version` |
| `packages/elixir/mix.exs` | `version` |
| `packages/java/pom.xml` | `project.scm.tag` — Central serves it verbatim |
| `sonar-project.properties` | `sonar.projectVersion` |
| `packages/typescript/package-lock.json` | `version` and `packages."".version` — npm validates neither against `package.json` |
| `packages/java/README.md` | the Maven `<version>` and Gradle install snippets — they ship in the jar as `META-INF/README.md` |
| `packages/java/skills/nebula-token-java/SKILL.md` | the install coordinate — ships in the jar |
| `packages/go/README.md` | the `go get …@vX.Y.Z` snippet — ships in the module zip |
| `packages/go/go.mod` | none — Go reads the git tag |
| `composer.json` (repository root) | none — Packagist reads the git tag |

```bash
node scripts/version.mjs check     # assert all sixteen agree; used as a CI gate
node scripts/version.mjs set 1.2.0 # write all ten
```

`sonar.projectVersion` is bumped for a SonarQube project that no workflow in this
repository scans; it is maintained for the IDE extension and for whoever points a
scanner at this tree, and it is in the list so that "all the places a version
appears" stays true rather than nearly true.

The Go and PHP rows are checked too, in the other direction: `check` fails if
either manifest grows a version field, because a `version` key in
`composer.json` overrides the tag Packagist is supposed to read, and the mistake
is invisible until after publication.

The PHP manifest is the **repository-root** `composer.json`, and it is the only
one. Packagist reads `composer.json` from a repository root only, so a second
manifest under `packages/php` would be the file every gate in `scripts/` checked
while the file Packagist published said something else.

## Environments and secrets

Each publish job in `release.yml` runs in its own GitHub environment, so a
compromised step can reach only its own registry's credential — the npm job
cannot read the Maven signing key.

**Required reviewers cost one approval per registry, not one per release.** The
ten publish jobs are a strict `needs:` chain, so they are never pending at the
same time and GitHub can never batch their approvals: protecting all ten means
being asked ten times, each one blocking the next registry, with the release
half-published while you answer. Protect **`release-npm` only** — it is job 1,
so approving it is the human "go", and everything after it is already gated by
`preflight` having read a green conformance run. Protect more than that only if
you want a hold point mid-release and have decided what you would do with it.

| Environment | Secrets | Auth |
|---|---|---|
| `release-npm` | — | OIDC trusted publishing |
| `release-pypi` | — | OIDC Trusted Publishing |
| `release-crates` | `CARGO_REGISTRY_TOKEN` | token |
| `release-maven` | `MAVEN_GPG_PRIVATE_KEY`, `MAVEN_GPG_PASSPHRASE`, `CENTRAL_TOKEN_USERNAME`, `CENTRAL_TOKEN_PASSWORD` | Central Portal + GPG |
| `release-nuget` | `NUGET_API_KEY` | token |
| `release-rubygems` | — | OIDC trusted publishing |
| `release-hex` | `HEX_API_KEY` | token |
| `release-pub` | — | OIDC automated publishing |
| `release-packagist` | `PACKAGIST_USERNAME`, `PACKAGIST_TOKEN` | webhook |
| `release-go` | — | the job's own `GITHUB_TOKEN`, `contents: write` |

Five of the ten need no stored secret at all. Prefer that wherever a registry
offers it: a token that does not exist cannot leak. The `SPLIT_REPO_TOKEN` PAT
is gone with the mirrors it existed for — it was the only long-lived credential
in the release with write access to a repository rather than to a registry.

One environment per job, and no job reads two environments. A secret attached to
an environment is only visible to a job that names it; a job that names one
environment and reads another's secrets does not fail loudly, the secret simply
expands to the empty string.

Maven Central additionally requires a `release` profile in `packages/java/pom.xml`
that attaches sources, javadoc, GPG signatures and
`central-publishing-maven-plugin`, under the `dev.nebulatoken` groupId. Maven
treats an unknown `-P` profile as a warning rather than an error, so the
`preflight` job asserts the pom *names* all of it *before* npm is touched: six
literal greps, not a build. An incomplete pom blocks the release instead of
stranding it half-published at registry 4 of 10 — but a pom that names every
plugin and still fails to produce a Central-acceptable bundle is not caught here,
because nothing in CI runs `mvn -P release package`.

## Before the first release

Everything above assumes ten packages that already exist. For the **first**
release none of them do, and four of the ten authenticate with OIDC — which is
configured *on the package*, and so is the hardest thing to arrange for a package
that has never been published. Each row below is done once, by hand, before the
first tag is pushed:

| Registry | What must exist first |
|---|---|
| npm | **the package must already exist.** `npm trust`: *"The package you're configuring must already exist on the npm registry."* There is no pending form |
| PyPI | a **pending** publisher, registered from *your account* sidebar rather than a project's, naming the project it will create. It reserves nothing until first used |
| crates.io | account, and `CARGO_REGISTRY_TOKEN` in `release-crates`. A token publishes a new crate, so nothing to pre-create |
| Maven Central | the `dev.nebulatoken` namespace **verified** with Sonatype by a DNS TXT record on `nebulatoken.dev`, plus the GPG key published to a keyserver |
| NuGet | `NUGET_API_KEY` scoped with a **glob** (`NebulaToken*`), not to an existing package — a key scoped to a package that does not exist cannot create it |
| RubyGems | a **pending** trusted publisher at `rubygems.org/profile/oidc/pending_trusted_publishers`. *"Trusted publishers are not just for existing gems, they can also be used to push new gems"* |
| Hex.pm | account and `HEX_API_KEY` |
| pub.dev | **the package must already exist.** *"Today, you can only automate publishing of existing packages. To create a new package, you must publish the first version using `dart pub publish`"* |
| Packagist | the repository **submitted** to Packagist — the workflow's `POST /api/update-package` only nudges a package that is already registered, and `curl -f` fails the job if it is not |
| Go | nothing — `proxy.golang.org` indexes the tag |

**Exactly two of the ten cannot be pre-arranged: npm and pub.dev.** Both configure
OIDC on the package, and neither has a pending form, so the package has to exist
before the trusted publisher can be attached to it. Every other registry either
takes a token that creates the package on first push, or — PyPI and RubyGems —
accepts a *pending* publisher registered against a name nobody has claimed.

The one-time bootstrap is therefore narrow, and it is worth keeping it narrow:
publish **one prerelease, to those two registries only**, by hand; attach the
trusted publishers; then let the tag publish 1.0.0 to all ten from CI. The
prerelease is the exception to "publishes from CI only" — it is deliberately not
the release, and it exists to hold a name, not to be used.

**On npm the bootstrap prerelease WILL own `latest`, and you cannot take it
away.** Observed, not assumed. `npm publish --tag next` on a package that does
not exist yet sets *both* tags:

    latest: 1.0.0-rc.1
    next:   1.0.0-rc.1

and `npm dist-tag rm <pkg> latest` is refused by the registry —
`400 Bad Request - DELETE …/dist-tags/latest`. There is no second version to
point it at, and unpublishing to undo it would destroy the package record the
whole bootstrap existed to create, taking the trusted publisher with it. So:

  * `npm deprecate <pkg>@<rc> "…"` immediately, so every install prints why;
  * accept that `npm i <pkg>` resolves to the prerelease until the tag lands,
    and keep that window short;
  * `release.yml` passes `--tag latest` for any version without a `-`, so
    publishing 1.0.0 moves it with no further action.

pub.dev has no equivalent problem: a prerelease is not the stable version there,
and the package page says so.

Do **not** tag it. `release.yml` matches `v[0-9]+.[0-9]+.[0-9]+-*` as well as the
bare form, so a `v1.0.0-rc.1` tag would launch the full ten-registry chain against
publishers that do not exist yet, and strand the release at job 1.

The repository side is smaller but has the same shape — none of it exists on an
empty remote, and three of them silently do nothing rather than fail:

- a **default branch named `main`**, because `ci.yml`, `codeql.yml` and
  `scorecard.yml` all trigger on `push: branches: [main]` and on nothing else;
- the ten **environments**, or `release.yml` stalls at job 1;
- **Discussions** with a `q-a` category, linked as the primary support channel by
  `SUPPORT.md` and by the issue-template chooser;
- **private vulnerability reporting** enabled, which is the path `SECURITY.md`
  calls preferred;
- **Dependabot** version updates enabled in settings — the config file alone does
  nothing;
- the **`maintainers` team**, which `.github/CODEOWNERS` names as the owner of
  every path. It must be **visible** and must hold **explicit `write` access to
  this repository** — separately, even though its members already have write
  through the organization. Miss either and GitHub requests no review while the
  file still reads as enforced. Verify it on a real pull request before turning
  on branch protection, not after.

### The repository must be public before the first tag

Not a preference — three of the ten publishes require it, and they fail late:

- **Go** has no upload step at all. `proxy.golang.org` fetches the module by
  cloning the repository at `packages/go/vX.Y.Z`, so a private repository means
  the tag is pushed, the job is green, and `go get` returns 404 forever after.
- **Packagist** reads the root `composer.json` over HTTPS. The workflow's
  `POST /api/update-package` only nudges it to re-read; a repository it cannot
  fetch leaves the package empty.
- **npm provenance** attests a public source commit. Without a public
  repository, the attestation is worth nothing to the consumer verifying it.

So the order is fixed: **CI green → repository public → registries configured →
tag**. Everything before "repository public" can happen on a private repository;
nothing after it can. Going public is also when the first block of
[`.lycheeignore`](.lycheeignore) expires — see "After the tag".

## Cutting a release

1. **Confirm CI is green on `main`.** Every language, every supported runtime,
   plus the `gates`, `format`, `paper`, `links` and `docker-harness` jobs. A red
   job is a blocked release, never a waived one.

   **Nothing here builds a publishable artefact before the release does.** There
   is no packaging dry run: the first time each of the ten is packed is inside
   the job that uploads it. A pom that no longer produces a Central-acceptable
   bundle therefore strands the release at registry 4 of 10, and the `preflight`
   greps below are a cheap proxy for it, not a substitute.

2. **Update `CHANGELOG.md`.** One entry per user-visible change, grouped by
   Added / Changed / Deprecated / Removed / Fixed / Security. Name the affected
   languages when a change is not universal.

   **Date every changelog and `CITATION.cff` to the date of the tag you are
   about to push** — the `## [X.Y.Z] - YYYY-MM-DD` heading in `CHANGELOG.md`,
   the same heading in each `packages/*/CHANGELOG.md`, and `date-released` in
   `CITATION.cff` — and `project.build.outputTimestamp` in
   `packages/java/pom.xml`, which is the reproducible-build stamp Central serves
   inside the pom. Nine sites, read by four different audiences.
   `node scripts/version.mjs check` now enforces both halves: every one must
   name the version the manifests carry, and they must all carry the same
   date. It is a check, never a writer — the date of a release is not
   derivable from its number.

3. **Bump.** `node scripts/version.mjs set X.Y.Z`, then commit as
   `chore(release): X.Y.Z` — `release:` is not a Conventional Commits type, and
   `AGENTS.md` governs the commit style.

4. **Tag.** A release carries **two tags on this repository**, and only the first
   is pushed by hand:
   ```bash
   git tag -s vX.Y.Z -m "NEBULA X.Y.Z"        # signed; triggers the workflow
   git push origin main vX.Y.Z
   ```
   | Tag | Pushed by | What reads it |
   |---|---|---|
   | `vX.Y.Z` | the maintainer, signed | the release workflow, the GitHub release, Packagist |
   | `packages/go/vX.Y.Z` | the release workflow, after preflight | `proxy.golang.org` — and nothing else |

   Do not push `packages/go/vX.Y.Z` by hand. It is not a label on a release, it
   *is* the Go publish: the module proxy indexes it within minutes, and doing it
   before the workflow has run would publish Go without the conformance suite
   having passed. Go ignores the bare `vX.Y.Z` tag entirely — for a submodule,
   only directory-prefixed tags are versions ([`VERSIONING.md`](VERSIONING.md) §5).

5. **Let the workflow publish.** It runs on the tag and publishes in this order,
   stopping at the first failure:

   | # | Registry | Auth | Notes |
   |---|---|---|---|
   | 1 | npm | OIDC | `--provenance`; needs `id-token: write` |
   | 2 | PyPI | Trusted Publishing | no long-lived token exists |
   | 3 | crates.io | token | `cargo publish` |
   | 4 | Maven Central | Portal token + GPG | sources, javadoc and signatures are mandatory |
   | 5 | NuGet | token | symbols package alongside |
   | 6 | RubyGems | OIDC | |
   | 7 | Hex.pm | token | |
   | 8 | pub.dev | OIDC | |
   | 9 | Packagist | webhook | reads this repository's root `composer.json` and the `vX.Y.Z` tag |
   | 10 | Go | git tag | pushes `packages/go/vX.Y.Z` here, then warms the proxy |

6. **Verify from the outside.** Nothing in CI proves what a *user* gets: every
   job in `ci.yml` runs against the working tree, not against the published
   artefact. So, once the workflow is green, install each package from its
   public registry into a clean container and run the shared vectors from a
   repository checkout against the installed package — `npm i nebula-token`,
   `pip install nebula-token`, `cargo add nebula-token`, and so on for all ten.
   This is manual today and automating it has not been started; until it is,
   doing it by hand is not optional. A failure here is grounds for an immediate
   patch release, never for a re-tag.

7. **The GitHub release publishes itself**, with the changelog section, the
   SBOMs, the paper PDF, and `nebula-token-skills.zip` as attachments. This is
   the `github-release` job, it is not gated by an environment, and it is not a
   draft — it lands as soon as job 10 finishes, which is *before* you can have
   done step 6. It is listed here rather than under step 5 because what it
   attaches is worth checking, not because there is anything to do.
   The skills archive is
   the download `skills/README.md` sends people to
   (`releases/latest/download/nebula-token-skills.zip`), so `github-release`
   fails rather than publish a release without it. The `skills` job builds it by
   staging the ten `packages/*/skills/nebula-token-*/` directories — the
   canonical, installable copies, one per package — into one directory and
   zipping from inside it, so the archive entries stay `nebula-token-<lang>/`
   and the documented `unzip -d ~/.claude/skills/` line keeps working. It
   asserts ten directories staged and ten `SKILL.md` entries archived.

   **The archive survived the move to `.claude-plugin/marketplace.json`, on
   purpose.** Since that manifest exists, the ordinary way to install a skill is
   `npx skills add nebula-token/nebula-token --skill nebula-token-<lang>` or
   `/plugin install nebula-token-<lang>@nebula-token`, and `skills/README.md`
   now leads with both. Neither works without a `git clone` of GitHub: the
   `skills` CLI clones the source, and `/plugin marketplace add` clones it too.
   On an air-gapped or proxied network — where a single HTTPS asset download is
   permitted and outbound git is not, which is the normal shape of a locked-down
   build host — the zip is the only route that still delivers a skill. It costs
   one CI job over files that already exist and are already gated by
   `scripts/check-skills.mjs`, and it is the reason `skills/README.md` keeps it
   as a documented fallback rather than dropping it. Remove it only if that
   audience is deliberately dropped, and delete the `github-release` assertion,
   the `skills` job and the fallback section in the same change — not one of the
   three.

## One repository, ten registries

There are **no mirror repositories**. Everything publishes from
`nebula-token/nebula-token`. Eight ecosystems take an upload and do not care
where it came from; two read the repository itself, and each is handled in place.

### PHP — a root manifest plus `export-ignore`

Packagist reads `composer.json` from a repository **root** only. So the PHP
package's manifest is the root `composer.json`, and it is the *only* one: its
`autoload.psr-4` maps `NebulaToken\` onto `packages/php/src/`, `vendor/` lands at
the root, and CI runs `vendor/bin/phpunit -c packages/php/phpunit.xml` from the
root. A second manifest under `packages/php` declaring the same package name is
the trap this arrangement exists to avoid — every gate in `scripts/` would check
that file while Packagist published the other one.

What stops a PHP consumer downloading nine other languages is `.gitattributes`:
Composer builds a package's dist archive with `git archive`, which honours
`export-ignore`, so the published artefact is `composer.json`, `LICENSE`,
`README.md`, `SPECIFICATION.md` and `packages/php` minus its test suite —
21 files. Verify it after any change to that file:

```bash
composer archive --format=tar --dir=/tmp && tar -tf /tmp/nebula-token-*.tar
```

`export-ignore` applies to the **archive only**. `git clone` and
`actions/checkout` ignore it completely, so CI, the Docker harness and all ten
conformance suites still see `spec/` — which every runner locates by walking up
from its own source file.

### Go — a submodule and a directory-prefixed tag

The module is `github.com/nebula-token/nebula-token/packages/go`. Go resolves a
submodule's versions **only** from tags prefixed with the module's directory:

```
packages/go/v1.0.0     ← the Go module's version, pushed by the release workflow
v1.0.0                 ← everything else; invisible to the module proxy
```

There is no vanity import path any more. `go.nebulatoken.dev/nebula-token` needed
the `go.mod` at a repository root — hence the cancelled split repository — and it
put a permanent DNS dependency in front of every consumer: one host and one
`go-import` meta tag had to keep answering, forever, or `go get` broke in
everybody's CI. Resolving from `github.com` removes that dependency outright,
and with it the obligation to serve `go-import` from the website. The price is an
import path that names a directory, and a package clause (`nebulatoken`) that is
not the last path element — documented in
[`packages/go/README.md`](packages/go/README.md) so nobody has to guess.

## Cutting a release candidate

`release.yml` accepts `v[0-9]+.[0-9]+.[0-9]+-*` as well as the bare form, so an
RC is cut exactly like a release. Four things differ:

1. `node scripts/version.mjs set 1.0.0-rc.1` writes all ten version sites, and
   step 2's nine dated sites need the matching `## [1.0.0-rc.1] - YYYY-MM-DD`
   heading, or `preflight` refuses the tag. An RC is a full bump, not a tag on
   top of the release version.
2. **npm** publishes to the `next` dist-tag rather than `latest` — the workflow
   decides this from the `-` in the version. That is what makes
   [`VERSIONING.md`](VERSIONING.md) §4's "never the default install" true.
3. **PyPI normalises** `1.0.0-rc.1` to `1.0.0rc1` (PEP 440). The manifests and
   the published PyPI version will not be string-identical, and that is correct.
4. `github-release` marks the release as a prerelease, from the same `-`.

Maven Central and Packagist have no prerelease channel; there an RC is an
ordinary version that resolvers rank below the release. Do not cut an RC unless
you intend to publish it to all ten — a partial RC leaves the ten out of step,
which is the one thing this project exists to prevent.

## After the tag

Three artefacts can only be created once the tag exists, so they are steps here
rather than TODO markers in the files that will carry them:

1. **Mint an archival DOI** for the tag (Zenodo, or an equivalent your
   institution prefers) and add it to `CITATION.cff` under `identifiers:`. The
   commented block at the bottom of that file is the shape it takes.
2. **Once the paper is posted**, add a `preferred-citation:` block to
   `CITATION.cff` pointing at the preprint, so citing tools prefer the paper
   over the software record. Not before it is posted: a preferred-citation
   pointing at nothing makes every citing tool emit a dead reference.
3. **Prune [`.lycheeignore`](.lycheeignore).** Three of its blocks are temporary
   and each expires at a different moment. They cover the most load-bearing links
   in the repository, and an ignore list nobody prunes is how a genuinely broken
   link hides — so each one is deleted in the first pull request after its
   trigger, not "eventually":

   | Block | Expires when | What it masks **today** |
   |---|---|---|
   | ~~the two release URLs~~ | **gone** — retired after 1.0.1 shipped | it masked the `## [1.0.0]` link target, which had 404ed since the v1.0.0 tag was withdrawn; the heading now links to its commit |
   | ~~`nebulatoken.dev.*`~~ | **gone** — the site went live 2026-07-29 | it never masked anything the `links` job looks at; see below |
   | ~~the nine registry pages~~ | **gone** — retired after 1.0.1 reached all ten registries | nothing; they were pre-emptive and never appeared in a markdown file |

   All three temporary blocks are now retired. Anything added here in future
   carries the same obligation: delete it in the first pull request after its
   trigger fires, and say in this table what it masks while it stands.

   A fourth block, a blanket `github.com/nebula-token/.*`, was retired on
   2026-07-29 when the repository went public. It is worth saying what replaced
   it: two exact URLs, not a pattern. The blanket would have gone on silently
   exempting every repository link anyone added afterwards, which is the failure
   mode this file's opening comment describes.

   The last three blocks — hosts hostile to link checkers, and the RFC 2606 /
   6761 example hosts — are permanent and correct.

   **Two of the three are pre-emptive rather than coverage, and that is a gap
   worth naming.** `links` runs lychee over `**/*.md` and nothing else, while
   `https://nebulatoken.dev` lives in the ten package manifests and in
   `CITATION.cff`. Those are the most user-visible links the project has — the
   Homepage button on ten registry pages — and no gate checks them; the
   exemption reads as though one does. Widening the scan to the manifests and
   `CITATION.cff` is the fix, and it belongs in the first post-release pull
   request rather than beside a release: an XML namespace in `pom.xml` is not a
   fetchable URL, so it needs its own exemptions, and that is new failure surface
   on a job whose behaviour is already the least exercised thing here.

## Security releases

A vulnerability means **ten coordinated releases on one day**, and the process
differs from a normal release in three ways:

1. Work happens in a private fork, in a branch off the affected release tag —
   not on `main`, where the commit would disclose the issue.
2. The advisory is drafted *before* publishing, with the CVE requested through
   GitHub's CNA, and released the moment the last registry has the fix.
3. All ten packages are published even where a language is unaffected, so that
   "upgrade to X.Y.Z" is one instruction rather than a per-language matrix.

Timeline and disclosure policy are in [`SECURITY.md`](SECURITY.md).

## Yanking

Yank rather than delete, wherever the registry supports it — deletion breaks
lockfiles for people who did nothing wrong. Yank when an artefact is
functionally broken or carries a vulnerability with no fix yet available.
Announce every yank in `CHANGELOG.md` with the reason.

## Never

- Never publish from a workstation. Every artefact comes from a tagged CI run, so
  that provenance attestation means something.
- Never re-tag. A published version is immutable; if it is wrong, publish the
  next patch.
- Never publish a package whose conformance suite did not run in that same CI
  invocation.
- Never let the ten languages diverge in MAJOR.MINOR ([`VERSIONING.md`](VERSIONING.md)).
