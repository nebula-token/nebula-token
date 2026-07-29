# NEBULA agent skills

Ten agent skills — one per language — that teach an AI coding assistant to
integrate NEBULA refresh tokens correctly: engine setup, the login and refresh
endpoints, the production store contract, and the security rules that are easy
to get plausibly wrong (retry `CONFLICT` once, leave the reuse grace window at
0, never use the in-memory store in production, attribute a failure with the
`userId`/`familyId` it already carries, never log the token).

**The skills are not stored in this directory.** Each one lives inside the
package it documents, already in the shape a client can install — a directory
whose name is the skill name, containing `SKILL.md` with YAML frontmatter whose
`name` matches. This file is the index and the install page.

## Install

`.claude-plugin/marketplace.json` at the repository root declares all ten, so
the standard installers find them without a clone, a copy, or a download.

### Any agent — `npx skills add`

[`skills`](https://www.npmjs.com/package/skills) is the open agent-skills
installer; it targets Claude Code, Codex, Cursor, OpenCode, Gemini CLI and
dozens more.

```sh
# See what's on offer, install nothing
npx skills add nebula-token/nebula-token --list

# One language — substitute any skill name from the table below
npx skills add nebula-token/nebula-token --skill nebula-token-python

# All ten, to the agents actually installed on this machine
npx skills add nebula-token/nebula-token --skill '*'
```

> **Not `--all`.** It reads like "all ten skills", and it is documented as a
> shorthand for `--skill '*' --agent '*' -y` — but `--agent '*'` is *every
> agent the CLI knows about*, not every agent you have. Run it in a repository
> and it installs to all 75 agents it supports, leaving fifty-odd new
> directories — `.adal/`, `.kimchi/`, `.pochi/` — beside your `.claude/`.
> `--skill '*'` is the one that means "all ten", and it leaves the agents to
> detection: on a machine with Claude Code and Codex, that is two directories.

**Pick your scope.** This is the choice people get wrong. `skills add`
installs into the **project** by default — `.claude/skills/` in the current
repository, checked in and shared with your team. Add `-g` to install into your
**personal** directory instead, `~/.claude/skills/`, available in every project
and shared with nobody.

| Scope | Flag | Where it lands (Claude Code) | Use when |
|---|---|---|---|
| Project | *(default)* | `<your repo>/.claude/skills/` | your team should get the skill from the checkout |
| Personal | `-g` | `~/.claude/skills/` | you want it everywhere and in nobody's diff |

Other agents get their own directory — `.agents/skills/` for Codex, Cursor and
OpenCode, and so on. Restrict the targets with `-a`, and skip every prompt with
`-y`:

```sh
npx skills add nebula-token/nebula-token --skill nebula-token-go -a claude-code -g -y
```

Useful afterwards: `npx skills list` shows what is installed, `npx skills
update` refreshes it, `npx skills remove nebula-token-python` takes it away.

> The `add-skill` binary is the same CLI under an older name, and its v2.0.0 is
> deprecated in favour of `npx skills add`. Use `skills`.

### Claude Code natively — `/plugin`

Each language is also a [plugin](https://code.claude.com/docs/en/plugin-marketplaces)
in the `nebula-token` marketplace:

```text
/plugin marketplace add nebula-token/nebula-token
/plugin install nebula-token-python@nebula-token
```

`/plugin marketplace update nebula-token` pulls later changes; `/reload-plugins`
picks them up without a restart. The same thing works headless, for a Dockerfile
or a machine-setup script:

```sh
claude plugin marketplace add nebula-token/nebula-token
claude plugin install nebula-token-python@nebula-token
```

No entry declares a `version`, so an install pins to the commit it was fetched
at and `update` is what moves it.

## The ten

| Skill | Language | Canonical path | Package |
|---|---|---|---|
| `nebula-token-typescript` | TypeScript / Node.js | [`packages/typescript/skills/nebula-token-typescript/`](../packages/typescript/skills/nebula-token-typescript) | `nebula-token` (npm) |
| `nebula-token-python` | Python | [`packages/python/skills/nebula-token-python/`](../packages/python/skills/nebula-token-python) | `nebula-token` (PyPI) |
| `nebula-token-go` | Go | [`packages/go/skills/nebula-token-go/`](../packages/go/skills/nebula-token-go) | `github.com/nebula-token/nebula-token/packages/go` |
| `nebula-token-rust` | Rust | [`packages/rust/skills/nebula-token-rust/`](../packages/rust/skills/nebula-token-rust) | `nebula-token` (crates.io) |
| `nebula-token-java` | Java / Kotlin / Scala | [`packages/java/skills/nebula-token-java/`](../packages/java/skills/nebula-token-java) | `dev.nebulatoken:nebula-token` |
| `nebula-token-php` | PHP | [`packages/php/skills/nebula-token-php/`](../packages/php/skills/nebula-token-php) | `nebula-token/nebula-token` |
| `nebula-token-csharp` | C# / .NET | [`packages/csharp/skills/nebula-token-csharp/`](../packages/csharp/skills/nebula-token-csharp) | `NebulaToken` (NuGet) |
| `nebula-token-dart` | Dart | [`packages/dart/skills/nebula-token-dart/`](../packages/dart/skills/nebula-token-dart) | `nebula_token` (pub.dev) |
| `nebula-token-ruby` | Ruby | [`packages/ruby/skills/nebula-token-ruby/`](../packages/ruby/skills/nebula-token-ruby) | `nebula-token` (RubyGems) |
| `nebula-token-elixir` | Elixir | [`packages/elixir/skills/nebula-token-elixir/`](../packages/elixir/skills/nebula-token-elixir) | `nebula_token` (Hex) |

## How that works, and why nothing was moved

A marketplace entry's skills load from the `skills/` directory under its
`source`. The ten entries in
[`.claude-plugin/marketplace.json`](../.claude-plugin/marketplace.json) point at
`./packages/<language>`, whose `skills/nebula-token-<language>/` is the
canonical skill — so both installers read the same single copy in place. There
is no generated mirror, no build step, and nothing to drift.

Each entry sets `"strict": false`, which is what lets the marketplace entry be
the whole plugin definition: no `plugin.json` per package, no eleventh manifest.

## Fallbacks

Every route below installs the same directory. Use one when the standard
tooling cannot reach the repository.

### From a package you have already installed

Every published artefact carries its own skill at the same relative path, so an
installed dependency is already a source of the skill — no clone, no download,
no repackaging:

```sh
cp -r node_modules/nebula-token/skills/nebula-token-typescript ~/.claude/skills/
```

The equivalent for the other ecosystems, once the package is installed:

| Package | Skill inside the artefact |
|---|---|
| npm | `node_modules/nebula-token/skills/nebula-token-typescript/` |
| PyPI | `<site-packages>/nebula_token/skills/nebula-token-python/` |
| Go | `$(go env GOMODCACHE)/github.com/nebula-token/nebula-token/packages/go@vX.Y.Z/skills/nebula-token-go/` |
| crates.io | `~/.cargo/registry/src/*/nebula-token-X.Y.Z/skills/nebula-token-rust/` |
| Maven Central | `META-INF/skills/nebula-token-java/` inside the jar |
| Packagist | `vendor/nebula-token/nebula-token/packages/php/skills/nebula-token-php/` |
| NuGet | `skills/nebula-token-csharp/` inside the extracted `.nupkg` |
| pub.dev | `<pub cache>/hosted/pub.dev/nebula_token-X.Y.Z/skills/nebula-token-dart/` |
| RubyGems | `<gem dir>/gems/nebula-token-X.Y.Z/skills/nebula-token-ruby/` |
| Hex | `deps/nebula_token/skills/nebula-token-elixir/` |

### From a clone

`skills add` takes a local path, which is the right form if you already have
the repository — it reads the same manifest and needs no network:

```sh
npx skills add ./nebula-token --skill nebula-token-typescript
```

Or copy the directory yourself, into whichever scope you want:

```sh
cp -r packages/typescript/skills/nebula-token-typescript ~/.claude/skills/
cp -r packages/*/skills/nebula-token-*     ~/.claude/skills/   # all ten
```

### From the release archive — offline and air-gapped

Every release attaches all ten as one archive, whose entries are
`nebula-token-<lang>/SKILL.md`. This is the only route that needs neither `git`
nor a package registry, only the ability to fetch one file:

```sh
curl -fsSL -o nebula-token-skills.zip \
  https://github.com/nebula-token/nebula-token/releases/latest/download/nebula-token-skills.zip
unzip -d ~/.claude/skills/ nebula-token-skills.zip
```

One language only:

```sh
unzip -j nebula-token-skills.zip 'nebula-token-typescript/*' -d ~/.claude/skills/nebula-token-typescript/
```

Substitute any other skill name from the table above.

### Other clients

Any tool that reads the `SKILL.md` directory format can consume these
unmodified — the files are plain Markdown with YAML frontmatter and no
client-specific syntax. Point your tool at the directory it expects; the layout
is deliberately not tied to one vendor's installer.

For a client that instead takes a single file of context, `SKILL.md` is
self-contained: paste or `@`-reference it directly.

## One copy, checked

There is exactly one copy of each skill in this repository — the one inside its
package — and two gates keep it that way:

```sh
node scripts/check-skills.mjs        # the skills themselves
node scripts/check-marketplace.mjs   # and their manifest
```

Both run in CI and in the release workflow.

`check-skills.mjs` fails the build if a `SKILL.md` appears anywhere but its
canonical path, if a frontmatter `name` stops matching the directory it ships
in, if any manifest would publish an artefact without the skill, or if a skill
stops stating one of the rules that make it safe to act on — the `CONFLICT`
retry rule ([N-35]), the reuse-grace default and its cost ([N-30]), that the
in-memory store is not for production ([N-21]), that a failure result carries
`userId` and `familyId` ([N-39]), that `revokeToken` can refuse ([N-36]), and
the never-log rule ([N-14]/[N-46]).

`check-marketplace.mjs` fails the build if the manifest and the tree stop
describing the same ten things, in either direction: an entry pointing at a
package with no skill, a skill in the tree that no entry claims, a name that
disagrees with the directory or the frontmatter, a missing `strict: false`, or
a `/plugin install` line in this documentation that names a marketplace this
repository does not publish.
