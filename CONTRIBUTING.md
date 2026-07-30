# Contributing to NEBULA

Thank you for considering a contribution. NEBULA is a security specification with
ten implementations that must agree with each other exactly, so the bar is higher
than for a typical library — and the rules below exist to keep that agreement
mechanical rather than aspirational.

---

## The one rule everything else follows from

**The specification is the source of truth, and conformance is data.**

Behaviour is defined in [`SPECIFICATION.md`](SPECIFICATION.md) as numbered
requirements `[N-1]`..`[N-53]`, and enforced by two published artefacts:

- [`spec/test-vectors.json`](spec/test-vectors.json) — the primitives and the parser
- [`spec/behavior-vectors.json`](spec/behavior-vectors.json) — the state machine

A behavioural change therefore lands in a fixed order:

```
SPECIFICATION.md  →  spec/*.json  →  all ten implementations  →  docs
```

Never the other way around. A pull request that changes one implementation's
behaviour without a vector is a pull request that makes the ten drift apart, and
it will be asked for the vector first.

## Types of contribution

### Reporting an interoperability defect

The most valuable report this project can receive: **two conforming
implementations that disagree**. Include the input, both outputs, and the
versions. That is a specification defect by definition, and the fix is a new
vector plus an erratum.

### Fixing a bug in one language

If the behaviour was already correct in the other nine, this is a plain bug fix:
patch it and add **the vector that would have caught it** — not a hand-written
test in that one language, which only one of the ten runs and so cannot stop the
same divergence reappearing in another. [`AGENTS.md`](AGENTS.md), "Adding a test",
says which of the two vector files it belongs in. That the vectors missed it is
the more interesting half of the report; say so.

### Changing behaviour

Open an issue first. Behavioural changes within `spec_version = 1` are limited to
what [`COMPATIBILITY.md`](COMPATIBILITY.md) permits, which is very little by
design. Expect the discussion to be about whether the change is possible at all
before it is about whether it is desirable.

### Adding a language port

Very welcome. See "Adding an implementation" below.

### Security issues

Never in a public issue or PR. Follow [`SECURITY.md`](SECURITY.md).

## Ground rules

1. **No novel cryptography.** HMAC-SHA-256, CSPRNG output, constant-time
   comparison. Nothing else, in any language, ever.
2. **No new runtime dependencies** unless the language has no standard-library
   primitive for the job. Justify any addition in the PR description, and expect
   it to be questioned.
3. **Every implementation runs the shared vectors** — not a copy of them, not a
   port of them, the files themselves, resolved from the repository root.
4. **Errors are values; infrastructure failures are exceptions.** [N-20] and
   [N-29] draw the line. Getting this wrong makes a store failure look like a
   successful revocation, which is the worst failure mode this project has.
5. **Fail closed.** If you cannot prove an operation happened, never report that
   it did.
6. **Idiomatic in the target language.** A Go developer should not be able to
   tell the library was designed elsewhere. Where idiom and uniformity conflict,
   idiom wins for names and shapes; uniformity wins for behaviour, always.

## Working on the code

If a coding agent is doing the work, point it at [`AGENTS.md`](AGENTS.md) first.

Each package is self-contained; its README has the build and test commands. To
run what CI runs:

```bash
cd scripts && npm ci && npm run check   # the eleven repository gates, in one command
```

That chains versions, vectors, licences, skills, marketplace, runtime matrix,
`AGENTS.md`, links, pinned actions, examples and the Docker harness in `--check`
mode, which needs no daemon; it is exactly what CI runs. To run the ten language
suites with nothing installed but Docker, use the conformance harness:

```bash
node scripts/docker-test.mjs        # all ten, in official images at the declared floors
node scripts/docker-test.mjs ruby   # one language
```

It mounts this repository read-only and runs the same commands CI runs, which
makes it the supported way to reproduce the conformance claim on a machine that
does not have ten toolchains. See [`docker/README.md`](docker/README.md).

## Adding an implementation

1. Create `packages/<language>/` following the layout of an existing package.
2. Implement the engine and the six-method store contract exactly as specified.
3. Write **two runners**, not a hand-written suite:
   - one over `spec/test-vectors.json`, asserting the executed count equals the
     published `counts` block ([N-48]);
   - one over `spec/behavior-vectors.json`, executing every scenario and
     reporting by id any conditional scenario your runtime cannot satisfy.
4. Add a language-specific test file for what vectors cannot express:
   concurrency, the constant-time guard, store-failure fail-closed behaviour, and
   configuration validation.
5. Ship an in-memory store that is safe under your runtime's normal request
   concurrency ([N-21]), documented as unsuitable for production.
6. Copy the root `LICENSE` into the package directory — byte-identical, it is the
   only licence file — and wire it into the manifest's file-inclusion list, so
   the published artefact carries it. `scripts/check-licenses.mjs` enforces both.
   **Then add `/packages/<language> export-ignore` to the root
   `.gitattributes`.** Seven manifests are allow-lists, but PHP's dist is built
   with `git archive` from that deny-list, so a new package ships inside every
   PHP consumer's `vendor/` until it is named there. Dart's `.pubignore` is the
   second deny-list; check it too if the new package sits under
   `packages/dart`.
7. Add the language to `.github/workflows/ci.yml`, including a formatting check
   and the strictest linter the ecosystem offers.
8. Add a package `README.md` with install, quickstart, and the `SPEC_VERSION` it
   implements.
9. Write the agent skill at
   `packages/<language>/skills/nebula-token-<language>/SKILL.md` — that exact
   path, because a client discovers a skill by directory name and the
   frontmatter `name` must equal it, and because shipping the directory rather
   than a bare file is what makes the skill installable straight out of the
   published artefact. Wire the path into the manifest's file-inclusion list
   like the licence in step 6. `scripts/check-skills.mjs` enforces the path, the
   name, the inclusion list, and that the skill states the rules an agent would
   otherwise violate while producing code that compiles ([N-21], [N-30],
   [N-35], [N-36], [N-39], [N-14]/[N-46]).
10. Add the skill to [`.claude-plugin/marketplace.json`](.claude-plugin/marketplace.json):
    one more entry, `{"name": "nebula-token-<language>", "source":
    "./packages/<language>", "strict": false}` plus a description of what the
    skill is *for*. That is what makes it installable with `npx skills add` and
    `/plugin install` instead of by hand, and it copies nothing — the entry
    points at the directory step 9 created. `scripts/check-marketplace.mjs`
    fails the build both when an entry has no skill and when a skill has no
    entry, so a language added without this step does not merge.

### Third-party ports

You do not need our permission to implement NEBULA, and you may state that your
implementation "conforms to NEBULA spec version 1" once it passes §9 in full. The
claim is yours; this project neither certifies nor endorses it ([N-53]).

To be listed in the README, open a PR adding it to the table with a link to a CI
run showing both vector suites passing. We check that the run exists and that the
counts match; we do not audit your code.

## Pull requests

- One logical change per PR.
- [Conventional Commits](https://www.conventionalcommits.org/), scoped by package
  where it applies: `fix(ruby): return MALFORMED for non-UTF-8 input`.
- The PR template asks which `[N-*]` requirements your change touches and whether
  the vectors changed. Answer both; "none" is a fine answer for a docs fix.
- CI must be green on every language before review, not after.
- Sign your commits if you can (`git commit -S`). Not required, appreciated.

## Licensing of contributions

Contributions are licensed **Apache-2.0**, matching the project, with no
additional terms. There is no CLA to sign and there will not be one: Apache-2.0
§5 already says that anything you intentionally submit for inclusion is under the
terms of the licence itself unless you explicitly state otherwise. Inbound equals
outbound, so a separate agreement would add paperwork without adding a grant.

That inbound grant carries §3 with it, so a merged contribution brings its
author's patent licence along too. This is precisely what a CLA is usually for,
and it is why one is unnecessary here.

If you cannot make that grant — because your employer owns the copyright, for
example — say so in the PR and we will work it out before merging.

## Code of conduct

[`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md) applies everywhere this project
operates.
