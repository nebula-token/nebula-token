# Governance

How decisions are made, who makes them, how the specification changes, and how a
third-party implementation gets listed ([N-53]).

This is a small project with a deliberately small surface. The process below is
sized accordingly: enough structure that an adopter can predict what will happen
to the thing they depend on, and no more.

---

## 1. What this project optimises for

Every rule further down follows from these four, and a proposal that conflicts
with one of them will be declined on that ground alone.

1. **The specification is the source of truth.** Behaviour changes in
   [`SPECIFICATION.md`](SPECIFICATION.md) first, then in the vectors, then in all
   ten implementations. Never the reverse; a clever fix in one language that the
   spec does not describe is a divergence, not an improvement.
2. **Conformance is executable.** A claim about behaviour that no vector checks
   is not a claim this project makes. New behaviour arrives with new vectors.
3. **The surface stays small.** No new runtime dependencies, no novel
   cryptography, no configuration knob that lets a deployment be quietly
   non-conforming.
4. **Honesty over enthusiasm.** Documented limitations stay documented. The list
   of what this project has *not* done ([`SECURITY.md`](SECURITY.md)) is a
   feature, and shortening it requires doing the work, not deleting the line.

## 2. Roles

| Role | What it is | How you get it |
|---|---|---|
| **User** | Anyone using a package. Files issues, asks in Discussions. | — |
| **Contributor** | Anyone whose patch has been merged. | Send a patch. |
| **Package maintainer** | Owns one language: reviews and merges patches to it, keeps its CI green, keeps its README and `SKILL.md` accurate, cuts its patch releases. | Sustained contribution to that package, then invitation by the lead maintainer with no objection from existing maintainers. |
| **Spec maintainer** | Reviews changes to `SPECIFICATION.md`, `spec/test-vectors.json` and `spec/behavior-vectors.json`. | Invitation. Requires having implemented the spec at least once, in any language. |
| **Security responder** | Receives private reports, coordinates fixes and advisories under [`SECURITY.md`](SECURITY.md). | Invitation by the lead maintainer. Deliberately a short list. |
| **Lead maintainer** | Breaks ties, holds the registry credentials, signs releases, and is accountable for the project's direction. Currently **Matteo Teodori**. | Succession is in §8. |

**As of 1.0.0 every role above is held by the lead maintainer, and there are
no other contributors.** The multi-approver gates in §3 and the succession
arrangement in §8 describe what happens once a second maintainer exists; until
then they are a statement of intent, not a control that can fire.
[`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md) names the same limitation for
conduct reports, where it matters most.

Maintainers are volunteers. Stepping back is normal and requires no explanation:
say so in an issue, and the role moves to emeritus. Emeritus maintainers keep the
credit and lose the merge rights, which is the correct way round.

## 3. How decisions are made

**Lazy consensus.** A proposal that nobody objects to within the review window
below is accepted. Objections must be technical and must say what would resolve
them; "I would have done it differently" is a comment, not a block.

**Ties are broken by the lead maintainer**, in public, in the thread, with the
reasoning written down. There is no vote, because a project this size cannot
afford the theatre of one.

| Change class | Approvals needed | Review window | Additional gate |
|---|---|---|---|
| Typos, prose, examples | 1 maintainer | — | — |
| Package patch: bug fix, no behaviour change | 1 maintainer of that package | 72 hours | CI green on every language |
| New supported runtime version | 1 maintainer | 72 hours | CI matrix updated in the same PR |
| Dropping an end-of-life runtime | 2 maintainers | 7 days | Announced one release in advance ([`COMPATIBILITY.md`](COMPATIBILITY.md) §7) |
| New capability or new error code | 2 maintainers **and** a spec change | 14 days | §4 in full |
| Any observable behaviour change | 2 maintainers **and** a spec change | 14 days | §4 in full |
| Erratum: spec text corrected without changing conforming behaviour | 1 spec maintainer + lead | 7 days | Recorded in `spec/ERRATA.md`, no `spec_version` bump ([`VERSIONING.md`](VERSIONING.md)) |
| New `spec_version` | Lead maintainer | 30 days | New wire prefix ([N-51]); expected never to happen |
| Security fix | Security responders | — | Private, per [`SECURITY.md`](SECURITY.md); the process above is deliberately bypassed |
| Adding a language to this repository | Lead maintainer | 14 days | §6 |

Everything happens in public issues and pull requests. There is no private
roadmap and no maintainers' back channel other than the security one, which
exists only because coordinated disclosure requires it.

## 4. How a specification change happens

This is the one process worth following exactly, because getting it wrong ships
ten packages that disagree.

1. **Issue first.** State the problem, not the patch. Cite the requirement ids
   involved. If the trigger is two implementations disagreeing, say which and on
   what input — that is a specification defect by
   [`COMPATIBILITY.md`](COMPATIBILITY.md) §8 even when both look reasonable.
2. **Check it is permitted.** Within `spec_version = 1`, [N-50] freezes the
   meaning of every existing requirement, every error code and every wire form.
   Additive changes (a new code, a new capability) are possible in a minor
   release; a change of meaning is not, at any version below a new
   `spec_version`.
3. **Write the requirement text.** A new or amended `[N-*]` paragraph, in
   specification voice, with RFC 2119 keywords used deliberately. New ids are
   appended; existing ids are never renumbered, because tests, threat-model
   entries and third-party reports cite them.
4. **Write the vectors before the code.** A behavioural change means new
   scenarios in [`spec/behavior-vectors.json`](spec/behavior-vectors.json); a
   parsing or hashing change means new cases in
   [`spec/test-vectors.json`](spec/test-vectors.json). Update the `counts` block
   in the same commit — a runner must assert it ([N-48]).
5. **Implement in TypeScript first.** It is the reference implementation; its
   test layout is the one the other nine follow.
6. **Implement in the remaining nine.** All ten land before release. A partially
   implemented spec change is the failure mode this whole document exists to
   prevent, so it is not merged to `main` piecemeal — it goes in one series, or
   behind a branch until it is complete.
7. **Update the affected documents.** [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md)
   traceability, [`docs/STORE.md`](docs/STORE.md), [`docs/INTEGRATION.md`](docs/INTEGRATION.md),
   [`COMPATIBILITY.md`](COMPATIBILITY.md), `CHANGELOG.md`.
8. **Release.** Per [`RELEASING.md`](RELEASING.md): one tag, ten registries, the
   same MAJOR.MINOR everywhere.

An erratum — a contradiction, an ambiguity, or a missing vector for a rule every
implementation already follows — skips steps 5 and 6, is recorded in
`spec/ERRATA.md`, and does not change `spec_version`.

## 5. Releases

Releases are cut by the lead maintainer, following
[`RELEASING.md`](RELEASING.md). Anyone may propose that a release be cut; the
answer is usually yes, because a small release is cheaper to reason about than a
large one. Nothing is published from a workstation, and no package is published
whose conformance suite did not run in the same CI invocation.

## 6. Adding a language to this repository

The bar is not "does it work". It is **"who will fix it at 2 a.m. when the
vectors change"**, because ten languages moving together is the entire value
proposition.

A new package is accepted when all of the following hold:

- It passes [`spec/test-vectors.json`](spec/test-vectors.json) and
  [`spec/behavior-vectors.json`](spec/behavior-vectors.json) in full, loading them
  from the repository rather than restating them.
- It has no runtime dependency the standard library could have satisfied.
- It follows the reference layout: one module, an in-memory store ([N-21]), a
  `README.md`, an agent skill at `skills/nebula-token-<language>/SKILL.md` inside
  the package, an example store adapter, and a copy of `LICENSE`.
- It exports every constant ([N-4]) and the `SPEC_VERSION` it implements.
- It adds a CI job to [`.github/workflows/ci.yml`](.github/workflows/ci.yml) and a
  row to [`RELEASING.md`](RELEASING.md)'s version table.
- **Someone has agreed to maintain it**, by name, and understands that a spec
  change is an obligation across all ten.

A package whose CI has been red for 30 days with no maintainer response is moved
to `packages/unmaintained/` and dropped from the release matrix, announced one
release in advance. It returns the moment someone picks it up.

## 7. Third-party implementations ([N-53])

You do not need anyone's permission to implement NEBULA. The specification and
the vectors are published under Apache-2.0 and complete; that is the point of
writing them down.

**The conformance claim is yours to make.** [N-53] permits an implementation that
passes §9 of the specification in full to state *"conforms to NEBULA spec version
1"*. This project neither certifies nor endorses that claim, does not test your
code, and takes no responsibility for it.

### Getting listed

Listings live in the README's *Third-party implementations* section. Open a pull
request adding a row there — the PR mechanics are in
[`CONTRIBUTING.md`](CONTRIBUTING.md) — establishing all of the following:

| Requirement | Why |
|---|---|
| The source is publicly readable | An unverifiable conformance claim cannot be listed, only asserted |
| It passes **both** vector files in full, at a stated `spec_version` | This is what the claim means ([N-47]) |
| It reports, by id, any conditional scenario it skipped | [N-48]: silently iterating zero cases is a failure, not a pass |
| A link to a public CI run showing that pass | So a reader can check today, not take your word from last year |
| A named maintainer and a security contact | Somebody has to receive the report when the spec changes or a flaw is found |
| A stated licence | Adopters need to know before they read the code |

### Staying listed

A listing is removed — with an issue opened first, and 30 days to respond — when
the implementation stops passing the current vectors for a released
`spec_version`, when its security contact stops answering, or when it has been
unmaintained for 12 months. Delisting is not a judgement about quality; it means
the claim is no longer checkable.

### Naming

Say *"an implementation of the NEBULA specification, version 1"* or
*"NEBULA-compatible"*. Do not describe an implementation as *certified*,
*official*, or *approved*: no certification programme exists, and this project
will not create one it cannot fund the testing for.

### Reviewing a listing request

Maintainers check that the CI run exists, that it executed both vector files, and
that the executed counts match the published `counts` blocks. **We do not audit
the code**, and a listing must never be read as one. The ten implementations in
[`packages/`](packages) are maintained here and are not third-party listings.

There are no listed third-party implementations yet.

## 8. Continuity

If the lead maintainer becomes unavailable, the project does not stall on
goodwill:

- The Apache-2.0 grant is irrevocable (§2 and §3 both say so), so anyone may fork
  at any time, for any reason, without asking.
- The specification and the vectors are the durable artefacts. An implementation
  can be rewritten from them; that is what the ten in this repository demonstrate.
- Security responders retain the ability to publish an advisory, so that once a
  second one exists a vulnerability is not gated on one person. Until then it is
  — see §2, and [`SECURITY.md`](SECURITY.md), which says so plainly.
- Should the lead maintainer be unreachable for 90 days, the security responders
  and package maintainers may jointly designate a new lead, in a public issue.
  The registry namespaces would need transferring, which is a request to each
  registry and not something this document can promise on their behalf. Two of
  the ten need nothing beyond the repository itself: the Go module resolves from
  `github.com/nebula-token/nebula-token/packages/go` and the PHP package from
  this repository's root `composer.json`, so both move with the repository rather
  than with an account or a DNS record ([`VERSIONING.md`](VERSIONING.md) §5). The
  reversed-domain namespace `dev.nebulatoken` is the one identifier still bound
  to a domain, permanently, by Sonatype's verification.

## 9. Conduct

[`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md) applies everywhere this project has a
presence. Enforcement is the lead maintainer's, escalating to a temporary or
permanent ban. Security reports are handled under [`SECURITY.md`](SECURITY.md) and
a good-faith report is never treated as unauthorised access, whatever it turns up.
