# Compatibility contract

This document states what NEBULA 1.0.0 freezes and what it does not. It exists
because "stable" is not a feeling: an adopter putting this on an authentication
path is entitled to know, before they start, exactly which surfaces are
guaranteed and which may move.

Read alongside [`VERSIONING.md`](VERSIONING.md) (how versions relate to the spec)
and [`RELEASING.md`](RELEASING.md) (how a release is cut).

---

## 1. Frozen for the life of spec version 1

Nothing below can change without a new `spec_version`, which by definition means
a new wire format and a new prefix ([N-51]).

| Surface | Frozen value |
|---|---|
| Token prefix | `nbl` |
| Wire format | `nbl.{kid}.{selector}.{verifier}`, four dot-separated parts |
| Token grammar | The ABNF in [N-5]; canonical unpadded base64url only |
| Selector / verifier sizes | 16 and 32 CSPRNG bytes → 22 and 43 characters |
| Keyed primitive | HMAC-SHA-256, and nothing else |
| Hash inputs | `verifier_bytes`; `"device:" ‖ deviceId` — both per [N-11], UTF-8 |
| Hash output form | Lowercase hexadecimal |
| Record fields | The thirteen fields of [N-10], with their meanings |
| Check order | The ten steps of [N-26], in that order |
| Error code names | The ten names of [N-38] |
| Grace semantics | The six preconditions of [N-30], including non-extendability |

A conforming implementation written today will interoperate with a conforming
implementation written in ten years, against the same database, without
coordination. That is the whole point of the exercise.

## 2. Frozen for the life of package major version 1

These are API surfaces rather than wire surfaces. They change only in a package
major release, which may happen without a spec change.

- The six store methods of [N-16], their names, parameters and return types.
- The engine operations: `issue`, `refresh`, `revokeToken`, `revokeFamily`,
  `revokeAllForUser`.
- The shape of the issue and refresh results, including integer Unix-second
  timestamps ([N-2]).
- Configuration option names and their defaults.
- The exceptions/error types a package raises for caller mistakes.

## 3. Explicitly NOT frozen

Relying on any of these is relying on an implementation detail.

- **Human-readable messages.** Every diagnostic string is non-normative and may
  change in any release ([N-41]). Match on codes, never on text.
- **The set of error codes, upward.** A future **minor** version may add a code.
  Consumers must treat an unrecognised code as a refusal ([N-40]); the types are
  declared open where the language allows it. No existing code will be removed
  or redefined within spec version 1.
- **Internal helpers** that a package exports for its own conformance tests
  (`parseToken`, `hashVerifier`, `constantTimeEqualHex` and their equivalents).
  They are public so third parties can test, not so applications can build on
  them. Their behaviour is pinned by the vectors; their signatures are not.
- **Performance characteristics**, allocation counts, and the concrete types
  used internally.
- **The in-memory store.** It is a development and test fixture ([N-21]). Its
  behaviour beyond the store contract — including `deleteExpired` and any test
  helpers — may change at any time.

### Two documented differences, both outside the vectors' observation points

**Configuration validation.** Go reads `AbsoluteTTLSeconds`, `IdleTTLSeconds` and `ReuseGraceSeconds` under the
language's zero-value convention: an omitted field is `0`, which means "unset,
use the default". The other nine reject an explicit `0` for the two TTLs as a
configuration error. The *effective* values are identical everywhere — always
`> 0`, `> 0` and `>= 0` as §5 requires — and no protocol behaviour differs; what
differs is whether passing `0` explicitly is an error or a request for the
default. Go cannot distinguish the two without a pointer field, and a pointer
there would be un-idiomatic for no protocol gain. It is named here rather than
silently reconciled.

**Expiry arithmetic at absurd TTLs.** §5 puts no ceiling on
`absoluteTtlSeconds`, and above a certain size the ten stop producing the same
`expiresAt`. The boundary is not where you would guess, so it is stated
precisely rather than left as "very large numbers behave badly":

| `absoluteTtlSeconds` | Behaviour |
|---|---|
| up to 2<sup>53</sup> − 1 (≈ 285 million years) | every implementation returns the same integer |
| 2<sup>53</sup> … i64 max | TypeScript and Dart lose precision — their number type is an IEEE-754 double, so `now + ttl` rounds. Measured at 2<sup>62</sup>: TypeScript returns `4611686020127388000` where Python returns `4611686020127387904`. |
| beyond i64 max − `now` | Rust panics on overflow in a debug build, Go wraps to a negative deadline, Python's unbounded integers keep going |

No deployment reaches this. A refresh-token lifetime is measured in days; the
first divergence is at **285 million years**, and a mistyped configuration
produces `30000000`, not a sixteen-digit number — you arrive here only by
passing something close to the integer ceiling on purpose.

It is left unbounded on purpose. Bounding it means a new normative constraint on
a configuration option, and [N-50] freezes the *meaning* of the requirements in
`spec_version = 1`. New ids may still be appended, so if this is ever worth
closing it can be closed — as a new requirement in a later minor version, with
its own vector and its own validation in all ten, rather than as a late
constraint bolted on beside a release. The honest position today is that the
ten agree at every value any deployment can hold, and that the boundary is
here in writing.

## 4. What an adopter must provide

NEBULA deliberately stops at the edges below. These are not gaps to be filled in
a later version; they are the boundary of the specification (§10, Non-goals), and
they will not move.

| Concern | Why it is yours |
|---|---|
| Transport | HTTPS, cookie attributes, CORS — see [`docs/INTEGRATION.md`](docs/INTEGRATION.md) |
| Rate limiting | Must be enforced at the edge, before the engine |
| Access tokens | NEBULA issues no access token and reads no claims |
| Session metadata | IP, user agent, device labels: store them in your own table keyed by `familyId`, which is stable for the life of a session |
| Session enumeration | "Your active devices" is a query over your own table |
| Authorisation of admin paths | `revokeFamily` and `revokeAllForUser` trust the caller ([N-37]) |
| Record garbage collection | A periodic job, no earlier than `familyExpiresAt` ([N-15]) |

`familyId` is the join key for all of the above, and it is stable and frozen. A
record does not need extra columns for you to attach your own.

## 5. Deprecation policy

1. A surface is deprecated only in a **minor** release, never a patch.
2. Deprecation is announced in `CHANGELOG.md`, in the release notes, and — where
   the language supports it — with a compiler-visible annotation.
3. A deprecated surface keeps working for the remainder of the major version,
   with a minimum of **12 months** between deprecation and removal.
4. Removal happens only in the next major version.
5. No surface listed in §1 or §2 will be deprecated within spec version 1
   except to correct a security defect, handled under [`SECURITY.md`](SECURITY.md).

## 6. Support window

| Line | Status | Security fixes until |
|---|---|---|
| 1.x | Current | At least 24 months after 2.0.0 is released |

Only the latest patch of the current minor line receives fixes. There is no LTS
branch: the surface is small enough that upgrading within 1.x is intended to be
a version bump and nothing else.

## 7. Runtime support

A runtime is supported when CI exercises it. Dropping a runtime that has reached
its own end of life is a **minor** change, not a major one, and is announced one
release in advance. The current matrix is in [`SUPPORT.md`](SUPPORT.md).

## 8. Interoperability guarantee

Two implementations that pass [`spec/test-vectors.json`](spec/test-vectors.json)
and [`spec/behavior-vectors.json`](spec/behavior-vectors.json) in full will agree
at every observation point those artefacts define: the accept/reject decision for
the token strings the parsing vectors cover, the byte-level output of both keyed
hashes, and — per scenario — the outcome code, the generation, the family and
expiry relations, and the resulting multiset of record statuses in the store.

**That is a bounded claim, not a universal one, and it is deliberately the one
this project makes.** The vectors do not observe timing, log output or the order
of store calls, and no differential harness yet drives all ten from one random
transcript. Two conforming implementations could still differ somewhere no vector
looks — §3 above documents the two places they are known to. `README.md` states
the same bound in the same words; if the two ever drift apart, that is a defect
in this document.

That is a claim about the vectors, not about intentions. If you find two
conforming implementations that disagree, that is a specification defect and we
want the report — see [`CONTRIBUTING.md`](CONTRIBUTING.md). The fix will be a new
vector, published as an erratum, and the disagreement resolved in the direction
the specification already implies.
