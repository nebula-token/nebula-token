# Errata — spec version 1

**One erratum has been published for `spec_version = 1`:** E-1, below.

This file exists because [N-50] names it. It is the only place a correction to
[`SPECIFICATION.md`](../SPECIFICATION.md) is recorded, and an implementer who
follows the specification plus this file is following the current text.

## What belongs here

An erratum corrects an **internal contradiction or an ambiguity** in the
specification without changing what a conforming implementation does. Requirement
ids are never renumbered and `spec_version` is never bumped for one — that is the
whole point of the category. See [`VERSIONING.md`](../VERSIONING.md) §1 and
[`GOVERNANCE.md`](../GOVERNANCE.md) for who may publish one and on what timeline.

A change that alters an accept/reject decision, a hash, an error code, a record
state or a timestamp is **not** an erratum. It is a behavioural change, and it
lands in the order [`AGENTS.md`](../AGENTS.md) states — specification, then
vectors, then all ten implementations, then the docs — or not at all.

## Format

Each entry, newest first:

```
## E-1 — <one line: what was contradictory>

- **Affects** [N-nn] (and any other id whose text moved)
- **Published** YYYY-MM-DD, in <version>
- **Was** the sentence as it read
- **Is** the sentence as it now reads
- **Why this is not a behavioural change** the argument that every conforming
  implementation already did the thing the corrected text now says
- **Vector** the case added to pin it, or `none — no observable behaviour`
```

An erratum that cannot fill in the "why this is not a behavioural change" line is
not an erratum.

---

## E-1 — [N-11] did not say whether a device identifier is decided on its bytes or on its declared encoding

- **Affects** [N-11]. No other id changes.
- **Published** 2026-08-04, in 1.0.2
- **Was** "The HMAC message for `deviceIdHash` is the UTF-8 encoding of the
  string `"device:"` concatenated with the device identifier. Implementations
  MUST NOT apply any other text encoding, normalisation form, case
  transformation, or trimming to either input."
- **Is** the same, followed by a paragraph stating that where a runtime gives a
  string value a declared encoding alongside its bytes, and those bytes are
  already a valid UTF-8 encoding, the bytes **are** the input: acceptance MUST
  NOT be decided on the declared encoding, and the value MUST NOT be transcoded
  from it.
- **Why this is not a behavioural change** the rule was already there, twice
  over. "The UTF-8 encoding of the string" names a byte sequence, and a value
  whose bytes are already that sequence needs no conversion to obtain it;
  transcoding to reach it is "any other text encoding", which the same sentence
  already forbids. Nine of the ten implementations read it that way from the
  start and are unchanged. Ruby read "the string" as the runtime's *tagged*
  string and transcoded from the tag, which refused an identifier — one arriving
  as a binary-tagged `String`, from `String#b`, `File.binread` or a socket read —
  that the other nine accept; in `refresh` that refusal is a sender-binding
  failure and revoked the whole family. That was a defect in one port against
  the text as it stood, fixed in `nebula-token` 1.0.2 for Ruby, and this
  paragraph exists so that the eleventh implementation does not have to infer it.
  Deployments see no change: no accept/reject decision, hash, error code, record
  state or timestamp differs for any input that the nine already handled.
- **Vector** `dh-08` and `dh-09` in
  [`spec/test-vectors.json`](test-vectors.json), which carry the optional
  `device_id_bytes` field — the UTF-8 encoding of the case's `device_id`, as
  lowercase hex. A runner whose strings are bytes, or carry an encoding tag
  distinct from them, feeds those bytes; one whose strings are Unicode decodes
  them as UTF-8. Both must produce the case's single expected hash.
  `counts.device_hashing` rose from 7 to 9 in the same commit ([N-48]).
