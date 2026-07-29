# Errata — spec version 1

**No errata have been published for `spec_version = 1`.**

This file exists because [N-50] names it. It is the only place a correction to
[`SPECIFICATION.md`](../SPECIFICATION.md) is recorded, and an implementer who
follows the specification plus this file is following the current text.

## What belongs here

An erratum corrects an **internal contradiction or an ambiguity** in the
specification without changing what a conforming implementation does. Requirement
ids are never renumbered and `spec_version` is never bumped for one — that is the
whole point of the category. See [`VERSIONING.md`](../VERSIONING.md) §2 and
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
