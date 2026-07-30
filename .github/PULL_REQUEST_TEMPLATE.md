<!--
Ten implementations must agree. Most of this template exists to make a
behavioural change impossible to merge by accident: if a change alters what any
implementation does, it has to say so, cite the requirement, and bring the
vectors with it.

A pull request that only touches documentation, comments or tooling can say so
in one line and skip most of the boxes below.
-->

## What

<!-- One paragraph. What changes, and in which packages? -->

## Why

<!-- Link the issue. A behavioural change needs a spec discussion first
     (GOVERNANCE.md); a pull request is not the place to have it. -->

Closes #

## Does this change behaviour?

<!-- Behaviour = anything an implementation does that an adopter or another
     implementation could observe: an accept/reject decision, a hash, an error
     code, a record state, a timestamp. Renaming a private helper is not
     behaviour. Changing when it is called is. -->

- [ ] **No.** Documentation, comments, tests, tooling or refactoring only.
- [ ] **Yes.** Then every box in this section is required:

  **Requirements touched** — list every `[N-*]` this changes, adds or newly
  constrains, one per line, with what changes about each:

  | Requirement | What changes |
  |---|---|
  | `[N-  ]` |  |

  - [ ] `SPECIFICATION.md` is updated, and the discussion that agreed it is linked above.
  - [ ] `spec/test-vectors.json` and/or `spec/behavior-vectors.json` are updated,
        **including the `counts` block** — a vector added without bumping the count
        is a vector no runner is required to execute ([N-47], [N-48]).
  - [ ] `spec/traceability.json` regenerated (`node scripts/build-traceability.mjs`).
  - [ ] The new or changed vectors **fail without this change** and pass with it.
        Say how you confirmed that:
        <!-- e.g. "reverted src/, ran the suite, scenario reuse-04 failed as expected" -->
  - [ ] **All ten** implementations updated, or an issue is open for each one
        that is not, and it is linked here. A behavioural change lands
        everywhere or nowhere (VERSIONING.md §2).

## Checklist

- [ ] Conforms to `SPECIFICATION.md`, or updates it per the section above.
- [ ] The shared vectors pass for every package I touched.
- [ ] No new runtime dependency (or justified below — the packages are
      dependency-free by design).
- [ ] Public API changes are reflected in `COMPATIBILITY.md`, and I have said
      below which bump they require (MAJOR / MINOR / PATCH) and why.
- [ ] Supported-runtime changes edit `.github/runtime-matrix.json` **and** the
      package manifest in the same commit (`node scripts/check-runtime-matrix.mjs`).
- [ ] `CHANGELOG.md` updated, naming the affected languages if the change is not
      universal.
- [ ] This is **not** a security fix. Those never arrive as a public pull
      request — see `SECURITY.md`.

## Notes for the reviewer

<!-- The thing you would say out loud if you were walking someone through the
     diff: the part you are least sure about, the alternative you rejected, the
     edge case you decided was out of scope. -->
