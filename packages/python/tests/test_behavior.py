"""
Normative behavioral suite — spec/behavior-vectors.json (SPECIFICATION.md [N-47]).

Every scenario is a published vector, not a hand-written case, so this suite
cannot silently drift from the other nine implementations.
"""

from __future__ import annotations

from typing import Any

import pytest

from behavior_runner import (
    SATISFIED_CONDITIONS,
    is_applicable,
    load_behavior_vectors,
    run_behavior_vectors,
    run_scenario,
)

VECTORS = load_behavior_vectors()


def test_spec_version_matches_the_published_vectors() -> None:
    import nebula_token as nt

    assert nt.SPEC_VERSION == VECTORS["spec_version"]


def test_every_applicable_scenario_passes() -> None:
    outcome = run_behavior_vectors(VECTORS)

    # [N-48]: a runner that silently iterated nothing must not report success.
    assert len(outcome.executed) + len(outcome.skipped) == VECTORS["counts"]["scenarios"], (
        "every published scenario must be either executed or explicitly skipped"
    )
    assert len(outcome.executed) >= VECTORS["counts"]["unconditional"], (
        "every unconditional scenario must be executed"
    )
    # Reported by id, per the runner contract in the vectors file. CPython's str
    # admits an unpaired surrogate, so nothing is inapplicable here.
    assert [s.id for s in outcome.skipped] == [], (
        f"skipped: {[(s.id, s.condition) for s in outcome.skipped]}"
    )


@pytest.mark.parametrize(
    "scenario", VECTORS["scenarios"], ids=lambda s: str(s["id"])
)
def test_scenario(scenario: dict[str, Any]) -> None:
    """Each scenario runs in isolation and is individually named in the report."""
    if not is_applicable(scenario):
        pytest.skip(
            f"{scenario['id']}: runtime does not satisfy {scenario['condition']!r} "
            f"(satisfied: {sorted(SATISFIED_CONDITIONS)})"
        )
    run_scenario(VECTORS, scenario)
