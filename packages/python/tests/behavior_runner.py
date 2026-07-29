"""
Runner for the normative behavioral suite, spec/behavior-vectors.json
(SPECIFICATION.md [N-47], [N-49]).

The scenarios are data. This file is the only thing that is language-specific,
which is what stops the ten ports from drifting apart the way ten hand-written
suites did.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Optional, Union

from nebula_token import (
    IssueResult,
    MemoryRefreshTokenStore,
    NebulaEngine,
    RefreshError,
    RefreshOk,
    RevokeError,
    TokenRecord,
    TokenStatus,
)


def _repo_root() -> Path:
    """Walk up from this file to the repository root ([N-49] artifacts live in
    <root>/spec). Never hardcoded, never vendored into the package."""
    for parent in Path(__file__).resolve().parents:
        if (parent / "spec" / "behavior-vectors.json").is_file():
            return parent
    raise RuntimeError("spec/behavior-vectors.json not found in any parent of this file")


SPEC_DIR = _repo_root() / "spec"

Vectors = dict[str, Any]
Scenario = dict[str, Any]
Step = dict[str, Any]


def load_behavior_vectors() -> Vectors:
    data: Vectors = json.loads((SPEC_DIR / "behavior-vectors.json").read_text(encoding="utf-8"))
    return data


#: Conditions this runtime satisfies. CPython's `str` is a sequence of code
#: points and can hold an unpaired surrogate — `json.loads(r'"\ud800"')` returns
#: one — so the invalid-Unicode scenario applies here.
SATISFIED_CONDITIONS = frozenset({"runtime-admits-invalid-unicode-strings"})

#: 32 zero bytes, canonically encoded: well-formed, and never the real secret.
FORGED_VERIFIER = "A" * 43
FORGED_SELECTOR = "A" * 22
LONE_SURROGATE = "\ud800"


class ControllableStore:
    """Wraps the reference store so a scenario can force one compare-and-set to lose."""

    def __init__(self) -> None:
        self.inner = MemoryRefreshTokenStore()
        self._fail_next: set[str] = set()

    def fail_next_cas(self, method: str) -> None:
        self._fail_next.add(method)

    def _consume(self, method: str) -> bool:
        if method in self._fail_next:
            self._fail_next.discard(method)
            return True
        return False

    def find_by_selector(self, selector: str) -> Optional[TokenRecord]:
        return self.inner.find_by_selector(selector)

    def insert(self, record: TokenRecord) -> None:
        self.inner.insert(record)

    def mark_rotated(
        self,
        selector: str,
        from_status: TokenStatus,
        rotated_at: int,
        replaced_by_selector: str,
    ) -> bool:
        if self._consume("markRotated"):
            return False
        return self.inner.mark_rotated(selector, from_status, rotated_at, replaced_by_selector)

    def revoke_if_active(self, selector: str) -> bool:
        if self._consume("revokeIfActive"):
            return False
        return self.inner.revoke_if_active(selector)

    def revoke_family(self, family_id: str) -> int:
        return self.inner.revoke_family(family_id)

    def revoke_user(self, user_id: str) -> int:
        return self.inner.revoke_user(user_id)


@dataclass(frozen=True)
class Binding:
    token: str
    family_id: str
    expires_at: int


@dataclass(frozen=True)
class SkippedScenario:
    id: str
    condition: str


@dataclass
class RunOutcome:
    executed: list[str] = field(default_factory=list)
    skipped: list[SkippedScenario] = field(default_factory=list)


class ScenarioFailure(AssertionError):
    """A divergence from a published scenario."""


def _fail(scenario: Scenario, index: int, message: str) -> "ScenarioFailure":
    requirements = ", ".join(scenario.get("requirements", []))
    return ScenarioFailure(f"[{scenario['id']}] step {index} ({requirements}): {message}")


def is_applicable(scenario: Scenario) -> bool:
    condition = scenario.get("condition")
    return condition is None or condition in SATISFIED_CONDITIONS


def run_behavior_vectors(vectors: Vectors) -> RunOutcome:
    """Execute every applicable scenario. Raises on the first divergence."""
    outcome = RunOutcome()
    for scenario in vectors["scenarios"]:
        if not is_applicable(scenario):
            outcome.skipped.append(SkippedScenario(scenario["id"], scenario["condition"]))
            continue
        run_scenario(vectors, scenario)
        outcome.executed.append(scenario["id"])
    return outcome


class _Clock:
    def __init__(self, now: int) -> None:
        self.now = now

    def __call__(self) -> int:
        return self.now


def run_scenario(vectors: Vectors, scenario: Scenario) -> None:
    cfg: dict[str, Any] = {**vectors["defaults"], **scenario.get("config", {})}
    store = ControllableStore()
    bindings: dict[str, Binding] = {}
    issued_secrets: list[str] = []
    device_ids: set[str] = set()
    clock = _Clock(cfg["now"])

    def build(kids: list[str], active_kid: str) -> NebulaEngine:
        return NebulaEngine(
            peppers={kid: vectors["peppers"][kid] for kid in kids},
            active_kid=active_kid,
            store=store,
            absolute_ttl_seconds=cfg["absoluteTtlSeconds"],
            idle_ttl_seconds=cfg["idleTtlSeconds"],
            reuse_grace_seconds=cfg["reuseGraceSeconds"],
            clock=clock,
        )

    engine = build(cfg["peppers"], cfg["activeKid"])

    def resolve_token(step: Step, index: int) -> str:
        ref: dict[str, Any] = step.get("token") or {}
        if "literal" in ref:
            literal: str = ref["literal"]
            return literal
        if "ref" not in ref:
            raise _fail(scenario, index, "step has no token reference")
        bound = bindings.get(ref["ref"])
        if bound is None:
            raise _fail(scenario, index, f"unknown binding {ref['ref']!r}")
        forge = ref.get("forge")
        if forge is None:
            return bound.token
        parts = bound.token.split(".")
        if forge == "verifier":
            parts[3] = FORGED_VERIFIER
        elif forge == "unknownKid":
            parts[1] = "zz"
        elif forge == "unknownSelector":
            parts[2] = FORGED_SELECTOR
        else:
            raise _fail(scenario, index, f"unknown forge {forge!r}")
        return ".".join(parts)

    def device_of(step: Step) -> Optional[str]:
        # Absence and the empty string are different values ([N-25]), so this
        # must not collapse a missing key into "".
        if step.get("deviceIdKind") == "lone-surrogate":
            return LONE_SURROGATE
        device_id: Optional[str] = step.get("deviceId")
        return device_id

    def check_success(
        result: Union[IssueResult, RefreshOk], expect: Optional[dict[str, Any]], index: int
    ) -> None:
        if not expect:
            return
        if "generation" in expect and result.generation != expect["generation"]:
            raise _fail(
                scenario, index, f"expected generation {expect['generation']}, got {result.generation}"
            )
        if "kid" in expect:
            kid = result.token.split(".")[1]
            if kid != expect["kid"]:
                raise _fail(scenario, index, f"expected kid {expect['kid']}, got {kid}")
        if "sameFamilyAs" in expect:
            other = bindings[expect["sameFamilyAs"]]
            if result.family_id != other.family_id:
                raise _fail(scenario, index, "family_id changed across rotation")
        if "sameExpiresAtAs" in expect:
            other = bindings[expect["sameExpiresAtAs"]]
            if result.expires_at != other.expires_at:
                raise _fail(
                    scenario,
                    index,
                    f"absolute deadline moved: {other.expires_at} -> {result.expires_at}",
                )
        if expect.get("idleEqualsExpires") and result.idle_expires_at != result.expires_at:
            raise _fail(
                scenario,
                index,
                f"idle_expires_at {result.idle_expires_at} should be clamped to {result.expires_at}",
            )

    def check_attribution(
        result: Union[RefreshError, RevokeError], expect: Optional[dict[str, Any]], index: int
    ) -> None:
        """[N-39] attribution, tri-state. `true` demands the field, `false`
        demands its absence — the exclusion list (MALFORMED, UNKNOWN_KID,
        NOT_FOUND) is a requirement too, and a truthy-only check could never
        observe it. Absent means the scenario does not assert it. Here a field
        is "absent" when it is None, which is how the engine signals that no
        record was resolved."""
        if expect is None:
            return
        want_user = expect.get("hasUserId")
        if want_user is not None and (result.user_id is not None) != want_user:
            raise _fail(
                scenario, index, f"expected user_id {'present' if want_user else 'absent'} ([N-39])"
            )
        want_family = expect.get("hasFamilyId")
        if want_family is not None and (result.family_id is not None) != want_family:
            raise _fail(
                scenario,
                index,
                f"expected family_id {'present' if want_family else 'absent'} ([N-39])",
            )

    def bind(step: Step, result: Union[IssueResult, RefreshOk]) -> None:
        name = step.get("bind")
        if name is not None:
            bindings[name] = Binding(result.token, result.family_id, result.expires_at)
        issued_secrets.append(result.token.split(".")[3])

    for index, step in enumerate(scenario["steps"]):
        expect: Optional[dict[str, Any]] = step.get("expect")
        op = step["op"]

        if op == "issue":
            device_id = device_of(step)
            issued = engine.issue(step["userId"], device_id)
            if expect is not None and expect.get("ok") is False:
                raise _fail(scenario, index, "expected issue to fail")
            check_success(issued, expect, index)
            bind(step, issued)
            if device_id:
                device_ids.add(device_id)

        elif op == "refresh":
            result = engine.refresh(resolve_token(step, index), device_of(step))
            wants_success = expect is None or (
                expect.get("ok") is True or ("ok" not in expect and "error" not in expect)
            )
            if wants_success:
                if not result.ok:
                    raise _fail(scenario, index, f"expected success, got {result.error}")
                check_success(result, expect, index)
                bind(step, result)
            else:
                assert expect is not None
                if result.ok:
                    raise _fail(scenario, index, f"expected {expect.get('error')}, got success")
                if result.error != expect.get("error"):
                    raise _fail(
                        scenario, index, f"expected {expect.get('error')}, got {result.error}"
                    )
                check_attribution(result, expect, index)

        elif op == "revokeToken":
            revoked = engine.revoke_token(resolve_token(step, index))
            if expect is not None and expect.get("ok") is False:
                if revoked.ok:
                    raise _fail(scenario, index, f"expected {expect.get('error')}, got success")
                if revoked.error != expect.get("error"):
                    raise _fail(
                        scenario, index, f"expected {expect.get('error')}, got {revoked.error}"
                    )
                # [N-39] governs every failure result, revoke_token's included.
                check_attribution(revoked, expect, index)
            else:
                if not revoked.ok:
                    raise _fail(scenario, index, f"expected success, got {revoked.error}")
                if expect is not None and "revoked" in expect and revoked.revoked != expect["revoked"]:
                    raise _fail(
                        scenario, index, f"expected {expect['revoked']} revoked, got {revoked.revoked}"
                    )

        elif op == "revokeFamilyOf":
            count = engine.revoke_family(bindings[step["of"]].family_id)
            if expect is not None and "revoked" in expect and count != expect["revoked"]:
                raise _fail(scenario, index, f"expected {expect['revoked']} revoked, got {count}")

        elif op == "revokeUser":
            count = engine.revoke_all_for_user(step["userId"])
            if expect is not None and "revoked" in expect and count != expect["revoked"]:
                raise _fail(scenario, index, f"expected {expect['revoked']} revoked, got {count}")

        elif op == "advance":
            clock.now += step["seconds"]

        elif op == "reconfigure":
            engine = build(step["peppers"], step["activeKid"])

        elif op == "failNextCas":
            store.fail_next_cas(step["method"])

        elif op == "expectStatusCounts":
            actual: dict[str, int] = {"active": 0, "rotated": 0, "revoked": 0}
            for row in store.inner.all():
                actual[row.status] += 1
            for status, want in step["counts"].items():
                if actual[status] != want:
                    raise _fail(
                        scenario, index, f"expected {want} {status}, got {actual[status]} ({actual})"
                    )

        elif op == "expectNoRawSecrets":
            # asdict, not repr: the record's repr redacts hashes ([N-14]), and a
            # redacted dump would make this assertion vacuous.
            dump = json.dumps([asdict(row) for row in store.inner.all()])
            for secret in issued_secrets:
                if secret in dump:
                    raise _fail(scenario, index, "a raw verifier reached the store ([N-14])")
            for device_id_value in device_ids:
                if device_id_value in dump:
                    raise _fail(scenario, index, "a raw device identifier reached the store ([N-14])")

        else:
            raise _fail(scenario, index, f"unknown op {op!r}")
