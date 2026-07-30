"""
Language-specific tests: properties that cannot be expressed as portable
behavior vectors. All cross-language behavior lives in
spec/behavior-vectors.json and is exercised by test_behavior.py.
"""

from __future__ import annotations

import json
import threading
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, replace
from typing import Any, Callable, Optional

import pytest

from nebula_token import (
    MemoryRefreshTokenStore,
    NebulaConfigError,
    NebulaEngine,
    RefreshTokenStore,
    TokenRecord,
    TokenStatus,
    constant_time_equal_hex,
    hash_device_id,
    hash_verifier,
    parse_token,
)

PEPPER = "pepper-one-0123456789abcdef0123456789ab"
HASH = "a" * 64
START = 1_700_000_000


class Clock:
    def __init__(self, now: int = START) -> None:
        self.now = now

    def __call__(self) -> int:
        return self.now

    def advance(self, seconds: int) -> None:
        self.now += seconds


def make_engine(**overrides: Any) -> tuple[NebulaEngine, MemoryRefreshTokenStore, Clock]:
    store: MemoryRefreshTokenStore = overrides.pop("store", None) or MemoryRefreshTokenStore()
    clock: Clock = overrides.pop("clock", None) or Clock()
    engine = NebulaEngine(
        peppers=overrides.pop("peppers", {"k1": PEPPER}),
        active_kid=overrides.pop("active_kid", "k1"),
        store=store,
        clock=clock,
        **overrides,
    )
    return engine, store, clock


# ── Constant-time comparison ([N-31]) ───────────────────────────────────────


def test_constant_time_equal_hex_rejects_anything_but_64_lowercase_hex_chars() -> None:
    assert constant_time_equal_hex(HASH, HASH) is True
    assert constant_time_equal_hex(HASH, "b" * 64) is False

    # `bytes.fromhex` accepts ASCII whitespace and upper-case digits, so without
    # the guard every case below would compare EQUAL or raise.
    assert constant_time_equal_hex("abc", "abd") is False, "odd-length prefixes"
    assert constant_time_equal_hex(HASH, HASH + "   ") is False, "space-padded CHAR column"
    assert constant_time_equal_hex(HASH, "   " + HASH) is False, "leading whitespace"
    assert constant_time_equal_hex(HASH, HASH + "\n") is False, "trailing newline"
    assert constant_time_equal_hex(HASH, HASH + "zzzz") is False, "junk suffix"
    assert constant_time_equal_hex(HASH, HASH.upper()) is False, "case is not folded"
    assert constant_time_equal_hex(HASH.upper(), HASH.upper()) is False, "upper-cased on both sides"
    assert constant_time_equal_hex(HASH[:63], HASH[:63]) is False, "truncated column"
    assert constant_time_equal_hex(HASH[:32], HASH[:32]) is False, "half a digest"
    assert constant_time_equal_hex("", "") is False, "empty is never equal"


def test_constant_time_equal_hex_never_raises() -> None:
    hostile: list[object] = [None, 42, 3.5, b"a" * 64, bytearray(b"x"), {}, [], "", "zz", " " * 64, "\ud800" * 64]
    for value in hostile:
        assert constant_time_equal_hex(value, HASH) is False, repr(value)
        assert constant_time_equal_hex(HASH, value) is False, repr(value)


def test_a_stored_hash_corrupted_after_the_fact_fails_closed() -> None:
    engine, store, _ = make_engine()
    issued = engine.issue("u1")
    row = store.all()[0]
    # The same record, but the column was upper-cased by an ETL job.
    store.insert(replace(row, selector="x" * 22, verifier_hash=row.verifier_hash.upper()))

    parts = issued.token.split(".")
    parts[2] = "x" * 22
    result = engine.refresh(".".join(parts))
    assert not result.ok
    assert result.error == "VERIFIER_MISMATCH"


# ── Concurrency ([N-17], [N-18], [N-34]) ────────────────────────────────────


class BarrierStore:
    """Forces N refreshes to interleave at the worst possible moment.

    Every thread has read the record and inserted its successor before any of
    them attempts the rotation compare-and-set, which is exactly the "two tabs
    refresh together" race [N-34] exists to close. Without a barrier the threads
    would usually serialise and the test would prove nothing.
    """

    def __init__(self, inner: MemoryRefreshTokenStore, parties: int) -> None:
        self._inner = inner
        self._barrier = threading.Barrier(parties)

    def find_by_selector(self, selector: str) -> Optional[TokenRecord]:
        return self._inner.find_by_selector(selector)

    def insert(self, record: TokenRecord) -> None:
        self._inner.insert(record)
        self._barrier.wait(timeout=30)

    def mark_rotated(
        self, selector: str, from_status: TokenStatus, rotated_at: int, replaced_by_selector: str
    ) -> bool:
        return self._inner.mark_rotated(selector, from_status, rotated_at, replaced_by_selector)

    def revoke_if_active(self, selector: str) -> bool:
        return self._inner.revoke_if_active(selector)

    def revoke_family(self, family_id: str) -> int:
        return self._inner.revoke_family(family_id)

    def revoke_user(self, user_id: str) -> int:
        return self._inner.revoke_user(user_id)


@pytest.mark.parametrize("threads", [2, 16])
def test_concurrent_refreshes_never_fork_the_family(threads: int) -> None:
    rows = MemoryRefreshTokenStore()
    clock = Clock()
    issuer = NebulaEngine(peppers={"k1": PEPPER}, active_kid="k1", store=rows, clock=clock)
    token = issuer.issue("u1").token

    racing = NebulaEngine(
        peppers={"k1": PEPPER}, active_kid="k1", store=BarrierStore(rows, threads), clock=clock
    )
    with ThreadPoolExecutor(max_workers=threads) as pool:
        results = [f.result() for f in [pool.submit(racing.refresh, token) for _ in range(threads)]]

    winners = [r for r in results if r.ok]
    losers = [r for r in results if not r.ok]
    assert len(winners) == 1, "exactly one refresh may win the compare-and-set"
    assert all(r.ok is False and r.error == "CONFLICT" for r in losers)
    # [N-34]: the losers must not leave their orphan successors behind.
    assert len([r for r in rows.all() if r.status == "active"]) == 1
    # The single winner is the live lineage; `issuer` shares the same rows but
    # is not wired through the barrier, so this last call does not block.
    winner = winners[0]
    assert winner.ok
    assert issuer.refresh(winner.token).ok


def test_the_conflict_loser_may_simply_retry() -> None:
    """[N-35]: CONFLICT is transient and revokes nothing beyond the orphan."""
    engine, store, _ = make_engine()
    token = engine.issue("u1").token
    winner = engine.refresh(token)
    assert winner.ok
    replay = engine.refresh(token)  # the loser's retry meets the ordinary reuse path
    assert not replay.ok
    assert replay.error == "REUSE_DETECTED"


# ── Store failures fail closed ([N-20]) ─────────────────────────────────────


class StoreOnFire:
    """Every method delegates, except the one named — which raises, as a driver
    would when the database is unreachable."""

    def __init__(self, fail_on: str) -> None:
        self._inner = MemoryRefreshTokenStore()
        self.fail_on = fail_on

    def _guard(self, method: str) -> None:
        if method == self.fail_on:
            raise RuntimeError("database is on fire")

    def find_by_selector(self, selector: str) -> Optional[TokenRecord]:
        self._guard("find_by_selector")
        return self._inner.find_by_selector(selector)

    def insert(self, record: TokenRecord) -> None:
        self._guard("insert")
        self._inner.insert(record)

    def mark_rotated(
        self, selector: str, from_status: TokenStatus, rotated_at: int, replaced_by_selector: str
    ) -> bool:
        self._guard("mark_rotated")
        return self._inner.mark_rotated(selector, from_status, rotated_at, replaced_by_selector)

    def revoke_if_active(self, selector: str) -> bool:
        self._guard("revoke_if_active")
        return self._inner.revoke_if_active(selector)

    def revoke_family(self, family_id: str) -> int:
        self._guard("revoke_family")
        return self._inner.revoke_family(family_id)

    def revoke_user(self, user_id: str) -> int:
        self._guard("revoke_user")
        return self._inner.revoke_user(user_id)


def test_a_failing_insert_never_hands_back_a_token() -> None:
    engine = NebulaEngine(peppers={"k1": PEPPER}, active_kid="k1", store=StoreOnFire("insert"))
    with pytest.raises(RuntimeError, match="database is on fire"):
        engine.issue("u1")


def test_a_failing_revoke_family_is_not_reported_as_a_revocation() -> None:
    store = StoreOnFire("never")
    engine = NebulaEngine(peppers={"k1": PEPPER}, active_kid="k1", store=store)
    token = engine.issue("u1").token
    assert engine.refresh(token).ok

    store.fail_on = "revoke_family"
    # The replay must attempt a family revocation; the exception propagates
    # rather than being swallowed into a confident REUSE_DETECTED ([N-20]).
    with pytest.raises(RuntimeError, match="database is on fire"):
        engine.refresh(token)


def test_a_failing_lookup_is_not_a_protocol_outcome() -> None:
    engine = NebulaEngine(
        peppers={"k1": PEPPER}, active_kid="k1", store=StoreOnFire("find_by_selector")
    )
    token = NebulaEngine(
        peppers={"k1": PEPPER}, active_kid="k1", store=MemoryRefreshTokenStore()
    ).issue("u1").token
    with pytest.raises(RuntimeError, match="database is on fire"):
        engine.refresh(token)
    with pytest.raises(RuntimeError, match="database is on fire"):
        engine.revoke_token(token)


def test_a_failing_rotation_write_never_hands_back_a_token() -> None:
    store = StoreOnFire("never")
    engine = NebulaEngine(peppers={"k1": PEPPER}, active_kid="k1", store=store)
    token = engine.issue("u1").token

    store.fail_on = "mark_rotated"
    # A failed compare-and-set write is not a CONFLICT: CONFLICT means the store
    # answered "no", not that it never answered ([N-20] vs [N-34]).
    with pytest.raises(RuntimeError, match="database is on fire"):
        engine.refresh(token)


def test_a_failing_revoke_user_is_not_reported_as_a_count() -> None:
    engine = NebulaEngine(peppers={"k1": PEPPER}, active_kid="k1", store=StoreOnFire("revoke_user"))
    with pytest.raises(RuntimeError, match="database is on fire"):
        engine.revoke_all_for_user("u1")


# ── Configuration (§5, [N-23], [N-24]) ──────────────────────────────────────


def test_constructor_validation() -> None:
    store = MemoryRefreshTokenStore()

    def bad(**cfg: Any) -> None:
        with pytest.raises(NebulaConfigError):
            NebulaEngine(store=store, **cfg)

    bad(peppers={"k1": "short"}, active_kid="k1")
    bad(peppers={"k1": PEPPER}, active_kid="nope")
    bad(peppers={"k.1": PEPPER}, active_kid="k.1")
    bad(peppers={"k+1": PEPPER}, active_kid="k+1")
    bad(peppers={"": PEPPER}, active_kid="")
    bad(peppers={"k" * 65: PEPPER}, active_kid="k" * 65)
    bad(peppers={"k1": PEPPER}, active_kid="k1", absolute_ttl_seconds=0)
    bad(peppers={"k1": PEPPER}, active_kid="k1", idle_ttl_seconds=-5)
    bad(peppers={"k1": PEPPER}, active_kid="k1", reuse_grace_seconds=-1)
    # [N-11] a pepper with no UTF-8 encoding is not a usable HMAC key. Both are
    # well over the byte floor, so only the encoding rule can reject them.
    bad(peppers={"k1": "\ud800" + PEPPER}, active_kid="k1")
    bad(peppers={"k1": PEPPER + "\udc00"}, active_kid="k1")

    # A kid at exactly MAX_KID_LENGTH and a grace of 0 are both legal.
    NebulaEngine(peppers={"k" * 64: PEPPER}, active_kid="k" * 64, store=store, reuse_grace_seconds=0)


def test_nebula_config_error_is_a_value_error() -> None:
    # Callers that already handle argument errors keep working ([N-29]: this is
    # the native error channel, not a protocol outcome).
    store = MemoryRefreshTokenStore()
    with pytest.raises(ValueError):
        NebulaEngine(peppers={"k1": "short"}, active_kid="k1", store=store)


def test_a_pepper_without_a_utf8_encoding_fails_construction() -> None:
    """[N-11]/§5: the HMAC key is the pepper encoded as UTF-8, so a `str` that
    has no UTF-8 encoding is not a pepper. `os.environ` hands back exactly this
    for an undecodable byte (`surrogateescape`), so the failure must land at
    construction rather than as a UnicodeEncodeError on the first request."""
    store = MemoryRefreshTokenStore()
    with pytest.raises(NebulaConfigError):
        NebulaEngine(peppers={"k1": "\ud800" * 32}, active_kid="k1", store=store)


def test_min_pepper_length_counts_bytes_not_characters() -> None:
    """[N-1]: 16 CJK characters are 48 UTF-8 bytes and are a legal pepper."""
    store = MemoryRefreshTokenStore()
    wide = "日" * 16
    assert len(wide) == 16 and len(wide.encode("utf-8")) == 48
    NebulaEngine(peppers={"k1": wide}, active_kid="k1", store=store)
    with pytest.raises(NebulaConfigError):
        NebulaEngine(peppers={"k1": "a" * 31}, active_kid="k1", store=store)


def test_the_pepper_map_is_copied() -> None:
    """[N-24]: mutating the caller's mapping cannot weaken the engine."""
    store = MemoryRefreshTokenStore()
    peppers = {"k1": PEPPER}
    engine = NebulaEngine(peppers=peppers, active_kid="k1", store=store)

    peppers["k1"] = "x"  # would otherwise key every HMAC with a one-byte secret
    del peppers["k1"]

    issued = engine.issue("u1")
    parsed = parse_token(issued.token)
    assert parsed is not None
    assert store.all()[0].verifier_hash == hash_verifier(PEPPER, parsed.verifier)
    assert engine.refresh(issued.token).ok


def test_the_clock_is_injectable() -> None:
    """[N-3]: conformance tests must be able to drive time deterministically."""
    engine, _, clock = make_engine(absolute_ttl_seconds=100, idle_ttl_seconds=100)
    issued = engine.issue("u1")
    assert issued.expires_at == START + 100
    clock.advance(100)
    result = engine.refresh(issued.token)
    assert not result.ok
    assert result.error == "EXPIRED_ABSOLUTE"


# ── Device identifiers ([N-11], [N-12], [N-14]) ─────────────────────────────


def test_issue_rejects_an_invalid_unicode_device_id_at_the_call_site() -> None:
    """[N-12]: at issue the value comes from the application, not the attacker."""
    engine, _, _ = make_engine()
    with pytest.raises(NebulaConfigError):
        engine.issue("u1", "\ud800")


def test_refresh_treats_an_invalid_unicode_device_id_as_a_binding_failure() -> None:
    """[N-12]: reachable through `json.loads`, so it must never escape as an
    UnicodeEncodeError out of the refresh endpoint."""
    lone_surrogate = json.loads(r'"\ud800"')
    engine, store, _ = make_engine()
    issued = engine.issue("u1", "devA")

    result = engine.refresh(issued.token, lone_surrogate)
    assert not result.ok
    assert result.error == "DEVICE_MISMATCH"
    # The mandated family revocation happened; it did not die on the encode.
    assert [r.status for r in store.all()] == ["revoked"]

    # Unbound families ignore the value entirely rather than failing.
    engine2, _, _ = make_engine()
    assert engine2.refresh(engine2.issue("u2").token, lone_surrogate).ok

    # revoke_token is not on this path at all: it takes no device identifier
    # ([N-36]), so a device-bound family logs out with the token alone.
    engine3, _, _ = make_engine()
    issued3 = engine3.issue("u3", "devA")
    assert engine3.revoke_token(issued3.token).ok


def test_hash_device_id_applies_no_normalisation_trimming_or_case_folding() -> None:
    """[N-11]. The escapes are deliberate: an editor that normalises this file
    must not be able to collapse the NFC/NFD pair into one literal."""
    nfc, nfd = "Café", "Café"
    assert nfc != nfd
    assert hash_device_id(PEPPER, nfc) != hash_device_id(PEPPER, nfd)
    assert hash_device_id(PEPPER, "x") != hash_device_id(PEPPER, " x")
    assert hash_device_id(PEPPER, "x") != hash_device_id(PEPPER, "X")


def test_hash_device_id_refuses_invalid_unicode() -> None:
    with pytest.raises(NebulaConfigError):
        hash_device_id(PEPPER, "\ud800")


# ── Secret hygiene ([N-14], [N-46]) ─────────────────────────────────────────


def test_no_raw_secret_reaches_the_store() -> None:
    engine, store, _ = make_engine()
    issued = engine.issue("u1", "devA")
    refreshed = engine.refresh(issued.token, "devA")
    assert refreshed.ok

    dump = json.dumps([asdict(row) for row in store.all()])
    assert issued.token.split(".")[3] not in dump, "raw verifier"
    assert refreshed.token.split(".")[3] not in dump, "raw verifier"
    assert "devA" not in dump, "raw device identifier"
    assert PEPPER not in dump, "pepper"


def test_repr_never_prints_a_secret() -> None:
    """[N-14]: a traceback captured by an error tracker must not carry the
    verifier, which the dataclass-generated repr would happily print."""
    engine, store, _ = make_engine()
    issued = engine.issue("u1", "devA")
    parsed = parse_token(issued.token)
    assert parsed is not None

    assert parsed.verifier.hex() not in repr(parsed)
    assert str(parsed.verifier) not in repr(parsed)
    assert parsed.selector in repr(parsed)

    row = store.all()[0]
    assert row.verifier_hash not in repr(row)
    assert row.device_id_hash is not None and row.device_id_hash not in repr(row)
    assert row.selector in repr(row), "the selector is the one loggable correlation id"
    # The redaction must not cost the fields anyone actually debugs with.
    assert "u1" in repr(row) and row.family_id in repr(row)


def test_result_reprs_never_print_the_live_token() -> None:
    """[N-14]: `token` is the raw credential. The generated dataclass repr would
    print it into every traceback frame, `logger.info("%r", result)` and
    error-tracker payload that captures a refresh handler's locals."""
    engine, _, _ = make_engine()
    issued = engine.issue("u1")
    assert issued.token not in repr(issued)
    assert issued.token.split(".")[3] not in repr(issued)
    assert "<redacted>" in repr(issued)
    # The redaction must not cost the fields anyone actually debugs with.
    assert "u1" in repr(issued) and issued.family_id in repr(issued)
    # …and the caller still gets the value itself.
    assert issued.token.startswith("nbl.")

    refreshed = engine.refresh(issued.token)
    assert refreshed.ok
    assert refreshed.token not in repr(refreshed)
    assert refreshed.token.split(".")[3] not in repr(refreshed)
    assert "<redacted>" in repr(refreshed)
    assert refreshed.family_id in repr(refreshed)


def test_results_still_compare_by_value_despite_the_custom_repr() -> None:
    engine, _, _ = make_engine()
    issued = engine.issue("u1")
    assert issued == replace(issued)
    assert issued != replace(issued, generation=1)


def test_minted_tokens_are_unique_and_well_formed() -> None:
    """[N-43]/[N-33]: every mint draws fresh CSPRNG bytes, and the wire form is
    exactly what the parser accepts."""
    engine, store, _ = make_engine()
    tokens = {engine.issue("u1").token for _ in range(200)}
    assert len(tokens) == 200, "a repeated selector or verifier means a degenerate RNG"

    selectors = set()
    verifiers = set()
    for token in tokens:
        parsed = parse_token(token)
        assert parsed is not None, token
        assert parsed.kid == "k1"
        assert len(parsed.selector) == 22 and len(parsed.verifier) == 32
        selectors.add(parsed.selector)
        verifiers.add(parsed.verifier)
    assert len(selectors) == 200 and len(verifiers) == 200
    assert len(store.all()) == 200


def test_records_still_compare_by_value_despite_the_custom_repr() -> None:
    row = TokenRecord(
        selector="A" * 22, verifier_hash=HASH, kid="k1", family_id="f", generation=0,
        user_id="u1", device_id_hash=None, created_at=0, family_expires_at=1, idle_expires_at=1,
    )
    assert row == replace(row)
    assert row != replace(row, generation=1)


# ── Result shape ([N-2], [N-39]) ────────────────────────────────────────────


def test_timestamps_are_integer_unix_seconds() -> None:
    """[N-2]: seconds as `int`, never `datetime`, never milliseconds."""
    engine, _, _ = make_engine()
    issued = engine.issue("u1")
    assert isinstance(issued.expires_at, int) and isinstance(issued.idle_expires_at, int)
    assert issued.expires_at == START + 60 * 60 * 24 * 30

    refreshed = engine.refresh(issued.token)
    assert refreshed.ok
    assert isinstance(refreshed.expires_at, int) and isinstance(refreshed.idle_expires_at, int)
    assert refreshed.expires_at == issued.expires_at


def test_failures_carry_user_id_and_family_id_once_a_record_is_resolved() -> None:
    """[N-39]."""
    engine, _, _ = make_engine()
    issued = engine.issue("u1")
    assert engine.refresh(issued.token).ok

    replay = engine.refresh(issued.token)
    assert not replay.ok
    assert replay.user_id == "u1" and replay.family_id == issued.family_id

    # Before a record is resolved there is nothing to attribute.
    for token in ["garbage", f"nbl.k1.{'A' * 22}.{'A' * 43}"]:
        unresolved = engine.refresh(token)
        assert not unresolved.ok
        assert unresolved.user_id is None and unresolved.family_id is None


# ── In-memory store hygiene ([N-15], [N-21]) ────────────────────────────────


def test_the_memory_store_refuses_a_duplicate_selector() -> None:
    store = MemoryRefreshTokenStore()
    row = TokenRecord(
        selector="A" * 22, verifier_hash=HASH, kid="k1", family_id="f", generation=0,
        user_id="u1", device_id_hash=None, created_at=0, family_expires_at=1, idle_expires_at=1,
    )
    store.insert(row)
    with pytest.raises(ValueError, match="duplicate selector"):
        store.insert(row)


def test_the_memory_store_hands_out_copies() -> None:
    store = MemoryRefreshTokenStore()
    engine = NebulaEngine(peppers={"k1": PEPPER}, active_kid="k1", store=store)
    engine.issue("u1")

    borrowed = store.find_by_selector(store.all()[0].selector)
    assert borrowed is not None
    borrowed.status = "revoked"
    assert store.all()[0].status == "active", "a caller must not mutate stored state by reference"


def test_delete_expired_only_removes_records_past_the_family_deadline() -> None:
    """[N-15]: deleting rotated rows early silently disables reuse detection."""
    engine, store, _ = make_engine(absolute_ttl_seconds=100, idle_ttl_seconds=100)
    token = engine.issue("u1").token
    assert engine.refresh(token).ok

    assert store.delete_expired(START + 99) == 0, "nothing may be dropped before the deadline"
    assert len(store.all()) == 2
    assert store.delete_expired(START + 100) == 2


def test_the_memory_store_satisfies_the_protocol() -> None:
    # A structural check that the six-method contract is what the engine sees.
    store: RefreshTokenStore = MemoryRefreshTokenStore()
    for name in (
        "find_by_selector", "insert", "mark_rotated",
        "revoke_if_active", "revoke_family", "revoke_user",
    ):
        method: Optional[Callable[..., Any]] = getattr(store, name, None)
        assert callable(method), name
