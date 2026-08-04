"""Shared conformance vectors — spec/test-vectors.json (SPECIFICATION.md [N-47])."""

from __future__ import annotations

import base64
import json
from pathlib import Path
from typing import Any

import pytest

import nebula_token as nt


def _repo_root() -> Path:
    """Walk up from this file until the published spec artifacts appear.

    Not a hardcoded path and not a copy inside the package: the vectors are the
    single normative artifact ([N-49]), and a port that vendors them can pass
    its own stale snapshot.
    """
    for parent in Path(__file__).resolve().parents:
        if (parent / "spec" / "test-vectors.json").is_file():
            return parent
    raise RuntimeError("spec/test-vectors.json not found in any parent of this test file")


SPEC_DIR = _repo_root() / "spec"
VECTORS: dict[str, Any] = json.loads((SPEC_DIR / "test-vectors.json").read_text(encoding="utf-8"))


def _b64url_decode(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def test_spec_version_matches_the_published_vectors() -> None:
    assert nt.SPEC_VERSION == VECTORS["spec_version"]


@pytest.mark.parametrize("section", ["verifier_hashing", "device_hashing", "parsing"])
def test_every_section_is_present_and_non_empty(section: str) -> None:
    # [N-48]: silently iterating zero cases is a conformance failure, not a pass.
    assert VECTORS.get(section), f"section {section} is absent or empty"
    assert VECTORS["counts"][section] == len(VECTORS[section])


def test_constants_match_the_specification() -> None:
    published: dict[str, Any] = VECTORS["constants"]
    compared: dict[str, Any] = {
        "prefix": nt.PREFIX,
        "selector_bytes": nt.SELECTOR_BYTES,
        "verifier_bytes": nt.VERIFIER_BYTES,
        "selector_chars": nt.SELECTOR_CHARS,
        "verifier_chars": nt.VERIFIER_CHARS,
        "max_kid_length": nt.MAX_KID_LENGTH,
        "max_token_length": nt.MAX_TOKEN_LENGTH,
        "min_pepper_length": nt.MIN_PEPPER_LENGTH,
        "default_absolute_ttl_seconds": nt.DEFAULT_ABSOLUTE_TTL,
        "default_idle_ttl_seconds": nt.DEFAULT_IDLE_TTL,
        "default_reuse_grace_seconds": nt.DEFAULT_REUSE_GRACE,
    }
    # [N-48]: every published constant is compared, not only the ones we
    # remembered to name here.
    assert compared.keys() == published.keys(), "a published constant was never asserted"
    for name, value in compared.items():
        assert value == published[name], name


def test_verifier_hashing_vectors() -> None:
    executed = 0
    for v in VECTORS["verifier_hashing"]:
        actual = nt.hash_verifier(v["pepper"], _b64url_decode(v["verifier_b64url"]))
        assert actual == v["expected_hmac_sha256_hex"], f"{v['id']}: {v['note']}"
        executed += 1
    assert executed == VECTORS["counts"]["verifier_hashing"], "executed count must equal published count ([N-48])"


def test_device_hashing_vectors() -> None:
    executed = 0
    for v in VECTORS["device_hashing"]:
        actual = nt.hash_device_id(v["pepper"], v["device_id"])
        assert actual == v["expected_hmac_sha256_hex"], f"{v['id']}: {v['note']}"
        if "device_id_bytes" in v:
            # [N-11] keys the HMAC on the UTF-8 encoding of the identifier, not
            # on however the runtime happens to hold it. A Python str is a
            # sequence of code points, so the byte form is decoded back to a str
            # here; a runner whose strings ARE bytes feeds them straight in.
            # Either way the case's one expected hash must come out, which is
            # the portable statement of the rule — and the assertion that a
            # runtime cannot decide a device identifier on anything but its
            # bytes.
            from_bytes = bytes.fromhex(v["device_id_bytes"]).decode("utf-8")
            assert from_bytes == v["device_id"], f"{v['id']}: device_id_bytes must be the UTF-8 encoding of device_id"
            assert nt.hash_device_id(v["pepper"], from_bytes) == v["expected_hmac_sha256_hex"], f"{v['id']} from bytes"
        executed += 1
    assert executed == VECTORS["counts"]["device_hashing"], "executed count must equal published count ([N-48])"


def test_parsing_vectors() -> None:
    executed = 0
    for v in VECTORS["parsing"]:
        parsed = nt.parse_token(v["token"])
        if v["valid"]:
            assert parsed is not None, f"{v['id']} should parse: {v['note']}"
            assert parsed.kid == v["kid"], v["id"]
            assert parsed.selector == v["selector"], v["id"]
            assert len(parsed.verifier) == nt.VERIFIER_BYTES, v["id"]
        else:
            assert parsed is None, f"{v['id']} should be MALFORMED: {v['note']}"
        executed += 1
    assert executed == VECTORS["counts"]["parsing"], "executed count must equal published count ([N-48])"


def test_parsing_is_total_nothing_raises() -> None:
    """[N-8]: every rejection is a value, for every input the runtime admits."""
    hostile: list[object] = [
        None,
        42,
        3.5,
        object(),
        b"nbl.k1.AAECAwQFBgcICQoLDA0ODw.AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8",
        bytearray(b"nbl"),
        [],
        {},
        "",
        " ",
        "." * 1000,
        "nbl." + "k" * 10_000,
        f"nbl.k1.{' ' * 22}.{'A' * 43}",
        # Not valid Unicode: a lone surrogate, and bytes that are not UTF-8 at
        # all decoded with `surrogateescape` — both reachable from real input.
        "nbl.k1.\ud800" + "A" * 21 + "." + "A" * 43,
        b"\xff\xfe".decode("utf-8", "surrogateescape"),
        "\ud800",
    ]
    for value in hostile:
        assert nt.parse_token(value) is None, repr(value)
