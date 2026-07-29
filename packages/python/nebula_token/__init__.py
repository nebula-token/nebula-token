"""
NEBULA — Opaque Rotating Refresh Tokens
Python reference implementation of SPECIFICATION.md (spec version 1).

Standard library only. Python >= 3.11.

Requirement identifiers in comments ([N-*]) refer to SPECIFICATION.md.

The store contract is **synchronous** ([N-16] defers synchrony to the idiom of
the ecosystem, and blocking database drivers are the Python norm). Under asyncio
call the engine through ``asyncio.to_thread`` / ``run_in_executor``; do not hand
the engine a store whose methods return coroutines — nothing awaits them, so the
engine would hand out tokens for state that was never written.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import re
import secrets
import threading
import time
from dataclasses import dataclass, replace
from typing import Callable, Literal, Mapping, Optional, Protocol, Union

__all__ = [
    "SPEC_VERSION", "PREFIX", "SELECTOR_BYTES", "VERIFIER_BYTES",
    "SELECTOR_CHARS", "VERIFIER_CHARS", "MAX_KID_LENGTH",
    "MAX_TOKEN_LENGTH", "MIN_PEPPER_LENGTH",
    "DEFAULT_ABSOLUTE_TTL", "DEFAULT_IDLE_TTL", "DEFAULT_REUSE_GRACE",
    "TokenStatus", "NebulaErrorCode", "ErrorCode", "ERROR_CODES",
    "TokenRecord", "RefreshTokenStore", "MemoryRefreshTokenStore",
    "NebulaEngine", "NebulaConfigError",
    "IssueResult", "RefreshOk", "RefreshError", "RefreshResult",
    "RevokeOk", "RevokeError", "RevokeResult", "ParsedToken",
    "parse_token", "hash_verifier", "hash_device_id", "constant_time_equal_hex",
]

# ─── Spec constants (§1, [N-4]) ──────────────────────────────────────────────

#: Version of SPECIFICATION.md this package implements ([N-52]).
SPEC_VERSION = 1
PREFIX = "nbl"
SELECTOR_BYTES = 16
VERIFIER_BYTES = 32
SELECTOR_CHARS = 22
VERIFIER_CHARS = 43
MAX_KID_LENGTH = 64
MAX_TOKEN_LENGTH = 512
MIN_PEPPER_LENGTH = 32
DEFAULT_ABSOLUTE_TTL = 60 * 60 * 24 * 30
DEFAULT_IDLE_TTL = 60 * 60 * 24 * 7
DEFAULT_REUSE_GRACE = 0

#: HMAC-SHA-256 output, in lowercase hex characters.
_HASH_HEX_CHARS = 64

# `\A…\Z`, never `^…$`: Python's `$` also matches immediately before a trailing
# newline, so `^[A-Za-z0-9_-]+$` accepts "…{verifier}\n" as well-formed ([N-6.4]).
_B64URL_RE = re.compile(r"\A[A-Za-z0-9_-]+\Z")
_LOWER_HEX_64_RE = re.compile(r"\A[0-9a-f]{64}\Z")

TokenStatus = Literal["active", "rotated", "revoked"]

#: Protocol outcomes ([N-38]).
#:
#: Treat this alias as **open** ([N-40]): Python has no `#[non_exhaustive]`, so
#: the policy is documented instead — a future minor version MAY add a code, and
#: consumers MUST treat an unrecognised value as a refusal rather than assuming
#: their `if/elif` chain is exhaustive. Never `assert False` on the `else` branch.
NebulaErrorCode = Literal[
    "MALFORMED",
    "UNKNOWN_KID",
    "NOT_FOUND",
    "VERIFIER_MISMATCH",
    "REUSE_DETECTED",
    "REVOKED",
    "EXPIRED_ABSOLUTE",
    "EXPIRED_IDLE",
    "DEVICE_MISMATCH",
    "CONFLICT",
]

#: Backwards-compatible alias for :data:`NebulaErrorCode`.
ErrorCode = NebulaErrorCode

#: The codes defined by spec version 1, for logging and metric label whitelists.
#: A code absent from this tuple is still a refusal ([N-40]).
ERROR_CODES: tuple[str, ...] = (
    "MALFORMED", "UNKNOWN_KID", "NOT_FOUND", "VERIFIER_MISMATCH",
    "REUSE_DETECTED", "REVOKED", "EXPIRED_ABSOLUTE", "EXPIRED_IDLE",
    "DEVICE_MISMATCH", "CONFLICT",
)


class NebulaConfigError(ValueError):
    """Caller mistakes: engine construction and `issue` arguments ([N-12], §5).

    Distinct from a protocol outcome ([N-29]): protocol outcomes are returned as
    values, this is raised. Subclasses `ValueError` so ordinary argument-error
    handling catches it.
    """

    def __init__(self, message: str) -> None:
        super().__init__(f"[NEBULA] {message}")


# ─── Spec primitives (§2, §6.4) — pure, exported for conformance testing ─────


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _b64url_decode(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def _utf8_len(s: str) -> int:
    """Length in bytes of the UTF-8 encoding ([N-1]).

    ``surrogatepass`` is what keeps this total ([N-8]): a `str` holding an
    unpaired surrogate has no UTF-8 encoding and would otherwise raise
    `UnicodeEncodeError` here, before the parser ever got to reject the input.
    """
    return len(s.encode("utf-8", "surrogatepass"))


def _is_well_formed_unicode(s: str) -> bool:
    """True iff the string has a UTF-8 encoding, i.e. holds no lone surrogate.

    `str` in CPython is a sequence of code points, and `json.loads('"\\ud800"')`
    hands back an unpaired one, so this is reachable from ordinary request
    parsing ([N-12]).
    """
    try:
        s.encode("utf-8")
    except UnicodeEncodeError:
        return False
    return True


@dataclass(frozen=True, repr=False)
class ParsedToken:
    kid: str
    selector: str
    #: Raw 32 secret bytes. Never persist or log this ([N-14]).
    verifier: bytes

    def __repr__(self) -> str:
        # [N-14]: the dataclass-generated repr would print the raw verifier into
        # every traceback, log line and error-tracker payload that touches a
        # ParsedToken. The secret is never part of a debug representation.
        return f"ParsedToken(kid={self.kid!r}, selector={self.selector!r}, verifier=<redacted>)"


def parse_token(token: object) -> Optional[ParsedToken]:
    """Parse a wire token (§2, [N-5]..[N-9]).

    Total: returns ``None`` for every malformed input and never raises — the
    argument is deliberately typed `object`, because a caller reading a header
    or a JSON body may hand over `None`, an `int`, `bytes`, or a `str` holding
    an unpaired surrogate ([N-8]).
    """
    if not isinstance(token, str) or not token:
        return None

    # [N-6.1] length in BYTES, checked before any other parsing work. `len(token)`
    # counts code points and would disagree with the byte-counting ports.
    if _utf8_len(token) > MAX_TOKEN_LENGTH:
        return None

    parts = token.split(".")
    if len(parts) != 4:  # [N-6.2]
        return None
    prefix, kid, selector, verifier_b64 = parts
    if prefix != PREFIX:  # [N-6.3] case-sensitive
        return None
    if not kid or not selector or not verifier_b64:  # [N-6.2]
        return None

    # [N-6.5]/[N-6.6] exact lengths. The alphabet check below is ASCII-only, so
    # code-point length and byte length coincide for anything that survives it.
    if len(kid) > MAX_KID_LENGTH:
        return None
    if len(selector) != SELECTOR_CHARS or len(verifier_b64) != VERIFIER_CHARS:
        return None

    # [N-6.4] alphabet: rejects padding, whitespace, '+', '/' and any non-ASCII.
    if not _B64URL_RE.match(kid):
        return None
    if not _B64URL_RE.match(selector):
        return None
    if not _B64URL_RE.match(verifier_b64):
        return None

    try:
        verifier = _b64url_decode(verifier_b64)
    # `binascii.Error` IS a `ValueError` (see its MRO), so naming both caught
    # nothing extra and only suggested they were different failure modes.
    except ValueError:  # pragma: no cover - alphabet pre-checked
        return None
    if len(verifier) != VERIFIER_BYTES:  # [N-6.7]
        return None

    # [N-7] canonical encoding: a 32-byte value has four 43-character spellings,
    # because the last character carries four significant bits and two unused
    # ones. Only the minimal encoding is a token.
    if _b64url_encode(verifier) != verifier_b64:
        return None

    return ParsedToken(kid=kid, selector=selector, verifier=verifier)


def hash_verifier(pepper: str, verifier: bytes) -> str:
    """verifierHash = lowercase hex HMAC-SHA-256(pepper, verifier) ([N-11], [N-13])."""
    return hmac.new(pepper.encode("utf-8"), verifier, hashlib.sha256).hexdigest()


def hash_device_id(pepper: str, device_id: str) -> str:
    """deviceIdHash = lowercase hex HMAC-SHA-256(pepper, "device:" + deviceId) ([N-11]).

    No normalisation, trimming or case folding is applied to either operand.

    Raises `NebulaConfigError` for a device identifier that is not valid Unicode:
    it has no UTF-8 encoding, so [N-11] cannot define a hash for it, and hashing
    a replacement character instead would make the same identifier hash
    differently across languages. Callers on the attacker-reachable path
    (`refresh`) MUST pre-check rather than let this raise ([N-12]).
    """
    if not _is_well_formed_unicode(device_id):
        raise NebulaConfigError("device_id is not valid Unicode (unpaired surrogate)")
    return hmac.new(
        pepper.encode("utf-8"),
        ("device:" + device_id).encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()


def constant_time_equal_hex(a_hex: object, b_hex: object) -> bool:
    """Constant-time comparison of two hex digests ([N-31]). Never raises.

    Operands that are not exactly 64 lowercase hex characters compare unequal.
    The guard is deliberate: `bytes.fromhex` accepts ASCII whitespace and
    upper-case digits, so a stored hash that a CHAR column space-padded, or that
    an ETL job upper-cased, would keep verifying instead of failing closed.
    Truncated operands are rejected by the fixed length rather than compared as
    equal-length prefixes.
    """
    if not isinstance(a_hex, str) or not isinstance(b_hex, str):
        return False
    if len(a_hex) != _HASH_HEX_CHARS or len(b_hex) != _HASH_HEX_CHARS:
        return False
    if not _LOWER_HEX_64_RE.match(a_hex) or not _LOWER_HEX_64_RE.match(b_hex):
        return False
    return hmac.compare_digest(bytes.fromhex(a_hex), bytes.fromhex(b_hex))


# ─── Records and store contract (§3, §4) ─────────────────────────────────────


@dataclass(repr=False)
class TokenRecord:
    """Server-side record — one row per issued token ([N-10])."""

    selector: str
    verifier_hash: str
    kid: str
    family_id: str
    generation: int
    user_id: str
    device_id_hash: Optional[str]
    created_at: int
    family_expires_at: int
    idle_expires_at: int
    status: TokenStatus = "active"
    rotated_at: Optional[int] = None
    replaced_by_selector: Optional[str] = None

    def __repr__(self) -> str:
        # [N-14]/[N-46]: secret-derived material stays out of debug output. The
        # selector is the one token-derived value that may be logged.
        device = "<redacted>" if self.device_id_hash is not None else None
        return (
            f"TokenRecord(selector={self.selector!r}, verifier_hash=<redacted>, "
            f"kid={self.kid!r}, family_id={self.family_id!r}, "
            f"generation={self.generation!r}, user_id={self.user_id!r}, "
            f"device_id_hash={device}, created_at={self.created_at!r}, "
            f"family_expires_at={self.family_expires_at!r}, "
            f"idle_expires_at={self.idle_expires_at!r}, status={self.status!r}, "
            f"rotated_at={self.rotated_at!r}, "
            f"replaced_by_selector={self.replaced_by_selector!r})"
        )


class RefreshTokenStore(Protocol):
    """Storage contract ([N-16]) — six methods, implement over Postgres / Redis / etc.

    Synchronous by design: blocking drivers are the Python norm, and an engine
    that never awaits cannot be handed a coroutine by mistake. Under asyncio,
    call the engine with ``await asyncio.to_thread(engine.refresh, token)``.

    Two failure channels ([N-20]): protocol outcomes are the return values below;
    infrastructure failures (store unreachable, timeout, constraint violation)
    MUST raise. The exception propagates out of the engine — it is never
    converted into a `RefreshError`, so the caller always fails closed.
    """

    def find_by_selector(self, selector: str) -> Optional[TokenRecord]: ...

    def insert(self, record: TokenRecord) -> None: ...

    def mark_rotated(
        self,
        selector: str,
        from_status: TokenStatus,
        rotated_at: int,
        replaced_by_selector: str,
    ) -> bool:
        """Compare-and-set ([N-17]).

        Apply the rotation write **only if** the stored record's status is still
        `from_status`, and report whether it was applied.

        SQL: ``UPDATE … SET status='rotated', rotated_at=?, replaced_by_selector=?
        WHERE selector=? AND status=?`` → ``cursor.rowcount == 1``.

        Returning `True` unconditionally is non-conforming: it re-opens the race
        in which two concurrent refreshes both mint a successor and fork the
        family into two independently valid lineages.
        """
        ...

    def revoke_if_active(self, selector: str) -> bool:
        """Compare-and-set ([N-18]): revoke only if still `active`; report whether it did."""
        ...

    def revoke_family(self, family_id: str) -> int:
        """Revoke every record of the family. Returns how many changed ([N-19])."""
        ...

    def revoke_user(self, user_id: str) -> int:
        """Revoke every record of the user. Returns how many changed ([N-19])."""
        ...


class MemoryRefreshTokenStore:
    """Reference store ([N-21]).

    A mutex guards every method, so the two compare-and-set operations are
    atomic under the ordinary Python request-concurrency model — threads, and
    the thread pools that WSGI/ASGI servers and ``asyncio.to_thread`` use. The
    GIL is not a substitute: a read-modify-write across several bytecodes can be
    interrupted, and free-threaded builds remove the interpreter lock entirely.

    NOT FOR PRODUCTION: state is per-process and lost on restart, so reuse
    detection does not survive a deploy and does not work behind more than one
    instance. Implement `RefreshTokenStore` over your database instead — see
    ``examples/sqlite_store.py`` and docs/STORE.md.
    """

    def __init__(self) -> None:
        self._rows: dict[str, TokenRecord] = {}
        self._lock = threading.Lock()

    def find_by_selector(self, selector: str) -> Optional[TokenRecord]:
        with self._lock:
            row = self._rows.get(selector)
            # A copy: callers must not be able to mutate stored state by holding
            # on to the returned record, the way no SQL driver would let them.
            return replace(row) if row is not None else None

    def insert(self, record: TokenRecord) -> None:
        with self._lock:
            if record.selector in self._rows:
                # A real store has a PRIMARY KEY here; silently overwriting would
                # destroy the predecessor's rotation state ([N-15]).
                raise ValueError(f"[NEBULA] duplicate selector {record.selector}")
            self._rows[record.selector] = replace(record)

    def mark_rotated(
        self,
        selector: str,
        from_status: TokenStatus,
        rotated_at: int,
        replaced_by_selector: str,
    ) -> bool:
        with self._lock:
            row = self._rows.get(selector)
            if row is None or row.status != from_status:
                return False
            row.status = "rotated"
            row.rotated_at = rotated_at
            row.replaced_by_selector = replaced_by_selector
            return True

    def revoke_if_active(self, selector: str) -> bool:
        with self._lock:
            row = self._rows.get(selector)
            if row is None or row.status != "active":
                return False
            row.status = "revoked"
            return True

    def revoke_family(self, family_id: str) -> int:
        with self._lock:
            changed = 0
            for row in self._rows.values():
                if row.family_id == family_id and row.status != "revoked":
                    row.status = "revoked"
                    changed += 1
            return changed

    def revoke_user(self, user_id: str) -> int:
        with self._lock:
            changed = 0
            for row in self._rows.values():
                if row.user_id == user_id and row.status != "revoked":
                    row.status = "revoked"
                    changed += 1
            return changed

    # ── Test helpers — not part of the store contract ──────────────────────

    def all(self) -> list[TokenRecord]:
        """Every record currently stored."""
        with self._lock:
            return [replace(row) for row in self._rows.values()]

    def delete_expired(self, now: int) -> int:
        """Drop records whose family deadline has passed ([N-15]).

        Nothing may be dropped earlier: reuse detection *is* the act of finding a
        rotated record.
        """
        with self._lock:
            doomed = [s for s, row in self._rows.items() if now >= row.family_expires_at]
            for selector in doomed:
                del self._rows[selector]
            return len(doomed)


# ─── Results ─────────────────────────────────────────────────────────────────


@dataclass(frozen=True, repr=False)
class IssueResult:
    token: str
    user_id: str
    family_id: str
    generation: int
    #: Unix seconds ([N-2]) — the family's fixed absolute deadline.
    expires_at: int
    #: Unix seconds ([N-2]) — this token's sliding idle deadline.
    idle_expires_at: int

    def __repr__(self) -> str:
        # [N-14]/[N-46]: `token` carries the raw verifier, so the generated repr
        # would print a live credential into every traceback, `logger.info("%r")`
        # and error-tracker frame that captures this result. The value is still
        # in `.token` for the caller; only the debug representation is redacted.
        return (
            f"IssueResult(token=<redacted>, user_id={self.user_id!r}, "
            f"family_id={self.family_id!r}, generation={self.generation!r}, "
            f"expires_at={self.expires_at!r}, idle_expires_at={self.idle_expires_at!r})"
        )


@dataclass(frozen=True, repr=False)
class RefreshOk:
    token: str
    user_id: str
    family_id: str
    generation: int
    expires_at: int
    idle_expires_at: int
    ok: Literal[True] = True

    def __repr__(self) -> str:
        # [N-14]/[N-46], as for IssueResult: the successor token is a live secret.
        return (
            f"RefreshOk(token=<redacted>, user_id={self.user_id!r}, "
            f"family_id={self.family_id!r}, generation={self.generation!r}, "
            f"expires_at={self.expires_at!r}, "
            f"idle_expires_at={self.idle_expires_at!r}, ok=True)"
        )


@dataclass(frozen=True)
class RefreshError:
    """`user_id` and `family_id` are populated whenever the engine resolved a
    record — every code except MALFORMED, UNKNOWN_KID and NOT_FOUND — so that a
    REUSE_DETECTED or DEVICE_MISMATCH event can be attributed to a session
    without a second lookup of a token you were told never to log ([N-39])."""

    error: NebulaErrorCode
    user_id: Optional[str] = None
    family_id: Optional[str] = None
    ok: Literal[False] = False


RefreshResult = Union[RefreshOk, RefreshError]


@dataclass(frozen=True)
class RevokeOk:
    user_id: str
    family_id: str
    #: Number of records revoked ([N-36]).
    revoked: int
    ok: Literal[True] = True


@dataclass(frozen=True)
class RevokeError:
    """`user_id` and `family_id` are populated whenever the engine resolved a
    record, exactly as in `RefreshError` — [N-39] governs every failure result,
    not `refresh` alone. `revoke_token` resolves its record before proving the
    verifier, so a VERIFIER_MISMATCH there is attributable and carries both;
    MALFORMED, UNKNOWN_KID and NOT_FOUND never do."""

    error: NebulaErrorCode
    user_id: Optional[str] = None
    family_id: Optional[str] = None
    ok: Literal[False] = False


RevokeResult = Union[RevokeOk, RevokeError]


# ─── Engine ──────────────────────────────────────────────────────────────────


class NebulaEngine:
    """The protocol engine (§6). Stateless apart from its configuration."""

    def __init__(
        self,
        peppers: Mapping[str, str],
        active_kid: str,
        store: RefreshTokenStore,
        *,
        absolute_ttl_seconds: int = DEFAULT_ABSOLUTE_TTL,
        idle_ttl_seconds: int = DEFAULT_IDLE_TTL,
        reuse_grace_seconds: int = DEFAULT_REUSE_GRACE,
        clock: Optional[Callable[[], int]] = None,
    ) -> None:
        # [N-24] copy: mutating the caller's mapping afterwards must not change
        # engine behavior — otherwise a later `peppers["k1"] = "x"` silently
        # re-keys every HMAC with a one-byte secret.
        copied: dict[str, str] = {}
        for kid, secret in peppers.items():
            if not isinstance(kid, str) or not _B64URL_RE.match(kid) or _utf8_len(kid) > MAX_KID_LENGTH:
                raise NebulaConfigError(
                    f"kid {kid!r} must be 1-{MAX_KID_LENGTH} bytes from [A-Za-z0-9_-]"
                )
            # [N-11]: the HMAC key is the pepper encoded as UTF-8, so a `str`
            # that has no UTF-8 encoding (a lone surrogate — exactly what
            # `os.environ` yields for an undecodable byte under
            # `surrogateescape`) is not a usable pepper. §5 requires the
            # violation to fail construction, rather than letting every later
            # `issue`/`refresh` die on a UnicodeEncodeError. The message never
            # carries the secret itself ([N-14]).
            if not isinstance(secret, str) or not _is_well_formed_unicode(secret):
                raise NebulaConfigError(
                    f"pepper {kid!r} must be a str with a UTF-8 encoding"
                )
            # [N-1] bytes, not characters: 16 CJK characters are 48 UTF-8 bytes
            # and are a legal pepper; 31 ASCII characters are not.
            if _utf8_len(secret) < MIN_PEPPER_LENGTH:
                raise NebulaConfigError(
                    f"pepper {kid!r} must be at least {MIN_PEPPER_LENGTH} bytes"
                )
            copied[kid] = secret
        if active_kid not in copied:
            raise NebulaConfigError(f"active_kid {active_kid!r} not present in peppers")

        _require_positive_int("absolute_ttl_seconds", absolute_ttl_seconds)
        _require_positive_int("idle_ttl_seconds", idle_ttl_seconds)
        _require_non_negative_int("reuse_grace_seconds", reuse_grace_seconds)

        self._peppers = copied
        self._active_kid = active_kid
        self._store = store
        self._absolute_ttl = absolute_ttl_seconds
        self._idle_ttl = idle_ttl_seconds
        self._reuse_grace = reuse_grace_seconds
        # [N-3] injectable clock, unix seconds.
        self._clock: Callable[[], int] = clock if clock is not None else (lambda: int(time.time()))

    # ── Public API ─────────────────────────────────────────────────────────

    def issue(self, user_id: str, device_id: Optional[str] = None) -> IssueResult:
        """Issue the first token of a new family ([N-25]). Call at login.

        `device_id=None` is an unbound family; `device_id=""` is a real binding
        to the empty string. The two are distinguishable by construction ([N-25]).
        """
        if device_id is not None and not _is_well_formed_unicode(device_id):
            # [N-12]: at issue the value comes from the application, so surface
            # the defect at the call site rather than minting a binding that
            # nothing can ever satisfy.
            raise NebulaConfigError("device_id is not valid Unicode (unpaired surrogate)")

        now = self._clock()
        family_id = secrets.token_hex(16)
        family_expires_at = now + self._absolute_ttl
        device_hash = (
            hash_device_id(self._active_pepper(), device_id) if device_id is not None else None
        )
        token, record = self._mint(
            user_id=user_id,
            family_id=family_id,
            generation=0,
            device_id_hash=device_hash,
            family_expires_at=family_expires_at,
            now=now,
        )
        # [N-20]: a store failure propagates; no token is returned for state that
        # was never written.
        self._store.insert(record)
        return IssueResult(
            token=token,
            user_id=user_id,
            family_id=family_id,
            generation=0,
            expires_at=family_expires_at,
            idle_expires_at=record.idle_expires_at,
        )

    def refresh(self, token: str, device_id: Optional[str] = None) -> RefreshResult:
        """Exchange a refresh token for its successor ([N-26]).

        The check order is normative and observable ([N-28]).
        """
        parsed = parse_token(token)  # 1
        if parsed is None:
            return RefreshError("MALFORMED")

        if parsed.kid not in self._peppers:  # 2
            return RefreshError("UNKNOWN_KID")

        record = self._store.find_by_selector(parsed.selector)  # 3
        if record is None:
            return RefreshError("NOT_FOUND")

        # 4. Verifier proof — pepper of the RECORD's kid, constant time.
        record_pepper = self._peppers.get(record.kid)
        if record_pepper is None:  # [N-27] the record's pepper was retired
            return RefreshError("UNKNOWN_KID")
        presented = hash_verifier(record_pepper, parsed.verifier)
        if not constant_time_equal_hex(presented, record.verifier_hash):
            # [N-28] no family revocation here: knowledge of a selector alone
            # must never be sufficient to destroy a session.
            return self._failure("VERIFIER_MISMATCH", record)

        now = self._clock()

        if record.status == "rotated":  # 5
            return self._handle_reuse(record, record_pepper, device_id, now)
        if record.status == "revoked":  # 6
            return self._failure("REVOKED", record)

        if now >= record.family_expires_at:  # 7
            self._store.revoke_family(record.family_id)
            return self._failure("EXPIRED_ABSOLUTE", record)
        if now >= record.idle_expires_at:  # 8
            self._store.revoke_family(record.family_id)
            return self._failure("EXPIRED_IDLE", record)

        # 9. Sender binding — pepper of the RECORD's kid ([N-32]).
        if record.device_id_hash is not None and not self._device_matches(
            record, record_pepper, device_id
        ):
            self._store.revoke_family(record.family_id)
            return self._failure("DEVICE_MISMATCH", record)

        return self._rotate(record, device_id, now, "active", now)  # 10

    def revoke_token(self, token: str) -> RevokeResult:
        """Revoke the family a token belongs to ([N-36]).

        Authenticated: the verifier is proved exactly as in `refresh`, because
        the selector is a public lookup key and must not by itself be a
        capability to terminate an arbitrary session. Succeeds whatever the
        record's status, so a client can still log out with a token that was
        already rotated or revoked.

        Takes no device identifier and performs no sender-binding check
        ([N-36]): [N-36] specifies steps 1-4 of [N-26] and no sender-binding
        step, because logout must keep working for a client that can no longer
        produce its device identifier -- a cleared cookie, a reinstalled app, a
        laptop being disowned from another machine. The operation is already
        authenticated by the verifier proof below.
        """
        parsed = parse_token(token)
        if parsed is None:
            return RevokeError("MALFORMED")
        if parsed.kid not in self._peppers:
            return RevokeError("UNKNOWN_KID")

        record = self._store.find_by_selector(parsed.selector)
        if record is None:
            return RevokeError("NOT_FOUND")

        record_pepper = self._peppers.get(record.kid)
        if record_pepper is None:
            return RevokeError("UNKNOWN_KID")
        if not constant_time_equal_hex(
            hash_verifier(record_pepper, parsed.verifier), record.verifier_hash
        ):
            # [N-39]: the record was resolved above, so this refusal is
            # attributable. An unauthenticated attempt to terminate somebody's
            # session is exactly the event an operator needs to see, and the
            # selector alone will not identify the victim.
            return RevokeError(
                "VERIFIER_MISMATCH", user_id=record.user_id, family_id=record.family_id
            )

        # No sender-binding step ([N-36]): revocation is authenticated by the
        # verifier proof above and takes no device identifier at all.
        revoked = self._store.revoke_family(record.family_id)
        return RevokeOk(user_id=record.user_id, family_id=record.family_id, revoked=revoked)

    def revoke_family(self, family_id: str) -> int:
        """Revoke a whole family by its server-side identifier ([N-37]).

        Requires no token; the caller is responsible for authorising it.
        Returns the number of records revoked. Idempotent.
        """
        return self._store.revoke_family(family_id)

    def revoke_all_for_user(self, user_id: str) -> int:
        """Revoke every session of a user ([N-37]). Returns the number revoked."""
        return self._store.revoke_user(user_id)

    # ── Private ────────────────────────────────────────────────────────────

    @staticmethod
    def _failure(error: NebulaErrorCode, record: TokenRecord) -> RefreshError:
        return RefreshError(error=error, user_id=record.user_id, family_id=record.family_id)

    def _handle_reuse(
        self,
        record: TokenRecord,
        record_pepper: str,
        device_id: Optional[str],
        now: int,
    ) -> RefreshResult:
        rotated_at = record.rotated_at
        replaced_by = record.replaced_by_selector

        # [N-30] all six preconditions. Condition 6 (now < family_expires_at) is
        # what stops a grace retry from minting a token past the family ceiling.
        if (
            self._reuse_grace > 0  # 1
            and rotated_at is not None  # 2
            and now - rotated_at <= self._reuse_grace  # 3
            and replaced_by is not None  # 4
            and now < record.family_expires_at  # 6
        ):
            successor = self._store.find_by_selector(replaced_by)  # 5
            if successor is not None and successor.status == "active":
                # Sender binding first: a retry from another device is theft.
                if record.device_id_hash is not None and not self._device_matches(
                    record, record_pepper, device_id
                ):
                    self._store.revoke_family(record.family_id)
                    return self._failure("DEVICE_MISMATCH", record)
                # Compare-and-set: exactly one concurrent retry may consume the
                # unused successor. The loser mints nothing and reports CONFLICT.
                if not self._store.revoke_if_active(successor.selector):
                    return self._failure("CONFLICT", record)
                # Preserve the original rotated_at: the window is anchored to the
                # first rotation and cannot be walked forward ([N-30]).
                return self._rotate(record, device_id, now, "rotated", rotated_at)

        self._store.revoke_family(record.family_id)
        return self._failure("REUSE_DETECTED", record)

    def _rotate(
        self,
        record: TokenRecord,
        device_id: Optional[str],
        now: int,
        from_status: TokenStatus,
        rotated_at: int,
    ) -> RefreshResult:
        # [N-33] step 4: re-hash with the ACTIVE pepper, migrating the binding
        # forward across pepper rotation. Reaching here with a bound record means
        # the device check already passed, so `device_id` is valid Unicode.
        if record.device_id_hash is not None and device_id is not None:
            device_hash: Optional[str] = hash_device_id(self._active_pepper(), device_id)
        else:
            device_hash = record.device_id_hash

        token, nxt = self._mint(
            user_id=record.user_id,
            family_id=record.family_id,
            generation=record.generation + 1,
            device_id_hash=device_hash,
            family_expires_at=record.family_expires_at,
            now=now,
        )
        self._store.insert(nxt)

        applied = self._store.mark_rotated(record.selector, from_status, rotated_at, nxt.selector)
        if not applied:
            # [N-34] step 5: a concurrent refresh won the compare-and-set. Clean
            # up the successor we just inserted and report a retryable conflict —
            # never a token for a rotation that did not happen.
            self._store.revoke_if_active(nxt.selector)
            return self._failure("CONFLICT", record)

        return RefreshOk(
            token=token,
            user_id=record.user_id,
            family_id=record.family_id,
            generation=nxt.generation,
            expires_at=nxt.family_expires_at,
            idle_expires_at=nxt.idle_expires_at,
        )

    def _mint(
        self,
        *,
        user_id: str,
        family_id: str,
        generation: int,
        device_id_hash: Optional[str],
        family_expires_at: int,
        now: int,
    ) -> tuple[str, TokenRecord]:
        # [N-43] platform CSPRNG, never a fallback.
        selector = _b64url_encode(secrets.token_bytes(SELECTOR_BYTES))
        verifier = secrets.token_bytes(VERIFIER_BYTES)
        record = TokenRecord(
            selector=selector,
            verifier_hash=hash_verifier(self._active_pepper(), verifier),
            kid=self._active_kid,
            family_id=family_id,
            generation=generation,
            user_id=user_id,
            device_id_hash=device_id_hash,
            created_at=now,
            family_expires_at=family_expires_at,
            idle_expires_at=min(now + self._idle_ttl, family_expires_at),
        )
        token = f"{PREFIX}.{self._active_kid}.{selector}.{_b64url_encode(verifier)}"
        return token, record

    def _device_matches(
        self, record: TokenRecord, record_pepper: str, device_id: Optional[str]
    ) -> bool:
        if device_id is None or record.device_id_hash is None:
            return False
        # [N-12]: on the attacker-reachable path an invalid device identifier is
        # a binding failure, never an exception.
        if not _is_well_formed_unicode(device_id):
            return False
        return constant_time_equal_hex(
            hash_device_id(record_pepper, device_id), record.device_id_hash
        )

    def _active_pepper(self) -> str:
        return self._peppers[self._active_kid]


def _require_positive_int(name: str, value: int) -> None:
    # `bool` is a subclass of `int`; `True` is not a TTL.
    if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
        raise NebulaConfigError(f"{name} must be a positive integer")


def _require_non_negative_int(name: str, value: int) -> None:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise NebulaConfigError(f"{name} must be a non-negative integer")
