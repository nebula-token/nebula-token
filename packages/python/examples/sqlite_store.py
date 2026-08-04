"""
Production-style SQL store for NEBULA — SQLite reference (stdlib only, runnable).

Best practices demonstrated:
  * Parameterized queries only — never interpolate token material into SQL.
  * The store persists ONLY hashes (the engine guarantees this; the schema
    has no column for raw secrets by design).
  * Lookups key exclusively on the non-secret `selector` (primary key) ([N-45]).
  * `mark_rotated` and `revoke_if_active` are compare-and-set: the `WHERE`
    clause carries the expected status and the method returns `rowcount == 1`
    ([N-17], [N-18]). Returning `True` unconditionally is non-conforming — it
    re-opens the race in which two concurrent refreshes fork the family.
  * `revoke_family` / `revoke_user` return the number of rows they changed
    ([N-19]), which is what `revoke_token` and `revoke_all_for_user` report.
  * Infrastructure failures are left to raise ([N-20]): sqlite3 exceptions
    propagate out of the engine so the caller fails closed. Never catch one
    here and return a protocol-looking value.
  * `delete_expired()` for periodic GC — keep rotated/revoked rows until the
    family's absolute deadline: they are what makes reuse detection work ([N-15]).
  * The connection is put in autocommit mode, so every write is durable on its
    own. Wrapping a refresh request in ONE transaction at the call site
    (`with store.tx(): engine.refresh(...)`) additionally makes insert +
    mark_rotated commit together, so a crash between them cannot leave a
    half-rotated family ([N-22]).

For PostgreSQL: replace `?` placeholders with `%s`, connect with psycopg,
and keep everything else identical (schema in docs/STORE.md).
"""

from __future__ import annotations

import sqlite3
from contextlib import contextmanager
from typing import Generator, Optional

from nebula_token import TokenRecord, TokenStatus

SCHEMA = """
CREATE TABLE IF NOT EXISTS refresh_tokens (
  selector             TEXT PRIMARY KEY,
  verifier_hash        TEXT    NOT NULL,
  kid                  TEXT    NOT NULL,
  family_id            TEXT    NOT NULL,
  generation           INTEGER NOT NULL,
  user_id              TEXT    NOT NULL,
  device_id_hash       TEXT,
  created_at           INTEGER NOT NULL,
  family_expires_at    INTEGER NOT NULL,
  idle_expires_at      INTEGER NOT NULL,
  status               TEXT    NOT NULL DEFAULT 'active',
  rotated_at           INTEGER,
  replaced_by_selector TEXT
);
CREATE INDEX IF NOT EXISTS idx_rt_family ON refresh_tokens (family_id);
CREATE INDEX IF NOT EXISTS idx_rt_user   ON refresh_tokens (user_id);
"""

_COLS = (
    "selector, verifier_hash, kid, family_id, generation, user_id, device_id_hash, "
    "created_at, family_expires_at, idle_expires_at, status, rotated_at, replaced_by_selector"
)


class SqliteRefreshTokenStore:
    """Implements the six-method store contract (SPECIFICATION.md §4, [N-16])."""

    def __init__(self, conn: sqlite3.Connection) -> None:
        self._conn = conn
        # sqlite3 defaults to isolation_level = '': it opens an implicit
        # transaction before DML and never commits on its own. Left that way,
        # every write here is invisible to any other connection and is rolled
        # back when this one closes — so issue() would hand the caller a live
        # token for a row that does not exist, and revoke_token() would report
        # `revoked: N` for an UPDATE that never lands. That is precisely the
        # failure [N-20] forbids reporting. None is autocommit: each statement
        # is durable on its own, and tx() below still groups a whole refresh
        # into one transaction for [N-22].
        conn.isolation_level = None
        conn.executescript(SCHEMA)

    @contextmanager
    def tx(self) -> Generator[None, None, None]:
        """Wrap a whole refresh request for atomicity ([N-22]).

        Optional: the store is durable without it. What it adds is that the
        successor insert and the predecessor's compare-and-set commit together,
        so a crash between them cannot leave a half-rotated family.
        """
        self._conn.execute("BEGIN")
        try:
            yield
            self._conn.execute("COMMIT")
        except Exception:
            self._conn.execute("ROLLBACK")
            raise

    def find_by_selector(self, selector: str) -> Optional[TokenRecord]:
        row = self._conn.execute(
            f"SELECT {_COLS} FROM refresh_tokens WHERE selector = ?", (selector,)
        ).fetchone()
        if row is None:
            return None
        return TokenRecord(
            selector=row[0], verifier_hash=row[1], kid=row[2], family_id=row[3],
            generation=row[4], user_id=row[5], device_id_hash=row[6],
            created_at=row[7], family_expires_at=row[8], idle_expires_at=row[9],
            status=row[10], rotated_at=row[11], replaced_by_selector=row[12],
        )

    def insert(self, r: TokenRecord) -> None:
        self._conn.execute(
            f"INSERT INTO refresh_tokens ({_COLS}) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (r.selector, r.verifier_hash, r.kid, r.family_id, r.generation, r.user_id,
             r.device_id_hash, r.created_at, r.family_expires_at, r.idle_expires_at,
             r.status, r.rotated_at, r.replaced_by_selector),
        )

    def mark_rotated(
        self,
        selector: str,
        from_status: TokenStatus,
        rotated_at: int,
        replaced_by_selector: str,
    ) -> bool:
        """Compare-and-set ([N-17]): the write applies only from `from_status`."""
        cur = self._conn.execute(
            "UPDATE refresh_tokens SET status='rotated', rotated_at=?, replaced_by_selector=? "
            "WHERE selector=? AND status=?",
            (rotated_at, replaced_by_selector, selector, from_status),
        )
        return cur.rowcount == 1

    def revoke_if_active(self, selector: str) -> bool:
        """Compare-and-set ([N-18]): revoke only while still active."""
        cur = self._conn.execute(
            "UPDATE refresh_tokens SET status='revoked' WHERE selector=? AND status='active'",
            (selector,),
        )
        return cur.rowcount == 1

    def revoke_family(self, family_id: str) -> int:
        cur = self._conn.execute(
            "UPDATE refresh_tokens SET status='revoked' WHERE family_id=? AND status<>'revoked'",
            (family_id,),
        )
        return cur.rowcount

    def revoke_user(self, user_id: str) -> int:
        cur = self._conn.execute(
            "UPDATE refresh_tokens SET status='revoked' WHERE user_id=? AND status<>'revoked'",
            (user_id,),
        )
        return cur.rowcount

    # ── operational helper (not part of the contract) ──

    def delete_expired(self, now: int) -> int:
        """GC: remove rows whose whole family is past its absolute deadline ([N-15])."""
        cur = self._conn.execute(
            "DELETE FROM refresh_tokens WHERE family_expires_at <= ?", (now,)
        )
        return cur.rowcount
