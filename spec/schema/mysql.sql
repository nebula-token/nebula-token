-- NEBULA — refresh-token store schema (MySQL 8.0.16+ / MariaDB 10.5+)
-- Spec version 1.
--
-- Field set, types and semantics: SPECIFICATION.md §3, requirement [N-10].
-- Retention:  a row MUST survive, with its status and replaced_by_selector
--             intact, until at least family_expires_at — requirement [N-15].
--             Deleting rotated or revoked rows earlier silently turns every
--             replay into NOT_FOUND and disables reuse detection.
-- Statements: the exact SQL for each of the six store methods ([N-16]) is in
--             docs/STORE.md. This file is the only copy of the DDL.
--
-- Two MySQL-specific decisions, both load-bearing:
--
-- 1. Every token-derived column is `CHARACTER SET ascii COLLATE ascii_bin`.
--    MySQL's default collation is case-insensitive (utf8mb4_0900_ai_ci on 8.0,
--    utf8mb4_general_ci on MariaDB). Selectors are case-sensitive base64url:
--    under a case-insensitive collation `Ab...` and `aB...` are the same key,
--    so a lookup can return a different session's row and a PRIMARY KEY
--    collision can reject a legitimate insert. ascii_bin also makes the
--    hex columns byte-exact, which is what [N-31] assumes.
--
-- 2. Key columns are VARCHAR with an explicit length, never TEXT: MySQL cannot
--    index a TEXT column without a prefix length, and a prefix index on the
--    selector would silently allow prefix collisions on the primary key.
--
-- CHECK constraints are enforced from MySQL 8.0.16 and MariaDB 10.2.1. On an
-- older server they parse and are ignored — the schema still works, but the
-- shape invariants stop being enforced by the database. Unlike the PostgreSQL
-- file, this one carries no regular-expression constraints: REGEXP_LIKE in a
-- CHECK is accepted by some versions and rejected by others, so the character
-- set, the collation and the column lengths carry that job instead.
--
-- Keep STRICT_TRANS_TABLES in sql_mode. It is the default from MySQL 5.7, and
-- without it MySQL truncates an over-long value instead of rejecting it: a
-- 26-character selector is stored as its first 22 characters, which maps two
-- different tokens onto one row. This is not hypothetical — it is what a
-- session that has cleared sql_mode does today.

CREATE TABLE refresh_tokens (
  -- Public lookup key: base64url of 16 CSPRNG bytes, exactly 22 characters.
  -- The only token-derived value that may be indexed ([N-45]).
  selector             VARCHAR(22)  CHARACTER SET ascii   COLLATE ascii_bin    NOT NULL,

  -- Lowercase hex HMAC-SHA-256(pepper[kid], verifier_bytes) ([N-11], [N-13]).
  -- VARCHAR, never CHAR: a blank-padded CHAR value compares unequal under the
  -- constant-time hex comparison required by [N-31], which fails closed.
  verifier_hash        VARCHAR(64)  CHARACTER SET ascii   COLLATE ascii_bin    NOT NULL,

  -- Pepper identifier used for verifier_hash AND device_id_hash.
  -- MAX_KID_LENGTH is 64 bytes ([N-1]); ascii makes characters and bytes equal.
  kid                  VARCHAR(64)  CHARACTER SET ascii   COLLATE ascii_bin    NOT NULL,

  -- Lowercase hex of 16 CSPRNG bytes. Fixed at login, shared by every rotation
  -- of one session. The join key for your own session-metadata tables.
  family_id            VARCHAR(32)  CHARACTER SET ascii   COLLATE ascii_bin    NOT NULL,

  -- 0 at issue, +1 per rotation.
  generation           INT          NOT NULL,

  -- Application-defined owner identifier. 255 utf8mb4 characters is 1020
  -- bytes, inside InnoDB's 3072-byte index-key limit with ROW_FORMAT=DYNAMIC.
  -- utf8mb4_bin so that two user ids differing only in case or accent are two
  -- users, as they are everywhere else in your system.
  user_id              VARCHAR(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin  NOT NULL,

  -- Lowercase hex HMAC-SHA-256(pepper[kid], 'device:' || device_id), or NULL
  -- when the family is unbound. The raw device identifier is never stored
  -- ([N-14]).
  device_id_hash       VARCHAR(64)  CHARACTER SET ascii   COLLATE ascii_bin    NULL,

  -- All timestamps are integer Unix seconds ([N-2]). Not DATETIME/TIMESTAMP:
  -- the specification compares integers, TIMESTAMP is bounded at 2038, and a
  -- session-timezone conversion must never be able to move a deadline.
  created_at           BIGINT       NOT NULL,

  -- Absolute deadline, fixed at login. MUST never be extended ([N-10]).
  family_expires_at    BIGINT       NOT NULL,

  -- Sliding deadline: min(now + idle_ttl, family_expires_at) ([N-33]).
  idle_expires_at      BIGINT       NOT NULL,

  -- active | rotated | revoked. An ENUM works equally well; VARCHAR keeps the
  -- three engine schemas identical and avoids ENUM's ordinal-reordering trap.
  status               VARCHAR(8)   CHARACTER SET ascii   COLLATE ascii_bin    NOT NULL DEFAULT 'active',

  -- Set on first rotation. A grace retry MUST keep the original value ([N-30]).
  rotated_at           BIGINT       NULL,

  -- Selector of the successor record.
  replaced_by_selector VARCHAR(22)  CHARACTER SET ascii   COLLATE ascii_bin    NULL,

  PRIMARY KEY (selector),

  -- revokeFamily(family_id) ([N-19]).
  KEY idx_rt_family (family_id),

  -- revokeUser(user_id) ([N-19]).
  KEY idx_rt_user (user_id),

  -- Garbage collection. Without this index the deletion predicate at the foot
  -- of this file is a full table scan over the largest table you own.
  KEY idx_rt_gc (family_expires_at),

  CONSTRAINT refresh_tokens_status_ck
    CHECK (status IN ('active', 'rotated', 'revoked')),

  CONSTRAINT refresh_tokens_generation_ck
    CHECK (generation >= 0),

  -- [N-33] step 3: the sliding deadline is clamped to the absolute one.
  CONSTRAINT refresh_tokens_idle_le_family_ck
    CHECK (idle_expires_at <= family_expires_at),

  -- An active record has not been rotated.
  CONSTRAINT refresh_tokens_active_shape_ck
    CHECK (status <> 'active'
           OR (rotated_at IS NULL AND replaced_by_selector IS NULL)),

  -- A rotated record always points at its successor ([N-34] step 3); this is
  -- the pair the grace path in [N-30] reads. A revoked record may carry either
  -- shape, because revocation can hit a record in any state.
  CONSTRAINT refresh_tokens_rotated_shape_ck
    CHECK (status <> 'rotated'
           OR (rotated_at IS NOT NULL AND replaced_by_selector IS NOT NULL))
) ENGINE = InnoDB
  DEFAULT CHARSET = utf8mb4
  ROW_FORMAT = DYNAMIC;

-- Garbage collection, run periodically. `<=` and not `<`: at exactly
-- family_expires_at the family is already dead ([N-26] step 7 compares
-- now < family_expires_at), so the row has no remaining evidentiary value.
--
--   DELETE FROM refresh_tokens WHERE family_expires_at <= ?;
--
-- Batch it on a large table — MySQL supports LIMIT on DELETE directly, and a
-- bounded delete keeps the undo log and any replicas from falling behind:
--
--   DELETE FROM refresh_tokens WHERE family_expires_at <= ? LIMIT 10000;
--
-- Optional, only if you audit pepper retirement (docs/OPERATIONS.md):
--
--   CREATE INDEX idx_rt_kid_gc ON refresh_tokens (kid, family_expires_at);
