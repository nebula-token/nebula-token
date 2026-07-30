-- NEBULA — refresh-token store schema (SQLite 3.37+)
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
-- STRICT requires SQLite 3.37 (2021). It rejects a string written into an
-- INTEGER column instead of silently storing it, which is worth having on a
-- table whose deadlines are integers. Drop the keyword for an older engine;
-- nothing else in this file depends on it.
--
-- SQLite compares TEXT byte-by-byte unless a column declares COLLATE NOCASE,
-- so the case sensitivity that selectors require is the default here. Do not
-- add NOCASE to any column below.
--
-- SQLite is a fine store for a single-process deployment and for tests. It is
-- not a fine store for several application instances: reuse detection is a
-- property of one shared, consistent view of this table (docs/STORE.md).

CREATE TABLE refresh_tokens (
  -- Public lookup key: base64url of 16 CSPRNG bytes, 22 characters. The only
  -- token-derived value that may be indexed ([N-45]).
  selector             TEXT    NOT NULL PRIMARY KEY,

  -- Lowercase hex HMAC-SHA-256(pepper[kid], verifier_bytes) ([N-11], [N-13]).
  verifier_hash        TEXT    NOT NULL,

  -- Pepper identifier used for verifier_hash AND device_id_hash.
  kid                  TEXT    NOT NULL,

  -- Lowercase hex of 16 CSPRNG bytes. Fixed at login, shared by every rotation
  -- of one session. The join key for your own session-metadata tables.
  family_id            TEXT    NOT NULL,

  -- 0 at issue, +1 per rotation.
  generation           INTEGER NOT NULL,

  -- Application-defined owner identifier.
  user_id              TEXT    NOT NULL,

  -- Lowercase hex HMAC-SHA-256(pepper[kid], 'device:' || device_id), or NULL
  -- when the family is unbound. The raw device identifier is never stored
  -- ([N-14]).
  device_id_hash       TEXT,

  -- All timestamps are integer Unix seconds ([N-2]). SQLite's INTEGER is
  -- 64-bit, which is what [N-2] requires.
  created_at           INTEGER NOT NULL,

  -- Absolute deadline, fixed at login. MUST never be extended ([N-10]).
  family_expires_at    INTEGER NOT NULL,

  -- Sliding deadline: min(now + idle_ttl, family_expires_at) ([N-33]).
  idle_expires_at      INTEGER NOT NULL,

  -- active | rotated | revoked.
  status               TEXT    NOT NULL DEFAULT 'active',

  -- Set on first rotation. A grace retry MUST keep the original value ([N-30]).
  rotated_at           INTEGER,

  -- Selector of the successor record.
  replaced_by_selector TEXT,

  CONSTRAINT refresh_tokens_status_ck
    CHECK (status IN ('active', 'rotated', 'revoked')),

  -- GLOB is case-sensitive; LIKE is not. The double negative is the SQLite
  -- idiom for "every character is drawn from this set".
  CONSTRAINT refresh_tokens_selector_ck
    CHECK (length(selector) = 22 AND selector NOT GLOB '*[^A-Za-z0-9_-]*'),

  CONSTRAINT refresh_tokens_replaced_by_ck
    CHECK (replaced_by_selector IS NULL
           OR (length(replaced_by_selector) = 22
               AND replaced_by_selector NOT GLOB '*[^A-Za-z0-9_-]*')),

  CONSTRAINT refresh_tokens_verifier_hash_ck
    CHECK (length(verifier_hash) = 64 AND verifier_hash NOT GLOB '*[^0-9a-f]*'),

  CONSTRAINT refresh_tokens_device_id_hash_ck
    CHECK (device_id_hash IS NULL
           OR (length(device_id_hash) = 64
               AND device_id_hash NOT GLOB '*[^0-9a-f]*')),

  CONSTRAINT refresh_tokens_family_id_ck
    CHECK (length(family_id) = 32 AND family_id NOT GLOB '*[^0-9a-f]*'),

  -- MAX_KID_LENGTH is 64 bytes ([N-1]); the kid grammar is base64url ([N-5]).
  CONSTRAINT refresh_tokens_kid_ck
    CHECK (length(kid) BETWEEN 1 AND 64 AND kid NOT GLOB '*[^A-Za-z0-9_-]*'),

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
) STRICT;

-- revokeFamily(family_id) ([N-19]).
CREATE INDEX idx_rt_family ON refresh_tokens (family_id);

-- revokeUser(user_id) ([N-19]).
CREATE INDEX idx_rt_user ON refresh_tokens (user_id);

-- Garbage collection. Without this index the deletion predicate below scans
-- the whole table.
CREATE INDEX idx_rt_gc ON refresh_tokens (family_expires_at);

-- Garbage collection, run periodically. `<=` and not `<`: at exactly
-- family_expires_at the family is already dead ([N-26] step 7 compares
-- now < family_expires_at), so the row has no remaining evidentiary value.
--
--   DELETE FROM refresh_tokens WHERE family_expires_at <= ?;
--
-- Optional, only if you audit pepper retirement (docs/OPERATIONS.md):
--
--   CREATE INDEX idx_rt_kid_gc ON refresh_tokens (kid, family_expires_at);
