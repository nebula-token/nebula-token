-- NEBULA — refresh-token store schema (PostgreSQL 12+)
-- Spec version 1.
--
-- Field set, types and semantics: SPECIFICATION.md §3, requirement [N-10].
-- Retention:  a row MUST survive, with its status and replaced_by_selector
--             intact, until at least family_expires_at — requirement [N-15].
--             Deleting rotated or revoked rows earlier silently turns every
--             replay into NOT_FOUND and disables reuse detection.
-- Statements: the exact SQL for each of the six store methods ([N-16]) is in
--             docs/STORE.md. This file is the only copy of the DDL; the prose
--             documents link here rather than restating it.
--
-- Column names are the canonical snake_case spelling. Your language's record
-- field names ([N-10]) map to them one-to-one.

CREATE TABLE refresh_tokens (
  -- Public lookup key: base64url of 16 CSPRNG bytes, 22 characters. The only
  -- token-derived value that may be indexed ([N-45]).
  selector             text    PRIMARY KEY,

  -- Lowercase hex HMAC-SHA-256(pepper[kid], verifier_bytes) ([N-11], [N-13]).
  -- text, never char(64): a blank-padded CHAR value compares unequal under the
  -- constant-time hex comparison required by [N-31], which fails closed and
  -- would silently reject every token in the table.
  verifier_hash        text    NOT NULL,

  -- Pepper identifier used for verifier_hash AND device_id_hash.
  kid                  text    NOT NULL,

  -- Lowercase hex of 16 CSPRNG bytes. Fixed at login, shared by every
  -- rotation of one session. This is the join key for your own session
  -- metadata tables.
  family_id            text    NOT NULL,

  -- 0 at issue, +1 per rotation.
  generation           integer NOT NULL,

  -- Application-defined owner identifier.
  user_id              text    NOT NULL,

  -- Lowercase hex HMAC-SHA-256(pepper[kid], 'device:' || device_id), or NULL
  -- when the family is unbound. The raw device identifier is never stored
  -- ([N-14]).
  device_id_hash       text,

  -- All timestamps are integer Unix seconds ([N-2]). Not timestamptz: the
  -- specification compares integers, and a timezone-aware column invites a
  -- conversion that changes the comparison.
  created_at           bigint  NOT NULL,

  -- Absolute deadline, fixed at login. MUST never be extended ([N-10]).
  family_expires_at    bigint  NOT NULL,

  -- Sliding deadline: min(now + idle_ttl, family_expires_at) ([N-33]).
  idle_expires_at      bigint  NOT NULL,

  -- active | rotated | revoked.
  status               text    NOT NULL DEFAULT 'active',

  -- Set on first rotation. A grace retry MUST keep the original value ([N-30]).
  rotated_at           bigint,

  -- Selector of the successor record.
  replaced_by_selector text,

  CONSTRAINT refresh_tokens_status_ck
    CHECK (status IN ('active', 'rotated', 'revoked')),

  CONSTRAINT refresh_tokens_selector_ck
    CHECK (selector ~ '^[A-Za-z0-9_-]{22}$'),

  CONSTRAINT refresh_tokens_replaced_by_ck
    CHECK (replaced_by_selector IS NULL OR replaced_by_selector ~ '^[A-Za-z0-9_-]{22}$'),

  CONSTRAINT refresh_tokens_verifier_hash_ck
    CHECK (verifier_hash ~ '^[0-9a-f]{64}$'),

  CONSTRAINT refresh_tokens_device_id_hash_ck
    CHECK (device_id_hash IS NULL OR device_id_hash ~ '^[0-9a-f]{64}$'),

  CONSTRAINT refresh_tokens_family_id_ck
    CHECK (family_id ~ '^[0-9a-f]{32}$'),

  -- MAX_KID_LENGTH is 64 bytes ([N-1]); the kid grammar is base64url ([N-5]).
  CONSTRAINT refresh_tokens_kid_ck
    CHECK (octet_length(kid) BETWEEN 1 AND 64 AND kid ~ '^[A-Za-z0-9_-]+$'),

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
);

-- revokeFamily(family_id) ([N-19]).
CREATE INDEX idx_rt_family ON refresh_tokens (family_id);

-- revokeUser(user_id) ([N-19]).
CREATE INDEX idx_rt_user ON refresh_tokens (user_id);

-- Garbage collection. Without this index the deletion predicate below is a
-- sequential scan over the whole table, which on a busy deployment is the
-- largest table you own.
CREATE INDEX idx_rt_gc ON refresh_tokens (family_expires_at);

-- Garbage collection, run periodically. `<=` and not `<`: at exactly
-- family_expires_at the family is already dead ([N-26] step 7 compares
-- now < family_expires_at), so the row has no remaining evidentiary value.
--
--   DELETE FROM refresh_tokens WHERE family_expires_at <= $1;
--
-- Batch it on a large table:
--
--   DELETE FROM refresh_tokens
--    WHERE ctid IN (SELECT ctid FROM refresh_tokens
--                    WHERE family_expires_at <= $1 LIMIT 10000);
--
-- Optional, only if you audit pepper retirement (docs/OPERATIONS.md): an index
-- on (kid, family_expires_at) turns "when may this kid be deleted?" into a
-- lookup instead of a scan. It earns its write cost only if you ask often.
--
--   CREATE INDEX idx_rt_kid_gc ON refresh_tokens (kid, family_expires_at);
--
-- Optional: if the table is dominated by revoked rows, partial indexes keep the
-- bulk-revocation paths small.
--
--   CREATE INDEX idx_rt_family_live ON refresh_tokens (family_id)
--     WHERE status <> 'revoked';
