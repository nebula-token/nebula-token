# frozen_string_literal: true

# Production-style SQL store for NEBULA — PostgreSQL example (pg gem).
#
# Implements the six-method contract of SPECIFICATION.md §4 ([N-16]). The two
# compare-and-set methods are the load-bearing ones: `mark_rotated` and
# `revoke_if_active` MUST apply their write only if the current status still
# matches, and MUST report whether it was applied ([N-17], [N-18]). Returning
# true unconditionally re-opens the race in which two concurrent refreshes both
# mint a successor and fork the family.
#
# Other best practices: parameterized queries only; lookups keyed on the
# non-secret selector ([N-45]); keep rotated/revoked rows until the family's
# absolute deadline — they ARE the reuse detector ([N-15]); wrap each refresh
# request in one transaction (`conn.transaction { engine.refresh(...) }`, [N-22]);
# GC with #delete_expired. Let connection errors propagate: they are
# infrastructure failures, not protocol outcomes ([N-20]).
#
# Schema: see docs/STORE.md. Works with any object exposing #exec_params
# (PG::Connection or a connection checked out from a pool).

require 'nebula_token'

class PgRefreshTokenStore
  include NebulaToken::RefreshTokenStore

  COLS = %w[selector verifier_hash kid family_id generation user_id device_id_hash
            created_at family_expires_at idle_expires_at status rotated_at
            replaced_by_selector].join(', ')

  def initialize(conn)
    @conn = conn
  end

  def find_by_selector(selector)
    res = @conn.exec_params("SELECT #{COLS} FROM refresh_tokens WHERE selector = $1", [selector])
    return nil if res.ntuples.zero?

    row = res[0]
    NebulaToken::TokenRecord.new(
      selector: row['selector'], verifier_hash: row['verifier_hash'], kid: row['kid'],
      family_id: row['family_id'], generation: row['generation'], user_id: row['user_id'],
      device_id_hash: row['device_id_hash'], created_at: row['created_at'],
      family_expires_at: row['family_expires_at'], idle_expires_at: row['idle_expires_at'],
      # The pg gem hands back strings; TokenRecord normalises the status and the
      # integer columns at this boundary, and refuses to treat an unrecognised
      # status as active.
      status: row['status'], rotated_at: row['rotated_at'],
      replaced_by_selector: row['replaced_by_selector']
    )
  end

  def insert(record)
    @conn.exec_params(
      "INSERT INTO refresh_tokens (#{COLS}) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)",
      [record.selector, record.verifier_hash, record.kid, record.family_id, record.generation,
       record.user_id, record.device_id_hash, record.created_at, record.family_expires_at,
       record.idle_expires_at, record.status.to_s, record.rotated_at, record.replaced_by_selector]
    )
    nil
  end

  # Compare-and-set ([N-17]): the `AND status = $5` is what makes concurrent
  # refreshes of the same token safe.
  def mark_rotated(selector, from_status, rotated_at, replaced_by_selector)
    res = @conn.exec_params(
      "UPDATE refresh_tokens SET status = 'rotated', rotated_at = $2, replaced_by_selector = $3 " \
      'WHERE selector = $1 AND status = $4',
      [selector, rotated_at, replaced_by_selector, from_status.to_s]
    )
    res.cmd_tuples == 1
  end

  # Compare-and-set ([N-18]).
  def revoke_if_active(selector)
    res = @conn.exec_params(
      "UPDATE refresh_tokens SET status = 'revoked' WHERE selector = $1 AND status = 'active'",
      [selector]
    )
    res.cmd_tuples == 1
  end

  # [N-19]: return the number of records actually changed, and be idempotent —
  # hence the `status <> 'revoked'` guard, without which a second call would
  # report a revocation that did not happen.
  def revoke_family(family_id)
    @conn.exec_params(
      "UPDATE refresh_tokens SET status = 'revoked' WHERE family_id = $1 AND status <> 'revoked'",
      [family_id]
    ).cmd_tuples
  end

  def revoke_user(user_id)
    @conn.exec_params(
      "UPDATE refresh_tokens SET status = 'revoked' WHERE user_id = $1 AND status <> 'revoked'",
      [user_id]
    ).cmd_tuples
  end

  # Operational helper: GC families past their absolute deadline. Nothing may be
  # deleted before it ([N-15]).
  def delete_expired(now)
    @conn.exec_params('DELETE FROM refresh_tokens WHERE family_expires_at <= $1', [now]).cmd_tuples
  end
end
