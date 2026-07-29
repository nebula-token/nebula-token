/**
 * Production-style SQL store for NEBULA — PostgreSQL example.
 *
 * Works with `pg` (node-postgres): pass a Pool or a checked-out client.
 * Only the minimal query interface is required, so it also fits pg-pool,
 * pgbouncer-backed clients, or a transaction-scoped client.
 *
 * Best practices demonstrated:
 *  - Parameterized queries only — token material never interpolated into SQL.
 *  - Lookups key exclusively on the non-secret `selector` (primary key).
 *  - Keep rotated/revoked rows until the family's absolute deadline: they
 *    are what makes reuse detection work. GC with `deleteExpired()`.
 *  - Wrap each refresh request in ONE transaction at the call site
 *    (BEGIN → engine.refresh() → COMMIT) so insert + markRotated are atomic.
 *
 * Schema: docs/STORE.md. This file lives in examples/ and is not part of
 * the published package.
 */

import type { RefreshTokenStore, TokenRecord, TokenStatus } from '../src/index.ts';

/** Minimal slice of pg's Pool/Client interface. */
export interface SqlClient {
  query(text: string, values?: unknown[]): Promise<{ rows: Record<string, unknown>[]; rowCount: number | null }>;
}

const COLS =
  'selector, verifier_hash, kid, family_id, generation, user_id, device_id_hash, ' +
  'created_at, family_expires_at, idle_expires_at, status, rotated_at, replaced_by_selector';

function rowToRecord(r: Record<string, unknown>): TokenRecord {
  return {
    selector: r.selector as string,
    verifierHash: r.verifier_hash as string,
    kid: r.kid as string,
    familyId: r.family_id as string,
    generation: Number(r.generation),
    userId: r.user_id as string,
    deviceIdHash: (r.device_id_hash as string | null) ?? null,
    createdAt: Number(r.created_at),
    familyExpiresAt: Number(r.family_expires_at),
    idleExpiresAt: Number(r.idle_expires_at),
    status: r.status as TokenStatus,
    rotatedAt: r.rotated_at === null ? null : Number(r.rotated_at),
    replacedBySelector: (r.replaced_by_selector as string | null) ?? null,
  };
}

export class PostgresRefreshTokenStore implements RefreshTokenStore {
  constructor(private readonly db: SqlClient) {}

  async findBySelector(selector: string): Promise<TokenRecord | null> {
    const res = await this.db.query(
      `SELECT ${COLS} FROM refresh_tokens WHERE selector = $1`,
      [selector],
    );
    return res.rows[0] ? rowToRecord(res.rows[0]) : null;
  }

  async insert(r: TokenRecord): Promise<void> {
    await this.db.query(
      `INSERT INTO refresh_tokens (${COLS})
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)`,
      [r.selector, r.verifierHash, r.kid, r.familyId, r.generation, r.userId,
       r.deviceIdHash, r.createdAt, r.familyExpiresAt, r.idleExpiresAt,
       r.status, r.rotatedAt, r.replacedBySelector],
    );
  }

  /**
   * Compare-and-set ([N-17]). `AND status = $4` is the whole point: it is what
   * makes two concurrent refreshes of the same record produce one winner and one
   * `CONFLICT` instead of two successors and a forked family. `fromStatus` is the
   * caller's, never a literal — hard-coding `'active'` here turns every grace
   * retry ([N-30]) into a silent no-op. See docs/STORE.md.
   */
  async markRotated(
    selector: string,
    fromStatus: TokenStatus,
    rotatedAt: number,
    replacedBySelector: string,
  ): Promise<boolean> {
    const res = await this.db.query(
      `UPDATE refresh_tokens
       SET status = 'rotated', rotated_at = $2, replaced_by_selector = $3
       WHERE selector = $1 AND status = $4`,
      [selector, rotatedAt, replacedBySelector, fromStatus],
    );
    return res.rowCount === 1;
  }

  /**
   * Compare-and-set ([N-18]). Not "revoke": it must refuse a record that is
   * already `rotated` or `revoked`, and report whether it applied.
   */
  async revokeIfActive(selector: string): Promise<boolean> {
    const res = await this.db.query(
      `UPDATE refresh_tokens SET status = 'revoked' WHERE selector = $1 AND status = 'active'`,
      [selector],
    );
    return res.rowCount === 1;
  }

  /** `status <> 'revoked'` keeps the count honest ([N-19]) — it counts changes, not matches. */
  async revokeFamily(familyId: string): Promise<number> {
    const res = await this.db.query(
      `UPDATE refresh_tokens SET status = 'revoked' WHERE family_id = $1 AND status <> 'revoked'`,
      [familyId],
    );
    return res.rowCount ?? 0;
  }

  async revokeUser(userId: string): Promise<number> {
    const res = await this.db.query(
      `UPDATE refresh_tokens SET status = 'revoked' WHERE user_id = $1 AND status <> 'revoked'`,
      [userId],
    );
    return res.rowCount ?? 0;
  }

  /** Operational helper: GC families past their absolute deadline. */
  async deleteExpired(now: number): Promise<number> {
    const res = await this.db.query(
      `DELETE FROM refresh_tokens WHERE family_expires_at < $1`, [now],
    );
    return res.rowCount ?? 0;
  }
}
