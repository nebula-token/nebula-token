/**
 * NEBULA — Opaque Rotating Refresh Tokens
 * TypeScript reference implementation of SPECIFICATION.md (spec version 1).
 *
 * Zero runtime dependencies. Node.js >= 22.
 *
 * Requirement identifiers in comments ([N-*]) refer to SPECIFICATION.md.
 */

import * as crypto from 'node:crypto';

// ─── Spec constants (§1) ─────────────────────────────────────────────────────

/** Version of SPECIFICATION.md this package implements ([N-52]). */
export const SPEC_VERSION = 1;
export const PREFIX = 'nbl';
export const SELECTOR_BYTES = 16;
export const VERIFIER_BYTES = 32;
export const SELECTOR_CHARS = 22;
export const VERIFIER_CHARS = 43;
export const MAX_KID_LENGTH = 64;
export const MAX_TOKEN_LENGTH = 512;
export const MIN_PEPPER_LENGTH = 32;
export const DEFAULT_ABSOLUTE_TTL = 60 * 60 * 24 * 30;
export const DEFAULT_IDLE_TTL = 60 * 60 * 24 * 7;
export const DEFAULT_REUSE_GRACE = 0;

/** HMAC-SHA-256 output, in lowercase hex characters. */
const HASH_HEX_CHARS = 64;

// ─── Types ───────────────────────────────────────────────────────────────────

export type TokenStatus = 'active' | 'rotated' | 'revoked';

/** Server-side record — one row per issued token ([N-10]). */
export interface TokenRecord {
  selector: string;
  verifierHash: string;
  kid: string;
  familyId: string;
  generation: number;
  userId: string;
  deviceIdHash: string | null;
  createdAt: number;
  familyExpiresAt: number;
  idleExpiresAt: number;
  status: TokenStatus;
  rotatedAt: number | null;
  replacedBySelector: string | null;
}

/**
 * Storage contract ([N-16]) — six methods, implement over Postgres / Redis / etc.
 *
 * Two failure channels ([N-20]): protocol outcomes are the return values below;
 * infrastructure failures (store unreachable, timeout, constraint violation)
 * MUST reject the returned promise. A rejection propagates out of the engine —
 * it is never converted into a `RefreshResult`, so the caller always fails closed.
 */
export interface RefreshTokenStore {
  findBySelector(selector: string): Promise<TokenRecord | null>;

  insert(record: TokenRecord): Promise<void>;

  /**
   * Compare-and-set ([N-17]). Apply the rotation write **only if** the stored
   * record's status is still `fromStatus`, and report whether it was applied.
   *
   * SQL: `UPDATE … SET status='rotated', rotated_at=$2, replaced_by_selector=$3
   *       WHERE selector=$1 AND status=$4` → `rowCount === 1`.
   *
   * Returning `true` unconditionally is non-conforming: it re-opens the race in
   * which two concurrent refreshes both mint a successor and fork the family.
   */
  markRotated(
    selector: string,
    fromStatus: TokenStatus,
    rotatedAt: number,
    replacedBySelector: string,
  ): Promise<boolean>;

  /** Compare-and-set ([N-18]): revoke only if still `active`; report whether it did. */
  revokeIfActive(selector: string): Promise<boolean>;

  /** Revoke every record of the family. Returns how many changed ([N-19]). */
  revokeFamily(familyId: string): Promise<number>;

  /** Revoke every record of the user. Returns how many changed ([N-19]). */
  revokeUser(userId: string): Promise<number>;
}

export interface NebulaConfig {
  /** Map kid → pepper secret. Each secret >= 32 bytes; see [N-23] for entropy. */
  peppers: Record<string, string>;
  /** kid used for newly minted tokens. */
  activeKid: string;
  store: RefreshTokenStore;
  absoluteTtlSeconds?: number;
  idleTtlSeconds?: number;
  /** See [N-30] for the security trade-off before raising this above 0. */
  reuseGraceSeconds?: number;
  /** Injectable clock, unix seconds ([N-3]). */
  clock?: () => number;
}

/**
 * Protocol outcomes ([N-38]).
 *
 * Treat this union as open ([N-40]): a future minor version may add a code, and
 * consumers must treat an unrecognised value as a refusal rather than assuming
 * their `switch` is exhaustive.
 */
export type NebulaErrorCode =
  | 'MALFORMED'
  | 'UNKNOWN_KID'
  | 'NOT_FOUND'
  | 'VERIFIER_MISMATCH'
  | 'REUSE_DETECTED'
  | 'REVOKED'
  | 'EXPIRED_ABSOLUTE'
  | 'EXPIRED_IDLE'
  | 'DEVICE_MISMATCH'
  | 'CONFLICT';

export interface IssueResult {
  token: string;
  userId: string;
  familyId: string;
  generation: number;
  /** Unix seconds ([N-2]) — the family's fixed absolute deadline. */
  expiresAt: number;
  /** Unix seconds ([N-2]) — this token's sliding idle deadline. */
  idleExpiresAt: number;
}

export interface RefreshSuccess {
  ok: true;
  token: string;
  userId: string;
  familyId: string;
  generation: number;
  expiresAt: number;
  idleExpiresAt: number;
}

/**
 * `userId` and `familyId` are populated whenever the engine resolved a record —
 * every code except MALFORMED, UNKNOWN_KID and NOT_FOUND — so that a
 * REUSE_DETECTED or DEVICE_MISMATCH event can be attributed without a second
 * lookup of a token you were told never to log ([N-39]).
 */
export interface RefreshFailure {
  ok: false;
  error: NebulaErrorCode;
  userId?: string;
  familyId?: string;
}

export type RefreshResult = RefreshSuccess | RefreshFailure;

/**
 * `userId` and `familyId` are populated on a failure whenever the engine
 * resolved a record, exactly as in {@link RefreshFailure} — [N-39] governs
 * every failure result, not only `refresh`. `revokeToken` resolves its record
 * before proving the verifier, so a `VERIFIER_MISMATCH` there is attributable
 * and carries both; `MALFORMED`, `UNKNOWN_KID` and `NOT_FOUND` never do.
 */
export type RevokeResult =
  | { ok: true; userId: string; familyId: string; revoked: number }
  | { ok: false; error: NebulaErrorCode; userId?: string; familyId?: string };

export interface ParsedToken {
  kid: string;
  selector: string;
  /** Raw 32 secret bytes. Never persist or log this ([N-14]). */
  verifier: Uint8Array;
}

/**
 * Node's debug-rendering hook, referenced by well-known symbol rather than by
 * importing `node:util`, so the module keeps its single `node:crypto` import.
 */
const INSPECT = Symbol.for('nodejs.util.inspect.custom');

/**
 * Attach a redacted debug rendering to a value that carries secret material
 * ([N-14], [N-46]).
 *
 * `console.log(result)`, `util.inspect`, a `pino`/`winston` serialiser walking
 * an object graph and an unhandled-rejection dump all route through this hook,
 * and without it they print a live token or the raw verifier into the log. The
 * property is non-enumerable, so `JSON.stringify`, `{...spread}`,
 * `Object.keys` and every other read of the value are unaffected — a handler
 * that legitimately sends the token to the client keeps working. This mirrors
 * `__repr__` in Python, `inspect` in Ruby, `Debug` in Rust and `__debugInfo`
 * in PHP: the *debug* representation is redacted, serialisation is not.
 */
function redact<T extends object>(value: T, render: () => unknown): T {
  Object.defineProperty(value, INSPECT, { value: render, enumerable: false });
  return value;
}

/** Thrown by the constructor and by `issue` for caller mistakes ([N-12], §5). */
export class NebulaConfigError extends Error {
  constructor(message: string) {
    super(`[NEBULA] ${message}`);
    this.name = 'NebulaConfigError';
  }
}

// ─── Spec primitives (§2, §6.4) — pure, exported for conformance testing ─────

/**
 * `\A…\z` semantics, never `^…$`: in several regex dialects `$` also matches
 * immediately before a trailing newline, which would accept "…{verifier}\n"
 * as well-formed. JavaScript's `$` is anchored without the `m` flag, and the
 * explicit character-class check below does not rely on that subtlety anyway.
 */
const B64URL_CHAR = /^[A-Za-z0-9_-]+$/;

/** Parse a wire token (§2, [N-5]..[N-9]). Total: returns null, never throws. */
export function parseToken(token: unknown): ParsedToken | null {
  if (typeof token !== 'string' || token.length === 0) return null;

  // [N-6.1] byte length, checked before any other parsing work. `token.length`
  // would count UTF-16 code units and disagree with the byte-counting
  // implementations in this family.
  if (Buffer.byteLength(token, 'utf8') > MAX_TOKEN_LENGTH) return null;

  const parts = token.split('.');
  if (parts.length !== 4) return null; // [N-6.2]

  // Indexed access is `string | undefined` under noUncheckedIndexedAccess; the
  // guard below is what narrows it, rather than a cast.
  const prefix = parts[0];
  const kid = parts[1];
  const selector = parts[2];
  const verifierB64 = parts[3];
  if (prefix === undefined || kid === undefined || selector === undefined || verifierB64 === undefined) {
    return null;
  }
  if (prefix !== PREFIX) return null; // [N-6.3] case-sensitive
  if (kid.length === 0 || selector.length === 0 || verifierB64.length === 0) return null; // [N-6.2]

  // [N-6.5]/[N-6.6] exact lengths. Because the alphabet is ASCII-only and
  // checked next, character length and byte length coincide here.
  if (kid.length > MAX_KID_LENGTH) return null;
  if (selector.length !== SELECTOR_CHARS) return null;
  if (verifierB64.length !== VERIFIER_CHARS) return null;

  // [N-6.4] alphabet: rejects padding, whitespace, '+', '/' and any non-ASCII.
  if (!B64URL_CHAR.test(kid)) return null;
  if (!B64URL_CHAR.test(selector)) return null;
  if (!B64URL_CHAR.test(verifierB64)) return null;

  const verifier = Buffer.from(verifierB64, 'base64url');
  if (verifier.length !== VERIFIER_BYTES) return null; // [N-6.7]

  // [N-7] canonical encoding: a 32-byte value has four 43-character spellings
  // and only one of them is the canonical minimal encoding.
  if (verifier.toString('base64url') !== verifierB64) return null;

  return redact({ kid, selector, verifier: new Uint8Array(verifier) }, () => ({
    kid,
    selector,
    verifier: '<redacted>',
  }));
}

/**
 * True iff the string is valid Unicode, i.e. contains no unpaired surrogate.
 * With the `u` flag, `\p{Surrogate}` can only match a lone surrogate, because
 * a well-formed pair is matched as the single astral code point it encodes.
 */
function isWellFormedUnicode(s: string): boolean {
  return !/\p{Surrogate}/u.test(s);
}

/** verifierHash = lowercase hex HMAC-SHA-256(pepper, verifier) ([N-11]). */
export function hashVerifier(pepper: string, verifier: Uint8Array): string {
  return crypto.createHmac('sha256', Buffer.from(pepper, 'utf8')).update(verifier).digest('hex');
}

/**
 * deviceIdHash = lowercase hex HMAC-SHA-256(pepper, "device:" + deviceId) ([N-11]).
 * Throws for a device id that is not valid Unicode; callers on the attacker-
 * reachable path must pre-check with {@link isWellFormedUnicode} ([N-12]).
 */
export function hashDeviceId(pepper: string, deviceId: string): string {
  if (!isWellFormedUnicode(deviceId)) {
    throw new NebulaConfigError('deviceId is not valid Unicode (unpaired surrogate)');
  }
  return crypto
    .createHmac('sha256', Buffer.from(pepper, 'utf8'))
    .update(Buffer.from(`device:${deviceId}`, 'utf8'))
    .digest('hex');
}

const LOWER_HEX_64 = /^[0-9a-f]{64}$/;

/**
 * Constant-time comparison of two hex digests ([N-31]).
 *
 * Operands that are not exactly 64 lowercase hex characters compare unequal.
 * The guard is deliberate: a lenient hex decode would stop at the first invalid
 * character and silently compare prefixes, so a stored hash that was truncated,
 * space-padded by a CHAR column, or upper-cased by an ETL job would keep
 * verifying instead of failing closed.
 */
export function constantTimeEqualHex(aHex: string, bHex: string): boolean {
  if (typeof aHex !== 'string' || typeof bHex !== 'string') return false;
  if (aHex.length !== HASH_HEX_CHARS || bHex.length !== HASH_HEX_CHARS) return false;
  if (!LOWER_HEX_64.test(aHex) || !LOWER_HEX_64.test(bHex)) return false;
  return crypto.timingSafeEqual(Buffer.from(aHex, 'hex'), Buffer.from(bHex, 'hex'));
}

// ─── Engine ──────────────────────────────────────────────────────────────────

export class NebulaEngine {
  // `#`-private, not TypeScript `private`: the latter is erased at compile time
  // and leaves an ordinary enumerable property, so `console.log(engine)` would
  // print every pepper. A `#` field is invisible to `util.inspect`,
  // `Object.keys` and `JSON.stringify` alike ([N-46]).
  readonly #peppers: Map<string, string>;
  readonly #activeKid: string;
  private readonly store: RefreshTokenStore;
  private readonly absoluteTtl: number;
  private readonly idleTtl: number;
  private readonly reuseGrace: number;
  private readonly clock: () => number;

  constructor(config: NebulaConfig) {
    // [N-24] copy: mutating the caller's map afterwards must not change behavior.
    const peppers = new Map<string, string>();
    for (const [kid, secret] of Object.entries(config.peppers ?? {})) {
      if (!kid || !B64URL_CHAR.test(kid) || Buffer.byteLength(kid, 'utf8') > MAX_KID_LENGTH) {
        throw new NebulaConfigError(
          `kid ${JSON.stringify(kid)} must be 1-${MAX_KID_LENGTH} characters from [A-Za-z0-9_-]`,
        );
      }
      // [N-11]: the HMAC key is the pepper encoded as UTF-8, so a string that
      // has no UTF-8 encoding — an unpaired surrogate, which arrives trivially
      // from a JSON secrets file or a lenient UTF-16 decode — is not a usable
      // key. Node would silently substitute U+FFFD, Java substitutes '?' and
      // Python refuses; three different HMAC keys for the same configured
      // value. §5 resolves it by failing construction everywhere. The message
      // never quotes the secret ([N-14]).
      if (typeof secret !== 'string' || !isWellFormedUnicode(secret)) {
        throw new NebulaConfigError(
          `pepper ${JSON.stringify(kid)} must be a string with a UTF-8 encoding (no unpaired surrogate)`,
        );
      }
      if (Buffer.byteLength(secret, 'utf8') < MIN_PEPPER_LENGTH) {
        throw new NebulaConfigError(
          `pepper ${JSON.stringify(kid)} must be at least ${MIN_PEPPER_LENGTH} bytes`,
        );
      }
      peppers.set(kid, secret);
    }
    this.#peppers = peppers;
    if (!this.#peppers.has(config.activeKid)) {
      throw new NebulaConfigError(`activeKid ${JSON.stringify(config.activeKid)} not present in peppers`);
    }
    this.#activeKid = config.activeKid;
    this.store = config.store;
    this.absoluteTtl = config.absoluteTtlSeconds ?? DEFAULT_ABSOLUTE_TTL;
    this.idleTtl = config.idleTtlSeconds ?? DEFAULT_IDLE_TTL;
    this.reuseGrace = config.reuseGraceSeconds ?? DEFAULT_REUSE_GRACE;
    if (!Number.isInteger(this.absoluteTtl) || this.absoluteTtl <= 0) {
      throw new NebulaConfigError('absoluteTtlSeconds must be a positive integer');
    }
    if (!Number.isInteger(this.idleTtl) || this.idleTtl <= 0) {
      throw new NebulaConfigError('idleTtlSeconds must be a positive integer');
    }
    if (!Number.isInteger(this.reuseGrace) || this.reuseGrace < 0) {
      throw new NebulaConfigError('reuseGraceSeconds must be a non-negative integer');
    }
    this.clock = config.clock ?? (() => Math.floor(Date.now() / 1000));
  }

  /** Issue the first token of a new family ([N-25]). Call at login. */
  async issue(userId: string, deviceId?: string): Promise<IssueResult> {
    if (deviceId !== undefined && !isWellFormedUnicode(deviceId)) {
      // [N-12] at issue the value comes from the application: surface the bug
      // at the call site rather than minting a binding nothing can satisfy.
      throw new NebulaConfigError('deviceId is not valid Unicode (unpaired surrogate)');
    }
    const now = this.clock();
    const familyId = crypto.randomBytes(16).toString('hex');
    const familyExpiresAt = now + this.absoluteTtl;
    const { token, record } = this.#mint({
      userId,
      familyId,
      generation: 0,
      deviceIdHash: deviceId !== undefined ? hashDeviceId(this.#activePepper(), deviceId) : null,
      familyExpiresAt,
      now,
    });
    await this.store.insert(record);
    return redact(
      {
        token,
        userId,
        familyId,
        generation: 0,
        expiresAt: familyExpiresAt,
        idleExpiresAt: record.idleExpiresAt,
      },
      () => ({
        token: '<redacted>',
        userId,
        familyId,
        generation: 0,
        expiresAt: familyExpiresAt,
        idleExpiresAt: record.idleExpiresAt,
      }),
    );
  }

  /** Exchange a refresh token for its successor ([N-26]). */
  async refresh(token: string, deviceId?: string): Promise<RefreshResult> {
    // 1. Parse
    const parsed = parseToken(token);
    if (!parsed) return { ok: false, error: 'MALFORMED' };

    // 2. Pepper lookup by the token's kid
    if (!this.#peppers.has(parsed.kid)) return { ok: false, error: 'UNKNOWN_KID' };

    // 3. Record lookup
    const record = await this.store.findBySelector(parsed.selector);
    if (!record) return { ok: false, error: 'NOT_FOUND' };

    // 4. Verifier proof — pepper of the RECORD's kid, constant time.
    const recordPepper = this.#peppers.get(record.kid);
    if (recordPepper === undefined) return { ok: false, error: 'UNKNOWN_KID' }; // [N-27]
    if (!constantTimeEqualHex(hashVerifier(recordPepper, parsed.verifier), record.verifierHash)) {
      // [N-28] no family revocation here: a selector alone must never be
      // sufficient to destroy a session.
      return this.#fail('VERIFIER_MISMATCH', record);
    }

    const now = this.clock();

    // 5. Reuse
    if (record.status === 'rotated') return this.#handleReuse(record, recordPepper, deviceId, now);

    // 6. Revoked
    if (record.status === 'revoked') return this.#fail('REVOKED', record);

    // 7-8. Expiry
    if (now >= record.familyExpiresAt) {
      await this.store.revokeFamily(record.familyId);
      return this.#fail('EXPIRED_ABSOLUTE', record);
    }
    if (now >= record.idleExpiresAt) {
      await this.store.revokeFamily(record.familyId);
      return this.#fail('EXPIRED_IDLE', record);
    }

    // 9. Sender binding — pepper of the RECORD's kid ([N-32]).
    if (record.deviceIdHash !== null && !this.#deviceMatches(record, recordPepper, deviceId)) {
      await this.store.revokeFamily(record.familyId);
      return this.#fail('DEVICE_MISMATCH', record);
    }

    // 10. Rotate
    return this.#rotate(record, deviceId, now, 'active', now);
  }

  /**
   * Revoke the family a token belongs to ([N-36]).
   *
   * Authenticated: the verifier is proved exactly as in `refresh`, because the
   * selector is a public lookup key and must not by itself be a capability to
   * terminate a session. Succeeds whatever the record's status, so a client can
   * still log out with a token that was already rotated or revoked.
   *
   * Takes **no device identifier** and performs no sender-binding check
   * ([N-36]): [N-36] specifies steps 1-4 of [N-26] and no sender-binding step,
   * so logout keeps working for a client that can no longer produce its device
   * identifier — a cleared cookie, a reinstalled app, a stolen laptop being
   * disowned from another machine. A binding check here would convert "I want
   * this session dead" into "prove you are still the device that holds it",
   * which is the opposite of the intent, and the operation is already
   * authenticated by the verifier proof above.
   */
  async revokeToken(token: string): Promise<RevokeResult> {
    const parsed = parseToken(token);
    if (!parsed) return { ok: false, error: 'MALFORMED' };
    if (!this.#peppers.has(parsed.kid)) return { ok: false, error: 'UNKNOWN_KID' };

    const record = await this.store.findBySelector(parsed.selector);
    if (!record) return { ok: false, error: 'NOT_FOUND' };

    const recordPepper = this.#peppers.get(record.kid);
    if (recordPepper === undefined) return { ok: false, error: 'UNKNOWN_KID' };
    if (!constantTimeEqualHex(hashVerifier(recordPepper, parsed.verifier), record.verifierHash)) {
      // [N-39]: the record was resolved above, so this refusal is attributable.
      // An unauthenticated attempt to terminate somebody's session is exactly
      // the event an operator needs to see, and the selector alone will not
      // identify the victim.
      return {
        ok: false,
        error: 'VERIFIER_MISMATCH',
        userId: record.userId,
        familyId: record.familyId,
      };
    }
    const revoked = await this.store.revokeFamily(record.familyId);
    return { ok: true, userId: record.userId, familyId: record.familyId, revoked };
  }

  /**
   * Revoke a whole family by its server-side identifier ([N-37]).
   * Requires no token; the caller is responsible for authorising it.
   */
  async revokeFamily(familyId: string): Promise<number> {
    return this.store.revokeFamily(familyId);
  }

  /** Revoke every session of a user ([N-37]). */
  async revokeAllForUser(userId: string): Promise<number> {
    return this.store.revokeUser(userId);
  }

  // ── Private ────────────────────────────────────────────────────────────────

  #fail(error: NebulaErrorCode, record: TokenRecord): RefreshFailure {
    return { ok: false, error, userId: record.userId, familyId: record.familyId };
  }

  async #handleReuse(
    record: TokenRecord,
    recordPepper: string,
    deviceId: string | undefined,
    now: number,
  ): Promise<RefreshResult> {
    // [N-30] all six preconditions. Condition 6 (now < familyExpiresAt) is what
    // stops a grace retry from minting a token past the absolute deadline.
    const withinGrace =
      this.reuseGrace > 0 &&
      record.rotatedAt !== null &&
      now - record.rotatedAt <= this.reuseGrace &&
      record.replacedBySelector !== null &&
      now < record.familyExpiresAt;

    if (withinGrace) {
      const successor = await this.store.findBySelector(record.replacedBySelector!);
      if (successor?.status === 'active') {
        if (record.deviceIdHash !== null && !this.#deviceMatches(record, recordPepper, deviceId)) {
          await this.store.revokeFamily(record.familyId);
          return this.#fail('DEVICE_MISMATCH', record);
        }
        // Compare-and-set: exactly one concurrent retry may consume the unused
        // successor. The loser rotates nothing and reports CONFLICT.
        if (!(await this.store.revokeIfActive(successor.selector))) {
          return this.#fail('CONFLICT', record);
        }
        // Preserve the original rotatedAt: the window is not extendable ([N-30]).
        return this.#rotate(record, deviceId, now, 'rotated', record.rotatedAt!);
      }
    }

    await this.store.revokeFamily(record.familyId);
    return this.#fail('REUSE_DETECTED', record);
  }

  async #rotate(
    record: TokenRecord,
    deviceId: string | undefined,
    now: number,
    fromStatus: TokenStatus,
    rotatedAt: number,
  ): Promise<RefreshResult> {
    const { token, record: next } = this.#mint({
      userId: record.userId,
      familyId: record.familyId,
      generation: record.generation + 1,
      // Re-hash with the ACTIVE pepper — migrates the binding forward across
      // pepper rotation ([N-33] step 4).
      deviceIdHash:
        record.deviceIdHash !== null && deviceId !== undefined
          ? hashDeviceId(this.#activePepper(), deviceId)
          : record.deviceIdHash,
      familyExpiresAt: record.familyExpiresAt,
      now,
    });

    await this.store.insert(next);

    const applied = await this.store.markRotated(record.selector, fromStatus, rotatedAt, next.selector);
    if (!applied) {
      // [N-34] step 5: a concurrent refresh won. Clean up the successor we
      // inserted and report a retryable conflict — never a token.
      await this.store.revokeIfActive(next.selector);
      return this.#fail('CONFLICT', record);
    }

    return redact(
      {
        ok: true as const,
        token,
        userId: record.userId,
        familyId: record.familyId,
        generation: next.generation,
        expiresAt: next.familyExpiresAt,
        idleExpiresAt: next.idleExpiresAt,
      },
      () => ({
        ok: true,
        token: '<redacted>',
        userId: record.userId,
        familyId: record.familyId,
        generation: next.generation,
        expiresAt: next.familyExpiresAt,
        idleExpiresAt: next.idleExpiresAt,
      }),
    );
  }

  #mint(args: {
    userId: string;
    familyId: string;
    generation: number;
    deviceIdHash: string | null;
    familyExpiresAt: number;
    now: number;
  }): { token: string; record: TokenRecord } {
    const selector = crypto.randomBytes(SELECTOR_BYTES).toString('base64url');
    const verifier = crypto.randomBytes(VERIFIER_BYTES);
    const record: TokenRecord = {
      selector,
      verifierHash: hashVerifier(this.#activePepper(), verifier),
      kid: this.#activeKid,
      familyId: args.familyId,
      generation: args.generation,
      userId: args.userId,
      deviceIdHash: args.deviceIdHash,
      createdAt: args.now,
      familyExpiresAt: args.familyExpiresAt,
      idleExpiresAt: Math.min(args.now + this.idleTtl, args.familyExpiresAt),
      status: 'active',
      rotatedAt: null,
      replacedBySelector: null,
    };
    return { token: `${PREFIX}.${this.#activeKid}.${selector}.${verifier.toString('base64url')}`, record };
  }

  #deviceMatches(record: TokenRecord, recordPepper: string, deviceId: string | undefined): boolean {
    if (deviceId === undefined || record.deviceIdHash === null) return false;
    // [N-12] on the attacker-reachable path an invalid device id is a binding
    // failure, never an exception.
    if (!isWellFormedUnicode(deviceId)) return false;
    return constantTimeEqualHex(hashDeviceId(recordPepper, deviceId), record.deviceIdHash);
  }

  #activePepper(): string {
    return this.#peppers.get(this.#activeKid)!;
  }
}

// ─── In-memory store — development and tests ONLY ───────────────────────────

/**
 * Reference store ([N-21]).
 *
 * Node runs JavaScript on a single thread, so the compare-and-set methods below
 * are atomic with respect to each other without further synchronisation: no
 * `await` occurs between reading and writing a row.
 *
 * NOT FOR PRODUCTION: state is per-process and lost on restart, so reuse
 * detection does not survive a deploy and does not work behind more than one
 * instance. Implement {@link RefreshTokenStore} over your database instead —
 * see docs/STORE.md.
 */
export class MemoryRefreshTokenStore implements RefreshTokenStore {
  private readonly rows = new Map<string, TokenRecord>();

  async findBySelector(selector: string): Promise<TokenRecord | null> {
    const r = this.rows.get(selector);
    return r ? { ...r } : null;
  }

  async insert(record: TokenRecord): Promise<void> {
    if (this.rows.has(record.selector)) {
      throw new Error(`[NEBULA] duplicate selector ${record.selector}`);
    }
    this.rows.set(record.selector, { ...record });
  }

  async markRotated(
    selector: string,
    fromStatus: TokenStatus,
    rotatedAt: number,
    replacedBySelector: string,
  ): Promise<boolean> {
    const r = this.rows.get(selector);
    if (r?.status !== fromStatus) return false;
    r.status = 'rotated';
    r.rotatedAt = rotatedAt;
    r.replacedBySelector = replacedBySelector;
    return true;
  }

  async revokeIfActive(selector: string): Promise<boolean> {
    const r = this.rows.get(selector);
    if (r?.status !== 'active') return false;
    r.status = 'revoked';
    return true;
  }

  async revokeFamily(familyId: string): Promise<number> {
    let n = 0;
    for (const r of this.rows.values()) {
      if (r.familyId === familyId && r.status !== 'revoked') {
        r.status = 'revoked';
        n++;
      }
    }
    return n;
  }

  async revokeUser(userId: string): Promise<number> {
    let n = 0;
    for (const r of this.rows.values()) {
      if (r.userId === userId && r.status !== 'revoked') {
        r.status = 'revoked';
        n++;
      }
    }
    return n;
  }

  /** Test helper: every record currently stored. Not part of the store contract. */
  all(): TokenRecord[] {
    return [...this.rows.values()].map((r) => ({ ...r }));
  }

  /** Test helper: drop records whose family deadline has passed ([N-15]). */
  deleteExpired(now: number): number {
    let n = 0;
    for (const [selector, r] of this.rows) {
      if (now >= r.familyExpiresAt) {
        this.rows.delete(selector);
        n++;
      }
    }
    return n;
  }
}
