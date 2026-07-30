/**
 * Language-specific tests: properties that cannot be expressed as portable
 * behavior vectors. All cross-language behavior lives in
 * spec/behavior-vectors.json and is exercised by behavior.test.ts.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';

import {
  NebulaEngine, MemoryRefreshTokenStore, NebulaConfigError,
  constantTimeEqualHex, hashVerifier, hashDeviceId, parseToken,
  type RefreshTokenStore, type TokenRecord, type TokenStatus,
} from '../src/index.ts';

const PEPPER = 'pepper-one-0123456789abcdef0123456789ab';
const HASH = 'a'.repeat(64);

function makeEngine(overrides: Record<string, unknown> = {}) {
  const store = new MemoryRefreshTokenStore();
  let now = 1_700_000_000;
  const engine = new NebulaEngine({
    peppers: { k1: PEPPER },
    activeKid: 'k1',
    store,
    clock: () => now,
    ...overrides,
  });
  return { engine, store, advance: (s: number) => { now += s; } };
}

// ── Constant-time comparison ([N-31]) ───────────────────────────────────────

test('constantTimeEqualHex rejects anything that is not 64 lowercase hex characters', () => {
  assert.equal(constantTimeEqualHex(HASH, HASH), true);
  assert.equal(constantTimeEqualHex(HASH, 'b'.repeat(64)), false);

  // A lenient hex decode stops at the first invalid character and compares
  // decoded prefixes, so every case below would otherwise compare EQUAL.
  assert.equal(constantTimeEqualHex('abc', 'abd'), false, 'odd-length prefixes');
  assert.equal(constantTimeEqualHex(HASH, `${HASH}   `), false, 'space-padded CHAR column');
  assert.equal(constantTimeEqualHex(HASH, `${HASH}\n`), false, 'trailing newline');
  assert.equal(constantTimeEqualHex(HASH, `${HASH}zzzz`), false, 'junk suffix');
  assert.equal(constantTimeEqualHex(HASH, HASH.toUpperCase()), false, 'case is not folded');
  assert.equal(constantTimeEqualHex(HASH.slice(0, 63), HASH.slice(0, 63)), false, 'truncated column');
  assert.equal(constantTimeEqualHex('', ''), false, 'empty is never equal');
});

test('constantTimeEqualHex never throws, whatever it is handed', () => {
  const hostile: unknown[] = [undefined, null, 42, {}, [], '', 'zz', ' '.repeat(64)];
  for (const a of hostile) {
    assert.doesNotThrow(() => constantTimeEqualHex(a as string, HASH));
    assert.equal(constantTimeEqualHex(a as string, HASH), false);
  }
});

test('a stored hash corrupted after the fact fails closed instead of verifying', async () => {
  const { engine, store } = makeEngine();
  const { token } = await engine.issue('u1');
  const row = store.all()[0]!;
  // Same record, but the column was upper-cased by an ETL job.
  await store.insert({ ...row, selector: 'x'.repeat(22), verifierHash: row.verifierHash.toUpperCase() });
  const forged = token.split('.');
  forged[2] = 'x'.repeat(22);
  const res = await engine.refresh(forged.join('.'));
  assert.equal(res.ok, false);
  assert.equal(res.ok === false && res.error, 'VERIFIER_MISMATCH');
});

// ── Concurrency ([N-17], [N-34]) ────────────────────────────────────────────

test('two concurrent refreshes of the same token never fork the family', async () => {
  const { engine, store } = makeEngine();
  const { token } = await engine.issue('u1');

  const [a, b] = await Promise.all([engine.refresh(token), engine.refresh(token)]);
  const winners = [a, b].filter((r) => r.ok);
  const losers = [a, b].filter((r) => !r.ok);

  assert.equal(winners.length, 1, 'exactly one refresh may win');
  assert.equal(losers[0]!.ok === false && losers[0]!.error, 'CONFLICT');
  assert.equal(
    store.all().filter((r) => r.status === 'active').length, 1,
    'the family must not fork into two live lineages',
  );
});

test('a burst of concurrent refreshes still leaves exactly one active record', async () => {
  const { engine, store } = makeEngine();
  const { token } = await engine.issue('u1');

  const results = await Promise.all(Array.from({ length: 16 }, () => engine.refresh(token)));
  assert.equal(results.filter((r) => r.ok).length, 1);
  assert.ok(results.filter((r) => !r.ok).every((r) => r.ok === false && r.error === 'CONFLICT'));
  assert.equal(store.all().filter((r) => r.status === 'active').length, 1);
});

// ── Store failures fail closed ([N-20]) ─────────────────────────────────────

class ExplodingStore implements RefreshTokenStore {
  private readonly inner = new MemoryRefreshTokenStore();
  constructor(private readonly failOn: keyof RefreshTokenStore) {}
  private guard<T>(m: keyof RefreshTokenStore, run: () => Promise<T>): Promise<T> {
    return m === this.failOn ? Promise.reject(new Error('database is on fire')) : run();
  }
  findBySelector(s: string) { return this.guard('findBySelector', () => this.inner.findBySelector(s)); }
  insert(r: TokenRecord) { return this.guard('insert', () => this.inner.insert(r)); }
  markRotated(s: string, f: TokenStatus, t: number, n: string) {
    return this.guard('markRotated', () => this.inner.markRotated(s, f, t, n));
  }
  revokeIfActive(s: string) { return this.guard('revokeIfActive', () => this.inner.revokeIfActive(s)); }
  revokeFamily(f: string) { return this.guard('revokeFamily', () => this.inner.revokeFamily(f)); }
  revokeUser(u: string) { return this.guard('revokeUser', () => this.inner.revokeUser(u)); }
}

test('a failing insert must not hand back a token for state that was never written', async () => {
  const engine = new NebulaEngine({
    peppers: { k1: PEPPER }, activeKid: 'k1', store: new ExplodingStore('insert'),
  });
  await assert.rejects(() => engine.issue('u1'), /database is on fire/);
});

test('a failing revokeFamily must not be reported as a successful revocation', async () => {
  const engine = new NebulaEngine({
    peppers: { k1: PEPPER }, activeKid: 'k1', store: new ExplodingStore('revokeFamily'),
  });
  const { token } = await engine.issue('u1');
  assert.equal((await engine.refresh(token)).ok, true);
  // The replay must attempt a family revocation; the rejection propagates
  // rather than being swallowed into a confident REUSE_DETECTED.
  await assert.rejects(() => engine.refresh(token), /database is on fire/);
});

// ── Configuration (§5, [N-23], [N-24]) ──────────────────────────────────────

test('constructor validation', () => {
  const store = new MemoryRefreshTokenStore();
  const bad = (cfg: Record<string, unknown>) =>
    assert.throws(() => new NebulaEngine({ store, ...cfg } as never), NebulaConfigError);

  bad({ peppers: { k1: 'short' }, activeKid: 'k1' });
  bad({ peppers: { k1: PEPPER }, activeKid: 'nope' });
  bad({ peppers: { 'k.1': PEPPER }, activeKid: 'k.1' });
  bad({ peppers: { '': PEPPER }, activeKid: '' });
  bad({ peppers: { ['k'.repeat(65)]: PEPPER }, activeKid: 'k'.repeat(65) });
  bad({ peppers: { k1: PEPPER }, activeKid: 'k1', absoluteTtlSeconds: 0 });
  bad({ peppers: { k1: PEPPER }, activeKid: 'k1', idleTtlSeconds: -5 });
  bad({ peppers: { k1: PEPPER }, activeKid: 'k1', reuseGraceSeconds: -1 });
  // [N-11] a pepper with no UTF-8 encoding is not a usable HMAC key. Each of
  // these is well over the byte floor, so only the encoding rule can reject
  // it: Node substitutes U+FFFD and Java '?', which would give one configured
  // value two different HMAC keys.
  bad({ peppers: { k1: '\uD800' + PEPPER }, activeKid: 'k1' });
  bad({ peppers: { k1: PEPPER + '\uDC00' }, activeKid: 'k1' });
});

test('MIN_PEPPER_LENGTH counts bytes, not characters ([N-1])', () => {
  const store = new MemoryRefreshTokenStore();
  const wide = '日'.repeat(16); // 16 characters, 48 UTF-8 bytes
  assert.equal(wide.length, 16);
  assert.doesNotThrow(() => new NebulaEngine({ peppers: { k1: wide }, activeKid: 'k1', store }));
  assert.throws(
    () => new NebulaEngine({ peppers: { k1: 'a'.repeat(31) }, activeKid: 'k1', store }),
    NebulaConfigError,
  );
});

test("the pepper map is copied: mutating the caller's object cannot weaken the engine ([N-24])", async () => {
  const store = new MemoryRefreshTokenStore();
  const peppers: Record<string, string> = { k1: PEPPER };
  const engine = new NebulaEngine({ peppers, activeKid: 'k1', store });

  peppers.k1 = 'x'; // would otherwise key the HMAC with a one-byte secret
  delete peppers.k1;

  const { token } = await engine.issue('u1');
  assert.equal(store.all()[0]!.verifierHash, hashVerifier(PEPPER, parseToken(token)!.verifier));
  assert.equal((await engine.refresh(token)).ok, true);
});

// ── Device identifiers ([N-11], [N-12], [N-14]) ─────────────────────────────

test('issue rejects a device id that is not valid Unicode, at the call site', async () => {
  const { engine } = makeEngine();
  await assert.rejects(() => engine.issue('u1', '\uD800'), NebulaConfigError);
});

test('hashDeviceId applies no normalisation, trimming or case folding ([N-11])', () => {
  assert.notEqual(
    hashDeviceId(PEPPER, 'Café'), hashDeviceId(PEPPER, 'Café'),
    'NFC and NFD must not be conflated',
  );
  assert.notEqual(hashDeviceId(PEPPER, 'x'), hashDeviceId(PEPPER, ' x'));
  assert.notEqual(hashDeviceId(PEPPER, 'x'), hashDeviceId(PEPPER, 'X'));
});

test('no raw secret appears in anything the engine stores ([N-14])', async () => {
  const { engine, store } = makeEngine();
  const { token } = await engine.issue('u1', 'devA');
  const dump = JSON.stringify(store.all());
  assert.ok(!dump.includes(token.split('.')[3]!), 'raw verifier');
  assert.ok(!dump.includes('devA'), 'raw device identifier');
  assert.ok(!dump.includes(PEPPER), 'pepper');
});

// ── Result shape ([N-2], [N-39]) ────────────────────────────────────────────

test('timestamps are integer unix seconds, not Date objects ([N-2])', async () => {
  const { engine } = makeEngine();
  const issued = await engine.issue('u1');
  assert.ok(Number.isInteger(issued.expiresAt) && Number.isInteger(issued.idleExpiresAt));
  const refreshed = await engine.refresh(issued.token);
  assert.ok(refreshed.ok && Number.isInteger(refreshed.expiresAt));
});

test('failures carry userId and familyId once a record is resolved ([N-39])', async () => {
  const { engine } = makeEngine();
  const { token, familyId } = await engine.issue('u1');
  await engine.refresh(token);

  const replay = await engine.refresh(token);
  assert.equal(replay.ok === false && replay.userId, 'u1');
  assert.equal(replay.ok === false && replay.familyId, familyId);

  // Before a record is resolved there is nothing to attribute.
  const unknown = await engine.refresh('garbage');
  assert.equal(unknown.ok === false && unknown.userId, undefined);
});

// ── Store hygiene ───────────────────────────────────────────────────────────

test('the in-memory store refuses a duplicate selector rather than overwriting a record', async () => {
  const store = new MemoryRefreshTokenStore();
  const row: TokenRecord = {
    selector: 'A'.repeat(22), verifierHash: HASH, kid: 'k1', familyId: 'f', generation: 0,
    userId: 'u1', deviceIdHash: null, createdAt: 0, familyExpiresAt: 1, idleExpiresAt: 1,
    status: 'active', rotatedAt: null, replacedBySelector: null,
  };
  await store.insert(row);
  await assert.rejects(() => store.insert(row), /duplicate selector/);
});

test('deleteExpired only removes records past the family deadline ([N-15])', async () => {
  const { engine, store } = makeEngine({ absoluteTtlSeconds: 100, idleTtlSeconds: 100 });
  const { token } = await engine.issue('u1');
  await engine.refresh(token);
  assert.equal(store.deleteExpired(1_700_000_099), 0, 'nothing may be dropped before the deadline');
  assert.equal(store.all().length, 2);
  assert.equal(store.deleteExpired(1_700_000_100), 2);
});
