/** Shared conformance vectors — spec/test-vectors.json (SPECIFICATION.md [N-47]). */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import {
  parseToken, hashVerifier, hashDeviceId,
  SPEC_VERSION, PREFIX, SELECTOR_BYTES, VERIFIER_BYTES, SELECTOR_CHARS, VERIFIER_CHARS,
  MAX_KID_LENGTH, MAX_TOKEN_LENGTH, MIN_PEPPER_LENGTH,
  DEFAULT_ABSOLUTE_TTL, DEFAULT_IDLE_TTL, DEFAULT_REUSE_GRACE,
} from '../src/index.ts';

const vectorsPath = join(dirname(fileURLToPath(import.meta.url)), '../../../spec/test-vectors.json');
const vectors = JSON.parse(readFileSync(vectorsPath, 'utf8'));

test('spec version matches the published vectors', () => {
  assert.equal(SPEC_VERSION, vectors.spec_version);
});

test('constants match the specification', () => {
  const c = vectors.constants;
  assert.equal(PREFIX, c.prefix);
  assert.equal(SELECTOR_BYTES, c.selector_bytes);
  assert.equal(VERIFIER_BYTES, c.verifier_bytes);
  assert.equal(SELECTOR_CHARS, c.selector_chars);
  assert.equal(VERIFIER_CHARS, c.verifier_chars);
  assert.equal(MAX_KID_LENGTH, c.max_kid_length);
  assert.equal(MAX_TOKEN_LENGTH, c.max_token_length);
  assert.equal(MIN_PEPPER_LENGTH, c.min_pepper_length);
  assert.equal(DEFAULT_ABSOLUTE_TTL, c.default_absolute_ttl_seconds);
  assert.equal(DEFAULT_IDLE_TTL, c.default_idle_ttl_seconds);
  assert.equal(DEFAULT_REUSE_GRACE, c.default_reuse_grace_seconds);
  // [N-48]: every published constant is compared, not only the ones we remembered.
  assert.equal(Object.keys(c).length, 11, 'a constant was published but never asserted');
});

test('verifier hashing vectors', () => {
  let n = 0;
  for (const v of vectors.verifier_hashing) {
    const verifier = Buffer.from(v.verifier_b64url, 'base64url');
    assert.equal(hashVerifier(v.pepper, verifier), v.expected_hmac_sha256_hex, v.id);
    n++;
  }
  assert.equal(n, vectors.counts.verifier_hashing, 'executed count must equal published count ([N-48])');
});

test('device hashing vectors', () => {
  let n = 0;
  for (const v of vectors.device_hashing) {
    assert.equal(hashDeviceId(v.pepper, v.device_id), v.expected_hmac_sha256_hex, v.id);
    if (v.device_id_bytes !== undefined) {
      // [N-11] keys the HMAC on the UTF-8 encoding of the identifier, not on
      // however the runtime happens to hold it. A JavaScript string is UTF-16,
      // so the byte form is decoded back to a string here; a runner whose
      // strings ARE bytes feeds them straight in. Either way the case's one
      // expected hash must come out, which is the portable statement of the
      // rule — and the assertion that a runtime cannot decide a device
      // identifier on anything but its bytes.
      const fromBytes = Buffer.from(v.device_id_bytes, 'hex').toString('utf8');
      assert.equal(fromBytes, v.device_id, `${v.id}: device_id_bytes must be the UTF-8 encoding of device_id`);
      assert.equal(hashDeviceId(v.pepper, fromBytes), v.expected_hmac_sha256_hex, `${v.id} from bytes`);
    }
    n++;
  }
  assert.equal(n, vectors.counts.device_hashing, 'executed count must equal published count ([N-48])');
});

test('parsing vectors', () => {
  let n = 0;
  for (const v of vectors.parsing) {
    const parsed = parseToken(v.token);
    if (v.valid) {
      assert.ok(parsed, `${v.id} should parse: ${v.note}`);
      assert.equal(parsed.kid, v.kid, v.id);
      assert.equal(parsed.selector, v.selector, v.id);
      assert.equal(parsed.verifier.length, VERIFIER_BYTES, v.id);
    } else {
      assert.equal(parsed, null, `${v.id} should be MALFORMED: ${v.note}`);
    }
    n++;
  }
  assert.equal(n, vectors.counts.parsing, 'executed count must equal published count ([N-48])');
});

test('parsing is total: nothing raises ([N-8])', () => {
  const hostile: unknown[] = [
    undefined, null, 42, {}, [], '', ' ', '.'.repeat(1000),
    'nbl.' + 'k'.repeat(10_000),
    `nbl.k1.${' '.repeat(22)}.${'A'.repeat(43)}`,
    Buffer.from([0xff, 0xfe]).toString('latin1'),
  ];
  for (const input of hostile) {
    assert.doesNotThrow(() => parseToken(input), `parseToken(${JSON.stringify(input)}) threw`);
    assert.equal(parseToken(input), null);
  }
});
