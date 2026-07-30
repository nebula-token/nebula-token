/// NEBULA — Opaque Rotating Refresh Tokens.
///
/// Dart implementation of SPECIFICATION.md (spec version 1). Requirement
/// identifiers in comments ([N-*]) refer to that document.
///
/// The store contract and the engine are asynchronous. [N-16] lets each
/// ecosystem pick its own synchrony, and for Dart the choice is forced: every
/// server-side driver worth storing tokens in is future-returning
/// (`package:postgres` exposes no blocking API at all) and `waitFor` — the last
/// escape hatch from a `Future` to a value — was removed in Dart 3. A blocking
/// contract would therefore have no conforming production implementation.
library;

import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

import 'package:crypto/crypto.dart';

// ─── Spec constants (§1, [N-4]) ──────────────────────────────────────────────

/// Version of SPECIFICATION.md this package implements ([N-52]).
const int specVersion = 1;

const String prefix = 'nbl';
const int selectorBytes = 16;
const int verifierBytes = 32;
const int selectorChars = 22;
const int verifierChars = 43;
const int maxKidLength = 64;
const int maxTokenLength = 512;
const int minPepperLength = 32;
const int defaultAbsoluteTtl = 60 * 60 * 24 * 30;
const int defaultIdleTtl = 60 * 60 * 24 * 7;
const int defaultReuseGrace = 0;

/// HMAC-SHA-256 output, in lowercase hex characters.
const int _hashHexChars = 64;

// ─── Types ───────────────────────────────────────────────────────────────────

enum TokenStatus { active, rotated, revoked }

/// Protocol outcomes ([N-38]).
///
/// Treat this enum as **open** ([N-40]). Dart has no `non_exhaustive`, so the
/// policy is documented instead: a future minor version MAY add a value, and a
/// consumer that switches over it MUST provide a `default` / wildcard branch
/// that treats an unrecognised code as a refusal. Exhaustive switches without a
/// default are outside the compatibility promise of this package.
enum NebulaError {
  malformed('MALFORMED'),
  unknownKid('UNKNOWN_KID'),
  notFound('NOT_FOUND'),
  verifierMismatch('VERIFIER_MISMATCH'),
  reuseDetected('REUSE_DETECTED'),
  revoked('REVOKED'),
  expiredAbsolute('EXPIRED_ABSOLUTE'),
  expiredIdle('EXPIRED_IDLE'),
  deviceMismatch('DEVICE_MISMATCH'),
  conflict('CONFLICT');

  const NebulaError(this.code);

  /// The spec error name. Only the code is stable; messages are not ([N-41]).
  final String code;
}

/// Server-side record — one row per issued token ([N-10]).
///
/// Every timestamp is integer Unix seconds ([N-2]); Dart's `int` is a 64-bit
/// signed integer on every non-web target, which is where this package runs.
class TokenRecord {
  TokenRecord({
    required this.selector,
    required this.verifierHash,
    required this.kid,
    required this.familyId,
    required this.generation,
    required this.userId,
    required this.deviceIdHash,
    required this.createdAt,
    required this.familyExpiresAt,
    required this.idleExpiresAt,
    this.status = TokenStatus.active,
    this.rotatedAt,
    this.replacedBySelector,
  });

  /// Primary key. The only token-derived value that may be indexed ([N-45]).
  final String selector;

  /// Lowercase hex of `HMAC-SHA-256(pepper[kid], verifier_bytes)`.
  final String verifierHash;

  /// Pepper id used for [verifierHash] **and** [deviceIdHash].
  final String kid;
  final String familyId;
  final int generation;
  final String userId;

  /// Lowercase hex of `HMAC-SHA-256(pepper[kid], "device:" + deviceId)`,
  /// or null when the family is unbound.
  final String? deviceIdHash;
  final int createdAt;

  /// Absolute deadline. Fixed at login, MUST never be extended.
  final int familyExpiresAt;

  /// Sliding deadline: `min(now + idleTtl, familyExpiresAt)`.
  final int idleExpiresAt;

  TokenStatus status;

  /// Set on first rotation. A grace retry MUST keep the original value ([N-30]).
  int? rotatedAt;
  String? replacedBySelector;

  TokenRecord copy() => TokenRecord(
    selector: selector,
    verifierHash: verifierHash,
    kid: kid,
    familyId: familyId,
    generation: generation,
    userId: userId,
    deviceIdHash: deviceIdHash,
    createdAt: createdAt,
    familyExpiresAt: familyExpiresAt,
    idleExpiresAt: idleExpiresAt,
    status: status,
    rotatedAt: rotatedAt,
    replacedBySelector: replacedBySelector,
  );

  /// Deliberately free of secret material ([N-14]): a record holds only hashes,
  /// and the selector is a public correlation identifier ([N-46]).
  @override
  String toString() =>
      'TokenRecord(selector: $selector, kid: $kid, family: $familyId, '
      'generation: $generation, status: ${status.name})';
}

/// Storage contract ([N-16]) — six methods, implement over Postgres / Redis / etc.
///
/// Two failure channels ([N-20]): protocol outcomes are the return values below;
/// infrastructure failures (store unreachable, timeout, constraint violation)
/// MUST complete the returned future with an error. That error propagates out of
/// the engine untouched — it is never folded into a [RefreshResult] — so a
/// caller whose database is down fails closed instead of being told a
/// revocation happened that did not.
abstract interface class RefreshTokenStore {
  Future<TokenRecord?> findBySelector(String selector);

  Future<void> insert(TokenRecord record);

  /// Compare-and-set ([N-17]). Apply the rotation write **only if** the stored
  /// record's status is still [fromStatus], and report whether it was applied.
  ///
  /// SQL: `UPDATE … SET status='rotated', rotated_at=?, replaced_by_selector=?
  ///       WHERE selector=? AND status=?` → affected rows == 1.
  ///
  /// Returning `true` unconditionally is non-conforming: it re-opens the race in
  /// which two concurrent refreshes both mint a successor and fork the family.
  Future<bool> markRotated(
    String selector,
    TokenStatus fromStatus,
    int rotatedAt,
    String replacedBySelector,
  );

  /// Compare-and-set ([N-18]): revoke only if still active; report whether it did.
  Future<bool> revokeIfActive(String selector);

  /// Revoke every record of the family. Returns how many changed ([N-19]).
  Future<int> revokeFamily(String familyId);

  /// Revoke every record of the user. Returns how many changed ([N-19]).
  Future<int> revokeUser(String userId);
}

/// Result of [NebulaEngine.issue] ([N-25]).
class IssueResult {
  const IssueResult({
    required this.token,
    required this.userId,
    required this.familyId,
    required this.generation,
    required this.expiresAt,
    required this.idleExpiresAt,
  });

  final String token;
  final String userId;
  final String familyId;
  final int generation;

  /// Unix seconds ([N-2]) — the family's fixed absolute deadline.
  final int expiresAt;

  /// Unix seconds ([N-2]) — this token's sliding idle deadline.
  final int idleExpiresAt;
}

/// Outcome of [NebulaEngine.refresh] ([N-26]).
///
/// Errors are values, never thrown ([N-29]). Switch or pattern-match on the
/// two subtypes; the [ok] getter exists for logging and metrics.
sealed class RefreshResult {
  const RefreshResult();

  bool get ok;
}

final class RefreshSuccess extends RefreshResult {
  const RefreshSuccess({
    required this.token,
    required this.userId,
    required this.familyId,
    required this.generation,
    required this.expiresAt,
    required this.idleExpiresAt,
  });

  final String token;
  final String userId;
  final String familyId;
  final int generation;
  final int expiresAt;
  final int idleExpiresAt;

  @override
  bool get ok => true;
}

/// [userId] and [familyId] are populated whenever the engine resolved a record —
/// every code except `MALFORMED`, `UNKNOWN_KID` and `NOT_FOUND` — so that a
/// `REUSE_DETECTED` or `DEVICE_MISMATCH` event can be attributed without a
/// second lookup of a token you were told never to log ([N-39]).
final class RefreshFailure extends RefreshResult {
  const RefreshFailure(this.error, {this.userId, this.familyId});

  final NebulaError error;
  final String? userId;
  final String? familyId;

  @override
  bool get ok => false;
}

/// Outcome of [NebulaEngine.revokeToken] ([N-36]).
sealed class RevokeResult {
  const RevokeResult();

  bool get ok;
}

final class RevokeSuccess extends RevokeResult {
  const RevokeSuccess({
    required this.userId,
    required this.familyId,
    required this.revoked,
  });

  final String userId;
  final String familyId;

  /// Number of records the revocation changed.
  final int revoked;

  @override
  bool get ok => true;
}

/// [userId] and [familyId] are populated on a failure whenever the engine
/// resolved a record, exactly as in [RefreshFailure] — [N-39] governs every
/// failure result, not only [NebulaEngine.refresh]. [NebulaEngine.revokeToken]
/// resolves its record before proving the verifier, so a `VERIFIER_MISMATCH`
/// there is attributable and carries both; `MALFORMED`, `UNKNOWN_KID` and
/// `NOT_FOUND` never do.
final class RevokeFailure extends RevokeResult {
  const RevokeFailure(this.error, {this.userId, this.familyId});

  final NebulaError error;
  final String? userId;
  final String? familyId;

  @override
  bool get ok => false;
}

/// Parsed wire token (§2).
class ParsedToken {
  const ParsedToken({
    required this.kid,
    required this.selector,
    required this.verifier,
  });

  final String kid;
  final String selector;

  /// Raw 32 secret bytes. Never persist or log this ([N-14]).
  final Uint8List verifier;

  /// Never renders [verifier] ([N-14]).
  @override
  String toString() => 'ParsedToken(kid: $kid, selector: $selector)';
}

/// Thrown by the constructor and by [NebulaEngine.issue] for caller mistakes
/// ([N-12], §5). Extends [ArgumentError] so it is catchable by the idiomatic
/// Dart handler for an invalid argument.
class NebulaConfigError extends ArgumentError {
  NebulaConfigError(String message) : super('[NEBULA] $message');
}

// ─── Spec primitives (§2, §6.4) — pure, exported for conformance testing ─────

/// True iff every code unit is in the base64url alphabet, and the string is
/// non-empty.
///
/// Scanning code units rather than matching `RegExp(r'^[A-Za-z0-9_-]+$')` is
/// deliberate. `$` in several regex dialects also matches immediately before a
/// trailing newline, which would accept `"…{verifier}\n"` as well formed
/// (vector `p-24`). A code-unit scan has no such edge, is unaffected by locale
/// or case-folding settings ([N-9]), and rejects every non-ASCII code unit
/// including lone surrogates without decoding anything.
bool _isB64Url(String s) {
  if (s.isEmpty) return false;
  for (var i = 0; i < s.length; i++) {
    final int c = s.codeUnitAt(i);
    final bool ok =
        (c >= 0x41 && c <= 0x5A) || // A-Z
        (c >= 0x61 && c <= 0x7A) || // a-z
        (c >= 0x30 && c <= 0x39) || // 0-9
        c == 0x2D || // '-'
        c == 0x5F; // '_'
    if (!ok) return false;
  }
  return true;
}

/// UTF-8 byte length of [s] without materialising the encoding ([N-1]).
///
/// A lone surrogate has no UTF-8 encoding at all; Dart's encoder substitutes
/// U+FFFD (three bytes) instead of throwing, and this counts it the same way, so
/// the length check stays total ([N-8]) and agrees with the bytes that would
/// actually be hashed.
int _utf8ByteLength(String s) {
  var n = 0;
  for (var i = 0; i < s.length; i++) {
    final int c = s.codeUnitAt(i);
    if (c < 0x80) {
      n += 1;
    } else if (c < 0x800) {
      n += 2;
    } else if (c >= 0xD800 &&
        c <= 0xDBFF &&
        i + 1 < s.length &&
        s.codeUnitAt(i + 1) >= 0xDC00 &&
        s.codeUnitAt(i + 1) <= 0xDFFF) {
      n += 4;
      i++; // consume the low surrogate of the pair
    } else {
      n += 3;
    }
  }
  return n;
}

/// True iff [s] is valid Unicode, i.e. contains no unpaired surrogate ([N-12]).
bool _isWellFormedUnicode(String s) {
  for (var i = 0; i < s.length; i++) {
    final int c = s.codeUnitAt(i);
    if (c >= 0xD800 && c <= 0xDBFF) {
      final int next = i + 1 < s.length ? s.codeUnitAt(i + 1) : 0;
      if (next < 0xDC00 || next > 0xDFFF) return false;
      i++;
    } else if (c >= 0xDC00 && c <= 0xDFFF) {
      return false; // low surrogate with no high surrogate before it
    }
  }
  return true;
}

/// base64url (RFC 4648 §5), unpadded.
String b64urlEncode(List<int> data) =>
    base64Url.encode(data).replaceAll('=', '');

/// Decode unpadded base64url. Returns null instead of throwing on any input.
Uint8List? b64urlDecode(String data) {
  if (!_isB64Url(data)) return null;
  final String padded = data + '=' * ((4 - data.length % 4) % 4);
  try {
    return base64Url.decode(padded);
  } on FormatException {
    return null;
  }
}

/// Parse a wire token (§2, [N-5]..[N-9]).
///
/// Total: returns null for every malformation and never throws. The parameter is
/// nullable because a missing cookie or header is the commonest hostile input of
/// all; Dart's sound typing makes any other type a compile-time error rather
/// than something this function could be handed at run time ([N-8]).
ParsedToken? parseToken(String? token) {
  if (token == null || token.isEmpty) return null;

  // [N-6.1] byte length, before any other parsing work. `String.length` counts
  // UTF-16 code units and would disagree with the byte rule in [N-1].
  if (_utf8ByteLength(token) > maxTokenLength) return null;

  final List<String> parts = token.split('.');
  if (parts.length != 4) return null; // [N-6.2]

  final String kid = parts[1];
  final String selector = parts[2];
  final String verifierB64 = parts[3];

  if (parts[0] != prefix) return null; // [N-6.3] case-sensitive
  if (kid.isEmpty || selector.isEmpty || verifierB64.isEmpty) {
    return null; // [N-6.2]
  }

  // [N-6.5]/[N-6.6] exact lengths. The alphabet is ASCII-only and is checked
  // next, so character length and byte length coincide here.
  if (kid.length > maxKidLength) return null;
  if (selector.length != selectorChars) return null;
  if (verifierB64.length != verifierChars) return null;

  // [N-6.4] alphabet: rejects padding, whitespace, '+', '/' and all non-ASCII.
  if (!_isB64Url(kid)) return null;
  if (!_isB64Url(selector)) return null;
  if (!_isB64Url(verifierB64)) return null;

  // [N-6.7] the verifier must decode to exactly VERIFIER_BYTES bytes.
  final Uint8List? verifier = b64urlDecode(verifierB64);
  if (verifier == null || verifier.length != verifierBytes) {
    return null;
  }

  // [N-7] canonical encoding: a 32-byte value has four 43-character spellings
  // and only the minimal one is a NEBULA token.
  if (b64urlEncode(verifier) != verifierB64) return null;

  return ParsedToken(kid: kid, selector: selector, verifier: verifier);
}

/// verifierHash = lowercase hex `HMAC-SHA-256(pepper, verifier)` ([N-11], [N-13]).
String hashVerifier(String pepper, List<int> verifier) =>
    Hmac(sha256, utf8.encode(pepper)).convert(verifier).toString();

/// deviceIdHash = lowercase hex `HMAC-SHA-256(pepper, "device:" + deviceId)`
/// ([N-11], [N-13]). No normalisation, trimming or case folding is applied.
///
/// Throws [NebulaConfigError] when [deviceId] is not valid Unicode: Dart's UTF-8
/// encoder would silently substitute U+FFFD for an unpaired surrogate, and
/// hashing the replacement character would make the same identifier hash
/// differently across languages ([N-12]). Callers on the attacker-reachable path
/// must pre-check and treat the value as a binding failure instead.
String hashDeviceId(String pepper, String deviceId) {
  if (!_isWellFormedUnicode(deviceId)) {
    throw NebulaConfigError(
      'deviceId is not valid Unicode (unpaired surrogate)',
    );
  }
  return Hmac(
    sha256,
    utf8.encode(pepper),
  ).convert(utf8.encode('device:$deviceId')).toString();
}

bool _isLowerHex64(String s) {
  if (s.length != _hashHexChars) return false;
  for (var i = 0; i < s.length; i++) {
    final int c = s.codeUnitAt(i);
    if (!((c >= 0x30 && c <= 0x39) || (c >= 0x61 && c <= 0x66))) return false;
  }
  return true;
}

/// Constant-time comparison of two hex digests ([N-31]). Never throws.
///
/// The 64-lowercase-hex guard runs first and is what makes the comparison safe,
/// not merely fast: a lenient hex decode stops at the first invalid character
/// and silently compares decoded prefixes, so a stored hash that a CHAR column
/// space-padded, an ETL job upper-cased, or a narrow column truncated would keep
/// verifying instead of failing closed. The guard depends only on the *shape* of
/// the operands; the comparison of their contents below is branch-free.
bool constantTimeEqualHex(String aHex, String bHex) {
  if (!_isLowerHex64(aHex) || !_isLowerHex64(bHex)) return false;
  var diff = 0;
  for (var i = 0; i < _hashHexChars; i++) {
    diff |= aHex.codeUnitAt(i) ^ bHex.codeUnitAt(i);
  }
  return diff == 0;
}

// ─── Engine ──────────────────────────────────────────────────────────────────

int _systemClock() => DateTime.now().millisecondsSinceEpoch ~/ 1000;

class NebulaEngine {
  NebulaEngine({
    required Map<String, String> peppers,
    required String activeKid,
    required RefreshTokenStore store,
    int absoluteTtlSeconds = defaultAbsoluteTtl,
    int idleTtlSeconds = defaultIdleTtl,
    // See [N-30] for the security trade-off before raising this above 0.
    int reuseGraceSeconds = defaultReuseGrace,
    // Injectable clock, Unix seconds ([N-3]).
    int Function()? clock,
  }) : // [N-24] copy: mutating the caller's map afterwards must not change
       // behavior. Validation below reads the copy, never the caller's object.
       _peppers = Map<String, String>.unmodifiable(peppers),
       _activeKid = activeKid,
       _store = store,
       _absoluteTtl = absoluteTtlSeconds,
       _idleTtl = idleTtlSeconds,
       _reuseGrace = reuseGraceSeconds,
       _clock = clock ?? _systemClock {
    for (final MapEntry<String, String> entry in _peppers.entries) {
      // The kid travels on the wire, so it must satisfy the same production as
      // the parser enforces (§2) — otherwise the engine could mint a token it
      // cannot itself parse.
      if (!_isB64Url(entry.key) || _utf8ByteLength(entry.key) > maxKidLength) {
        throw NebulaConfigError(
          'kid "${entry.key}" must be 1-$maxKidLength bytes from [A-Za-z0-9_-]',
        );
      }
      // [N-11]: the HMAC key is the pepper encoded as UTF-8, so a string that
      // has no UTF-8 encoding — an unpaired surrogate, which arrives trivially
      // from a JSON secrets file or a lenient UTF-16 decode — is not a usable
      // key. Dart would silently substitute U+FFFD, Java substitutes '?' and
      // Python refuses; three different HMAC keys for the same configured
      // value. §5 resolves it by failing construction everywhere. The message
      // never quotes the secret ([N-14]).
      if (!_isWellFormedUnicode(entry.value)) {
        throw NebulaConfigError(
          'pepper "${entry.key}" must be a string with a UTF-8 encoding '
          '(no unpaired surrogate)',
        );
      }
      // Bytes of that UTF-8 encoding, not characters ([N-1], [N-11]):
      // "日本語日本語日本語日" is 10 characters but 30 bytes, and would be a
      // weaker key than the floor allows. The check above makes the count
      // exact: no substitution can inflate it.
      // The secret itself never appears in the message ([N-46]).
      if (_utf8ByteLength(entry.value) < minPepperLength) {
        throw NebulaConfigError(
          'pepper "${entry.key}" must be at least $minPepperLength bytes',
        );
      }
    }
    if (!_peppers.containsKey(activeKid)) {
      throw NebulaConfigError('activeKid "$activeKid" not present in peppers');
    }
    if (_absoluteTtl <= 0) {
      throw NebulaConfigError('absoluteTtlSeconds must be positive');
    }
    if (_idleTtl <= 0) {
      throw NebulaConfigError('idleTtlSeconds must be positive');
    }
    if (_reuseGrace < 0) {
      throw NebulaConfigError('reuseGraceSeconds must be non-negative');
    }
  }

  final Map<String, String> _peppers;
  final String _activeKid;
  final RefreshTokenStore _store;
  final int _absoluteTtl;
  final int _idleTtl;
  final int _reuseGrace;
  final int Function() _clock;

  /// Platform CSPRNG ([N-43]). `Random.secure()` throws where no secure source
  /// exists rather than silently degrading to a weaker generator.
  final Random _random = Random.secure();

  /// Issue the first token of a new family ([N-25]). Call at login.
  Future<IssueResult> issue(String userId, [String? deviceId]) async {
    if (deviceId != null && !_isWellFormedUnicode(deviceId)) {
      // [N-12] at issue the value comes from the application: surface the bug at
      // the call site rather than minting a binding nothing can ever satisfy.
      throw NebulaConfigError(
        'deviceId is not valid Unicode (unpaired surrogate)',
      );
    }
    final int now = _clock();
    final String familyId = _hex(_randomBytes(16));
    final int familyExpiresAt = now + _absoluteTtl;
    // A null deviceId leaves the family unbound; an empty string is a real
    // binding, and the two must stay distinguishable ([N-25]).
    final minted = _mint(
      userId: userId,
      familyId: familyId,
      generation: 0,
      deviceIdHash: deviceId == null
          ? null
          : hashDeviceId(_activePepper, deviceId),
      familyExpiresAt: familyExpiresAt,
      now: now,
    );
    // A failed insert propagates: no token for state that was not written
    // ([N-20]).
    await _store.insert(minted.record);
    return IssueResult(
      token: minted.token,
      userId: userId,
      familyId: familyId,
      generation: 0,
      expiresAt: familyExpiresAt,
      idleExpiresAt: minted.record.idleExpiresAt,
    );
  }

  /// Exchange a refresh token for its successor ([N-26]).
  ///
  /// The check order is normative and observable ([N-28]); do not reorder.
  Future<RefreshResult> refresh(String token, [String? deviceId]) async {
    // 1. Parse
    final ParsedToken? parsed = parseToken(token);
    if (parsed == null) return const RefreshFailure(NebulaError.malformed);

    // 2. Pepper lookup by the token's kid
    if (!_peppers.containsKey(parsed.kid)) {
      return const RefreshFailure(NebulaError.unknownKid);
    }

    // 3. Record lookup — keyed only on the selector ([N-45])
    final TokenRecord? record = await _store.findBySelector(parsed.selector);
    if (record == null) return const RefreshFailure(NebulaError.notFound);

    // 4. Verifier proof — pepper of the RECORD's kid, constant time
    final String? recordPepper = _peppers[record.kid];
    if (recordPepper == null) {
      return const RefreshFailure(NebulaError.unknownKid); // [N-27]
    }
    if (!constantTimeEqualHex(
      hashVerifier(recordPepper, parsed.verifier),
      record.verifierHash,
    )) {
      // [N-28] no family revocation here: knowing a selector alone must never be
      // enough to destroy a session.
      return _fail(NebulaError.verifierMismatch, record);
    }

    final int now = _clock();

    // 5. Reuse
    if (record.status == TokenStatus.rotated) {
      return _handleReuse(record, recordPepper, deviceId, now);
    }

    // 6. Revoked
    if (record.status == TokenStatus.revoked) {
      return _fail(NebulaError.revoked, record);
    }

    // 7-8. Expiry
    if (now >= record.familyExpiresAt) {
      await _store.revokeFamily(record.familyId);
      return _fail(NebulaError.expiredAbsolute, record);
    }
    if (now >= record.idleExpiresAt) {
      await _store.revokeFamily(record.familyId);
      return _fail(NebulaError.expiredIdle, record);
    }

    // 9. Sender binding — pepper of the RECORD's kid ([N-32])
    if (record.deviceIdHash != null &&
        !_deviceMatches(record, recordPepper, deviceId)) {
      await _store.revokeFamily(record.familyId);
      return _fail(NebulaError.deviceMismatch, record);
    }

    // 10. Rotate
    return _rotate(record, deviceId, now, TokenStatus.active, now);
  }

  /// Revoke the family a token belongs to ([N-36]).
  ///
  /// Authenticated: the verifier is proved exactly as in [refresh], because the
  /// selector is a public lookup key and must not by itself be a capability to
  /// terminate a session. Succeeds whatever the record's status, so a client can
  /// still log out with a token that was already rotated or revoked.
  ///
  /// Takes no device identifier and performs no sender-binding check ([N-36]
  /// specifies steps 1-4 of [N-26] and no sender-binding step), because logout
  /// must keep working for a client that can no longer produce its device
  /// identifier. The operation is already authenticated by the verifier proof.
  Future<RevokeResult> revokeToken(String token) async {
    final ParsedToken? parsed = parseToken(token);
    if (parsed == null) return const RevokeFailure(NebulaError.malformed);
    if (!_peppers.containsKey(parsed.kid)) {
      return const RevokeFailure(NebulaError.unknownKid);
    }

    final TokenRecord? record = await _store.findBySelector(parsed.selector);
    if (record == null) return const RevokeFailure(NebulaError.notFound);

    final String? recordPepper = _peppers[record.kid];
    if (recordPepper == null) {
      return const RevokeFailure(NebulaError.unknownKid); // [N-27]
    }
    if (!constantTimeEqualHex(
      hashVerifier(recordPepper, parsed.verifier),
      record.verifierHash,
    )) {
      // [N-39]: the record was resolved above, so this refusal is attributable.
      // An unauthenticated attempt to terminate somebody's session is exactly
      // the event an operator needs to see, and the selector alone will not
      // identify the victim.
      return RevokeFailure(
        NebulaError.verifierMismatch,
        userId: record.userId,
        familyId: record.familyId,
      );
    }
    // No sender-binding step ([N-36]): revocation takes no device identifier.

    final int revoked = await _store.revokeFamily(record.familyId);
    return RevokeSuccess(
      userId: record.userId,
      familyId: record.familyId,
      revoked: revoked,
    );
  }

  /// Revoke a whole family by its server-side identifier ([N-37]).
  /// Requires no token; the caller is responsible for authorising it.
  Future<int> revokeFamily(String familyId) => _store.revokeFamily(familyId);

  /// Revoke every session of a user ([N-37]).
  Future<int> revokeAllForUser(String userId) => _store.revokeUser(userId);

  // ── Private ────────────────────────────────────────────────────────────────

  RefreshFailure _fail(NebulaError error, TokenRecord record) =>
      RefreshFailure(error, userId: record.userId, familyId: record.familyId);

  Future<RefreshResult> _handleReuse(
    TokenRecord record,
    String recordPepper,
    String? deviceId,
    int now,
  ) async {
    final int? rotatedAt = record.rotatedAt;
    final String? replacedBy = record.replacedBySelector;

    // [N-30] preconditions 1-4 and 6. Condition 6 (now < familyExpiresAt) is
    // what stops a grace retry from minting a token past the absolute deadline.
    final bool withinGrace =
        _reuseGrace > 0 &&
        rotatedAt != null &&
        now - rotatedAt <= _reuseGrace &&
        replacedBy != null &&
        now < record.familyExpiresAt;

    if (withinGrace) {
      // Precondition 5: the successor exists and is still unused.
      final TokenRecord? successor = await _store.findBySelector(replacedBy);
      if (successor != null && successor.status == TokenStatus.active) {
        if (record.deviceIdHash != null &&
            !_deviceMatches(record, recordPepper, deviceId)) {
          await _store.revokeFamily(record.familyId);
          return _fail(NebulaError.deviceMismatch, record);
        }
        // Compare-and-set: exactly one concurrent retry may consume the unused
        // successor. The loser rotates nothing and reports CONFLICT.
        if (!await _store.revokeIfActive(successor.selector)) {
          return _fail(NebulaError.conflict, record);
        }
        // Preserve the original rotatedAt: the window is anchored to the first
        // rotation and cannot be walked forward by repeated retries ([N-30]).
        return _rotate(record, deviceId, now, TokenStatus.rotated, rotatedAt);
      }
    }

    await _store.revokeFamily(record.familyId);
    return _fail(NebulaError.reuseDetected, record);
  }

  Future<RefreshResult> _rotate(
    TokenRecord record,
    String? deviceId,
    int now,
    TokenStatus fromStatus,
    int rotatedAt,
  ) async {
    final minted = _mint(
      userId: record.userId,
      familyId: record.familyId,
      generation: record.generation + 1,
      // Re-hash with the ACTIVE pepper — migrates the binding forward across
      // pepper rotation ([N-33] step 4).
      deviceIdHash: record.deviceIdHash != null && deviceId != null
          ? hashDeviceId(_activePepper, deviceId)
          : record.deviceIdHash,
      familyExpiresAt: record.familyExpiresAt,
      now: now,
    );

    await _store.insert(minted.record);

    final bool applied = await _store.markRotated(
      record.selector,
      fromStatus,
      rotatedAt,
      minted.record.selector,
    );
    if (!applied) {
      // [N-34] step 5: a concurrent refresh won the compare-and-set. Clean up
      // the successor we inserted and report a retryable conflict — never a
      // token, and nothing beyond that successor is revoked ([N-35]).
      await _store.revokeIfActive(minted.record.selector);
      return _fail(NebulaError.conflict, record);
    }

    return RefreshSuccess(
      token: minted.token,
      userId: record.userId,
      familyId: record.familyId,
      generation: minted.record.generation,
      expiresAt: minted.record.familyExpiresAt,
      idleExpiresAt: minted.record.idleExpiresAt,
    );
  }

  /// Mint a token and its record ([N-33]).
  ({String token, TokenRecord record}) _mint({
    required String userId,
    required String familyId,
    required int generation,
    required String? deviceIdHash,
    required int familyExpiresAt,
    required int now,
  }) {
    final Uint8List verifier = _randomBytes(verifierBytes);
    final String selector = b64urlEncode(_randomBytes(selectorBytes));
    final TokenRecord record = TokenRecord(
      selector: selector,
      verifierHash: hashVerifier(_activePepper, verifier),
      kid: _activeKid,
      familyId: familyId,
      generation: generation,
      userId: userId,
      deviceIdHash: deviceIdHash,
      createdAt: now,
      familyExpiresAt: familyExpiresAt,
      idleExpiresAt: min(now + _idleTtl, familyExpiresAt),
    );
    return (
      token: '$prefix.$_activeKid.$selector.${b64urlEncode(verifier)}',
      record: record,
    );
  }

  bool _deviceMatches(
    TokenRecord record,
    String recordPepper,
    String? deviceId,
  ) {
    final String? expected = record.deviceIdHash;
    // A missing device identifier against a bound record fails ([N-32]).
    if (deviceId == null || expected == null) return false;
    // [N-12] on the attacker-reachable path an invalid device identifier is a
    // binding failure, never an exception.
    if (!_isWellFormedUnicode(deviceId)) return false;
    return constantTimeEqualHex(hashDeviceId(recordPepper, deviceId), expected);
  }

  String get _activePepper => _peppers[_activeKid]!;

  Uint8List _randomBytes(int n) {
    final Uint8List out = Uint8List(n);
    for (var i = 0; i < n; i++) {
      out[i] = _random.nextInt(256);
    }
    return out;
  }

  String _hex(List<int> bytes) {
    final StringBuffer sb = StringBuffer();
    for (final int b in bytes) {
      sb.write(b.toRadixString(16).padLeft(2, '0'));
    }
    return sb.toString();
  }
}

// ─── In-memory store — development and tests ONLY ───────────────────────────

/// Reference store ([N-21]).
///
/// Every method below is an `async` function whose body contains no `await`, so
/// it runs to completion synchronously on the calling isolate's turn: no other
/// microtask can observe a half-applied write, which is exactly what makes
/// [markRotated] and [revokeIfActive] genuine compare-and-sets under Dart's
/// normal request concurrency ([N-17], [N-18]). Isolates do not share this
/// state, so a multi-isolate server needs a real store.
///
/// NOT FOR PRODUCTION: state is per-process and lost on restart, so reuse
/// detection does not survive a deploy and does not work behind more than one
/// instance. Implement [RefreshTokenStore] over your database instead — see
/// docs/STORE.md and `example/sql_store_example.dart`.
class MemoryRefreshTokenStore implements RefreshTokenStore {
  final Map<String, TokenRecord> _rows = <String, TokenRecord>{};

  @override
  Future<TokenRecord?> findBySelector(String selector) async =>
      _rows[selector]?.copy();

  @override
  Future<void> insert(TokenRecord record) async {
    if (_rows.containsKey(record.selector)) {
      throw StateError('[NEBULA] duplicate selector ${record.selector}');
    }
    _rows[record.selector] = record.copy();
  }

  @override
  Future<bool> markRotated(
    String selector,
    TokenStatus fromStatus,
    int rotatedAt,
    String replacedBySelector,
  ) async {
    final TokenRecord? row = _rows[selector];
    if (row == null || row.status != fromStatus) return false;
    row.status = TokenStatus.rotated;
    row.rotatedAt = rotatedAt;
    row.replacedBySelector = replacedBySelector;
    return true;
  }

  @override
  Future<bool> revokeIfActive(String selector) async {
    final TokenRecord? row = _rows[selector];
    if (row == null || row.status != TokenStatus.active) return false;
    row.status = TokenStatus.revoked;
    return true;
  }

  @override
  Future<int> revokeFamily(String familyId) async {
    var n = 0;
    for (final TokenRecord row in _rows.values) {
      if (row.familyId == familyId && row.status != TokenStatus.revoked) {
        row.status = TokenStatus.revoked;
        n++;
      }
    }
    return n;
  }

  @override
  Future<int> revokeUser(String userId) async {
    var n = 0;
    for (final TokenRecord row in _rows.values) {
      if (row.userId == userId && row.status != TokenStatus.revoked) {
        row.status = TokenStatus.revoked;
        n++;
      }
    }
    return n;
  }

  /// Test helper: every record currently stored. Not part of the store contract.
  List<TokenRecord> all() =>
      _rows.values.map((TokenRecord r) => r.copy()).toList();

  /// Test helper: drop records whose family deadline has passed ([N-15]).
  /// Deleting rotated or revoked rows any earlier disables reuse detection.
  int deleteExpired(int now) {
    final List<String> dead = <String>[
      for (final MapEntry<String, TokenRecord> e in _rows.entries)
        if (now >= e.value.familyExpiresAt) e.key,
    ];
    for (final String selector in dead) {
      _rows.remove(selector);
    }
    return dead.length;
  }
}
