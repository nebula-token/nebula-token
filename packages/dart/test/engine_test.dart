/// Language-specific tests: properties that cannot be expressed as portable
/// behavior vectors. All cross-language behavior lives in
/// spec/behavior-vectors.json and is exercised by behavior_test.dart.
library;

import 'package:nebula_token/nebula_token.dart';
import 'package:test/test.dart';

const String pepper = 'pepper-one-0123456789abcdef0123456789ab';
const String hash =
    'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
    'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';

class _Clock {
  int now = 1700000000;

  int call() => now;
}

/// Fails one named store method with an infrastructure error, as a driver whose
/// connection died would ([N-20]).
class ExplodingStore implements RefreshTokenStore {
  ExplodingStore(this.failOn);

  final String failOn;
  final MemoryRefreshTokenStore inner = MemoryRefreshTokenStore();

  Future<T> _guard<T>(String method, Future<T> Function() run) =>
      method == failOn
      ? Future<T>.error(StateError('database is on fire'))
      : run();

  @override
  Future<TokenRecord?> findBySelector(String s) =>
      _guard('findBySelector', () => inner.findBySelector(s));

  @override
  Future<void> insert(TokenRecord r) => _guard('insert', () => inner.insert(r));

  @override
  Future<bool> markRotated(String s, TokenStatus f, int t, String n) =>
      _guard('markRotated', () => inner.markRotated(s, f, t, n));

  @override
  Future<bool> revokeIfActive(String s) =>
      _guard('revokeIfActive', () => inner.revokeIfActive(s));

  @override
  Future<int> revokeFamily(String f) =>
      _guard('revokeFamily', () => inner.revokeFamily(f));

  @override
  Future<int> revokeUser(String u) =>
      _guard('revokeUser', () => inner.revokeUser(u));
}

NebulaEngine explodingEngine(String failOn) => NebulaEngine(
  peppers: <String, String>{'k1': pepper},
  activeKid: 'k1',
  store: ExplodingStore(failOn),
);

({NebulaEngine engine, MemoryRefreshTokenStore store, _Clock clock})
makeEngine({
  int absoluteTtlSeconds = defaultAbsoluteTtl,
  int idleTtlSeconds = defaultIdleTtl,
  int reuseGraceSeconds = defaultReuseGrace,
}) {
  final MemoryRefreshTokenStore store = MemoryRefreshTokenStore();
  final _Clock clock = _Clock();
  return (
    engine: NebulaEngine(
      peppers: <String, String>{'k1': pepper},
      activeKid: 'k1',
      store: store,
      absoluteTtlSeconds: absoluteTtlSeconds,
      idleTtlSeconds: idleTtlSeconds,
      reuseGraceSeconds: reuseGraceSeconds,
      clock: clock.call,
    ),
    store: store,
    clock: clock,
  );
}

void main() {
  // ── Constant-time comparison ([N-31]) ─────────────────────────────────────

  test(
    'constantTimeEqualHex rejects anything but 64 lowercase hex characters',
    () {
      expect(constantTimeEqualHex(hash, hash), isTrue);
      expect(constantTimeEqualHex(hash, 'b' * 64), isFalse);

      // A lenient hex decode stops at the first invalid character and compares
      // decoded prefixes, so every case below would otherwise compare EQUAL.
      expect(
        constantTimeEqualHex('abc', 'abd'),
        isFalse,
        reason: 'odd-length prefixes',
      );
      expect(
        constantTimeEqualHex(hash, '$hash   '),
        isFalse,
        reason: 'space-padded CHAR column',
      );
      expect(
        constantTimeEqualHex(hash, '$hash\n'),
        isFalse,
        reason: 'trailing newline',
      );
      expect(
        constantTimeEqualHex(hash, '${hash}zzzz'),
        isFalse,
        reason: 'junk suffix',
      );
      expect(
        constantTimeEqualHex(hash, hash.toUpperCase()),
        isFalse,
        reason: 'case is not folded',
      );
      expect(
        constantTimeEqualHex(hash.toUpperCase(), hash.toUpperCase()),
        isFalse,
        reason: 'an upper-cased column never verifies, not even against itself',
      );
      expect(
        constantTimeEqualHex(hash.substring(0, 63), hash.substring(0, 63)),
        isFalse,
        reason: 'truncated column',
      );
      expect(
        constantTimeEqualHex('', ''),
        isFalse,
        reason: 'empty is never equal',
      );
    },
  );

  test('constantTimeEqualHex never throws, whatever it is handed', () {
    for (final String hostile in <String>[
      '',
      ' ' * 64,
      'zz',
      '\u0000' * 64, // NUL characters
      '\uD800' * 64, // lone surrogates
      '0x${'a' * 62}',
    ]) {
      expect(constantTimeEqualHex(hostile, hash), isFalse);
      expect(constantTimeEqualHex(hash, hostile), isFalse);
      expect(constantTimeEqualHex(hostile, hostile), isFalse);
    }
  });

  test(
    'a stored hash corrupted after the fact fails closed instead of verifying',
    () async {
      final e = makeEngine();
      final IssueResult issued = await e.engine.issue('u1');
      final TokenRecord row = e.store.all().single;

      // Same record, but the column was upper-cased by an ETL job.
      const String twin = 'xxxxxxxxxxxxxxxxxxxxxx';
      await e.store.insert(
        TokenRecord(
          selector: twin,
          verifierHash: row.verifierHash.toUpperCase(),
          kid: row.kid,
          familyId: row.familyId,
          generation: row.generation,
          userId: row.userId,
          deviceIdHash: row.deviceIdHash,
          createdAt: row.createdAt,
          familyExpiresAt: row.familyExpiresAt,
          idleExpiresAt: row.idleExpiresAt,
        ),
      );

      final List<String> parts = issued.token.split('.');
      parts[2] = twin;
      final RefreshResult res = await e.engine.refresh(parts.join('.'));
      expect(res, isA<RefreshFailure>());
      expect((res as RefreshFailure).error, NebulaError.verifierMismatch);
    },
  );

  // ── Concurrency ([N-17], [N-34], [N-35]) ──────────────────────────────────
  //
  // These are the tests the behavior vectors cannot express: the vectors force
  // a compare-and-set to lose, whereas here the loss is produced by genuine
  // interleaving. Each `await` inside `refresh` yields the isolate, so two
  // in-flight refreshes really do observe the same `active` record before
  // either writes.

  test(
    'two concurrent refreshes of the same token never fork the family',
    () async {
      final e = makeEngine();
      final IssueResult issued = await e.engine.issue('u1');

      final List<RefreshResult> results = await Future.wait(
        <Future<RefreshResult>>[
          e.engine.refresh(issued.token),
          e.engine.refresh(issued.token),
        ],
      );

      expect(
        results.whereType<RefreshSuccess>().length,
        1,
        reason: 'exactly one refresh may win',
      );
      expect(
        results.whereType<RefreshFailure>().map((RefreshFailure r) => r.error),
        everyElement(NebulaError.conflict),
      );
      expect(
        e.store
            .all()
            .where((TokenRecord r) => r.status == TokenStatus.active)
            .length,
        1,
        reason: 'the family must not fork into two live lineages',
      );
    },
  );

  test(
    'a burst of concurrent refreshes still leaves exactly one active record',
    () async {
      final e = makeEngine();
      final IssueResult issued = await e.engine.issue('u1');

      final List<RefreshResult> results = await Future.wait(
        <Future<RefreshResult>>[
          for (var i = 0; i < 16; i++) e.engine.refresh(issued.token),
        ],
      );

      expect(results.whereType<RefreshSuccess>().length, 1);
      expect(
        results.whereType<RefreshFailure>().map((RefreshFailure r) => r.error),
        everyElement(NebulaError.conflict),
      );
      expect(
        e.store
            .all()
            .where((TokenRecord r) => r.status == TokenStatus.active)
            .length,
        1,
      );
      // The 15 losers each cleaned up the successor they had already inserted
      // ([N-34] step 5): nothing is left dangling and nothing else was revoked.
      expect(
        e.store
            .all()
            .where((TokenRecord r) => r.status == TokenStatus.revoked)
            .length,
        15,
      );
      expect(
        e.store
            .all()
            .where((TokenRecord r) => r.status == TokenStatus.rotated)
            .length,
        1,
      );
    },
  );

  test(
    'concurrent grace retries: exactly one consumes the unused successor',
    () async {
      final e = makeEngine(reuseGraceSeconds: 60);
      final IssueResult issued = await e.engine.issue('u1');
      expect(await e.engine.refresh(issued.token), isA<RefreshSuccess>());

      final List<RefreshResult> results = await Future.wait(
        <Future<RefreshResult>>[
          e.engine.refresh(issued.token),
          e.engine.refresh(issued.token),
        ],
      );

      expect(results.whereType<RefreshSuccess>().length, 1);
      expect(
        results.whereType<RefreshFailure>().map((RefreshFailure r) => r.error),
        everyElement(NebulaError.conflict),
      );
      expect(
        e.store
            .all()
            .where((TokenRecord r) => r.status == TokenStatus.active)
            .length,
        1,
      );
    },
  );

  // ── Store failures fail closed ([N-20]) ───────────────────────────────────

  test(
    'a failing insert must not hand back a token for state never written',
    () async {
      expect(
        () => explodingEngine('insert').issue('u1'),
        throwsA(isA<StateError>()),
      );
    },
  );

  test(
    'a failing revokeFamily must not be reported as a successful revocation',
    () async {
      final NebulaEngine engine = explodingEngine('revokeFamily');
      final IssueResult issued = await engine.issue('u1');
      expect(await engine.refresh(issued.token), isA<RefreshSuccess>());
      // The replay must attempt a family revocation; the error propagates rather
      // than being swallowed into a confident REUSE_DETECTED.
      expect(
        () => engine.refresh(issued.token),
        throwsA(isA<StateError>()),
        reason: 'infrastructure failures use the native error channel ([N-20])',
      );
    },
  );

  test('a failing markRotated is an error, not a CONFLICT', () async {
    final NebulaEngine engine = explodingEngine('markRotated');
    final IssueResult issued = await engine.issue('u1');
    expect(() => engine.refresh(issued.token), throwsA(isA<StateError>()));
  });

  test('a failing revokeUser must not report a revocation count', () async {
    expect(
      () => explodingEngine('revokeUser').revokeAllForUser('u1'),
      throwsA(isA<StateError>()),
    );
  });

  // ── Configuration (§5, [N-23], [N-24]) ────────────────────────────────────

  test('constructor validation', () {
    void bad(
      Map<String, String> peppers,
      String activeKid, {
      int absolute = defaultAbsoluteTtl,
      int idle = defaultIdleTtl,
      int grace = defaultReuseGrace,
    }) {
      expect(
        () => NebulaEngine(
          peppers: peppers,
          activeKid: activeKid,
          store: MemoryRefreshTokenStore(),
          absoluteTtlSeconds: absolute,
          idleTtlSeconds: idle,
          reuseGraceSeconds: grace,
        ),
        throwsA(isA<NebulaConfigError>()),
      );
    }

    bad(<String, String>{'k1': 'short'}, 'k1');
    bad(<String, String>{'k1': pepper}, 'nope');
    bad(<String, String>{'k.1': pepper}, 'k.1'); // '.' is not in the alphabet
    bad(<String, String>{'k+1': pepper}, 'k+1');
    bad(<String, String>{'': pepper}, '');
    bad(<String, String>{'k' * 65: pepper}, 'k' * 65);
    bad(<String, String>{'k1': pepper}, 'k1', absolute: 0);
    bad(<String, String>{'k1': pepper}, 'k1', idle: -5);
    bad(<String, String>{'k1': pepper}, 'k1', grace: -1);
    // [N-11] a pepper with no UTF-8 encoding is not a usable HMAC key. Both are
    // well over the byte floor, so only the encoding rule can reject them.
    bad(<String, String>{'k1': '\uD800\$pepper'}, 'k1');
    bad(<String, String>{'k1': '\$pepper\uDC00'}, 'k1');

    // A kid at exactly MAX_KID_LENGTH is legal (vector p-03).
    expect(
      () => NebulaEngine(
        peppers: <String, String>{'k' * 64: pepper},
        activeKid: 'k' * 64,
        store: MemoryRefreshTokenStore(),
      ),
      returnsNormally,
    );
  });

  test('NebulaConfigError is catchable as an ArgumentError', () {
    expect(
      () => NebulaEngine(
        peppers: <String, String>{'k1': 'short'},
        activeKid: 'k1',
        store: MemoryRefreshTokenStore(),
      ),
      throwsArgumentError,
    );
  });

  test('a config error never quotes the pepper it rejected ([N-46])', () {
    try {
      NebulaEngine(
        peppers: <String, String>{'k1': 'too-short-secret'},
        activeKid: 'k1',
        store: MemoryRefreshTokenStore(),
      );
      fail('expected a NebulaConfigError');
    } on NebulaConfigError catch (err) {
      expect(err.toString(), isNot(contains('too-short-secret')));
      expect(err.toString(), contains('k1'));
    }
  });

  test('MIN_PEPPER_LENGTH counts bytes, not characters ([N-1])', () {
    final String wide = '日' * 16; // 16 characters, 48 UTF-8 bytes
    expect(wide.length, 16);
    expect(
      () => NebulaEngine(
        peppers: <String, String>{'k1': wide},
        activeKid: 'k1',
        store: MemoryRefreshTokenStore(),
      ),
      returnsNormally,
    );

    final String narrow = '日' * 10; // 10 characters, 30 bytes — under the floor
    expect(narrow.length, 10);
    expect(
      () => NebulaEngine(
        peppers: <String, String>{'k1': narrow},
        activeKid: 'k1',
        store: MemoryRefreshTokenStore(),
      ),
      throwsA(isA<NebulaConfigError>()),
    );
    expect(
      () => NebulaEngine(
        peppers: <String, String>{'k1': 'a' * 31},
        activeKid: 'k1',
        store: MemoryRefreshTokenStore(),
      ),
      throwsA(isA<NebulaConfigError>()),
    );
  });

  test("the pepper map is copied: mutating the caller's map cannot weaken the "
      'engine ([N-24])', () async {
    final MemoryRefreshTokenStore store = MemoryRefreshTokenStore();
    final Map<String, String> peppers = <String, String>{'k1': pepper};
    final NebulaEngine engine = NebulaEngine(
      peppers: peppers,
      activeKid: 'k1',
      store: store,
    );

    peppers['k1'] = 'x'; // would otherwise key the HMAC with a one-byte secret
    peppers.remove('k1');

    final IssueResult issued = await engine.issue('u1');
    final ParsedToken parsed = parseToken(issued.token)!;
    expect(
      store.all().single.verifierHash,
      hashVerifier(pepper, parsed.verifier),
    );
    expect(await engine.refresh(issued.token), isA<RefreshSuccess>());
  });

  // ── Device identifiers ([N-11], [N-12], [N-14]) ───────────────────────────

  test(
    'issue rejects a device id that is not valid Unicode, at the call site',
    () {
      final e = makeEngine();
      expect(
        () => e.engine.issue('u1', '\uD800'),
        throwsA(isA<NebulaConfigError>()),
      );
    },
  );

  test('hashDeviceId refuses invalid Unicode rather than hashing U+FFFD', () {
    expect(
      () => hashDeviceId(pepper, '\uD800'),
      throwsA(isA<NebulaConfigError>()),
    );
    // The trap this guards: Dart's encoder substitutes the replacement
    // character silently, so both would otherwise hash identically ([N-12]).
    expect(hashDeviceId(pepper, '�'), isNot(hashDeviceId(pepper, 'x')));
  });

  test(
    'hashDeviceId applies no normalisation, trimming or case folding ([N-11])',
    () {
      expect(
        hashDeviceId(pepper, 'Café'),
        isNot(hashDeviceId(pepper, 'Café')),
        reason: 'NFC and NFD must not be conflated',
      );
      expect(hashDeviceId(pepper, 'x'), isNot(hashDeviceId(pepper, ' x')));
      expect(hashDeviceId(pepper, 'x'), isNot(hashDeviceId(pepper, 'X')));
      expect(hashDeviceId(pepper, ''), isNot(hashDeviceId(pepper, 'device:')));
    },
  );

  test(
    'no raw secret appears in anything the engine stores ([N-14])',
    () async {
      final e = makeEngine();
      final IssueResult issued = await e.engine.issue('u1', 'devA');
      final TokenRecord row = e.store.all().single;
      final String verifierPart = issued.token.split('.')[3];

      expect(row.verifierHash, isNot(contains(verifierPart)));
      expect(row.verifierHash, matches(RegExp(r'^[0-9a-f]{64}$')));
      expect(row.deviceIdHash, isNot(contains('devA')));
      expect(row.deviceIdHash, matches(RegExp(r'^[0-9a-f]{64}$')));
      expect(row.toString(), isNot(contains(verifierPart)));
      expect(row.toString(), isNot(contains('devA')));
      expect(row.toString(), isNot(contains(pepper)));

      final ParsedToken parsed = parseToken(issued.token)!;
      expect(parsed.toString(), isNot(contains(verifierPart)));
    },
  );

  // ── Result shape ([N-2], [N-39]) ──────────────────────────────────────────

  test('timestamps are integer unix seconds, not DateTime ([N-2])', () async {
    final e = makeEngine();
    final IssueResult issued = await e.engine.issue('u1');
    expect(issued.expiresAt, e.clock.now + defaultAbsoluteTtl);
    expect(issued.idleExpiresAt, e.clock.now + defaultIdleTtl);
    expect(issued.generation, 0);
    expect(issued.userId, 'u1');

    final RefreshResult res = await e.engine.refresh(issued.token);
    expect(res, isA<RefreshSuccess>());
    expect((res as RefreshSuccess).expiresAt, issued.expiresAt);
    expect(res.idleExpiresAt, e.clock.now + defaultIdleTtl);
  });

  test(
    'failures carry userId and familyId once a record is resolved ([N-39])',
    () async {
      final e = makeEngine();
      final IssueResult issued = await e.engine.issue('u1');
      await e.engine.refresh(issued.token);

      final RefreshResult replay = await e.engine.refresh(issued.token);
      expect(replay, isA<RefreshFailure>());
      expect((replay as RefreshFailure).userId, 'u1');
      expect(replay.familyId, issued.familyId);

      // Before a record is resolved there is nothing to attribute.
      final RefreshResult unknown = await e.engine.refresh('garbage');
      expect((unknown as RefreshFailure).userId, isNull);
      expect(unknown.familyId, isNull);
    },
  );

  test('every spec error code is present exactly once ([N-38])', () {
    expect(NebulaError.values.map((NebulaError e) => e.code).toList(), <String>[
      'MALFORMED',
      'UNKNOWN_KID',
      'NOT_FOUND',
      'VERIFIER_MISMATCH',
      'REUSE_DETECTED',
      'REVOKED',
      'EXPIRED_ABSOLUTE',
      'EXPIRED_IDLE',
      'DEVICE_MISMATCH',
      'CONFLICT',
    ]);
  });

  // ── Store hygiene ─────────────────────────────────────────────────────────

  test('the in-memory store refuses a duplicate selector', () async {
    final MemoryRefreshTokenStore store = MemoryRefreshTokenStore();
    TokenRecord row() => TokenRecord(
      selector: 'A' * 22,
      verifierHash: hash,
      kid: 'k1',
      familyId: 'f',
      generation: 0,
      userId: 'u1',
      deviceIdHash: null,
      createdAt: 0,
      familyExpiresAt: 1,
      idleExpiresAt: 1,
    );
    await store.insert(row());
    expect(() => store.insert(row()), throwsStateError);
  });

  test(
    'deleteExpired only removes records past the family deadline ([N-15])',
    () async {
      final e = makeEngine(absoluteTtlSeconds: 100, idleTtlSeconds: 100);
      final IssueResult issued = await e.engine.issue('u1');
      expect(await e.engine.refresh(issued.token), isA<RefreshSuccess>());

      expect(
        e.store.deleteExpired(e.clock.now + 99),
        0,
        reason: 'nothing may be dropped before the deadline',
      );
      expect(e.store.all().length, 2);
      expect(e.store.deleteExpired(e.clock.now + 100), 2);
    },
  );

  test('token shape and uniqueness', () async {
    final e = makeEngine();
    final Set<String> seen = <String>{};
    for (var i = 0; i < 100; i++) {
      final IssueResult issued = await e.engine.issue('u1');
      expect(seen.add(issued.token), isTrue);
      final ParsedToken? parsed = parseToken(issued.token);
      expect(parsed, isNotNull);
      expect(parsed!.kid, 'k1');
      expect(parsed.selector.length, selectorChars);
      expect(parsed.verifier.length, verifierBytes);
    }
  });
}
