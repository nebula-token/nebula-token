/// Runner for the normative behavioral suite, spec/behavior-vectors.json
/// (SPECIFICATION.md [N-47], [N-49]).
///
/// The scenarios are data. This file is the only thing that is language
/// specific, which is what stops the ten ports from drifting apart the way ten
/// hand-written suites did.
library;

import 'dart:convert';
import 'dart:io';

import 'package:nebula_token/nebula_token.dart';

/// Locate `spec/` by walking up from the package directory to the repository
/// root. The vectors are shared, published data ([N-49]); a package that copied
/// them into itself would silently stop tracking the specification.
File _specFile(String name) {
  for (Directory d = Directory.current.absolute; ; d = d.parent) {
    final File f = File('${d.path}/spec/$name');
    if (f.existsSync()) return f;
    if (d.parent.path == d.path) {
      throw StateError('spec/$name not found above ${Directory.current.path}');
    }
  }
}

// ─── Vector model ────────────────────────────────────────────────────────────

class BehaviorVectors {
  BehaviorVectors(this.raw);

  final Map<String, Object?> raw;

  int get specVersion => raw['spec_version']! as int;

  Map<String, Object?> get counts => raw['counts']! as Map<String, Object?>;

  int get scenarioCount => counts['scenarios']! as int;

  int get unconditionalCount => counts['unconditional']! as int;

  Map<String, String> get peppers =>
      (raw['peppers']! as Map<String, Object?>).cast<String, String>();

  Map<String, Object?> get defaults => raw['defaults']! as Map<String, Object?>;

  List<Scenario> get scenarios => <Scenario>[
    for (final Object? s in raw['scenarios']! as List<Object?>)
      Scenario(s! as Map<String, Object?>),
  ];

  /// A single-scenario view, so each scenario can also run in isolation.
  BehaviorVectors withOnly(Scenario scenario) =>
      BehaviorVectors(<String, Object?>{
        ...raw,
        'scenarios': <Object?>[scenario.raw],
        'counts': <String, Object?>{'scenarios': 1, 'unconditional': 1},
      });
}

class Scenario {
  Scenario(this.raw);

  final Map<String, Object?> raw;

  String get id => raw['id']! as String;

  String get title => raw['title']! as String;

  String? get condition => raw['condition'] as String?;

  List<String> get requirements =>
      (raw['requirements']! as List<Object?>).cast<String>();

  Map<String, Object?> get config =>
      (raw['config'] as Map<String, Object?>?) ?? const <String, Object?>{};

  List<Map<String, Object?>> get steps => <Map<String, Object?>>[
    for (final Object? s in raw['steps']! as List<Object?>)
      s! as Map<String, Object?>,
  ];
}

BehaviorVectors loadBehaviorVectors() => BehaviorVectors(
  jsonDecode(_specFile('behavior-vectors.json').readAsStringSync())
      as Map<String, Object?>,
);

// ─── Runtime capabilities ────────────────────────────────────────────────────

/// Conditions this runtime satisfies (`runner.conditions` in the vectors). Dart
/// strings are UTF-16 code-unit sequences and can hold an unpaired surrogate, so
/// the invalid-Unicode scenario applies here and is executed, not skipped.
const Set<String> satisfiedConditions = <String>{
  'runtime-admits-invalid-unicode-strings',
};

/// 32 zero bytes, canonically encoded: well formed, and never the real secret.
const String _forgedVerifier = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';
const String _forgedSelector = 'AAAAAAAAAAAAAAAAAAAAAA';
const String _loneSurrogate = '\uD800';

// ─── Store wrapper ───────────────────────────────────────────────────────────

/// Wraps the reference store so a scenario can force one compare-and-set to
/// lose. That is how `conflict-01` and `conflict-02` reproduce a lost race
/// deterministically, without depending on scheduler timing.
class ControllableStore implements RefreshTokenStore {
  final MemoryRefreshTokenStore inner = MemoryRefreshTokenStore();
  final Set<String> _failNext = <String>{};

  void failNextCas(String method) => _failNext.add(method);

  @override
  Future<TokenRecord?> findBySelector(String selector) =>
      inner.findBySelector(selector);

  @override
  Future<void> insert(TokenRecord record) => inner.insert(record);

  @override
  Future<bool> markRotated(
    String selector,
    TokenStatus fromStatus,
    int rotatedAt,
    String replacedBySelector,
  ) async {
    if (_failNext.remove('markRotated')) return false;
    return inner.markRotated(
      selector,
      fromStatus,
      rotatedAt,
      replacedBySelector,
    );
  }

  @override
  Future<bool> revokeIfActive(String selector) async {
    if (_failNext.remove('revokeIfActive')) return false;
    return inner.revokeIfActive(selector);
  }

  @override
  Future<int> revokeFamily(String familyId) => inner.revokeFamily(familyId);

  @override
  Future<int> revokeUser(String userId) => inner.revokeUser(userId);
}

// ─── Execution ───────────────────────────────────────────────────────────────

class _Binding {
  _Binding(this.token, this.familyId, this.expiresAt);

  final String token;
  final String familyId;
  final int expiresAt;
}

class RunOutcome {
  final List<String> executed = <String>[];

  /// scenario id → the condition that was not satisfied.
  final Map<String, String> skipped = <String, String>{};
}

class BehaviorVectorFailure implements Exception {
  BehaviorVectorFailure(this.message);

  final String message;

  @override
  String toString() => message;
}

/// Execute every applicable scenario. Throws on the first divergence.
Future<RunOutcome> runBehaviorVectors(BehaviorVectors vectors) async {
  final RunOutcome outcome = RunOutcome();
  for (final Scenario scenario in vectors.scenarios) {
    final String? condition = scenario.condition;
    if (condition != null && !satisfiedConditions.contains(condition)) {
      outcome.skipped[scenario.id] = condition;
      continue;
    }
    await _runScenario(vectors, scenario);
    outcome.executed.add(scenario.id);
  }
  return outcome;
}

Never _fail(Scenario scenario, int index, String message) {
  throw BehaviorVectorFailure(
    '[${scenario.id}] step $index '
    '(${scenario.requirements.join(', ')}): $message',
  );
}

/// [N-39] attribution, tri-state. `true` demands the field, `false` demands its
/// absence — the exclusion list (`MALFORMED`, `UNKNOWN_KID`, `NOT_FOUND`) is a
/// requirement too, and a truthy-only check could never observe it. Absent
/// means the scenario does not assert it. Both failure types declare the fields
/// nullable, so "absent" reads as null on either branch.
void _checkAttribution(
  String? userId,
  String? familyId,
  Map<String, Object?>? expect,
  Scenario scenario,
  int i,
) {
  final bool? wantUserId = expect?['hasUserId'] as bool?;
  if (wantUserId != null && (userId != null) != wantUserId) {
    _fail(
      scenario,
      i,
      'expected userId ${wantUserId ? 'present' : 'absent'} ([N-39])',
    );
  }
  final bool? wantFamilyId = expect?['hasFamilyId'] as bool?;
  if (wantFamilyId != null && (familyId != null) != wantFamilyId) {
    _fail(
      scenario,
      i,
      'expected familyId ${wantFamilyId ? 'present' : 'absent'} ([N-39])',
    );
  }
}

String _describe(RefreshResult r) =>
    r is RefreshFailure ? r.error.code : 'success';

String _describeRevoke(RevokeResult r) =>
    r is RevokeFailure ? r.error.code : 'success';

Future<void> _runScenario(BehaviorVectors vectors, Scenario scenario) async {
  final Map<String, Object?> cfg = <String, Object?>{
    ...vectors.defaults,
    ...scenario.config,
  };
  final ControllableStore store = ControllableStore();
  final Map<String, _Binding> bindings = <String, _Binding>{};
  final List<String> issuedSecrets = <String>[];
  final Set<String> deviceIds = <String>{};
  var now = cfg['now']! as int;

  NebulaEngine build(List<String> kids, String activeKid) => NebulaEngine(
    peppers: <String, String>{
      for (final String k in kids) k: vectors.peppers[k]!,
    },
    activeKid: activeKid,
    store: store,
    absoluteTtlSeconds: cfg['absoluteTtlSeconds']! as int,
    idleTtlSeconds: cfg['idleTtlSeconds']! as int,
    reuseGraceSeconds: cfg['reuseGraceSeconds']! as int,
    clock: () => now,
  );

  NebulaEngine engine = build(
    (cfg['peppers']! as List<Object?>).cast<String>(),
    cfg['activeKid']! as String,
  );

  String resolveToken(Map<String, Object?> step, int i) {
    final Map<String, Object?>? ref = step['token'] as Map<String, Object?>?;
    if (ref == null) _fail(scenario, i, 'step has no token reference');
    final String? literal = ref['literal'] as String?;
    if (literal != null) return literal;
    final String? name = ref['ref'] as String?;
    if (name == null) _fail(scenario, i, 'step has no token reference');
    final _Binding? bound = bindings[name];
    if (bound == null) _fail(scenario, i, 'unknown binding "$name"');
    final String? forge = ref['forge'] as String?;
    if (forge == null) return bound.token;
    final List<String> parts = bound.token.split('.');
    if (forge == 'verifier') {
      parts[3] = _forgedVerifier;
    } else if (forge == 'unknownKid') {
      parts[1] = 'zz';
    } else if (forge == 'unknownSelector') {
      parts[2] = _forgedSelector;
    } else {
      _fail(scenario, i, 'unknown forge "$forge"');
    }
    return parts.join('.');
  }

  String? deviceOf(Map<String, Object?> step) =>
      step['deviceIdKind'] == 'lone-surrogate'
      ? _loneSurrogate
      : step['deviceId'] as String?;

  void checkSuccess({
    required Map<String, Object?>? expect,
    required int i,
    required String token,
    required String familyId,
    required int generation,
    required int expiresAt,
    required int idleExpiresAt,
  }) {
    if (expect == null) return;
    final Object? wantGeneration = expect['generation'];
    if (wantGeneration != null && generation != wantGeneration) {
      _fail(
        scenario,
        i,
        'expected generation $wantGeneration, got $generation',
      );
    }
    final Object? wantKid = expect['kid'];
    if (wantKid != null) {
      final String kid = token.split('.')[1];
      if (kid != wantKid) _fail(scenario, i, 'expected kid $wantKid, got $kid');
    }
    final Object? sameFamilyAs = expect['sameFamilyAs'];
    if (sameFamilyAs != null && familyId != bindings[sameFamilyAs]?.familyId) {
      _fail(scenario, i, 'familyId changed across rotation');
    }
    final Object? sameExpiresAtAs = expect['sameExpiresAtAs'];
    if (sameExpiresAtAs != null) {
      final int? other = bindings[sameExpiresAtAs]?.expiresAt;
      if (expiresAt != other) {
        _fail(scenario, i, 'absolute deadline moved: $other -> $expiresAt');
      }
    }
    if (expect['idleEqualsExpires'] == true && idleExpiresAt != expiresAt) {
      _fail(
        scenario,
        i,
        'idleExpiresAt $idleExpiresAt should be clamped to $expiresAt',
      );
    }
  }

  void bind(
    Map<String, Object?> step,
    String token,
    String familyId,
    int expiresAt,
  ) {
    final String? name = step['bind'] as String?;
    if (name != null) bindings[name] = _Binding(token, familyId, expiresAt);
    issuedSecrets.add(token.split('.')[3]);
  }

  final List<Map<String, Object?>> steps = scenario.steps;
  for (var i = 0; i < steps.length; i++) {
    final Map<String, Object?> step = steps[i];
    final Map<String, Object?>? expect =
        step['expect'] as Map<String, Object?>?;
    final String? wantError = expect?['error'] as String?;
    final Object? wantRevoked = expect?['revoked'];

    switch (step['op']! as String) {
      case 'issue':
        {
          final String? deviceId = deviceOf(step);
          final IssueResult res = await engine.issue(
            step['userId']! as String,
            deviceId,
          );
          if (expect?['ok'] == false) {
            _fail(scenario, i, 'expected issue to fail');
          }
          checkSuccess(
            expect: expect,
            i: i,
            token: res.token,
            familyId: res.familyId,
            generation: res.generation,
            expiresAt: res.expiresAt,
            idleExpiresAt: res.idleExpiresAt,
          );
          bind(step, res.token, res.familyId, res.expiresAt);
          if (deviceId != null && deviceId.isNotEmpty) deviceIds.add(deviceId);
        }

      case 'refresh':
        {
          final RefreshResult res = await engine.refresh(
            resolveToken(step, i),
            deviceOf(step),
          );
          final bool wantOk =
              expect?['ok'] == true ||
              (expect?['ok'] == null && wantError == null);
          if (wantOk) {
            if (res is! RefreshSuccess) {
              _fail(scenario, i, 'expected success, got ${_describe(res)}');
            }
            checkSuccess(
              expect: expect,
              i: i,
              token: res.token,
              familyId: res.familyId,
              generation: res.generation,
              expiresAt: res.expiresAt,
              idleExpiresAt: res.idleExpiresAt,
            );
            bind(step, res.token, res.familyId, res.expiresAt);
          } else {
            if (res is! RefreshFailure) {
              _fail(scenario, i, 'expected $wantError, got success');
            }
            if (res.error.code != wantError) {
              _fail(scenario, i, 'expected $wantError, got ${res.error.code}');
            }
            _checkAttribution(res.userId, res.familyId, expect, scenario, i);
          }
        }

      case 'revokeToken':
        {
          final RevokeResult res = await engine.revokeToken(
            resolveToken(step, i),
          );
          if (expect?['ok'] == false) {
            if (res is! RevokeFailure) {
              _fail(scenario, i, 'expected $wantError, got success');
            }
            if (res.error.code != wantError) {
              _fail(scenario, i, 'expected $wantError, got ${res.error.code}');
            }
            // [N-39] governs every failure result, revokeToken's included.
            _checkAttribution(res.userId, res.familyId, expect, scenario, i);
          } else {
            if (res is! RevokeSuccess) {
              _fail(
                scenario,
                i,
                'expected success, got ${_describeRevoke(res)}',
              );
            }
            if (wantRevoked != null && res.revoked != wantRevoked) {
              _fail(
                scenario,
                i,
                'expected $wantRevoked revoked, got ${res.revoked}',
              );
            }
          }
        }

      case 'revokeFamilyOf':
        {
          final _Binding? bound = bindings[step['of']! as String];
          if (bound == null) {
            _fail(scenario, i, 'unknown binding "${step['of']}"');
          }
          final int n = await engine.revokeFamily(bound.familyId);
          if (wantRevoked != null && n != wantRevoked) {
            _fail(scenario, i, 'expected $wantRevoked revoked, got $n');
          }
        }

      case 'revokeUser':
        {
          final int n = await engine.revokeAllForUser(
            step['userId']! as String,
          );
          if (wantRevoked != null && n != wantRevoked) {
            _fail(scenario, i, 'expected $wantRevoked revoked, got $n');
          }
        }

      case 'advance':
        now += step['seconds']! as int;

      case 'reconfigure':
        // A new engine over the SAME store: that is what a pepper rotation
        // looks like from the outside.
        engine = build(
          (step['peppers']! as List<Object?>).cast<String>(),
          step['activeKid']! as String,
        );

      case 'expectStatusCounts':
        {
          final Map<String, int> actual = <String, int>{
            'active': 0,
            'rotated': 0,
            'revoked': 0,
          };
          for (final TokenRecord r in store.inner.all()) {
            actual[r.status.name] = actual[r.status.name]! + 1;
          }
          final Map<String, Object?> want =
              step['counts']! as Map<String, Object?>;
          for (final MapEntry<String, Object?> e in want.entries) {
            if (actual[e.key] != e.value) {
              _fail(
                scenario,
                i,
                'expected ${e.value} ${e.key}, got ${actual[e.key]} ($actual)',
              );
            }
          }
        }

      case 'failNextCas':
        store.failNextCas(step['method']! as String);

      case 'expectNoRawSecrets':
        {
          // Everything the store was handed, as one haystack. A record holds
          // only hashes; a raw verifier or device id appearing here would mean
          // the engine leaked a secret into persistence ([N-14]).
          final String dump = store.inner
              .all()
              .map(
                (TokenRecord r) => <Object?>[
                  r.selector,
                  r.verifierHash,
                  r.kid,
                  r.familyId,
                  r.userId,
                  r.deviceIdHash,
                  r.replacedBySelector,
                ].join(' '),
              )
              .join(' ');
          for (final String secret in issuedSecrets) {
            if (dump.contains(secret)) {
              _fail(scenario, i, 'a raw verifier reached the store ([N-14])');
            }
          }
          for (final String deviceId in deviceIds) {
            if (dump.contains(deviceId)) {
              _fail(
                scenario,
                i,
                'a raw device identifier reached the store ([N-14])',
              );
            }
          }
        }

      default:
        _fail(scenario, i, 'unknown op "${step['op']}"');
    }
  }
}
