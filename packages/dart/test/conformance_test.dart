/// Shared conformance vectors — spec/test-vectors.json (SPECIFICATION.md [N-47]).
library;

import 'dart:convert';
import 'dart:io';

import 'package:nebula_token/nebula_token.dart' as nt;
import 'package:test/test.dart';

/// Locate `spec/` by walking up from the package directory to the repository
/// root, so the vectors are read from the single published copy and the path
/// survives being run from anywhere ([N-49] — the vectors are shared data, not
/// a per-package fixture to be copied and left to rot).
File _specFile(String name) {
  for (Directory d = Directory.current.absolute; ; d = d.parent) {
    final File f = File('${d.path}/spec/$name');
    if (f.existsSync()) return f;
    if (d.parent.path == d.path) {
      throw StateError('spec/$name not found above ${Directory.current.path}');
    }
  }
}

void main() {
  final Map<String, Object?> vectors =
      jsonDecode(_specFile('test-vectors.json').readAsStringSync())
          as Map<String, Object?>;
  final Map<String, Object?> counts =
      vectors['counts']! as Map<String, Object?>;

  List<Map<String, Object?>> section(String name) {
    final Object? raw = vectors[name];
    // [N-48]: a missing or empty section is a conformance failure, not a pass.
    expect(raw, isA<List<Object?>>(), reason: 'section "$name" is absent');
    final List<Object?> list = raw! as List<Object?>;
    expect(list, isNotEmpty, reason: 'section "$name" is empty');
    return list.cast<Map<String, Object?>>();
  }

  test('spec version matches the published vectors', () {
    expect(nt.specVersion, vectors['spec_version']);
  });

  test('constants match the specification', () {
    final Map<String, Object?> c =
        vectors['constants']! as Map<String, Object?>;
    expect(nt.prefix, c['prefix']);
    expect(nt.selectorBytes, c['selector_bytes']);
    expect(nt.verifierBytes, c['verifier_bytes']);
    expect(nt.selectorChars, c['selector_chars']);
    expect(nt.verifierChars, c['verifier_chars']);
    expect(nt.maxKidLength, c['max_kid_length']);
    expect(nt.maxTokenLength, c['max_token_length']);
    expect(nt.minPepperLength, c['min_pepper_length']);
    expect(nt.defaultAbsoluteTtl, c['default_absolute_ttl_seconds']);
    expect(nt.defaultIdleTtl, c['default_idle_ttl_seconds']);
    expect(nt.defaultReuseGrace, c['default_reuse_grace_seconds']);
    // [N-48]: every published constant is compared, not only the ones we
    // remembered to list above.
    expect(c.keys.toSet(), <String>{
      'prefix',
      'selector_bytes',
      'verifier_bytes',
      'selector_chars',
      'verifier_chars',
      'max_kid_length',
      'max_token_length',
      'min_pepper_length',
      'default_absolute_ttl_seconds',
      'default_idle_ttl_seconds',
      'default_reuse_grace_seconds',
    }, reason: 'a constant was published but never asserted');
  });

  test('verifier hashing vectors', () {
    var n = 0;
    for (final Map<String, Object?> v in section('verifier_hashing')) {
      final List<int> verifier = nt.b64urlDecode(
        v['verifier_b64url']! as String,
      )!;
      expect(
        nt.hashVerifier(v['pepper']! as String, verifier),
        v['expected_hmac_sha256_hex'],
        reason: '${v['id']}: ${v['note']}',
      );
      n++;
    }
    expect(
      n,
      counts['verifier_hashing'],
      reason: 'executed count must equal published count ([N-48])',
    );
  });

  test('device hashing vectors', () {
    var n = 0;
    for (final Map<String, Object?> v in section('device_hashing')) {
      expect(
        nt.hashDeviceId(v['pepper']! as String, v['device_id']! as String),
        v['expected_hmac_sha256_hex'],
        reason: '${v['id']}: ${v['note']}',
      );
      n++;
    }
    expect(
      n,
      counts['device_hashing'],
      reason: 'executed count must equal published count ([N-48])',
    );
  });

  test('parsing vectors', () {
    var n = 0;
    for (final Map<String, Object?> v in section('parsing')) {
      final nt.ParsedToken? parsed = nt.parseToken(v['token']! as String);
      if (v['valid']! as bool) {
        expect(
          parsed,
          isNotNull,
          reason: '${v['id']} should parse: ${v['note']}',
        );
        expect(parsed!.kid, v['kid'], reason: '${v['id']}');
        expect(parsed.selector, v['selector'], reason: '${v['id']}');
        expect(parsed.verifier.length, nt.verifierBytes, reason: '${v['id']}');
      } else {
        expect(
          parsed,
          isNull,
          reason: '${v['id']} should be MALFORMED (${v['rule']}): ${v['note']}',
        );
      }
      n++;
    }
    expect(
      n,
      counts['parsing'],
      reason: 'executed count must equal published count ([N-48])',
    );
  });

  test('parsing is total: nothing raises ([N-8])', () {
    // Dart's sound typing makes a non-String argument a compile-time error, so
    // the reachable hostile inputs are null, degenerate strings, and strings
    // that are not valid Unicode.
    final List<String?> hostile = <String?>[
      null,
      '',
      ' ',
      '.' * 1000,
      'nbl.${'k' * 10000}',
      'nbl.k1.${' ' * 22}.${'A' * 43}',
      '\uD800', // lone high surrogate: no UTF-8 encoding exists
      'nbl.k1.${'\uDC00' * 22}.${'A' * 43}', // lone low surrogates
      'nbl.k1.${'A' * 22}.${'A' * 43} ',
    ];
    for (final String? input in hostile) {
      expect(
        nt.parseToken(input),
        isNull,
        reason: 'input: ${jsonEncode(input)}',
      );
    }
  });
}
