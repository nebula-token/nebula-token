/// Normative behavioral suite — spec/behavior-vectors.json
/// (SPECIFICATION.md [N-47], [N-49]).
///
/// Every scenario is a published vector, not a hand-written case, so this suite
/// cannot silently drift from the other nine implementations.
library;

import 'package:nebula_token/nebula_token.dart' as nt;
import 'package:test/test.dart';

import 'behavior_runner.dart';

void main() {
  final BehaviorVectors vectors = loadBehaviorVectors();

  test('the package implements the spec version the vectors were cut from', () {
    expect(nt.specVersion, vectors.specVersion);
  });

  test('behavior vectors: every applicable scenario passes', () async {
    final RunOutcome outcome = await runBehaviorVectors(vectors);

    // [N-48]: a runner that silently iterated nothing must not report success.
    expect(
      outcome.executed.length + outcome.skipped.length,
      vectors.scenarioCount,
      reason: 'every published scenario must be executed or explicitly skipped',
    );
    expect(
      outcome.executed.length,
      greaterThanOrEqualTo(vectors.unconditionalCount),
      reason: 'every unconditional scenario must be executed',
    );

    // Dart strings are UTF-16, so the one conditional scenario applies here too
    // and nothing is inapplicable. Skips are reported by id when they happen.
    expect(
      outcome.skipped,
      isEmpty,
      reason: 'skipped scenarios: ${outcome.skipped}',
    );
  });

  group('behavior vectors: each scenario in isolation', () {
    for (final Scenario scenario in vectors.scenarios) {
      final String? condition = scenario.condition;
      test(
        '${scenario.id} — ${scenario.title}',
        () async {
          final RunOutcome outcome = await runBehaviorVectors(
            vectors.withOnly(scenario),
          );
          expect(outcome.executed, <String>[scenario.id]);
        },
        skip: condition != null && !satisfiedConditions.contains(condition)
            ? 'runtime does not satisfy "$condition"'
            : null,
      );
    }
  });
}
