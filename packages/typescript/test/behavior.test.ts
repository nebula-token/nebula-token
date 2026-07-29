/**
 * Normative behavioral suite — spec/behavior-vectors.json (SPECIFICATION.md [N-47]).
 *
 * Every scenario is a published vector, not a hand-written case, so this suite
 * cannot silently drift from the other nine implementations.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';

import { loadBehaviorVectors, runBehaviorVectors } from './behavior-runner.ts';

const vectors = loadBehaviorVectors();

test('behavior vectors: every applicable scenario passes', async () => {
  const outcome = await runBehaviorVectors(vectors);

  // [N-48]: a runner that silently iterated nothing must not report success.
  assert.equal(
    outcome.executed.length + outcome.skipped.length,
    vectors.counts.scenarios,
    'every published scenario must be either executed or explicitly skipped',
  );
  assert.ok(outcome.executed.length >= vectors.counts.unconditional,
    'every unconditional scenario must be executed');

  // This runtime's strings are UTF-16, so nothing should be skipped here.
  assert.deepEqual(outcome.skipped, [], 'no scenario is inapplicable to Node.js');
});

test('behavior vectors: each scenario runs in isolation and is individually named', async () => {
  for (const scenario of vectors.scenarios) {
    await test(scenario.id, async () => {
      const single = { ...vectors, scenarios: [scenario], counts: { scenarios: 1, unconditional: 1 } };
      const outcome = await runBehaviorVectors(single);
      assert.equal(outcome.executed.length + outcome.skipped.length, 1);
    });
  }
});
