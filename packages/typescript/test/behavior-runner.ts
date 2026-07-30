/**
 * Runner for the normative behavioral suite, spec/behavior-vectors.json
 * (SPECIFICATION.md [N-47], [N-49]).
 *
 * The scenarios are data. This file is the only thing that is language-specific,
 * which is what stops the ten ports from drifting apart the way ten
 * hand-written suites did.
 */

import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import {
  MemoryRefreshTokenStore,
  NebulaEngine,
  type IssueResult,
  type RefreshResult,
  type RefreshTokenStore,
  type TokenRecord,
  type TokenStatus,
} from '../src/index.ts';

const SPEC_DIR = join(dirname(fileURLToPath(import.meta.url)), '../../../spec');

export interface BehaviorVectors {
  spec_version: number;
  counts: { scenarios: number; unconditional: number };
  peppers: Record<string, string>;
  defaults: {
    now: number;
    absoluteTtlSeconds: number;
    idleTtlSeconds: number;
    reuseGraceSeconds: number;
    activeKid: string;
    peppers: string[];
  };
  scenarios: Scenario[];
}

interface Scenario {
  id: string;
  title: string;
  requirements: string[];
  condition?: string;
  config?: Partial<BehaviorVectors['defaults']>;
  steps: Step[];
}

interface TokenRef {
  ref?: string;
  literal?: string;
  forge?: 'verifier' | 'unknownKid' | 'unknownSelector';
}

interface Expect {
  ok?: boolean;
  error?: string;
  generation?: number;
  kid?: string;
  sameFamilyAs?: string;
  sameExpiresAtAs?: string;
  idleEqualsExpires?: boolean;
  hasUserId?: boolean;
  hasFamilyId?: boolean;
  revoked?: number;
}

/**
 * [N-39] attribution, tri-state. `true` demands the field, `false` demands its
 * absence — the exclusion list (MALFORMED, UNKNOWN_KID, NOT_FOUND) is a
 * requirement too, and a truthy-only check could never observe it. Absent
 * means the scenario does not assert it.
 */
function checkAttribution(
  res: { userId?: string; familyId?: string },
  exp: Expect | undefined,
  scenario: string,
  i: number,
): void {
  if (exp?.hasUserId !== undefined && (res.userId !== undefined) !== exp.hasUserId) {
    fail(scenario, i, `expected userId ${exp.hasUserId ? 'present' : 'absent'} ([N-39])`);
  }
  if (exp?.hasFamilyId !== undefined && (res.familyId !== undefined) !== exp.hasFamilyId) {
    fail(scenario, i, `expected familyId ${exp.hasFamilyId ? 'present' : 'absent'} ([N-39])`);
  }
}

interface Step {
  op: string;
  userId?: string;
  deviceId?: string;
  deviceIdKind?: 'lone-surrogate';
  token?: TokenRef;
  bind?: string;
  of?: string;
  seconds?: number;
  method?: 'markRotated' | 'revokeIfActive';
  peppers?: string[];
  activeKid?: string;
  counts?: Record<TokenStatus, number>;
  expect?: Expect;
}

export function loadBehaviorVectors(): BehaviorVectors {
  return JSON.parse(readFileSync(join(SPEC_DIR, 'behavior-vectors.json'), 'utf8')) as BehaviorVectors;
}

/**
 * Conditions this runtime satisfies. JavaScript strings are UTF-16 sequences
 * and can hold an unpaired surrogate, so the invalid-Unicode scenario applies.
 */
const SATISFIED_CONDITIONS = new Set(['runtime-admits-invalid-unicode-strings']);

/** 32 zero bytes, canonically encoded: well-formed, and never the real secret. */
const FORGED_VERIFIER = 'A'.repeat(43);
const FORGED_SELECTOR = 'A'.repeat(22);
const LONE_SURROGATE = '\uD800';

/** Wraps the reference store so a scenario can force one compare-and-set to lose. */
class ControllableStore implements RefreshTokenStore {
  readonly inner = new MemoryRefreshTokenStore();
  private failNext: Partial<Record<'markRotated' | 'revokeIfActive', boolean>> = {};

  failNextCas(method: 'markRotated' | 'revokeIfActive'): void {
    this.failNext[method] = true;
  }

  findBySelector(selector: string): Promise<TokenRecord | null> {
    return this.inner.findBySelector(selector);
  }

  insert(record: TokenRecord): Promise<void> {
    return this.inner.insert(record);
  }

  async markRotated(
    selector: string,
    fromStatus: TokenStatus,
    rotatedAt: number,
    replacedBySelector: string,
  ): Promise<boolean> {
    if (this.failNext.markRotated) {
      this.failNext.markRotated = false;
      return false;
    }
    return this.inner.markRotated(selector, fromStatus, rotatedAt, replacedBySelector);
  }

  async revokeIfActive(selector: string): Promise<boolean> {
    if (this.failNext.revokeIfActive) {
      this.failNext.revokeIfActive = false;
      return false;
    }
    return this.inner.revokeIfActive(selector);
  }

  revokeFamily(familyId: string): Promise<number> {
    return this.inner.revokeFamily(familyId);
  }

  revokeUser(userId: string): Promise<number> {
    return this.inner.revokeUser(userId);
  }
}

interface Binding {
  token: string;
  familyId: string;
  expiresAt: number;
}

export interface RunOutcome {
  executed: string[];
  skipped: { id: string; condition: string }[];
}

function fail(scenario: Scenario, index: number, message: string): never {
  throw new Error(`[${scenario.id}] step ${index} (${scenario.requirements.join(', ')}): ${message}`);
}

/** Execute every applicable scenario. Throws on the first divergence. */
export async function runBehaviorVectors(vectors: BehaviorVectors): Promise<RunOutcome> {
  const outcome: RunOutcome = { executed: [], skipped: [] };

  for (const scenario of vectors.scenarios) {
    if (scenario.condition && !SATISFIED_CONDITIONS.has(scenario.condition)) {
      outcome.skipped.push({ id: scenario.id, condition: scenario.condition });
      continue;
    }
    await runScenario(vectors, scenario);
    outcome.executed.push(scenario.id);
  }
  return outcome;
}

/**
 * Execute one scenario's steps against a fresh engine and store.
 *
 * typescript:S3776 measures cognitive complexity 97 here, against a threshold of
 * 15, and the measurement is accurate. It is suppressed rather than refactored,
 * and the reason is the artefact this file is:
 *
 * The `switch` below is an interpreter for the step vocabulary published in
 * `spec/behavior-vectors.json` under `runner.ops`. Each `case` is one entry of
 * that table, in the same order, and a reviewer checking that this runtime
 * implements the vectors correctly reads the two side by side. That one-to-one
 * correspondence is the only thing making a conformance runner auditable; a
 * dispatch over a published op vocabulary is branchy by construction, and the
 * branching is the specification's, not this file's.
 *
 * Extracting one function per op was considered and rejected. The ops share a
 * single mutable scenario state — `engine`, `store`, `bindings`, `issuedSecrets`,
 * `deviceIds`, `now` — and two of them mutate the bindings the rest read, while
 * `reconfigure` *reassigns* `engine` and `advance` reassigns `now`. Extracted
 * functions cannot do either without a context object threaded through all ten,
 * so the result would be ten functions with an identical parameter list, the
 * same total branching redistributed, and a dispatch table that no longer looks
 * like the vector format. The parts that *can* be lifted without that cost
 * already have been: `resolveToken`, `deviceOf`, `checkSuccess` and `build`.
 *
 * The same call is recorded in the other nine ports, so the ten runners stay
 * comparable line for line; see sonar-project.properties.
 */
// NOSONAR must sit on the DECLARATION line, not on a line of its own above it:
// it suppresses only issues whose primary location is the line carrying it, and
// S3776 is reported on the function declaration.
async function runScenario(vectors: BehaviorVectors, scenario: Scenario): Promise<void> { // NOSONAR(typescript:S3776) — vector-format dispatch; see the note above.
  const cfg = { ...vectors.defaults, ...scenario.config };
  const store = new ControllableStore();
  const bindings = new Map<string, Binding>();
  const issuedSecrets: string[] = [];
  const deviceIds = new Set<string>();
  let now = cfg.now;

  const build = (kids: string[], activeKid: string): NebulaEngine =>
    new NebulaEngine({
      peppers: Object.fromEntries(kids.map((k) => [k, vectors.peppers[k]!])),
      activeKid,
      store,
      absoluteTtlSeconds: cfg.absoluteTtlSeconds,
      idleTtlSeconds: cfg.idleTtlSeconds,
      reuseGraceSeconds: cfg.reuseGraceSeconds,
      clock: () => now,
    });

  let engine = build(cfg.peppers, cfg.activeKid);

  const resolveToken = (ref: TokenRef | undefined, scen: Scenario, i: number): string => {
    if (ref?.literal !== undefined) return ref.literal;
    if (ref?.ref === undefined) fail(scen, i, 'step has no token reference');
    const bound = bindings.get(ref.ref);
    if (!bound) fail(scen, i, `unknown binding "${ref.ref}"`);
    if (!ref.forge) return bound.token;
    const parts = bound.token.split('.');
    if (ref.forge === 'verifier') parts[3] = FORGED_VERIFIER;
    else if (ref.forge === 'unknownKid') parts[1] = 'zz';
    else if (ref.forge === 'unknownSelector') parts[2] = FORGED_SELECTOR;
    return parts.join('.');
  };

  const deviceOf = (step: Step): string | undefined =>
    step.deviceIdKind === 'lone-surrogate' ? LONE_SURROGATE : step.deviceId;

  const checkSuccess = (
    res: IssueResult | Extract<RefreshResult, { ok: true }>,
    exp: Expect | undefined,
    scen: Scenario,
    i: number,
  ): void => {
    if (!exp) return;
    if (exp.generation !== undefined && res.generation !== exp.generation) {
      fail(scen, i, `expected generation ${exp.generation}, got ${res.generation}`);
    }
    if (exp.kid !== undefined) {
      const kid = res.token.split('.')[1];
      if (kid !== exp.kid) fail(scen, i, `expected kid ${exp.kid}, got ${kid}`);
    }
    if (exp.sameFamilyAs !== undefined) {
      const other = bindings.get(exp.sameFamilyAs);
      if (res.familyId !== other?.familyId) fail(scen, i, 'familyId changed across rotation');
    }
    if (exp.sameExpiresAtAs !== undefined) {
      const other = bindings.get(exp.sameExpiresAtAs);
      if (res.expiresAt !== other?.expiresAt) {
        fail(scen, i, `absolute deadline moved: ${other?.expiresAt} -> ${res.expiresAt}`);
      }
    }
    if (exp.idleEqualsExpires && res.idleExpiresAt !== res.expiresAt) {
      fail(scen, i, `idleExpiresAt ${res.idleExpiresAt} should be clamped to ${res.expiresAt}`);
    }
  };

  for (const [i, step] of scenario.steps.entries()) {
    const exp = step.expect;

    switch (step.op) {
      case 'issue': {
        const deviceId = deviceOf(step);
        const res = await engine.issue(step.userId!, deviceId);
        if (exp?.ok === false) fail(scenario, i, 'expected issue to fail');
        checkSuccess(res, exp, scenario, i);
        if (step.bind) {
          bindings.set(step.bind, { token: res.token, familyId: res.familyId, expiresAt: res.expiresAt });
        }
        issuedSecrets.push(res.token.split('.')[3]!);
        if (deviceId !== undefined && deviceId !== '') deviceIds.add(deviceId);
        break;
      }

      case 'refresh': {
        const res = await engine.refresh(resolveToken(step.token, scenario, i), deviceOf(step));
        if (exp?.ok === true || (exp?.ok === undefined && exp?.error === undefined)) {
          if (!res.ok) fail(scenario, i, `expected success, got ${res.error}`);
          checkSuccess(res, exp, scenario, i);
          if (step.bind) {
            bindings.set(step.bind, { token: res.token, familyId: res.familyId, expiresAt: res.expiresAt });
          }
          issuedSecrets.push(res.token.split('.')[3]!);
        } else {
          if (res.ok) fail(scenario, i, `expected ${exp?.error}, got success`);
          if (res.error !== exp?.error) fail(scenario, i, `expected ${exp?.error}, got ${res.error}`);
          checkAttribution(res, exp, scenario, i);
        }
        break;
      }

      case 'revokeToken': {
        const res = await engine.revokeToken(resolveToken(step.token, scenario, i));
        if (exp?.ok === false) {
          if (res.ok) fail(scenario, i, `expected ${exp.error}, got success`);
          if (res.error !== exp.error) fail(scenario, i, `expected ${exp.error}, got ${res.error}`);
          // [N-39] governs every failure result, revokeToken's included.
          checkAttribution(res, exp, scenario, i);
        } else {
          if (!res.ok) fail(scenario, i, `expected success, got ${res.error}`);
          if (exp?.revoked !== undefined && res.revoked !== exp.revoked) {
            fail(scenario, i, `expected ${exp.revoked} revoked, got ${res.revoked}`);
          }
        }
        break;
      }

      case 'revokeFamilyOf': {
        const bound = bindings.get(step.of!);
        const n = await engine.revokeFamily(bound!.familyId);
        if (exp?.revoked !== undefined && n !== exp.revoked) {
          fail(scenario, i, `expected ${exp.revoked} revoked, got ${n}`);
        }
        break;
      }

      case 'revokeUser': {
        const n = await engine.revokeAllForUser(step.userId!);
        if (exp?.revoked !== undefined && n !== exp.revoked) {
          fail(scenario, i, `expected ${exp.revoked} revoked, got ${n}`);
        }
        break;
      }

      case 'advance':
        now += step.seconds!;
        break;

      case 'reconfigure':
        engine = build(step.peppers!, step.activeKid!);
        break;

      case 'failNextCas':
        store.failNextCas(step.method!);
        break;

      case 'expectStatusCounts': {
        const actual: Record<string, number> = { active: 0, rotated: 0, revoked: 0 };
        for (const r of store.inner.all()) actual[r.status]! += 1;
        for (const [status, want] of Object.entries(step.counts!)) {
          if (actual[status] !== want) {
            fail(scenario, i, `expected ${want} ${status}, got ${actual[status]} (${JSON.stringify(actual)})`);
          }
        }
        break;
      }

      case 'expectNoRawSecrets': {
        const dump = JSON.stringify(store.inner.all());
        for (const secret of issuedSecrets) {
          if (dump.includes(secret)) fail(scenario, i, 'a raw verifier reached the store ([N-14])');
        }
        for (const deviceId of deviceIds) {
          if (dump.includes(deviceId)) fail(scenario, i, 'a raw device identifier reached the store ([N-14])');
        }
        break;
      }

      default:
        fail(scenario, i, `unknown op "${step.op}"`);
    }
  }
}
