#!/usr/bin/env node
//
// scripts/validate-vectors.mjs — gate on the conformance artefacts themselves.
//
//   node scripts/validate-vectors.mjs
//
// Ten implementations are checked against spec/test-vectors.json and
// spec/behavior-vectors.json. Nothing, until now, checked those two files. A
// vector file can be wrong in ways that make every implementation agree and all
// of them wrong: a truncated array, a duplicated id masking a case that is never
// run, a citation of a requirement that was renumbered out of existence, a
// constant that drifted from the specification table.
//
// This script asserts, and exits non-zero on the first category that fails:
//
//   1. both files validate against their JSON Schemas (draft 2020-12, via ajv);
//   2. every declared `counts` entry equals the actual array length;
//   3. every case id is unique, within its file and across both;
//   4. every [N-*] requirement cited by either file exists in SPECIFICATION.md,
//      and every sub-rule index (N-6.4) is within that requirement's list;
//   5. `spec_version` agrees across both files and SPECIFICATION.md;
//   6. the `constants` block equals the table in SPECIFICATION.md section 1;
//   7. every scenario's bindings are defined before use and every `condition`
//      names a documented condition;
//   8. spec/traceability.json, which SPECIFICATION.md promises, is in step with
//      the vectors (regenerate with: node scripts/build-traceability.mjs).

import { readFileSync, existsSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join, resolve } from "node:path";
import { createRequire } from "node:module";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const require = createRequire(import.meta.url);

const problems = [];
const fail = (section, msg) => problems.push(`[${section}] ${msg}`);
const readText = (p) => readFileSync(join(ROOT, p), "utf8");
const readJson = (p) => JSON.parse(readText(p));

// ---------------------------------------------------------------- inputs

const SPEC = readText("SPECIFICATION.md");
const tv = readJson("spec/test-vectors.json");
const bv = readJson("spec/behavior-vectors.json");

// ------------------------------------------------- 1. schema validation

let Ajv2020, addFormats;
try {
  Ajv2020 = require("ajv/dist/2020.js").default ?? require("ajv/dist/2020.js");
  addFormats = require("ajv-formats").default ?? require("ajv-formats");
} catch {
  console.error("validate-vectors: ajv is not installed.\n  cd scripts && npm ci");
  process.exit(2);
}

// strictRequired is disabled deliberately: both schemas discriminate on the
// presence of a key (`if: { required: ["error"] }`, `oneOf` over ref/literal),
// which is exactly the idiom that lint flags as a probable typo. Every other
// strict check stays on, and the negative self-test below proves the schemas
// actually reject what they claim to reject.
const ajv = new Ajv2020({ allErrors: true, strict: true, strictRequired: false });
addFormats(ajv);

const validators = {};

for (const [dataPath, schemaPath, data] of [
  ["spec/test-vectors.json", "spec/test-vectors.schema.json", tv],
  ["spec/behavior-vectors.json", "spec/behavior-vectors.schema.json", bv],
]) {
  // The data file names its schema relatively; honour that rather than
  // hard-coding, so the two can never point at different files.
  const declared = data.$schema;
  const expected = "./" + schemaPath.split("/").pop();
  if (declared !== expected) {
    fail("schema", `${dataPath} declares $schema ${JSON.stringify(declared)}, expected ${JSON.stringify(expected)}`);
  }
  let validate;
  try {
    validate = ajv.compile(readJson(schemaPath));
  } catch (e) {
    fail("schema", `${schemaPath} is not a valid schema: ${e.message}`);
    continue;
  }
  validators[dataPath] = validate;
  if (!validate(data)) {
    for (const err of validate.errors.slice(0, 25)) {
      fail("schema", `${dataPath}${err.instancePath || " (root)"} ${err.message}` +
        (err.params && Object.keys(err.params).length ? ` ${JSON.stringify(err.params)}` : ""));
    }
    if (validate.errors.length > 25) {
      fail("schema", `${dataPath}: ${validate.errors.length - 25} further errors suppressed`);
    }
  }
}

// ---------------------------------------- 1b. the schemas must actually bite
//
// A schema that accepts everything passes silently forever. Each mutation below
// is a defect a reviewer could plausibly miss; the schema is required to reject
// it. This is what makes the gate worth having.

const MUTATIONS = [
  ["spec/test-vectors.json", "unknown key in a parsing case", (d) => { d.parsing[0].expected = "yes"; }],
  ["spec/test-vectors.json", "uppercase hex in an expected hash", (d) => { d.verifier_hashing[0].expected_hmac_sha256_hex = d.verifier_hashing[0].expected_hmac_sha256_hex.toUpperCase(); }],
  ["spec/test-vectors.json", "truncated hash", (d) => { d.device_hashing[0].expected_hmac_sha256_hex = "abc123"; }],
  ["spec/test-vectors.json", "rejected token that names no rule", (d) => { delete d.parsing.find((c) => !c.valid).rule; }],
  ["spec/test-vectors.json", "accepted token that also names a rule", (d) => { d.parsing.find((c) => c.valid).rule = "N-6.1"; }],
  ["spec/test-vectors.json", "case with no note", (d) => { delete d.parsing[0].note; }],
  ["spec/behavior-vectors.json", "misspelled op", (d) => { d.scenarios[0].steps[0].op = "isue"; }],
  ["spec/behavior-vectors.json", "unknown field on a step", (d) => { d.scenarios[0].steps[0].devicedId = "typo"; }],
  ["spec/behavior-vectors.json", "error code outside [N-38]", (d) => { const s = d.scenarios.flatMap((x) => x.steps).find((x) => x.expect?.error); s.expect.error = "EXPIRED"; }],
  ["spec/behavior-vectors.json", "failure expectation without a code", (d) => { const s = d.scenarios.flatMap((x) => x.steps).find((x) => x.expect?.error); delete s.expect.error; }],
  ["spec/behavior-vectors.json", "scenario citing no requirement", (d) => { d.scenarios[0].requirements = []; }],
  ["spec/behavior-vectors.json", "token that is both a ref and a literal", (d) => { const s = d.scenarios.flatMap((x) => x.steps).find((x) => x.token?.ref); s.token.literal = "nbl.x.y.z"; }],
  ["spec/behavior-vectors.json", "partial status assertion", (d) => { const s = d.scenarios.flatMap((x) => x.steps).find((x) => x.op === "expectStatusCounts"); delete s.counts.rotated; }],
  ["spec/behavior-vectors.json", "advance with no seconds", (d) => { const s = d.scenarios.flatMap((x) => x.steps).find((x) => x.op === "advance"); delete s.seconds; }],
];

let bites = 0;
for (const [dataPath, what, mutate] of MUTATIONS) {
  const validate = validators[dataPath];
  if (!validate) continue;
  const copy = JSON.parse(readText(dataPath));
  try {
    mutate(copy);
  } catch (e) {
    fail("schema-selftest", `could not apply mutation "${what}" to ${dataPath}: ${e.message}`);
    continue;
  }
  if (validate(copy)) {
    fail("schema-selftest", `${dataPath} schema ACCEPTS ${what} — the schema does not constrain what it claims to`);
  } else {
    bites += 1;
  }
}

// -------------------------------------------------------- 2. count blocks

const tvSections = ["verifier_hashing", "device_hashing", "parsing"];
for (const s of tvSections) {
  const declared = tv.counts?.[s];
  const actual = tv[s]?.length;
  if (declared !== actual) {
    fail("counts", `test-vectors.json counts.${s} = ${declared} but the array holds ${actual}`);
  }
}
const tvTotal = tvSections.reduce((n, s) => n + (tv[s]?.length ?? 0), 0);

if (bv.counts?.scenarios !== bv.scenarios?.length) {
  fail("counts", `behavior-vectors.json counts.scenarios = ${bv.counts?.scenarios} but the array holds ${bv.scenarios?.length}`);
}
const unconditional = bv.scenarios.filter((s) => s.condition === undefined).length;
if (bv.counts?.unconditional !== unconditional) {
  fail("counts", `behavior-vectors.json counts.unconditional = ${bv.counts?.unconditional} but ${unconditional} scenarios carry no condition`);
}

// ------------------------------------------------------------ 3. unique ids

const seen = new Map(); // id -> where
const claimId = (id, where) => {
  if (seen.has(id)) fail("ids", `duplicate id ${JSON.stringify(id)}: ${seen.get(id)} and ${where}`);
  else seen.set(id, where);
};
for (const s of tvSections) for (const c of tv[s] ?? []) claimId(c.id, `test-vectors.json ${s}`);
for (const s of bv.scenarios ?? []) claimId(s.id, "behavior-vectors.json scenarios");

// -------------------------------------------- 4. requirement citations exist

/** Requirement ids defined in SPECIFICATION.md, as **[N-n]** in bold. */
const defined = new Set([...SPEC.matchAll(/\*\*\[(N-\d+)\]/g)].map((m) => m[1]));
if (defined.size === 0) fail("requirements", "SPECIFICATION.md defines no **[N-*]** requirements — the extraction pattern is wrong");

/**
 * How many enumerated sub-rules a requirement lists, so that `N-6.4` can be
 * checked against the real list rather than merely against [N-6] existing. The
 * list is the run of `1.`-style items immediately following the requirement
 * paragraph.
 */
function subRuleCount(req) {
  const start = SPEC.indexOf(`**[${req}]**`);
  if (start === -1) return 0;
  const after = SPEC.slice(start);
  const listMatch = after.match(/\n\n((?:\d+\.[^\n]*\n)+)/);
  if (!listMatch) return 0;
  return listMatch[1].trimEnd().split("\n").filter((l) => /^\d+\./.test(l)).length;
}

const citations = new Map(); // "N-6.4" -> [where, ...]
const cite = (ref, where) => {
  if (!citations.has(ref)) citations.set(ref, []);
  citations.get(ref).push(where);
};
// Every case section, not just `parsing`: the hashing vectors cite [N-11]
// and pin it against fixed digests, so omitting them here reported a
// requirement as uncited that fourteen vectors execute.
for (const section of tvSections) {
  for (const c of tv[section] ?? []) if (c.rule) cite(c.rule, `test-vectors.json ${c.id}`);
}
for (const s of bv.scenarios ?? []) for (const r of s.requirements ?? []) cite(r, `behavior-vectors.json ${s.id}`);

for (const [ref, wheres] of citations) {
  const [base, sub] = ref.split(".");
  if (!defined.has(base)) {
    fail("requirements", `${ref} is cited by ${wheres.join(", ")} but [${base}] is not defined in SPECIFICATION.md`);
    continue;
  }
  if (sub !== undefined) {
    const n = subRuleCount(base);
    if (n === 0) {
      fail("requirements", `${ref} cites sub-rule ${sub} but [${base}] has no enumerated list (${wheres[0]})`);
    } else if (Number(sub) > n) {
      fail("requirements", `${ref} cites sub-rule ${sub} but [${base}] lists only ${n} (${wheres[0]})`);
    }
  }
}

// -------------------------------------------------------- 5. spec_version

const specVersionInDoc = SPEC.match(/\*\*Spec version:\*\*\s*(\d+)/)?.[1];
if (specVersionInDoc === undefined) {
  fail("spec_version", "SPECIFICATION.md does not state a **Spec version:**");
} else {
  for (const [name, doc] of [["test-vectors.json", tv], ["behavior-vectors.json", bv]]) {
    if (String(doc.spec_version) !== specVersionInDoc) {
      fail("spec_version", `${name} says ${doc.spec_version}, SPECIFICATION.md says ${specVersionInDoc}`);
    }
  }
}

// ---------------------------------------------------------- 6. constants

/**
 * The constants table of SPECIFICATION.md section 1, as
 * `| `NAME` | value |` rows. Values carry prose ("2 592 000 s (30 days)"), so a
 * number is taken as the first numeric run with digit-group spaces removed.
 */
function specConstants() {
  const table = SPEC.match(/## 1\. Constants\n([\s\S]*?)\n\n\*\*\[N-1\]/);
  if (!table) return null;
  const out = new Map();
  for (const line of table[1].split("\n")) {
    const m = line.match(/^\|\s*`([A-Z_]+)`\s*\|\s*(.+?)\s*\|$/);
    if (!m) continue;
    const [, name, raw] = m;
    const quoted = raw.match(/^`"(.*)"`$/);
    if (quoted) out.set(name, quoted[1]);
    else {
      const num = raw.replace(/[   ](?=\d)/g, "").match(/^(\d+)/);
      out.set(name, num ? Number(num[1]) : raw);
    }
  }
  return out;
}

// vectors key -> specification table key
const CONSTANT_MAP = {
  prefix: "PREFIX",
  selector_bytes: "SELECTOR_BYTES",
  verifier_bytes: "VERIFIER_BYTES",
  selector_chars: "SELECTOR_CHARS",
  verifier_chars: "VERIFIER_CHARS",
  max_kid_length: "MAX_KID_LENGTH",
  max_token_length: "MAX_TOKEN_LENGTH",
  min_pepper_length: "MIN_PEPPER_LENGTH",
  default_absolute_ttl_seconds: "DEFAULT_ABSOLUTE_TTL",
  default_idle_ttl_seconds: "DEFAULT_IDLE_TTL",
  default_reuse_grace_seconds: "DEFAULT_REUSE_GRACE",
};

const specConsts = specConstants();
if (!specConsts) {
  fail("constants", "could not locate the constants table in SPECIFICATION.md section 1");
} else {
  for (const [vecKey, specKey] of Object.entries(CONSTANT_MAP)) {
    if (!specConsts.has(specKey)) {
      fail("constants", `SPECIFICATION.md section 1 has no row for ${specKey}`);
      continue;
    }
    const want = specConsts.get(specKey);
    const got = tv.constants?.[vecKey];
    if (got !== want) {
      fail("constants", `test-vectors.json constants.${vecKey} = ${JSON.stringify(got)} but SPECIFICATION.md ${specKey} = ${JSON.stringify(want)}`);
    }
  }
  for (const name of specConsts.keys()) {
    if (!Object.values(CONSTANT_MAP).includes(name)) {
      fail("constants", `SPECIFICATION.md defines ${name}, which no vector constant mirrors — add it to test-vectors.json and to CONSTANT_MAP`);
    }
  }
}

// ------------------------------------------- 7. scenario internal integrity

const knownConditions = new Set(Object.keys(bv.runner?.conditions ?? {}));
const knownKids = new Set(Object.keys(bv.peppers ?? {}));

for (const s of bv.scenarios ?? []) {
  if (s.condition !== undefined && !knownConditions.has(s.condition)) {
    fail("scenarios", `${s.id}: condition ${JSON.stringify(s.condition)} is not documented in runner.conditions`);
  }
  const bound = new Set();
  for (const [i, step] of (s.steps ?? []).entries()) {
    const at = `${s.id} step ${i + 1} (${step.op})`;
    const refs = [];
    if (step.token?.ref) refs.push(["token.ref", step.token.ref]);
    if (step.of) refs.push(["of", step.of]);
    for (const key of ["sameFamilyAs", "sameExpiresAtAs"]) {
      if (step.expect?.[key]) refs.push([`expect.${key}`, step.expect[key]]);
    }
    for (const [what, name] of refs) {
      if (!bound.has(name)) fail("scenarios", `${at}: ${what} names ${JSON.stringify(name)}, which is not bound earlier in this scenario`);
    }
    if (step.bind) {
      if (bound.has(step.bind)) fail("scenarios", `${at}: rebinds ${JSON.stringify(step.bind)}, shadowing an earlier token`);
      // A failed operation returns no token, so binding its result is a defect.
      if (step.expect?.ok === false) fail("scenarios", `${at}: binds ${JSON.stringify(step.bind)} but expects failure`);
      else bound.add(step.bind);
    }
    for (const kid of [step.activeKid, ...(step.peppers ?? []), step.expect?.kid].filter(Boolean)) {
      if (!knownKids.has(kid)) fail("scenarios", `${at}: kid ${JSON.stringify(kid)} has no pepper in the top-level peppers map`);
    }
    if (step.op === "reconfigure" && !step.peppers.includes(step.activeKid)) {
      fail("scenarios", `${at}: activeKid ${JSON.stringify(step.activeKid)} is not among the configured peppers`);
    }
  }
  if (!(s.steps ?? []).some((st) => st.expect || st.op.startsWith("expect"))) {
    fail("scenarios", `${s.id}: no step asserts anything`);
  }
}

if (!bv.defaults?.peppers?.includes(bv.defaults?.activeKid)) {
  fail("scenarios", `defaults.activeKid ${JSON.stringify(bv.defaults?.activeKid)} is not among defaults.peppers`);
}

// --------------------------------------------------------- 8. traceability

const TRACE = "spec/traceability.json";
const buildTraceability = (await import("./build-traceability.mjs")).build;
const expectedTrace = buildTraceability({ tv, bv, defined });

if (!existsSync(join(ROOT, TRACE))) {
  fail("traceability", `${TRACE} is missing, but SPECIFICATION.md publishes it — run: node scripts/build-traceability.mjs`);
} else {
  const onDisk = readText(TRACE);
  if (onDisk.trim() !== JSON.stringify(expectedTrace, null, 2).trim()) {
    fail("traceability", `${TRACE} is stale — run: node scripts/build-traceability.mjs`);
  }
}

// ---------------------------------------------------------------- report

if (problems.length) {
  console.error(`vector validation FAILED — ${problems.length} problem(s)\n`);
  for (const p of problems) console.error(`  ${p}`);
  process.exit(1);
}

const covered = new Set([...citations.keys()].map((r) => r.split(".")[0]));
const uncited = [...defined].filter((r) => !covered.has(r));

console.log("vector validation OK");
console.log(`  spec version            ${tv.spec_version}`);
console.log(`  schema self-test        ${bites}/${MUTATIONS.length} planted defects rejected`);
const tvBreakdown = tvSections.map((s) => `${s} ${tv[s].length}`).join(", ");
console.log(`  test-vectors.json       ${tvTotal} cases (${tvBreakdown})`);
console.log(`  behavior-vectors.json   ${bv.scenarios.length} scenarios (${unconditional} unconditional)`);
console.log(`  requirements            ${defined.size} defined, ${covered.size} cited by vectors`);
console.log(`  constants               ${Object.keys(CONSTANT_MAP).length} checked against SPECIFICATION.md section 1`);
if (uncited.length) {
  // Not a failure: many requirements are about API shape, documentation or
  // deployment, and are not expressible as a vector.
  console.log(`  not cited by any vector ${uncited.join(", ")}`);
}
