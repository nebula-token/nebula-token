#!/usr/bin/env node
//
// scripts/check-agents-md.mjs — AGENTS.md still describes this repository.
//
//   node scripts/check-agents-md.mjs           check
//   node scripts/check-agents-md.mjs --write   regenerate the per-package table
//
// AGENTS.md is injected into an agent's context before it has read anything
// else, which makes a stale line in it worse than no line at all: a build
// command that no longer works costs a few minutes, but a rule that quietly
// stopped being true costs a wrong commit in ten languages. Everything in that
// file that is derivable is therefore derived here and gated, and everything
// that is not derivable is at least held to the repository it claims to
// describe (the scripts exist, the requirement ids exist, the npm scripts
// exist, the gate count is right).
//
// ---------------------------------------------------------------- root-only
//
// There is exactly one AGENTS.md, at the repository root, and check 1 below
// makes that a closed set rather than a convention.
//
// The reason is discovery, not taste. Codex walks from the repository root down
// to its CURRENT WORKING DIRECTORY, not down to the file it happens to be
// editing. `codex` launched at the root of this ten-package monorepo — the
// normal case — reads the root AGENTS.md and nothing else, so a
// packages/rust/AGENTS.md would be invisible to the tool most likely to want
// it. Nesting would move the per-package commands OUT of reach of the agent
// that needs them, and would additionally require a hand-maintained index of
// the ten in the root file: two copies of one fact, which this repository does
// not do. VS Code's nested support is still experimental and Jules documents
// root-only, so the same argument holds there.
//
// Nesting earns its keep when subprojects differ in conventions. Here they
// deliberately do not — uniformity across the ten IS the product ([N-50]) — and
// the one thing that genuinely varies per package, the literal build command
// and the version floor, is a ten-row generated table below. If nesting is ever
// genuinely needed, check 1 is where that decision gets revisited, on purpose,
// with this paragraph in front of you.
//
// --------------------------------------------------- why AGENTS.md, not CLAUDE.md
//
// AGENTS.md is the source because it is the format the widest set of tools
// reads. Claude Code does not read AGENTS.md at all; it reads CLAUDE.md. So
// CLAUDE.md is a one-line `@AGENTS.md` import — a bridge, not a copy — and
// check 2 holds it to exactly that. The moment somebody pastes real content
// into CLAUDE.md, two sets of instructions start drifting apart and an agent's
// behaviour depends on which tool it happens to be running under.
//
// ------------------------------------------------------------------- scope
//
// Relative links are NOT re-checked here: scripts/check-links.mjs already walks
// every tracked markdown file, so AGENTS.md is covered by it the moment it is
// committed. Version floors are not re-read from the ten package manifests
// either: scripts/check-runtime-matrix.mjs owns the equality between
// .github/runtime-matrix.json and those manifests, and a second reader of ten
// manifests would be exactly the duplication this gate exists to prevent.
//
// Dependency-free by design, like the other scripts here: node, and nothing
// else.

import { readFileSync, writeFileSync, readdirSync } from "node:fs";
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { dirname, join, resolve } from "node:path";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const read = (p) => readFileSync(join(ROOT, p), "utf8");

const AGENTS = "AGENTS.md";
const CLAUDE = "CLAUDE.md";
const CI_REL = ".github/workflows/ci.yml";
const MATRIX_REL = ".github/runtime-matrix.json";

// The caps. 210 rather than a round 200 is the honest number: the generated
// table grows by one row per new language, and a hard 200 would eventually
// force a real rule out of the file to make room for a generated one. The byte
// cap is the one that matters — Codex budgets 32,768 bytes for the whole
// concatenated chain, and root-only means this file IS the whole chain, but
// instruction adherence degrades long before any tool's cap. At 20,000 the
// remedy is splitting, and splitting is the decision the header says not to
// make silently.
const MAX_LINES = 210;
const MAX_BYTES = 20_000;

// Named only so that AGENTS.md can correct CONTRIBUTING.md's reference to it.
// Check 8 asserts it is still ABSENT; check 9 asserts the correction is still
// needed. A correction that outlives its bug is noise.
const KNOWN_ABSENT = new Set(["scripts/check-all.mjs"]);

const problems = [];

// --------------------------------------------------------------- ci.yml, matrix

/**
 * .github/workflows/ci.yml split into job blocks, keyed by job id, comments
 * dropped. Mirrors scripts/docker-test.mjs, deliberately: these are two dozen
 * lines of helper, not content, and lifting them into a shared module would put
 * a refactor through two currently-green gates to save nothing. The content has
 * exactly one source; only the reader is duplicated.
 *
 * Scoping to the job whose id equals the package directory is what makes check
 * 5 mean anything: `npm ci` also appears in the `gates` job, and a global
 * substring match would accept the TypeScript row long after the TypeScript job
 * stopped running it. Comments are dropped so that a commented-out step cannot
 * keep this green.
 */
function ciJobs(text) {
  const jobs = new Map();
  let inJobs = false;
  let cur = null;
  for (const line of text.split("\n")) {
    if (/^jobs:\s*$/.test(line)) { inJobs = true; continue; }
    if (/^[A-Za-z]/.test(line)) { inJobs = false; cur = null; }
    if (!inJobs) continue;
    const m = line.match(/^ {2}([A-Za-z][\w-]*):\s*$/);
    if (m) { cur = []; jobs.set(m[1], cur); continue; }
    if (cur && !/^\s*#/.test(line)) cur.push(line.trim());
  }
  return jobs;
}

/**
 * The `working-directory:` a CI job runs its steps from, or null if it declares
 * none (which means the repository root).
 *
 * This exists so that the table's "Run from" column is bound to CI the same way
 * its "Build and test" column already is. Without it the generated sub-line
 * under the table — which every agent reads — claimed the whole table "cannot
 * drift away from what CI actually runs" while one of its four columns was
 * asserted against nothing at all. `defaults.run.working-directory` and a
 * per-step one both appear as the same trimmed line inside the job block, which
 * is all this needs to know: the question is which directory the commands in the
 * row are meant to be pasted into, not which YAML key put it there.
 */
function workingDirOf(job) {
  for (const line of job) {
    const m = /^working-directory:\s*(\S+)\s*$/.exec(line);
    if (m) return m[1];
  }
  return null;
}

/** Compare dotted numeric versions: -1, 0, 1. Mirrors scripts/docker-test.mjs. */
function cmp(a, b) {
  const pa = String(a).replace(/^net/, "").split(".").map(Number);
  const pb = String(b).replace(/^net/, "").split(".").map(Number);
  for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
    const d = (pa[i] ?? 0) - (pb[i] ?? 0);
    if (d) return Math.sign(d);
  }
  return 0;
}

/**
 * The lowest version .github/runtime-matrix.json tests for a runtime — the floor
 * scripts/check-runtime-matrix.mjs holds equal to the package manifest's own
 * claim. Channel names ("stable") are not versions and are skipped. Mirrors
 * scripts/docker-test.mjs.
 */
function declaredFloor(matrix, runtime) {
  const listed = matrix[runtime];
  if (!Array.isArray(listed) || listed.length === 0) return null;
  const flat = listed.map((e) =>
    typeof e === "string" ? e : (e.framework ?? e.elixir ?? null),
  );
  const numeric = flat.filter((v) => v && /^(net)?\d/.test(v));
  return numeric.length ? numeric.slice().sort(cmp)[0] : null;
}

// ------------------------------------------------------------------ the table
//
// The only hand-maintained data in this script, and every column of it is
// asserted against something else:
//
//   key            ≡ a directory under packages/            (check 4, both ways)
//   runtime        → a key of .github/runtime-matrix.json   (check 6)
//   steps[].anchor → a line of the CI job named `key`       (check 5)
//
// so the table can be wrong in exactly one way — a label typo — and nothing
// else about it can drift.
//
// A step is a string, or {anchor, show} when the two differ. `anchor` is matched
// against CI raw; `show` is what a human reads, with `${{ matrix.* }}` replaced
// by the runtime's floor. That substitution is why the .NET row displays
// `-f net10.0` while still being anchored to CI's `-f ${{ matrix.framework }}`:
// raise the .NET floor and the displayed command follows by itself.
//
// `show` DIVERGING FROM `anchor` IS THE INTERESTING CASE, and there is one:
//
//   Ruby   — CI wraps the runner in a nullglob loop over an array, so a test
//            file added but never wired up cannot silently not run. The loop is
//            what a human can paste.
//
// There were two until the .NET package dropped to a single TFM. While it
// multi-targeted net8.0 and net10.0, the shown commands had to carry
// `-p:TargetFrameworks=` overrides, because a bare `dotnet restore` restores
// EVERY declared TFM and an SDK-8-only machine failed NETSDK1045 on the net10.0
// one. One TFM means CI's bare commands now run unmodified at the floor, so the
// overrides are gone from here, from docker/compose.yml and from AGENTS.md. Add
// a second TFM back and all three need them again.
const PACKAGES = [
  { key: "typescript", label: "TypeScript", runtime: "node",   dir: "packages/typescript",
    steps: ["npm ci", "npm run build", "npm test"] },
  { key: "python",     label: "Python",     runtime: "python", dir: "packages/python",
    steps: ["pip install -e .", "pip install pytest", "pytest -q"] },
  { key: "go",         label: "Go",         runtime: "go",     dir: "packages/go",
    steps: ["go build ./...", "go vet ./...", "go test -race -count=1 ./..."] },
  { key: "rust",       label: "Rust",       runtime: "rust",   dir: "packages/rust",
    steps: ["cargo test", "cargo build --examples", "cargo clippy --all-targets -- -D warnings"] },
  { key: "java",       label: "Java",       runtime: "java",   dir: "packages/java",
    steps: ["mvn -B -ntp verify"] },
  // No working directory: the composer project root IS the repository root,
  // because Packagist reads composer.json from a repository root only.
  { key: "php",        label: "PHP",        runtime: "php",    dir: "*the repository root*",
    steps: ["composer install --no-progress --no-interaction --prefer-dist",
            "vendor/bin/phpunit -c packages/php/phpunit.xml"] },
  // One TFM, so CI's commands are runnable as they stand; only the matrix
  // expression is substituted for the reader.
  { key: "csharp",     label: ".NET",       runtime: "dotnet", dir: "packages/csharp",
    steps: ["dotnet restore",
            "dotnet build -c Release -f ${{ matrix.framework }} --no-restore",
            "dotnet test -c Release -f ${{ matrix.framework }} --no-build"] },
  { key: "dart",       label: "Dart",       runtime: "dart",   dir: "packages/dart",
    steps: ["dart pub get", "dart analyze --fatal-infos", "dart test"] },
  { key: "ruby",       label: "Ruby",       runtime: "ruby",   dir: "packages/ruby",
    // CI wraps this in a nullglob loop over an array, so that a test file added
    // but never wired up cannot silently not run. The anchor is the part that
    // must survive; the shown form is the one a human can paste.
    steps: [{ anchor: 'ruby -Ilib "$f"', show: 'for f in test/*_test.rb; do ruby -Ilib "$f"; done' }] },
  { key: "elixir",     label: "Elixir",     runtime: "elixir", dir: "packages/elixir",
    steps: ["mix deps.get", "mix test"] },
];

const normalise = (s) => (typeof s === "string" ? { anchor: s, show: s } : s);

// ------------------------------------------------------------------- sources

const matrix = JSON.parse(read(MATRIX_REL));
const jobs = ciJobs(read(CI_REL));

/** The floor as displayed. Elixir carries its OTP floor too; the runners differ. */
function floorOf(pkg) {
  const floor = declaredFloor(matrix, pkg.runtime);
  if (!floor) return null;
  if (pkg.runtime !== "elixir") return floor;
  const otps = (matrix.elixir ?? []).map((e) => e.otp).filter(Boolean);
  return otps.length ? `${floor} / OTP ${otps.slice().sort(cmp)[0]}` : floor;
}

const floors = new Map();
for (const pkg of PACKAGES) {
  const f = floorOf(pkg);
  if (!f) {
    problems.push(`${pkg.label}: ${MATRIX_REL} has no usable floor under "${pkg.runtime}" — the table cannot be generated`);
  }
  floors.set(pkg.key, f ?? "?");
}

// -------------------------------------------------------------- the generated block

const BEGIN = "<!-- BEGIN GENERATED: package-commands -->";
const END = "<!-- END GENERATED: package-commands -->";

/** `${{ matrix.framework }}` -> the floor, so the shown command is runnable. */
const substitute = (s, floor) => s.replace(/\$\{\{\s*matrix\.[\w-]+\s*\}\}/g, floor);

function table() {
  const lines = [
    BEGIN,
    "",
    "| Package | Run from | Floor | Build and test |",
    "|---|---|---|---|",
    ...PACKAGES.map((p) => {
      const floor = floors.get(p.key);
      // A `dir` that is prose rather than a path (PHP) is marked with asterisks
      // in the table itself and must not be wrapped in a code span.
      const where = p.dir.includes("*") ? p.dir : `\`${p.dir}\``;
      const cmd = p.steps.map((s) => substitute(normalise(s).show, floor)).join(" && ");
      return `| ${p.label} | ${where} | ${floor} | \`${cmd}\` |`;
    }),
    "",
    // States exactly what checks 5 and 5b prove, and no more. The previous
    // wording — "this table cannot drift away from what CI actually runs" —
    // claimed all four columns were bound to CI when only the commands were,
    // and it also glossed over the two rows whose shown command is deliberately
    // NOT CI's (Ruby's loop).
    "<sub>Floors come from `.github/runtime-matrix.json`; each row's directory and commands are asserted against the CI job of the same name in `.github/workflows/ci.yml` by `scripts/check-agents-md.mjs`. One row shows more than CI runs, so that the command works on one machine: Ruby's loop — see below.</sub>",
    "",
    END,
  ];
  return lines.join("\n");
}

// ----------------------------------------------------------------- 1. closed set
//
// The file-set comes from git, exactly as scripts/check-links.mjs takes its —
// tracked plus untracked-but-not-ignored, so build output and the gitignored
// website/ are excluded by construction rather than by a skip list that rots.
// (javascript:S4036 on the PATH lookup for git: see the note in
// scripts/check-links.mjs and sonar-project.properties. execFileSync spawns the
// binary with a fixed argument vector and no shell.)

let found = [];
try {
  found = execFileSync("git", ["ls-files", "-co", "--exclude-standard", "--", "*AGENTS.md"], {
    cwd: ROOT,
    encoding: "utf8",
  })
    .split("\n")
    .map((s) => s.trim())
    .filter(Boolean);
} catch (e) {
  console.error(`check-agents-md: could not list files with git (${e.message})`);
  process.exit(2);
}

for (const stray of found.filter((f) => f !== AGENTS)) {
  problems.push(
    `${stray}: there is exactly one AGENTS.md and it lives at the repository root. ` +
    `Codex discovers root -> current working directory, not root -> edited file, so an agent ` +
    `launched at the repository root would never load this file — the per-package commands would ` +
    `be hidden in the one place they are needed. Fold it into ${AGENTS}, whose generated table ` +
    `already names the working directory and the command for all ten.`,
  );
}

let text = null;
if (found.includes(AGENTS)) {
  text = read(AGENTS);
} else {
  problems.push(
    `${AGENTS} is missing. It is the instruction file every coding agent reads first; ` +
    `this gate can regenerate its command table (--write) but not its prose.`,
  );
}

// ------------------------------------------------------------ 2. the CLAUDE.md bridge

const WANT_CLAUDE = "@AGENTS.md\n";
let claudeText = null;
try {
  claudeText = read(CLAUDE);
} catch {
  problems.push(
    `${CLAUDE} is missing. Claude Code does not read ${AGENTS}; the import is the bridge. ` +
    `Create it containing exactly "@AGENTS.md".`,
  );
}
if (claudeText !== null && claudeText !== WANT_CLAUDE) {
  problems.push(
    `${CLAUDE} must be exactly "@AGENTS.md" and nothing else. Claude Code does not read ` +
    `${AGENTS}; the import is the bridge. Anything else here is a second copy of the ` +
    `instructions, and the two will drift — an agent's behaviour would then depend on which ` +
    `tool it happens to be running under.`,
  );
}

// The rest only makes sense with a file to read.
if (text !== null) {
  // --------------------------------------------------------------------- 3. size

  const lineCount = text.replace(/\n$/, "").split("\n").length;
  const byteCount = Buffer.byteLength(text, "utf8");
  if (lineCount > MAX_LINES) {
    problems.push(
      `${AGENTS} is ${lineCount} lines (cap ${MAX_LINES}). Cut a section or move it into the ` +
      `document that owns it — do not raise the cap here without saying why in the same commit.`,
    );
  }
  if (byteCount > MAX_BYTES) {
    problems.push(
      `${AGENTS} is ${byteCount} bytes (cap ${MAX_BYTES}). This file is injected into every ` +
      `agent session; adherence degrades long before any tool's own cap. Cut, or split — and ` +
      `splitting is the root-only decision in this script's header, which is not to be made ` +
      `silently.`,
    );
  }

  // ------------------------------------------------------- 4. package coverage

  const byCodeUnit = (a, b) => {
    if (a < b) return -1;
    return a > b ? 1 : 0;
  };
  const dirs = readdirSync(join(ROOT, "packages"), { withFileTypes: true })
    .filter((e) => e.isDirectory())
    .map((e) => e.name)
    .sort(byCodeUnit);
  const keys = PACKAGES.map((p) => p.key);
  for (const d of dirs) {
    if (!keys.includes(d)) {
      problems.push(
        `packages/${d} has no row in the PACKAGES table in scripts/check-agents-md.mjs — an ` +
        `agent working in that package would find no command for it.`,
      );
    }
  }
  for (const k of keys) {
    if (!dirs.includes(k)) {
      problems.push(`scripts/check-agents-md.mjs has a row for "${k}", but there is no packages/${k}`);
    }
  }

  // ------------------------------------------------------ 5. command parity with CI

  let matched = 0;
  for (const pkg of PACKAGES) {
    const job = jobs.get(pkg.key);
    if (!job) {
      problems.push(
        `${CI_REL} has no job named "${pkg.key}" — the commands in the table are anchored to ` +
        `the job of the same name, and there is nothing to anchor them to.`,
      );
      continue;
    }
    for (const step of pkg.steps) {
      const { anchor } = normalise(step);
      if (job.some((line) => line.includes(anchor))) {
        matched += 1;
      } else {
        problems.push(
          `\`${anchor}\` appears in no step of the "${pkg.key}" job in ${CI_REL} — either the ` +
          `table in ${AGENTS} is stale or CI stopped running it. Whichever it is, the file is ` +
          `telling agents to run something CI does not.`,
        );
      }
    }

    // ---------------------------------------------- 5b. the "Run from" column
    //
    // DERIVED from `dir`, not typed a second time: a path-shaped `dir` must
    // equal the job's working-directory, and a prose one (PHP's *the repository
    // root*) must correspond to a job that declares none. Both directions, so
    // neither "CI moved and the table did not" nor "the table moved and CI did
    // not" can pass.
    const wantDir = pkg.dir.startsWith("packages/") ? pkg.dir : null;
    const gotDir = workingDirOf(job);
    if (wantDir !== gotDir) {
      const shown = (d) => (d === null ? "the repository root" : `\`${d}\``);
      problems.push(
        `${AGENTS} says the ${pkg.label} commands run from ${shown(wantDir)}, but the ` +
        `"${pkg.key}" job in ${CI_REL} runs them from ${shown(gotDir)}. The "Run from" column ` +
        `is the half of a command a reader cannot infer, and an agent that pastes the row would ` +
        `run it somewhere CI does not.`,
      );
    }
  }

  // -------------------------------------------------------- 7. the generated block

  const start = text.indexOf(BEGIN);
  const end = text.indexOf(END);
  if (start === -1 || end === -1) {
    problems.push(`${AGENTS} has no ${BEGIN} / ${END} block`);
  } else {
    const current = text.slice(start, end + END.length);
    const wanted = table();
    if (current !== wanted) {
      if (process.argv.includes("--write")) {
        const next = text.slice(0, start) + wanted + text.slice(end + END.length);
        writeFileSync(join(ROOT, AGENTS), next);
        text = next;
        console.log(`rewrote the per-package command table in ${AGENTS}`);
      } else {
        problems.push(`${AGENTS} is stale — run: node scripts/check-agents-md.mjs --write`);
      }
    }
  }

  // Everything below is about the hand-written prose, so the generated block is
  // removed first: check 5 already binds every command inside it to CI, and
  // re-checking `npm run build` here would fail for the TypeScript package's own
  // script, which has nothing to do with scripts/package.json.
  const s2 = text.indexOf(BEGIN);
  const e2 = text.indexOf(END);
  const prose = s2 === -1 || e2 === -1 ? text : text.slice(0, s2) + text.slice(e2 + END.length);

  // ------------------------------------------------------------- 8. script paths

  const mentioned = new Set([...prose.matchAll(/scripts\/[\w.-]+\.mjs/g)].map((m) => m[0]));
  for (const p of mentioned) {
    const absent = KNOWN_ABSENT.has(p);
    let exists = true;
    try {
      readFileSync(join(ROOT, p));
    } catch {
      exists = false;
    }
    if (!absent && !exists) {
      problems.push(`${AGENTS} names ${p}, which does not exist`);
    }
    if (absent && exists) {
      problems.push(
        `${p} now exists, but ${AGENTS} names it only to warn that it does not. ` +
        `Delete the correction — it has outlived its bug.`,
      );
    }
  }

  // ------------------------------------------- 9. the corrections outlive nothing
  //
  // AGENTS.md corrects two specific errors in CONTRIBUTING.md. Each correction is
  // coupled to the error it corrects, in BOTH directions: when CONTRIBUTING.md is
  // fixed this fails, and the remedy is to delete the correction in the same
  // commit. A correction that outlives its bug is noise, and noise in this file
  // is paid for in every agent session.
  let contributing = null;
  try {
    contributing = read("CONTRIBUTING.md");
  } catch {
    problems.push("CONTRIBUTING.md is missing");
  }
  if (contributing !== null) {
    const COUPLED = [
      {
        inAgents: "check-all.mjs",
        inContributing: "check-all.mjs",
        what: "the command CONTRIBUTING.md tells you to run",
      },
      {
        inAgents: "not nine",
        inContributing: "nine version fields",
        what: "the manifest count in CONTRIBUTING.md",
      },
    ];
    for (const c of COUPLED) {
      const corrected = prose.includes(c.inAgents);
      const stillWrong = contributing.includes(c.inContributing);
      if (corrected && !stillWrong) {
        problems.push(
          `${AGENTS} still corrects ${c.what}, but CONTRIBUTING.md has been fixed. ` +
          `Delete the correction from ${AGENTS}.`,
        );
      }
      if (!corrected && stillWrong) {
        problems.push(
          `CONTRIBUTING.md is still wrong about ${c.what}, and ${AGENTS} no longer says so. ` +
          `Fix CONTRIBUTING.md, or restore the correction.`,
        );
      }
    }
  }

  // ---------------------------------------------------------------- 10. npm scripts

  const pkgJson = JSON.parse(read("scripts/package.json"));
  const npmScripts = Object.keys(pkgJson.scripts ?? {});
  for (const m of prose.matchAll(/npm run ([\w:-]+)/g)) {
    if (!npmScripts.includes(m[1])) {
      problems.push(
        `${AGENTS} tells an agent to run \`npm run ${m[1]}\`, which is not a script in ` +
        `scripts/package.json (has: ${npmScripts.join(", ")})`,
      );
    }
  }

  // ------------------------------------------- 11. requirement ids and the gate count

  const SPEC = read("SPECIFICATION.md");
  // The same extraction scripts/validate-vectors.mjs uses. Note that a
  // requirement is written `**[N-20] Two failure channels.**`, so a naive
  // `**[N-20]**` search finds nothing.
  const defined = new Set([...SPEC.matchAll(/\*\*\[(N-\d+)\]/g)].map((m) => m[1]));
  if (defined.size === 0) {
    problems.push("SPECIFICATION.md defines no **[N-*]** requirements — the extraction pattern is wrong");
  } else {
    for (const m of prose.matchAll(/\[(N-\d+)\]/g)) {
      if (!defined.has(m[1])) {
        problems.push(`${AGENTS} cites [${m[1]}], which SPECIFICATION.md does not define`);
      }
    }

    // The file also types a RANGE — "[N-1]..[N-53]" — and the loop above only
    // proves both endpoints exist. Appending [N-54] to the specification (which
    // is the only legal way to add one, [N-50]) would leave the range naming a
    // real requirement that is no longer the last, and an agent reading it would
    // believe the set is closed at 53. `defined` is already built; this reads it.
    const range = prose.match(/\[N-(\d+)\]\.\.\[N-(\d+)\]/);
    if (range) {
      const highest = Math.max(...[...defined].map((id) => Number(id.slice(2))));
      if (Number(range[2]) !== highest) {
        problems.push(
          `${AGENTS} says the requirements are [N-${range[1]}]..[N-${range[2]}], but the highest ` +
          `SPECIFICATION.md defines is [N-${highest}]. Ids are appended, never renumbered, so the ` +
          `range's upper bound is the count — fix the range, not the specification.`,
        );
      }
    }
  }

  // The sentence "That chains eleven gates" is prose about a fact this
  // repository can count, so it is counted. A twelfth gate that forgets to
  // update the sentence leaves AGENTS.md quietly under-describing what runs.
  const WORDS = {
    one: 1, two: 2, three: 3, four: 4, five: 5, six: 6, seven: 7, eight: 8,
    nine: 9, ten: 10, eleven: 11, twelve: 12, thirteen: 13, fourteen: 14, fifteen: 15,
  };
  const claimed = prose.match(/That chains (\w+) gates/);
  const chain = pkgJson.scripts?.check ?? "";
  const gateCount = [...chain.matchAll(/(?:^|&&)\s*node\s/g)].length;
  if (!claimed) {
    problems.push(`${AGENTS} no longer says how many gates \`npm run check\` chains`);
  } else {
    const n = WORDS[claimed[1].toLowerCase()] ?? Number(claimed[1]);
    if (n !== gateCount) {
      problems.push(
        `${AGENTS} says \`npm run check\` chains ${claimed[1]} gates; scripts/package.json ` +
        `chains ${gateCount}`,
      );
    }
  }

  // ----------------------------------------- 11b. the gate NAMES, not just the count
  //
  // The same sentence also NAMES all eleven, and counting them proved only that
  // there were eleven nouns' worth of gates — rename check-links.mjs and the
  // count stays right while the sentence quietly names a script that is gone.
  //
  // The sentence is prose (it reads as English, with an "and" and an aside about
  // `--check`), so it is not generated; instead every script in the chain must
  // have a noun here, and that noun must appear in the sentence. Adding a gate
  // therefore fails twice — once on the count, once here with the noun missing —
  // and RENAMING one fails here alone, which is the case that used to be silent.
  const GATE_NOUNS = {
    "version.mjs": "versions",
    "validate-vectors.mjs": "vectors",
    "check-licenses.mjs": "licences",
    "check-skills.mjs": "skills",
    "check-marketplace.mjs": "marketplace",
    "check-runtime-matrix.mjs": "runtime matrix",
    "check-agents-md.mjs": "this file",
    "check-links.mjs": "links",
    "check-actions-pinned.mjs": "pinned actions",
    "check-examples.mjs": "examples",
    "docker-test.mjs": "Docker harness",
  };
  // Whitespace-collapsed, because the sentence is hard-wrapped at 80 columns and
  // a two-word noun ("Docker harness", "runtime matrix", "pinned actions") lands
  // across the wrap roughly half the time. A gate that fails on where the line
  // broke would be re-run until the prose was reflowed to please it.
  const sentence = (prose.match(/That chains \w+ gates[\s\S]*?(?:\n\n|$)/)?.[0] ?? "").replace(/\s+/g, " ");
  for (const m of chain.matchAll(/(?:^|&&)\s*node\s+([\w.-]+\.mjs)/g)) {
    const noun = GATE_NOUNS[m[1]];
    if (!noun) {
      problems.push(
        `scripts/package.json runs ${m[1]} in \`npm run check\`, and scripts/check-agents-md.mjs ` +
        `has no noun for it in GATE_NOUNS. ${AGENTS} names every gate in one sentence; add the ` +
        `noun there and here, in the same commit.`,
      );
    } else if (!sentence.includes(noun)) {
      problems.push(
        `${AGENTS} lists the gates \`npm run check\` chains and does not name "${noun}" (${m[1]}) ` +
        `among them. Either the gate was renamed and the sentence was not, or a gate is missing ` +
        `from it — an agent reads that sentence to decide what it has to make pass.`,
      );
    }
  }

  // ------------------------------------------------------------------- report

  if (problems.length === 0) {
    console.log("agents.md check OK");
    console.log(`  ${lineCount} lines, ${byteCount.toLocaleString("en-US")} bytes (cap ${MAX_LINES} / ${MAX_BYTES.toLocaleString("en-US")})`);
    console.log(`  ${PACKAGES.length} packages, ${matched} commands matched against ${CI_REL}`);
    console.log(`  ${CLAUDE} bridges to ${AGENTS}`);
    process.exit(0);
  }
}

console.error(`agents.md check FAILED — ${problems.length} problem(s)\n`);
for (const p of problems) console.error(`  - ${p}`);
console.error("\nAGENTS.md is read by an agent before anything else it does, so a line that");
console.error("stopped being true there is a wrong commit in ten languages.");
process.exit(1);
