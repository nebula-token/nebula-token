#!/usr/bin/env node
//
// scripts/check-examples.mjs — no example store template goes uncompiled.
//
//   node scripts/check-examples.mjs
//
// The store adapter is the part every adopter writes themselves, so the ten
// example templates are the most-copied code in the repository. Seven of them
// were never compiled by anything, and one had silently fallen behind the
// compare-and-set store contract while still reading as authoritative.
//
// An example that does not compile is worse than no example: it is a template
// for a bug, published with the project's name on it. This gate asserts that
// every package still has one and that CI still builds it.

import { readFileSync, readdirSync, existsSync, statSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join, resolve } from "node:path";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const CI = readFileSync(join(ROOT, ".github/workflows/ci.yml"), "utf8");

/**
 * How each package's examples get compiled.
 *
 * `command` is the literal text of the step that does the compiling, and it is
 * what this gate actually asserts. Matching on the directory path alone would
 * be satisfied by a comment: every mention of `packages/<x>/examples` in ci.yml
 * today happens to be inside one, so deleting the compile step and leaving the
 * comment behind would keep this check green — which is exactly the failure this
 * file exists to prevent.
 *
 * `why` explains, for a reader, how that command reaches the example directory.
 *
 * THE CEILING, stated so nobody expects more. This is a COVERAGE gate: it proves
 * CI compiles the examples, not that the examples compile. Replacing an example
 * with garbage passes here and fails in CI, which is the right division — this
 * gate has no toolchain for ten languages and should not pretend to. What it must
 * never again do is pass while CI compiles nothing, which is what happened.
 */

/**
 * The shell text of one CI job: `run:` one-liners plus the body of every `run: |`
 * block scalar, and nothing else.
 *
 * Deliberately NOT every line of the job. A step `name:`, an `if:`, a `with:`
 * input and a cache `key:` are all strings a maintainer can put a command in
 * without CI running it — and "go test -race -count=1 ./... (temporarily
 * disabled)" as a step name is exactly the shape that slips past a whole-job
 * substring match.
 */
function runLines(job) {
  const lines = CI.split("\n");
  const head = lines.findIndex((l) => l === `  ${job}:`);
  if (head < 0) return [];
  let end = lines.length;
  for (let i = head + 1; i < lines.length; i += 1) {
    if (/^  [a-z][a-z0-9-]*:$/.test(lines[i])) { end = i; break; }
  }

  const out = [];
  let blockIndent = null;
  for (let i = head + 1; i < end; i += 1) {
    const line = lines[i];
    if (blockIndent !== null) {
      const indent = line.search(/\S/);
      if (line.trim() === "" || indent >= blockIndent) { out.push(line.trim()); continue; }
      blockIndent = null;
    }
    const m = line.match(/^(\s*)-?\s*run:\s*(.*)$/);
    if (!m) continue;
    const rest = m[2].trim();
    if (rest === "|" || rest === "|-" || rest === ">" || rest === ">-") {
      blockIndent = m[1].length + 2;
    } else if (rest) {
      out.push(rest);
    }
  }
  return out.filter((l) => l !== "" && !l.startsWith("#"));
}

const PACKAGES = {
  typescript: {
    dir: "examples", ext: [".ts"],
    command: "npx tsc -p tsconfig.ci-examples.json",
    why: "a CI-only tsconfig type-checks src and examples together",
  },
  python: {
    dir: "examples", ext: [".py"],
    command: "python -m compileall -q examples",
    why: "byte-compiles every example",
  },
  go: {
    dir: "examples", ext: [".go"],
    command: "go build ./...",
    why: "compiles every package in the module, examples/sqlstore included",
  },
  rust: {
    dir: "examples", ext: [".rs"],
    command: "cargo build --examples",
    why: "examples/*.rs are cargo examples by convention",
  },
  java: {
    dir: "examples", ext: [".java"],
    command: "javac -Xlint:all -cp target/classes",
    why: "Maven never compiles examples/, so javac does it against the built classes",
  },
  php: {
    dir: "examples", ext: [".php"],
    command: 'glob("packages/php/examples/*.php")',
    why: "requiring the file is the check — PHP fatals at declaration time on an unsatisfied interface; the path is repository-relative because composer.json is the root manifest",
  },
  csharp: {
    dir: "examples", ext: [".cs"],
    command: 'dotnet build "$proj" -c Release',
    why: "a throwaway csproj compiles them against the library project",
  },
  dart: {
    dir: "example", ext: [".dart"],
    command: "dart analyze --fatal-infos",
    why: "analyses the whole package, example/ included",
  },
  ruby: {
    dir: "examples", ext: [".rb"],
    command: 'for f in examples/*.rb; do ruby -c "$f"; done',
    why: "the pg gem is absent, so a syntax check is the honest ceiling",
  },
  elixir: {
    dir: "examples", ext: [".ex"],
    command: "elixirc --ignore-module-conflict",
    why: "examples/ is outside lib/, so mix never compiles it",
  },
};

const problems = [];
const rows = [];

for (const [pkg, spec] of Object.entries(PACKAGES)) {
  const rel = `packages/${pkg}/${spec.dir}`;
  const abs = join(ROOT, rel);

  if (!existsSync(abs) || !statSync(abs).isDirectory()) {
    problems.push(`${rel} does not exist — every package ships a store template`);
    continue;
  }
  // Recursive: Go's template is a package directory (examples/sqlstore/), not a
  // loose file.
  const walk = (dir) =>
    readdirSync(dir, { withFileTypes: true }).flatMap((e) =>
      e.isDirectory() ? walk(join(dir, e.name)) : [e.name],
    );
  const files = walk(abs).filter((f) => spec.ext.some((e) => f.endsWith(e)));
  if (files.length === 0) {
    problems.push(`${rel} contains no ${spec.ext.join("/")} file`);
    continue;
  }

  // The assertion is that the compiling command is still something CI EXECUTES.
  //
  // This used to be `CI.includes(spec.command)` over the whole file, and it was
  // the weakest claim in the eleven gates: for TypeScript and C# the anchor was a
  // fragment of a heredoc that WRITES a config file, so deleting the `npx tsc` /
  // `dotnet build` line that consumes it left this gate printing
  // "type-checks src and examples together" while the reference implementation's
  // published PostgreSQL store template did not compile at all. That is not a
  // hypothetical — it shipped, and it was found by running tsc by hand.
  //
  // Two narrowings, both necessary:
  //   * the anchor is the INVOCATION, not the config it reads;
  //   * the search is the `run:` text of the job named after the package, so a
  //     step demoted to a `name:`, moved to an unrelated job, or commented out
  //     no longer counts.
  const compiles = runLines(pkg).some((line) => line.includes(spec.command));
  if (!compiles) {
    problems.push(
      `${rel} holds ${files.length} template(s) that .github/workflows/ci.yml no longer compiles — ` +
      `expected a step containing ${JSON.stringify(spec.command)} (${spec.why})`,
    );
    continue;
  }
  rows.push({ rel, count: files.length, how: spec.why });
}

if (problems.length) {
  console.error(`example coverage check FAILED — ${problems.length} problem(s)\n`);
  for (const p of problems) console.error(`  - ${p}`);
  process.exit(1);
}

console.log("example coverage check OK");
const w = Math.max(...rows.map((r) => r.rel.length));
for (const r of rows) {
  console.log(`  ${r.rel.padEnd(w)}  ${r.count} file(s)  ${r.how}`);
}
