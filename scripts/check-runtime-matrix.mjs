#!/usr/bin/env node
//
// scripts/check-runtime-matrix.mjs — CI must test what the manifests claim.
//
//   node scripts/check-runtime-matrix.mjs           check
//   node scripts/check-runtime-matrix.mjs --write   regenerate SUPPORT.md's table
//
// COMPATIBILITY.md section 7 states that "a runtime is supported when CI
// exercises it". Left to prose, that sentence decays in both directions: a
// manifest claims a floor nobody tests (users on that version discover the
// breakage), or CI tests a version the manifest never promised (effort spent
// defending a claim the project has not made).
//
// So the lowest version in .github/runtime-matrix.json MUST equal the floor
// declared by the package manifest — equal, not merely compatible — and
// SUPPORT.md is generated from the same file.

import { readFileSync, writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join, resolve } from "node:path";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const read = (p) => readFileSync(join(ROOT, p), "utf8");
const matrix = JSON.parse(read(".github/runtime-matrix.json"));

const problems = [];

/** Compare dotted numeric versions: -1, 0, 1. */
function cmp(a, b) {
  const pa = String(a).split(".").map(Number);
  const pb = String(b).split(".").map(Number);
  for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
    const d = (pa[i] ?? 0) - (pb[i] ?? 0);
    if (d) return Math.sign(d);
  }
  return 0;
}

/** Versions that are real numbers, not channel names like "stable". */
const numeric = (list) => list.filter((v) => /^\d/.test(v));

/**
 * Each runtime: where its floor is declared, how to read it, and how it is
 * displayed. `exact` means the whole set must match, not just the floor.
 */
const RUNTIMES = [
  {
    key: "node", label: "Node.js", package: "typescript",
    manifest: "packages/typescript/package.json",
    field: "engines.node",
    floor: (t) => JSON.parse(t).engines?.node?.match(/(\d+(?:\.\d+)*)/)?.[1],
  },
  {
    key: "python", label: "Python", package: "python",
    manifest: "packages/python/pyproject.toml",
    field: "requires-python",
    floor: (t) => t.match(/^requires-python\s*=\s*">=\s*([\d.]+)"/m)?.[1],
  },
  {
    key: "go", label: "Go", package: "go",
    manifest: "packages/go/go.mod",
    field: "go directive",
    floor: (t) => t.match(/^go\s+([\d.]+)/m)?.[1],
  },
  {
    key: "rust", label: "Rust", package: "rust",
    manifest: "packages/rust/Cargo.toml",
    field: "rust-version (MSRV)",
    floor: (t) => t.match(/^rust-version\s*=\s*"([\d.]+)"/m)?.[1],
  },
  {
    key: "java", label: "Java", package: "java",
    manifest: "packages/java/pom.xml",
    field: "maven.compiler.release",
    floor: (t) => t.match(/<maven\.compiler\.release>(\d+)</)?.[1],
  },
  {
    // The PHP manifest is the ROOT composer.json — Packagist reads composer.json
    // from a repository root only, so that is the file whose require.php a PHP
    // consumer's resolver actually sees.
    key: "php", label: "PHP", package: "php",
    manifest: "composer.json",
    field: "require.php",
    floor: (t) => JSON.parse(t).require?.php?.match(/(\d+(?:\.\d+)*)/)?.[1],
  },
  {
    key: "dotnet", label: ".NET", package: "csharp",
    manifest: "packages/csharp/src/NebulaToken/NebulaToken.csproj",
    field: "TargetFramework(s)",
    exact: true,
    // Singular or plural, one TFM or several — the package targets net10.0
    // alone today, but this must keep parsing a multi-targeted csproj:
    // <TargetFrameworks>net10.0;net12.0</TargetFrameworks> -> ["net10.0","net12.0"]
    declared: (t) => {
      const raw = t.match(/<TargetFrameworks?>([^<]+)</)?.[1];
      return raw ? raw.split(";").map((s) => s.trim()).filter(Boolean) : null;
    },
    normalise: (entry) => entry.framework,
    display: (entry) => `${entry.framework} (SDK ${entry.sdk})`,
    // The test project must cover every framework the library claims, or a
    // targeted framework ships having never executed a single test.
    alsoCheck(problems, libTfms) {
      const testProj = "packages/csharp/tests/NebulaToken.Tests/NebulaToken.Tests.csproj";
      let text;
      try {
        text = read(testProj);
      } catch {
        problems.push(`.NET: cannot read ${testProj}`);
        return;
      }
      const raw = text.match(/<TargetFrameworks?>([^<]+)</)?.[1];
      const testTfms = raw ? raw.split(";").map((s) => s.trim()).filter(Boolean) : [];
      for (const tfm of libTfms) {
        if (!testTfms.includes(tfm)) {
          problems.push(
            `.NET: the library targets ${tfm} but ${testProj} does not, so ${tfm} would ship untested`,
          );
        }
      }
    },
  },
  {
    key: "dart", label: "Dart", package: "dart",
    manifest: "packages/dart/pubspec.yaml",
    field: "environment.sdk",
    floor: (t) => t.match(/sdk:\s*"?>=\s*([\d.]+)/)?.[1],
  },
  {
    key: "ruby", label: "Ruby", package: "ruby",
    manifest: "packages/ruby/nebula-token.gemspec",
    field: "required_ruby_version",
    floor: (t) => t.match(/required_ruby_version\s*=\s*['"]>=\s*([\d.]+)['"]/)?.[1],
  },
  {
    key: "elixir", label: "Elixir", package: "elixir",
    manifest: "packages/elixir/mix.exs",
    field: "elixir requirement",
    pairs: true,
    floor: (t) => t.match(/elixir:\s*"~>\s*([\d.]+)"/)?.[1],
    // The package raises at build time below this OTP; see mix.exs.
    otpFloor: (t) => t.match(/@minimum_otp\s+(\d+)/)?.[1],
  },
];

const rows = [];

for (const rt of RUNTIMES) {
  const listed = matrix[rt.key];
  if (!Array.isArray(listed) || listed.length === 0) {
    problems.push(`${rt.key}: .github/runtime-matrix.json has no versions`);
    continue;
  }
  let text;
  try {
    text = read(rt.manifest);
  } catch {
    problems.push(`${rt.key}: cannot read ${rt.manifest}`);
    continue;
  }

  if (rt.pairs) {
    const elixirs = listed.map((p) => p.elixir);
    const otps = listed.map((p) => p.otp);
    const floor = rt.floor(text);
    if (!floor) {
      problems.push(`${rt.key}: could not read ${rt.field} from ${rt.manifest}`);
    } else {
      const lowest = numeric(elixirs).sort(cmp)[0];
      if (cmp(lowest, floor) !== 0) {
        problems.push(
          `${rt.label}: ${rt.manifest} claims a floor of ${floor} (${rt.field}) but the lowest tested is ${lowest}`,
        );
      }
    }
    const otpFloor = rt.otpFloor(text);
    if (otpFloor) {
      const lowestOtp = otps.slice().sort(cmp)[0];
      if (cmp(lowestOtp, otpFloor) !== 0) {
        problems.push(
          `${rt.label}: ${rt.manifest} requires OTP ${otpFloor} but the lowest tested is OTP ${lowestOtp}`,
        );
      }
    }
    // Built in two steps rather than as a template nested inside a template
    // (javascript:S4624): the OTP half is conditional, and reading a `?:` out of
    // the middle of an interpolation is where a stray space goes unnoticed.
    const otpSuffix = otpFloor ? ` / OTP ${otpFloor}` : "";
    rows.push({
      label: rt.label,
      pkg: rt.package,
      tested: listed.map((p) => `${p.elixir} / OTP ${p.otp}`).join(", "),
      floor: `${rt.floor(text) ?? "?"}${otpSuffix}`,
      source: rt.field,
    });
    continue;
  }

  if (rt.exact) {
    const declared = rt.declared(text);
    if (!declared) {
      problems.push(`${rt.key}: could not read ${rt.field} from ${rt.manifest}`);
      continue;
    }
    const tested = listed.map(rt.normalise);
    for (const m of declared.filter((d) => !tested.includes(d))) {
      problems.push(`${rt.label}: ${rt.manifest} targets ${m} but CI does not test it`);
    }
    for (const e of tested.filter((t2) => !declared.includes(t2))) {
      problems.push(`${rt.label}: CI tests ${e} but ${rt.manifest} does not target it`);
    }
    rt.alsoCheck?.(problems, declared);
    rows.push({
      label: rt.label,
      pkg: rt.package,
      tested: listed.map(rt.display).join(", "),
      floor: declared.join(", "),
      source: rt.field,
    });
    continue;
  }

  const floor = rt.floor(text);
  if (!floor) {
    problems.push(`${rt.key}: could not read ${rt.field} from ${rt.manifest}`);
    continue;
  }
  const nums = numeric(listed);
  if (nums.length === 0) {
    problems.push(`${rt.label}: the matrix names only channels (${listed.join(", ")}) — the ${floor} floor is never actually tested`);
  } else {
    const lowest = nums.slice().sort(cmp)[0];
    if (cmp(lowest, floor) !== 0) {
      problems.push(
        cmp(lowest, floor) > 0
          ? `${rt.label}: ${rt.manifest} claims support from ${floor} (${rt.field}) but the lowest tested is ${lowest} — either test ${floor} or raise the floor`
          : `${rt.label}: CI tests ${lowest} but ${rt.manifest} only claims ${floor} (${rt.field}) — either lower the floor or stop testing ${lowest}`,
      );
    }
  }
  rows.push({ label: rt.label, pkg: rt.package, tested: listed.join(", "), floor, source: rt.field });
}

// ------------------------------------------------------------- SUPPORT.md

const BEGIN = "<!-- BEGIN GENERATED: runtime-matrix -->";
const END = "<!-- END GENERATED: runtime-matrix -->";

function table() {
  const lines = [
    BEGIN,
    "",
    "| Runtime | Package | Declared floor | Exercised by CI |",
    "|---|---|---|---|",
    ...rows.map((r) => `| ${r.label} | \`packages/${r.pkg}\` | ${r.floor} | ${r.tested} |`),
    "",
    `<sub>Generated from \`.github/runtime-matrix.json\` by \`scripts/check-runtime-matrix.mjs\`. "Declared floor" is read from each package manifest; CI fails if the two disagree.</sub>`,
    "",
    END,
  ];
  return lines.join("\n");
}

const SUPPORT = "SUPPORT.md";
let supportText = null;
try {
  supportText = read(SUPPORT);
} catch {
  problems.push(`${SUPPORT} is missing — COMPATIBILITY.md section 7 points at it. Run: node scripts/check-runtime-matrix.mjs --write`);
}

if (supportText !== null) {
  const start = supportText.indexOf(BEGIN);
  const end = supportText.indexOf(END);
  if (start === -1 || end === -1) {
    problems.push(`${SUPPORT} has no ${BEGIN} / ${END} block`);
  } else {
    const current = supportText.slice(start, end + END.length);
    const wanted = table();
    if (current !== wanted) {
      if (process.argv.includes("--write")) {
        writeFileSync(join(ROOT, SUPPORT), supportText.slice(0, start) + wanted + supportText.slice(end + END.length));
        console.log(`rewrote the runtime table in ${SUPPORT}`);
      } else {
        problems.push(`${SUPPORT} is stale — run: node scripts/check-runtime-matrix.mjs --write`);
      }
    }
  }
}

// ---------------------------------------------------------------- report

if (problems.length) {
  console.error(`runtime matrix check FAILED — ${problems.length} problem(s)\n`);
  for (const p of problems) console.error(`  - ${p}`);
  console.error("\nCI must test what the manifests claim, and the manifests must not");
  console.error("claim what CI does not test (COMPATIBILITY.md section 7).");
  process.exit(1);
}

console.log("runtime matrix check OK");
const w = Math.max(...rows.map((r) => r.label.length));
for (const r of rows) {
  console.log(`  ${r.label.padEnd(w)}  floor ${String(r.floor).padEnd(14)} tested ${r.tested}`);
}
