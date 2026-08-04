#!/usr/bin/env node
//
// scripts/version.mjs — the single tool that reads and writes the package
// version, and the gate that keeps the release DATE from drifting with it.
//
//   node scripts/version.mjs check              assert every manifest agrees
//   node scripts/version.mjs check --expect X   ...and equals X (used on a release tag)
//   node scripts/version.mjs set X.Y.Z          write X.Y.Z into every manifest
//
// The file list is the table in RELEASING.md. Eight manifests carry a version
// field; Go and PHP deliberately carry none, because their registries read the
// git tag instead. Two further sites carry the same version without being
// manifests — the Maven <scm><tag>, which is uploaded to Central inside the
// pom, and the Sonar project version — and they are managed here too, because
// "all the places a version appears" has to mean all of them or the sentence is
// worse than useless. The reproducible-build timestamp beside <scm><tag> is a
// date rather than a version, so it is checked with the changelogs below.
//
// Go's and PHP's absence is itself checked: a stray `version` key in
// composer.json would make Packagist ignore the tag it is supposed to follow,
// and the failure would only be visible after publication.
//
// Edits are surgical regex substitutions rather than parse-and-reserialise, so
// that formatting, comments and line endings survive untouched. Every pattern
// must match exactly once; a pattern that matches zero or several times is a
// hard error rather than a silent partial write.

import { readFileSync, writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join, resolve } from "node:path";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const SEMVER = /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-[0-9A-Za-z.-]+)?$/;

/**
 * A substitution over one manifest. `pattern` must contain exactly three
 * capture groups: everything before the version, the version, everything after.
 */
const sub = (pattern) => ({
  read: (text) => match(pattern, text)[2],
  write: (text, v) => {
    match(pattern, text); // re-validate uniqueness before writing
    return text.replace(pattern, (_m, before, _old, after) => before + v + after);
  },
});

function match(pattern, text) {
  const all = [...text.matchAll(new RegExp(pattern.source, pattern.flags.replace("g", "") + "g"))];
  if (all.length !== 1) {
    throw new Error(`pattern ${pattern} matched ${all.length} times, expected exactly 1`);
  }
  return all[0];
}

/** Manifests that MUST carry the version. */
const VERSIONED = [
  {
    id: "typescript",
    file: "packages/typescript/package.json",
    field: "version",
    ...sub(/^(  "version": ")([^"]+)(",)$/m),
  },
  {
    id: "python",
    file: "packages/python/pyproject.toml",
    field: "project.version",
    ...sub(/^(version = ")([^"]+)(")$/m),
  },
  {
    id: "rust",
    file: "packages/rust/Cargo.toml",
    field: "package.version",
    // Anchored to the line after `name = "nebula-token"` so that a future
    // [dependencies] entry carrying a `version` key cannot be hit by accident.
    ...sub(/^(name = "nebula-token"\r?\nversion = ")([^"]+)(")$/m),
  },
  {
    id: "java",
    file: "packages/java/pom.xml",
    field: "project.version",
    // Anchored to this project's own artifactId: dependency <version> elements
    // live deeper in the file and must not be touched.
    ...sub(/(<artifactId>nebula-token<\/artifactId>\s*\n\s*<version>)([^<]+)(<\/version>)/),
  },
  {
    id: "csharp",
    file: "packages/csharp/src/NebulaToken/NebulaToken.csproj",
    field: "Version",
    ...sub(/(<Version>)([^<]+)(<\/Version>)/),
  },
  {
    id: "dart",
    file: "packages/dart/pubspec.yaml",
    field: "version",
    ...sub(/^(version: )(\S+)(\s*)$/m),
  },
  {
    id: "ruby",
    file: "packages/ruby/nebula-token.gemspec",
    field: "spec.version",
    ...sub(/(spec\.version\s*=\s*')([^']+)(')/),
  },
  {
    id: "elixir",
    file: "packages/elixir/mix.exs",
    field: "version",
    ...sub(/(\n\s*version: ")([^"]+)(",)/),
  },
  {
    id: "java-scm-tag",
    file: "packages/java/pom.xml",
    field: "project.scm.tag",
    // Published: Maven Central serves this pom verbatim, so a stale tag here
    // points every consumer's "browse the source of this release" at the
    // previous one.
    ...sub(/(<tag>v)([^<]+)(<\/tag>)/),
  },
  {
    id: "sonar",
    file: "sonar-project.properties",
    field: "sonar.projectVersion",
    ...sub(/^(sonar\.projectVersion=)(\S+)(\s*)$/m),
  },
  {
    id: "typescript-lock",
    file: "packages/typescript/package-lock.json",
    field: "version",
    // npm keeps the root version in TWO places and validates NEITHER against
    // package.json: `npm ci` compares dependency trees only, so a stale value
    // here is silent until an unrelated `npm install` rewrites it as a stray
    // diff. It reached a released tag exactly that way. The lockfile is not
    // published, but the SBOM job catalogues the whole tree, so a stale entry
    // can be attested. Anchored on the two-space indent, which only the
    // top-level key has.
    ...sub(/^(  "version": ")([^"]+)(",)$/m),
  },
  {
    id: "typescript-lock-root",
    file: "packages/typescript/package-lock.json",
    field: 'packages."".version',
    // The `""` root entry. Anchored through the empty package key, because
    // `"name": "nebula-token"` alone also matches the top-level pair above.
    ...sub(/("": \{\s*\n\s*"name": "nebula-token",\s*\n\s*"version": ")([^"]+)(")/),
  },
  {
    id: "java-readme-maven",
    file: "packages/java/README.md",
    field: "Maven install snippet",
    // These four SHIP: the Java README and skill land in the jar as
    // META-INF/, and the Go README in the module zip. Maven Central and the Go
    // proxy never received 1.0.0, so a stale coordinate here resolves to
    // nothing at all — which is exactly what 1.0.1 had to fix BY HAND. Held
    // here so the next bump cannot repeat it.
    ...sub(/(<version>)([^<]+)(<\/version>)/),
  },
  {
    id: "java-readme-gradle",
    file: "packages/java/README.md",
    field: "Gradle install snippet",
    ...sub(/(implementation 'dev\.nebulatoken:nebula-token:)([^']+)(')/),
  },
  {
    id: "java-skill",
    file: "packages/java/skills/nebula-token-java/SKILL.md",
    field: "install coordinate",
    ...sub(/(Maven\/Gradle: dev\.nebulatoken:nebula-token:)(\S+)(\s*)$/m),
  },
  {
    id: "go-readme",
    file: "packages/go/README.md",
    field: "go get snippet",
    ...sub(/(`go get …@v)([^`]+)(` resolves)/),
  },
];


/**
 * The release DATE surface. Three audiences read it — the changelog a human
 * skims, the per-package changelog a registry renders, and the `date-released`
 * a citation tool emits — and nothing reconciled them, which is exactly how
 * `CITATION.cff` and `CHANGELOG.md` came to disagree before 1.0.0.
 *
 * Checked, never written: the date of a release is not derivable from its
 * number, so `set` cannot infer it. This only ever fails loudly.
 */
const DATED = [
  { file: "CHANGELOG.md", pattern: /^## \[([^\]]+)\] - (\d{4}-\d{2}-\d{2})\s*$/m },
  { file: "packages/typescript/CHANGELOG.md", pattern: /^## \[([^\]]+)\] - (\d{4}-\d{2}-\d{2})\s*$/m },
  { file: "packages/python/CHANGELOG.md", pattern: /^## \[([^\]]+)\] - (\d{4}-\d{2}-\d{2})\s*$/m },
  { file: "packages/rust/CHANGELOG.md", pattern: /^## \[([^\]]+)\] - (\d{4}-\d{2}-\d{2})\s*$/m },
  { file: "packages/dart/CHANGELOG.md", pattern: /^## \[([^\]]+)\] - (\d{4}-\d{2}-\d{2})\s*$/m },
  { file: "packages/ruby/CHANGELOG.md", pattern: /^## \[([^\]]+)\] - (\d{4}-\d{2}-\d{2})\s*$/m },
  { file: "packages/elixir/CHANGELOG.md", pattern: /^## \[([^\]]+)\] - (\d{4}-\d{2}-\d{2})\s*$/m },
  { file: "CITATION.cff", pattern: /^version: (\S+)[\s\S]*?^date-released: "(\d{4}-\d{2}-\d{2})"\s*$/m },
  // The Maven reproducible-build timestamp. It is a date site rather than a
  // version site, it is uploaded to Central inside the pom, and its own comment
  // says "Bump with the release" — which nothing enforced until it was listed
  // here. The version is read from the project coordinates directly above it so
  // that a pom bumped without a re-date fails the same way a changelog does.
  {
    file: "packages/java/pom.xml",
    pattern:
      /<artifactId>nebula-token<\/artifactId>\s*<version>(\S+)<\/version>[\s\S]*?<project\.build\.outputTimestamp>(\d{4}-\d{2}-\d{2})T[\d:]+Z<\/project\.build\.outputTimestamp>/,
  },
];

/**
 * Every dated site must name the same version as the manifests and the same
 * date as its siblings. Returns the problems it found; prints what it read.
 */
function checkDates(manifestVersion, width) {
  const problems = [];
  const seen = [];
  for (const d of DATED) {
    const text = read(d.file);
    const m = text.match(d.pattern);
    if (!m) {
      problems.push(`${d.file}: no "<version> - YYYY-MM-DD" entry found`);
      continue;
    }
    const [, version, date] = m;
    seen.push({ file: d.file, version, date });
    console.log(`  ${d.file.padEnd(width)}  ${version}  ${date}`);
    if (manifestVersion && version !== manifestVersion) {
      problems.push(`${d.file} documents ${version}, but the manifests are at ${manifestVersion}`);
    }
  }
  const dates = [...new Set(seen.map((s) => s.date))];
  if (dates.length > 1) {
    problems.push(
      `release dates disagree: ${dates.join(", ")} — RELEASING.md step 2 dates all of them to the tag`,
    );
  }
  return problems;
}

/** Manifests that MUST NOT carry a version — the registry reads the git tag. */
const UNVERSIONED = [
  {
    id: "go",
    file: "packages/go/go.mod",
    why: "Go resolves module versions from repository tags",
    forbidden: /^\s*version\s*[:=]/im,
  },
  {
    // The PHP manifest is the ROOT composer.json, not packages/php/composer.json:
    // Packagist reads composer.json from a repository root only, so there is
    // exactly one and it lives beside this repository's other root files. The
    // PHP sources it points at are still packages/php/src.
    id: "php",
    file: "composer.json",
    why: "Packagist reads the tag; a version key here would override it",
    // Parsed, not matched. The regex this replaced was line-anchored, so
    // `{ "version": "9.9.9",` on the same line as the opening brace — valid
    // JSON, and what any reformatter produces — declared a version that this
    // gate certified absent. The failure is invisible until after publication,
    // which is the whole reason the check exists.
    forbiddenKey: "version",
  },
];

const read = (file) => readFileSync(join(ROOT, file), "utf8");

function collect() {
  const rows = [];
  for (const t of VERSIONED) {
    let version = null;
    let error = null;
    try {
      version = t.read(read(t.file));
    } catch (e) {
      error = e.message;
    }
    rows.push({ ...t, version, error });
  }
  return rows;
}

function check(expected) {
  const rows = collect();
  const problems = [];

  const width = Math.max(...VERSIONED.map((t) => t.file.length));
  for (const r of rows) {
    if (r.error) {
      console.log(`  ${r.file.padEnd(width)}  !! ${r.error}`);
      problems.push(`${r.id}: cannot read version (${r.error})`);
      continue;
    }
    console.log(`  ${r.file.padEnd(width)}  ${r.version}`);
    if (!SEMVER.test(r.version)) problems.push(`${r.id}: "${r.version}" is not semver`);
  }

  const distinct = [...new Set(rows.filter((r) => r.version).map((r) => r.version))];
  if (distinct.length > 1) {
    problems.push(`version sites disagree: ${distinct.join(", ")}`);
  }

  for (const u of UNVERSIONED) {
    const text = read(u.file);
    const declares = u.forbiddenKey
      ? u.forbiddenKey in JSON.parse(text)
      : u.forbidden.test(text);
    if (declares) {
      problems.push(`${u.id}: ${u.file} declares a version, but it must not — ${u.why}`);
    } else {
      console.log(`  ${u.file.padEnd(width)}  (no version, by design — ${u.why})`);
    }
  }

  console.log();
  problems.push(...checkDates(distinct.length === 1 ? distinct[0] : null, width));

  if (expected != null) {
    if (!SEMVER.test(expected)) problems.push(`--expect "${expected}" is not semver`);
    else if (distinct.length === 1 && distinct[0] !== expected) {
      problems.push(`version sites are at ${distinct[0]} but --expect asked for ${expected}`);
    }
  }

  if (problems.length) {
    console.error("\nversion check FAILED");
    for (const p of problems) console.error(`  - ${p}`);
    console.error("\nRun: node scripts/version.mjs set <X.Y.Z>");
    process.exit(1);
  }

  console.log(
    `\nversion check OK — ${VERSIONED.length} version sites at ${distinct[0]}, ` +
      `${DATED.length} dated sites agreeing`,
  );
}

function set(version) {
  if (!SEMVER.test(version)) {
    console.error(`"${version}" is not a semantic version`);
    process.exit(1);
  }
  for (const t of VERSIONED) {
    const path = join(ROOT, t.file);
    const before = readFileSync(path, "utf8");
    const after = t.write(before, version);
    if (before !== after) {
      writeFileSync(path, after);
      console.log(`  ${t.file} -> ${version}`);
    } else {
      console.log(`  ${t.file} already ${version}`);
    }
  }
  console.log(`\nSet ${VERSIONED.length} version sites to ${version}.`);
  console.log("Go and PHP are versioned by their git tags and were not touched.");
}

const [cmd, ...rest] = process.argv.slice(2);
try {
  if (cmd === "check") {
    const i = rest.indexOf("--expect");
    check(i === -1 ? null : rest[i + 1]);
  } else if (cmd === "set") {
    if (!rest[0]) throw new Error("set requires a version: node scripts/version.mjs set 1.2.0");
    set(rest[0]);
  } else {
    console.error("usage: node scripts/version.mjs check [--expect X.Y.Z] | set X.Y.Z");
    process.exit(2);
  }
} catch (e) {
  console.error(`version.mjs: ${e.message}`);
  process.exit(1);
}
