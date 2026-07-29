#!/usr/bin/env node
//
// scripts/check-licenses.mjs — one licence, stated identically everywhere.
//
//   node scripts/check-licenses.mjs
//
// NEBULA is licensed Apache-2.0. Not "Apache-2.0 OR MIT", not "Apache-2.0 AND
// something": one grant, one file, one SPDX identifier. Ten packages are
// published to ten registries, and each one must carry that file byte-identical
// to the root copy. This is not bureaucracy: an artefact whose LICENSE differs
// from the repository's is, to anyone auditing it downstream, a different
// licence grant, and drift here is invisible until a legal review finds it.
//
// The gate therefore asserts five things, and each has been a real failure mode:
//
//   1. The root LICENSE is the verbatim Apache-2.0 text with the appendix
//      copyright filled in — not a pointer file, not a summary.
//   2. Every package has exactly ONE licence file, named LICENSE, byte-identical
//      to the root. No LICENSE-MIT, no LICENSE-APACHE, no LICENSE.txt beside it.
//   3. Every manifest declares Apache-2.0 in its own ecosystem's required form
//      (a string where the ecosystem wants a string, a one-element list where it
//      wants a list) — that field is what the registry displays and what
//      dependency scanners consume.
//   4. Every manifest's file-inclusion list still names LICENSE. A package can
//      declare a licence and ship an artefact without one; that has happened
//      here before, and it is what blocks a distro packager and fails SCA
//      intake. This is the check that stops it recurring.
//   5. Every npm lockfile's own ("") entry agrees. npm copies `license` there
//      from package.json, SBOM and SCA tools read it, and it was the one place
//      the collapse to a single licence was missed.
//
// There is deliberately no NOTICE file. Apache-2.0 §4(d) only obliges
// redistributors to propagate a NOTICE that exists; creating one would impose
// that obligation on every downstream for no benefit, since the attribution it
// would carry is already in LICENSE's appendix.

import { readFileSync, existsSync, readdirSync, statSync } from "node:fs";
import { createHash } from "node:crypto";
import { fileURLToPath } from "node:url";
import { dirname, join, resolve } from "node:path";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");

const SPDX = "Apache-2.0";
const PACKAGES = [
  "typescript", "python", "go", "rust", "java",
  "php", "csharp", "dart", "ruby", "elixir",
];

// Files that must not exist anywhere the licence lives: the collapsed halves of
// the old dual licence, and any second copy under a different name.
const FORBIDDEN_LICENCE_FILE = /^(licen[cs]e[-_.].*|copying(\..*)?)$/i;
const LICENCE_FILE = "LICENSE";

const problems = [];
const notes = [];

const sha = (p) => createHash("sha256").update(readFileSync(p)).digest("hex");
const read = (p) => readFileSync(p, "utf8");

// --------------------------------------------------------- 1. the root text

const rootPath = join(ROOT, LICENCE_FILE);
if (!existsSync(rootPath)) {
  console.error("licence check FAILED\n\n  - root LICENSE is missing");
  process.exit(1);
}
const rootText = read(rootPath);
const rootHash = sha(rootPath);

// Markers unique to the verbatim Apache-2.0 text. A pointer file, a summary or
// the MIT text fails all of them.
for (const marker of [
  "Apache License",
  "Version 2.0, January 2004",
  "http://www.apache.org/licenses/",
  "1. Definitions.",
  "3. Grant of Patent License.",
  "END OF TERMS AND CONDITIONS",
  "APPENDIX: How to apply the Apache License to your work.",
]) {
  if (!rootText.includes(marker)) {
    problems.push(`root LICENSE is not the verbatim Apache-2.0 text (missing ${JSON.stringify(marker)})`);
  }
}
// The appendix must state the copyright rather than leave the template in place,
// so the grant is self-contained in the file and not only in a manifest.
if (!rootText.includes("Copyright 2026 Matteo Teodori")) {
  problems.push('root LICENSE does not state "Copyright 2026 Matteo Teodori" in the appendix');
}
for (const template of ["[yyyy]", "[name of copyright owner]"]) {
  if (rootText.includes(template)) {
    problems.push(`root LICENSE still carries the unfilled appendix template ${template}`);
  }
}
// Nothing may suggest a second grant.
if (/\bMIT\b/.test(rootText) || /dual[- ]licen[cs]/i.test(rootText)) {
  problems.push("root LICENSE mentions a second licence; the project is Apache-2.0 only");
}
// .gitattributes normalises to LF. A CRLF copy would be a different byte
// sequence and would break the per-package identity check on a fresh clone.
if (rootText.includes("\r")) {
  problems.push("root LICENSE contains CR bytes; it must be LF-only (.gitattributes: text=auto eol=lf)");
}

// ---------------------------------------------- 2. exactly one copy, per package

let copies = 0;
for (const pkg of PACKAGES) {
  const dir = join(ROOT, "packages", pkg);
  if (!existsSync(dir)) {
    problems.push(`packages/${pkg} does not exist`);
    continue;
  }
  const p = join(dir, LICENCE_FILE);
  if (!existsSync(p)) {
    problems.push(`packages/${pkg}/LICENSE is missing — every published artefact carries the grant`);
  } else if (sha(p) !== rootHash) {
    problems.push(`packages/${pkg}/LICENSE differs from the root LICENSE`);
  } else {
    copies += 1;
  }
  for (const entry of readdirSync(dir)) {
    if (FORBIDDEN_LICENCE_FILE.test(entry) && statSync(join(dir, entry)).isFile()) {
      problems.push(`packages/${pkg}/${entry} exists; there is exactly one licence file and it is LICENSE`);
    }
  }
}
for (const entry of readdirSync(ROOT)) {
  if (FORBIDDEN_LICENCE_FILE.test(entry) && statSync(join(ROOT, entry)).isFile()) {
    problems.push(`root ${entry} exists; there is exactly one licence file and it is LICENSE`);
  }
}

// -------------------------------------- 3. + 4. manifest declaration and payload
//
// One checker per ecosystem. Each returns nothing and pushes its own problems,
// because "the correct form" differs: composer wants a string where it used to
// accept an array, hex wants a list, rubygems has both a singular and a plural
// field and only the singular one now means what we mean.

const manifest = (rel) => {
  const p = join(ROOT, rel);
  if (!existsSync(p)) {
    problems.push(`${rel} is missing`);
    return null;
  }
  return read(p);
};

// A syntactically broken manifest is a licence problem like any other: it is
// reported, not thrown, so one bad file does not hide the other nine packages.
const asJson = (rel, t) => {
  try {
    return JSON.parse(t);
  } catch (e) {
    problems.push(`${rel} is not valid JSON (${e.message}); its licence declaration cannot be read`);
    return null;
  }
};

// A file-inclusion list must name LICENSE and must not name a sibling that no
// longer exists — a stale entry is skipped silently by every packer we use.
const checkIncludes = (rel, list, label) => {
  if (!list.includes(LICENCE_FILE) && !list.includes(`/${LICENCE_FILE}`)) {
    problems.push(`${rel}: ${label} does not include LICENSE — the artefact would ship without the grant`);
  }
  const stale = list.filter((e) => /^\/?licen[cs]e[-_.]/i.test(e));
  if (stale.length) {
    problems.push(`${rel}: ${label} still names ${stale.join(", ")}, which no longer exists`);
  }
};

const CHECKS = {
  // npm: an SPDX expression string in "license", and "files" is the payload.
  typescript() {
    const rel = "packages/typescript/package.json";
    const t = manifest(rel);
    if (t === null) return;
    const json = asJson(rel, t);
    if (json === null) return;
    if (json.license !== SPDX) {
      problems.push(`${rel}: "license" is ${JSON.stringify(json.license)}; it must be the string "${SPDX}"`);
    }
    if (!Array.isArray(json.files)) {
      problems.push(`${rel}: "files" must be an allow-list array`);
    } else {
      checkIncludes(rel, json.files, '"files"');
    }
  },

  // PyPI / PEP 639: `license` is an SPDX expression string (NOT the legacy
  // `{ text = ... }` table), `license-files` lists the files copied into
  // .dist-info/licenses/, and the sdist has its own allow-list.
  python() {
    const rel = "packages/python/pyproject.toml";
    const t = manifest(rel);
    if (t === null) return;
    if (/^license\s*=\s*\{/m.test(t)) {
      problems.push(`${rel}: \`license\` is a table; PEP 639 requires the SPDX expression string "${SPDX}"`);
    }
    const declared = t.match(/^license\s*=\s*"([^"]+)"/m)?.[1];
    if (declared !== SPDX) {
      problems.push(`${rel}: \`license\` is ${JSON.stringify(declared ?? null)}; it must be "${SPDX}"`);
    }
    const files = t.match(/^license-files\s*=\s*\[([^\]]*)\]/m)?.[1];
    if (files === undefined) {
      problems.push(`${rel}: \`license-files\` is absent; the wheel would ship without the licence text`);
    } else {
      checkIncludes(rel, tomlList(files), "`license-files`");
    }
    const sdist = t.match(/\[tool\.hatch\.build\.targets\.sdist\][\s\S]*?include\s*=\s*\[([^\]]*)\]/)?.[1];
    if (sdist === undefined) {
      problems.push(`${rel}: the sdist has no \`include\` allow-list`);
    } else {
      checkIncludes(rel, tomlList(sdist), "the sdist `include`");
    }
  },

  // crates.io: `license` is an SPDX expression; `include` is the .crate payload.
  rust() {
    const rel = "packages/rust/Cargo.toml";
    const t = manifest(rel);
    if (t === null) return;
    const declared = t.match(/^license\s*=\s*"([^"]+)"/m)?.[1];
    if (declared !== SPDX) {
      problems.push(`${rel}: \`license\` is ${JSON.stringify(declared ?? null)}; it must be "${SPDX}"`);
    }
    if (/^license-file\s*=/m.test(t)) {
      problems.push(`${rel}: \`license-file\` is set; it is for non-SPDX licences and conflicts with \`license\``);
    }
    const include = t.match(/^include\s*=\s*\[([^\]]*)\]/m)?.[1];
    if (include === undefined) {
      problems.push(`${rel}: no \`include\` allow-list`);
    } else {
      checkIncludes(rel, tomlList(include), "`include`");
    }
  },

  // Maven: <licenses> is a conjunction, so exactly one <license> block. The jar
  // and the sources jar get META-INF/LICENSE from two separate mechanisms —
  // <build><resources> feeds maven-source-plugin, the copy-resources execution
  // feeds the main jar — and both lists are checked.
  java() {
    const rel = "packages/java/pom.xml";
    const raw = manifest(rel);
    if (raw === null) return;
    // XML comments are stripped before anything is asserted. This pom documents
    // its own licence plumbing at length — the prose names `<license>`,
    // `maven-source-plugin` and friends — and a check a comment can satisfy is
    // not a check: deleting the whole maven-source-plugin block still left the
    // word behind in a comment, and the sources jar (which is where one of the
    // two META-INF/LICENSE copies comes from) would have stopped being built.
    const t = stripXmlComments(raw);
    const blocks = [...t.matchAll(/<license>([\s\S]*?)<\/license>/g)].map((m) => m[1]);
    if (blocks.length !== 1) {
      problems.push(`${rel}: ${blocks.length} <license> blocks; Maven reads them as a conjunction, so there must be exactly 1`);
    }
    for (const b of blocks) {
      const name = b.match(/<name>([^<]+)<\/name>/)?.[1];
      const url = b.match(/<url>([^<]+)<\/url>/)?.[1];
      const dist = b.match(/<distribution>([^<]+)<\/distribution>/)?.[1];
      if (name !== SPDX) problems.push(`${rel}: <license><name> is ${JSON.stringify(name ?? null)}; it must be "${SPDX}"`);
      if (url !== "https://www.apache.org/licenses/LICENSE-2.0.txt") {
        problems.push(`${rel}: <license><url> is ${JSON.stringify(url ?? null)}; it must be https://www.apache.org/licenses/LICENSE-2.0.txt`);
      }
      if (dist !== "repo") problems.push(`${rel}: <license><distribution> is ${JSON.stringify(dist ?? null)}; it must be repo`);
    }
    const bundle = t.match(/<Bundle-License>([^<]+)<\/Bundle-License>/)?.[1];
    if (bundle !== SPDX) {
      problems.push(`${rel}: <Bundle-License> is ${JSON.stringify(bundle ?? null)}; it must be "${SPDX}"`);
    }
    // Both <includes> lists that put files under META-INF/. There are exactly
    // two by design: lose either one and an artefact ships without the licence.
    const lists = [...t.matchAll(/<includes>([\s\S]*?)<\/includes>/g)].map((m) => m[1]);
    if (lists.length !== 2) {
      problems.push(`${rel}: expected 2 resource <includes> lists (main jar via copy-resources, sources jar via <build><resources>), found ${lists.length}`);
    }
    lists.forEach((l, i) => {
      const entries = [...l.matchAll(/<include>([^<]+)<\/include>/g)].map((m) => m[1].trim());
      checkIncludes(rel, entries, `resource <includes> #${i + 1}`);
    });
    // The release profile must survive: Central rejects a bundle without these,
    // and the sources jar that carries the second copy of the licence only
    // exists because maven-source-plugin is declared here. Asserted as a real
    // <artifactId> element inside the release profile, not as a substring of the
    // file — see the comment-stripping note above.
    const profile = t.match(/<profile>[\s\S]*?<id>release<\/id>([\s\S]*?)<\/profile>/)?.[1];
    if (profile === undefined) {
      problems.push(`${rel}: no <profile> with <id>release</id>; the sources jar that carries META-INF/LICENSE is built there`);
    } else {
      for (const plugin of [
        "maven-source-plugin",
        "maven-javadoc-plugin",
        "maven-gpg-plugin",
        "central-publishing-maven-plugin",
      ]) {
        if (!profile.includes(`<artifactId>${plugin}</artifactId>`)) {
          problems.push(`${rel}: the release profile no longer declares ${plugin}`);
        }
      }
    }
  },

  // NuGet: PackageLicenseExpression is the only indexed form. The expression
  // alone puts a string on nuget.org and nothing in the .nupkg, so the packed
  // <None> item is what actually ships the text.
  csharp() {
    const rel = "packages/csharp/src/NebulaToken/NebulaToken.csproj";
    const raw = manifest(rel);
    if (raw === null) return;
    // Comments stripped, for the reason given in java(): this csproj discusses
    // PackageLicenseUrl and PackageLicenseExpression in prose next to the
    // elements it is asserting.
    const t = stripXmlComments(raw);
    const declared = t.match(/<PackageLicenseExpression>([^<]+)<\/PackageLicenseExpression>/)?.[1];
    if (declared !== SPDX) {
      problems.push(`${rel}: <PackageLicenseExpression> is ${JSON.stringify(declared ?? null)}; it must be "${SPDX}"`);
    }
    if (/<PackageLicenseFile>|<PackageLicenseUrl>/.test(t)) {
      problems.push(`${rel}: <PackageLicenseFile>/<PackageLicenseUrl> conflicts with <PackageLicenseExpression>`);
    }
    const packed = [...t.matchAll(/<None\s+Include="([^"]+)"[^>]*Pack="true"/g)].map((m) => m[1].split("/").pop());
    checkIncludes(rel, packed, "the packed <None> items");
  },

  // Packagist: a string for one licence. An array means a disjunction, which is
  // exactly what this project no longer offers.
  //
  // The manifest is the ROOT composer.json. Packagist reads composer.json from a
  // repository root only, so the PHP package is published from this repository's
  // root and there is no packages/php/composer.json — a second one would be a
  // manifest this gate could pass while the published artefact said something
  // else.
  php() {
    const rel = "composer.json";
    const t = manifest(rel);
    if (t === null) return;
    const json = asJson(rel, t);
    if (json === null) return;
    const l = json.license;
    if (Array.isArray(l)) {
      problems.push(`${rel}: "license" is an array (${l.join(", ")}); an array declares a choice of licences — use the string "${SPDX}"`);
    } else if (l !== SPDX) {
      problems.push(`${rel}: "license" is ${JSON.stringify(l ?? null)}; it must be the string "${SPDX}"`);
    }
    // Two things can drop LICENSE from the dist archive: "archive.exclude" in the
    // manifest, and an export-ignore rule in .gitattributes — which is the one
    // that actually trims this monorepo down to PHP, so it is the one most likely
    // to over-reach. Both are checked.
    const excluded = json.archive?.exclude ?? [];
    if (excluded.some((e) => /licen[cs]e/i.test(e))) {
      problems.push(`${rel}: "archive.exclude" excludes the licence file`);
    }
    const attrs = ".gitattributes";
    if (!existsSync(join(ROOT, attrs))) {
      problems.push(`${attrs} is missing — it is what trims the PHP dist archive, and nothing then guarantees LICENSE ships`);
    } else {
      for (const line of read(join(ROOT, attrs)).split("\n")) {
        const [pattern] = line.trim().split(/\s+/);
        if (!/export-ignore/.test(line) || /^#/.test(line.trim())) continue;
        if (/^\/?(LICENSE|packages\/php\/LICENSE)$/i.test(pattern)) {
          problems.push(`${attrs}: "${line.trim()}" export-ignores the licence file out of the PHP dist archive`);
        }
      }
    }
  },

  // RubyGems: `spec.license =` (singular) for one grant. `spec.licenses =`
  // (plural) would advertise a choice that does not exist.
  ruby() {
    const rel = "packages/ruby/nebula-token.gemspec";
    const t = manifest(rel);
    if (t === null) return;
    if (/spec\.licenses\s*=/.test(t)) {
      problems.push(`${rel}: uses \`spec.licenses\` (plural), which declares a choice of licences; use \`spec.license = '${SPDX}'\``);
    }
    const declared = t.match(/spec\.license\s*=\s*['"]([^'"]+)['"]/)?.[1];
    if (declared !== SPDX) {
      problems.push(`${rel}: \`spec.license\` is ${JSON.stringify(declared ?? null)}; it must be '${SPDX}'`);
    }
    const files = t.match(/spec\.files\s*=\s*Dir\[([\s\S]*?)\]/)?.[1];
    if (files === undefined) {
      problems.push(`${rel}: \`spec.files\` is not the expected Dir[...] allow-list`);
    } else {
      checkIncludes(rel, rubyList(files), "`spec.files`");
    }
  },

  // Hex: a list even for a single grant, so exactly one element.
  elixir() {
    const rel = "packages/elixir/mix.exs";
    const t = manifest(rel);
    if (t === null) return;
    const raw = t.match(/licenses:\s*\[([^\]]*)\]/)?.[1];
    const declared = raw === undefined ? [] : rubyList(raw);
    if (declared.length !== 1 || declared[0] !== SPDX) {
      problems.push(`${rel}: \`licenses\` is [${declared.join(", ")}]; it must be exactly ["${SPDX}"]`);
    }
    const files = t.match(/files:\s*\[([\s\S]*?)\]/)?.[1];
    if (files === undefined) {
      problems.push(`${rel}: no \`files\` allow-list; Hex's default set is not a guarantee`);
    } else {
      checkIncludes(rel, rubyList(files), "`files`");
    }
  },

  // pub.dev derives the licence badge from the LICENSE file itself; pubspec.yaml
  // has no licence field, and inventing one would be ignored while looking
  // authoritative. The file identity check above is the whole gate here.
  dart() {
    const rel = "packages/dart/pubspec.yaml";
    const t = manifest(rel);
    if (t === null) return;
    if (/^licen[cs]e\s*:/m.test(t)) {
      problems.push(`${rel}: declares a licence key that pub.dev ignores; it reads packages/dart/LICENSE`);
    }
    notes.push("dart: pub.dev reads packages/dart/LICENSE (pubspec.yaml has no licence field)");
  },

  // Go modules carry no licence metadata; pkg.go.dev classifies the LICENSE file.
  go() {
    notes.push("go: pkg.go.dev classifies packages/go/LICENSE (go.mod has no licence field)");
  },
};

function stripXmlComments(t) {
  return t.replace(/<!--[\s\S]*?-->/g, "");
}
function tomlList(inner) {
  return inner.split(",").map((s) => s.trim().replace(/#.*$/, "").trim())
    .filter(Boolean).map((s) => s.replace(/^["']|["']$/g, ""));
}
function rubyList(inner) {
  return inner.split(",").map((s) => s.replace(/#.*$/, "").trim())
    .filter(Boolean).map((s) => s.replace(/^['"]|['"]$/g, ""));
}

for (const pkg of PACKAGES) CHECKS[pkg]();

// --------------------------------------------- 4b. npm lockfile root entries
//
// A lockfile's "" entry is not a dependency: it is this project, and npm rewrites
// its `license` from the sibling package.json on every install. So a stale one is
// both a false machine-readable claim about our own terms — SBOM and SCA tools
// read lockfiles, and release.yml publishes an SPDX and a CycloneDX SBOM built
// from this tree — and a diff waiting to appear in someone's working copy. The
// nested node_modules/* entries legitimately name other licences and are ignored.
// This is checked because it was missed: packages/typescript/package-lock.json
// still said "MIT" after the manifests had all moved to Apache-2.0.

let locks = 0;
for (const dir of [".", "scripts", ...PACKAGES.map((p) => `packages/${p}`)]) {
  const rel = dir === "." ? "package-lock.json" : `${dir}/package-lock.json`;
  if (!existsSync(join(ROOT, rel))) continue;
  const json = asJson(rel, read(join(ROOT, rel)));
  if (json === null) continue;
  if (json.packages?.[""] === undefined) {
    problems.push(`${rel}: no root ("") entry (lockfileVersion ${json.lockfileVersion ?? "?"}); regenerate it with npm 7 or later so the licence is recorded`);
    continue;
  }
  const declared = json.packages[""].license;
  if (declared !== SPDX) {
    problems.push(`${rel}: the root ("") entry declares ${JSON.stringify(declared ?? null)}; npm copies it from the sibling package.json, so it must be "${SPDX}"`);
  } else {
    locks += 1;
  }
}

// ----------------------------------- 5. no prose or metadata says otherwise
//
// A half-collapsed licence is worse than either choice: the manifests, the
// licence file and the prose would disagree about the terms. These files are the
// ones that state the terms in words, and none of them may name a second grant.
// (Dependency lockfiles legitimately list MIT dependencies and are not scanned.)

const PROSE = [
  "README.md", "CONTRIBUTING.md", "GOVERNANCE.md", "CITATION.cff", "SECURITY.md",
  "COMPATIBILITY.md", "VERSIONING.md", "RELEASING.md", "SUPPORT.md", "CHANGELOG.md",
  "docs/COMPLIANCE.md", "docs/paper/nebula.tex",
  ".github/CODEOWNERS", ".github/workflows/ci.yml", "scripts/package.json",
  ...PACKAGES.map((p) => `packages/${p}/README.md`),
];
const FORBIDDEN_PROSE = [
  [/\bApache-2\.0 OR MIT\b/, "the old dual SPDX expression"],
  [/\bLICENSE-(MIT|APACHE)\b/, "a reference to a deleted licence file"],
  [/dual[- ]licen[cs]/i, 'the phrase "dual-licensed"'],
  [/\bMIT\b/, "the MIT licence"],
];
for (const rel of PROSE) {
  const p = join(ROOT, rel);
  if (!existsSync(p)) {
    problems.push(`${rel} is missing (it states the licence terms and is checked here)`);
    continue;
  }
  const t = read(p);
  for (const [re, what] of FORBIDDEN_PROSE) {
    const m = t.match(re);
    if (m) {
      const line = t.slice(0, m.index).split("\n").length;
      problems.push(`${rel}:${line} mentions ${what} (${JSON.stringify(m[0])}); the project is ${SPDX} only`);
    }
  }
}

// ------------------------------------------------------------------- report

if (problems.length) {
  console.error(`licence check FAILED — ${problems.length} problem(s)\n`);
  for (const p of problems) console.error(`  - ${p}`);
  console.error(`\nEvery published artefact must carry the same grant as the repository: ${SPDX}.`);
  process.exit(1);
}

console.log("licence check OK");
console.log(`  root LICENSE is the verbatim Apache-2.0 text, appendix copyright filled in`);
console.log(`  ${copies}/${PACKAGES.length} packages carry exactly one LICENSE, byte-identical to the root`);
console.log(`  ${PACKAGES.length - 2} manifests declare ${SPDX} and still ship the file; 2 ecosystems read the file directly`);
console.log(`  ${locks} npm lockfile root entries declare ${SPDX}`);
console.log(`  ${PROSE.length} prose and metadata files name no other grant`);
for (const n of notes) console.log(`  ${n}`);
