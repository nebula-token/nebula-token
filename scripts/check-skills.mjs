#!/usr/bin/env node
//
// scripts/check-skills.mjs — ten agent skills, shipped in installable form.
//
//   node scripts/check-skills.mjs
//
// NEBULA publishes a per-language agent skill so that a coding assistant asked
// to "add refresh tokens" writes a correct integration instead of a plausible
// one. That only works if the skill actually reaches the machine doing the
// work, and a skill reaches it as a DIRECTORY: a client discovers a skill by
// directory name, which must equal the frontmatter `name`. A bare SKILL.md is
// not installable — nothing about that path says the skill is called
// nebula-token-typescript, so a user would have to repackage it by hand.
//
// So the canonical location is the installable one, inside the package:
//
//     packages/<lang>/skills/nebula-token-<lang>/SKILL.md
//
// and every manifest ships that whole path. After `npm i nebula-token`:
//
//     cp -r node_modules/nebula-token/skills/nebula-token-typescript ~/.claude/skills/
//
// There is exactly one copy of each skill in this repository. (There used to be
// two — a generated mirror under skills/ — which is why the checks below are
// written as a closed set rather than a spot check: the invariant is that the
// ten canonical paths are ALL the SKILL.md files there are.)
//
// This gate asserts three separate claims, each of which has failed before:
//
//   1. Exactly ten skills exist, each at its canonical path, each with
//      frontmatter whose `name` equals its directory name. A name that stops
//      matching its directory installs a skill under the wrong identity, and a
//      stray copy left behind by a rename is delivered as a real skill that no
//      package backs.
//   2. Every published artefact carries it. A manifest can declare a file and
//      ship without it — that is exactly what happened to LICENSE before
//      scripts/check-licenses.mjs started asserting the inclusion lists rather
//      than the files' existence. Before this gate, 2 of the 10 manifests named
//      the skill; the other 8 published artefacts had no skill in them at all.
//   3. Each skill still states the content that makes it safe to act on. These
//      are not style rules: each one is a requirement an agent that skipped it
//      would violate while producing code that compiles and passes a smoke test.
//
//        [N-30]  reuseGraceSeconds defaults to 0, and raising it costs detectability
//        [N-35]  CONFLICT is transient — retry once
//        [N-21]  the in-memory store is not for production
//        [N-39]  a failure result carries userId and familyId
//        [N-14]/[N-46]  never log the token, verifier, pepper or raw device id
//        [N-36]  revokeToken is authenticated, so it can refuse
//
// The grace-window rule is checked hardest, because it is the one where a wrong
// default is invisible: a sample configured with a non-zero window rotates,
// refreshes and passes every test an agent would write, while silently serving
// a replayed credential a valid token and raising no REUSE_DETECTED at all.

import { readFileSync, existsSync, readdirSync } from "node:fs";
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { dirname, join, resolve } from "node:path";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");

const PACKAGES = [
  "typescript", "python", "go", "rust", "java",
  "php", "csharp", "dart", "ruby", "elixir",
];

/** Skill directory name for a package — must equal the frontmatter `name`. */
const skillDir = (pkg) => `nebula-token-${pkg}`;

/** The one canonical, installable location of a package's agent skill. */
const skillPath = (pkg) => `packages/${pkg}/skills/${skillDir(pkg)}/SKILL.md`;

const problems = [];
const notes = [];

const read = (rel) => readFileSync(join(ROOT, rel), "utf8");
const manifest = (rel) => {
  if (!existsSync(join(ROOT, rel))) {
    problems.push(`${rel} is missing`);
    return null;
  }
  return read(rel);
};
const stripXmlComments = (t) => t.replace(/<!--[\s\S]*?-->/g, "");

// --------------------------------------------- 1. exactly ten, at those paths
//
// The file set comes from git (tracked plus untracked-but-not-ignored), the
// same source scripts/check-links.mjs uses and for the same reason: build
// output, vendored dependencies and node_modules are excluded by construction
// rather than by a skip list that rots. A locally built jar or wheel copies
// SKILL.md into target/ or dist/, and none of those copies is a second source
// of truth — but a stray SKILL.md that git *does* see is.

const expectedPaths = new Map(PACKAGES.map((p) => [skillPath(p), p]));

let found;
try {
  found = execFileSync("git", ["ls-files", "-co", "--exclude-standard", "--", "*SKILL.md"], {
    cwd: ROOT,
    encoding: "utf8",
  })
    .split("\n")
    .map((s) => s.trim())
    .filter(Boolean)
    // git lists files that are tracked but deleted in the working tree. A clean
    // checkout has none; a working tree mid-rename does, and they are not a
    // duplicate skill.
    .filter((f) => existsSync(join(ROOT, f)));
} catch (e) {
  console.error(`check-skills: git could not list the skill files (${e.message})`);
  process.exit(2);
}

for (const rel of found) {
  if (expectedPaths.has(rel)) continue;
  problems.push(
    `${rel} is a SKILL.md outside the canonical layout — there is exactly one copy of each skill, at packages/<lang>/skills/nebula-token-<lang>/SKILL.md`,
  );
}

// ------------------------------------------ 2. each skill, read and asserted

for (const [rel, pkg] of expectedPaths) {
  if (!existsSync(join(ROOT, rel))) {
    problems.push(`${rel} is missing — every package carries its agent skill, in installable form`);
    continue;
  }
  const text = read(rel);
  const dir = rel.split("/").at(-2);

  // Frontmatter. A skill without it is not a skill: the client reads `name` and
  // `description` to decide whether to load the file at all.
  const fm = text.match(/^---\n([\s\S]*?)\n---\n/);
  if (!fm) {
    problems.push(`${rel}: no YAML frontmatter delimited by --- at the very start of the file`);
    continue;
  }
  const name = fm[1].match(/^name:\s*(.+?)\s*$/m)?.[1];
  const description = fm[1].match(/^description:\s*(.+?)\s*$/m)?.[1];

  // A client identifies an installed skill by the name of the directory it sits
  // in, so the two must agree or the skill announces itself under an identity
  // that is not the one it was installed as.
  if (name !== dir) {
    problems.push(`${rel}: frontmatter name is ${JSON.stringify(name ?? null)}; it must be "${dir}" to match the directory it ships in`);
  }
  if (dir !== skillDir(pkg)) {
    problems.push(`${rel}: the skill directory is "${dir}"; it must be "${skillDir(pkg)}"`);
  }
  if (!description) {
    problems.push(`${rel}: frontmatter has no description; a client uses it to decide when to load the skill`);
  } else if (description.length < 40) {
    problems.push(`${rel}: frontmatter description is ${description.length} characters; too short to route on`);
  }

  // ---------------------------------------- the rules every skill must carry
  //
  // Matched on the requirement tag plus a phrase, so that renaming a rule out of
  // existence fails here rather than silently shipping a skill that omits it.

  const required = [
    [/\[N-30\]/, "the [N-30] grace-window trade-off"],
    [/defaults to 0 \(strict\)/i, "that the reuse grace window defaults to 0 (strict)"],
    [/REUSE_DETECTED` is raised|REUSE_DETECTED\b[^.]*\braised/i, "that a non-zero grace window raises no REUSE_DETECTED"],
    [/\[N-35\]/, "the [N-35] CONFLICT retry rule"],
    [/CONFLICT/, "the CONFLICT error code"],
    [/\[N-21\]/, "the [N-21] in-memory-store rule"],
    [/not for production/i, "that the in-memory store is not for production"],
    [/\[N-39\]/, "the [N-39] failure-attribution rule"],
    [/\[N-14\]|\[N-46\]/, "the [N-14]/[N-46] never-log rule"],
    [/[Nn]ever log/, "the never-log instruction in plain words"],
    [/\[N-36\]/, "the [N-36] rule that revokeToken can refuse"],
    [/can refuse|REFUSED|it REFUSED/i, "in plain words that revokeToken can refuse"],
  ];
  for (const [re, what] of required) {
    if (!re.test(text)) {
      problems.push(`${rel}: does not state ${what}`);
    }
  }

  // The failure a running sample proved: a code sample that sets a non-zero
  // grace window is a copy-paste default that disables reuse detection.
  for (const m of text.matchAll(/^[^\n]*reuse[_ ]?grace[_ ]?seconds[^\n]*$/gim)) {
    const line = m[0];
    // Only assignments in code matter; the prose bullet naturally names the
    // option without setting it.
    const assigned = line.match(/reuse[_ ]?grace[_ ]?seconds\s*[:=]\s*(\d+)/i);
    if (assigned && Number(assigned[1]) !== 0) {
      const n = text.slice(0, m.index).split("\n").length;
      problems.push(`${rel}:${n}: a sample sets the reuse grace window to ${assigned[1]}; [N-30] says leave it at the default of 0 — a non-zero window serves a replayed token and raises no REUSE_DETECTED`);
    }
  }

  // A logout sample that calls revokeToken for its side effect and drops the
  // result. [N-36] makes revokeToken authenticated, so it CAN refuse
  // (MALFORMED, UNKNOWN_KID, NOT_FOUND, VERIFIER_MISMATCH) — and the refusal is
  // a return value, not an exception, in all ten languages. An agent that
  // copies the discarding form answers 204 to a logout that never happened and
  // leaves the session alive. Matched on the call being a bare statement, which
  // is precisely the shape that throws the outcome away.
  const revokeCall = /^\s*(?:await\s+|\$?\w+\s*=\s*)?[\w.$>:-]*\brevoke_?[Tt]oken\s*\(/;
  for (const m of text.matchAll(/^.*\brevoke_?[Tt]oken\s*\([^\n]*$/gm)) {
    const line = m[0];
    if (!revokeCall.test(line)) continue;
    // Bound to a name, matched on, or piped somewhere: the outcome is reachable.
    const captured = /=\s*[\w.$>:-]*\brevoke/.test(line)   // x = revokeToken(...)
      || /\b(?:case|match|if|unless|switch)\b/.test(line)     // matched inline
      || /\|>/.test(line);                                    // piped
    if (!captured) {
      const n = text.slice(0, m.index).split("\n").length;
      problems.push(`${rel}:${n}: a sample calls revokeToken and discards the result; [N-36] makes it authenticated, so it can refuse — bind the result and check it, or the sample teaches reporting a logout that never happened`);
    }
  }
}

// ---------------------------------------------- 3. skills/ is an index only
//
// The repository-root skills/ directory no longer holds skill files; it is a
// README that points at the ten canonical paths. A directory reappearing under
// it is a copy that nothing regenerates and nothing diffs — the drift this
// layout exists to make impossible.

const skillsRoot = join(ROOT, "skills");
if (!existsSync(join(ROOT, "skills/README.md"))) {
  problems.push("skills/README.md is missing — it is the index of the ten skills and their install lines");
}
if (existsSync(skillsRoot)) {
  for (const entry of readdirSync(skillsRoot, { withFileTypes: true })) {
    if (entry.isDirectory()) {
      problems.push(`skills/${entry.name}/ holds a copy of a skill; the canonical copy is packages/<lang>/skills/${entry.name}/ and skills/ is an index (README.md) only`);
    }
  }
}

// --------------------------------------------- 4. every manifest ships the file
//
// One checker per ecosystem, exactly as scripts/check-licenses.mjs does it, and
// for the same reason: "the correct form" is different in each, and a list that
// silently skips a missing entry is the failure mode being guarded against.
//
// Each list must name the whole path, not just the file: what ships has to be
// the directory a client can install, so `skills/nebula-token-<lang>/SKILL.md`
// is the entry, and the artefact reproduces that path.

const wanted = (pkg) => `skills/${skillDir(pkg)}/SKILL.md`;

const inList = (rel, list, label, want) => {
  const ok = list.some((e) => {
    const norm = e.replace(/^\.\//, "").replace(/^\//, "").replaceAll("\\", "/");
    return norm === want;
  });
  if (!ok) {
    problems.push(`${rel}: ${label} does not include ${want} — the artefact would ship without the agent skill`);
  }
};
const tomlList = (inner) =>
  inner.split(",").map((s) => s.trim().replace(/#.*$/, "").trim())
    .filter(Boolean).map((s) => s.replace(/^["']|["']$/g, ""));
const rubyList = (inner) =>
  inner.split(",").map((s) => s.replace(/#.*$/, "").trim())
    .filter(Boolean).map((s) => s.replace(/^['"]|['"]$/g, ""));

const CHECKS = {
  typescript() {
    const rel = "packages/typescript/package.json";
    const t = manifest(rel);
    if (t === null) return;
    let json;
    try {
      json = JSON.parse(t);
    } catch (e) {
      problems.push(`${rel} is not valid JSON (${e.message})`);
      return;
    }
    if (!Array.isArray(json.files)) {
      problems.push(`${rel}: "files" must be an allow-list array`);
    } else {
      inList(rel, json.files, '"files"', wanted("typescript"));
    }
  },

  // hatchling: `packages` copies only the importable directory, so the wheel
  // needs an explicit force-include; the sdist has its own allow-list. The
  // force-include target keeps the skill inside the installed package AND in
  // installable shape, so `cp -r <site-packages>/nebula_token/skills/... ` works.
  python() {
    const rel = "packages/python/pyproject.toml";
    const t = manifest(rel);
    if (t === null) return;
    const want = wanted("python");
    const sdist = t.match(/\[tool\.hatch\.build\.targets\.sdist\][\s\S]*?include\s*=\s*\[([^\]]*)\]/)?.[1];
    if (sdist === undefined) {
      problems.push(`${rel}: the sdist has no \`include\` allow-list`);
    } else {
      inList(rel, tomlList(sdist), "the sdist `include`", want);
    }
    const forced = t.match(/\[tool\.hatch\.build\.targets\.wheel\.force-include\]([\s\S]*?)(?=\n\[|$)/)?.[1];
    const mapping = forced?.match(new RegExp(String.raw`"${want}"\s*=\s*"([^"]+)"`))?.[1];
    if (mapping === undefined) {
      problems.push(`${rel}: the wheel has no \`[tool.hatch.build.targets.wheel.force-include]\` entry for ${want}; \`packages\` alone cannot carry a file from outside the importable directory`);
    } else if (!mapping.endsWith(want)) {
      problems.push(`${rel}: the wheel force-includes ${want} as "${mapping}"; it must end in ${want} so the installed package carries the skill as an installable directory`);
    }
  },

  rust() {
    const rel = "packages/rust/Cargo.toml";
    const t = manifest(rel);
    if (t === null) return;
    const include = t.match(/^include\s*=\s*\[([^\]]*)\]/m)?.[1];
    if (include === undefined) {
      problems.push(`${rel}: no \`include\` allow-list`);
    } else {
      inList(rel, tomlList(include), "`include`", wanted("rust"));
    }
  },

  // Both <includes> lists: the main jar via copy-resources, the sources jar via
  // <build><resources>. Lose either and one artefact ships without the skill.
  // The include is a path, so the ant-style copy reproduces the directory under
  // META-INF and the jar carries the skill installable.
  java() {
    const rel = "packages/java/pom.xml";
    const raw = manifest(rel);
    if (raw === null) return;
    const t = stripXmlComments(raw);
    const lists = [...t.matchAll(/<includes>([\s\S]*?)<\/includes>/g)].map((m) => m[1]);
    if (lists.length !== 2) {
      problems.push(`${rel}: expected 2 resource <includes> lists, found ${lists.length}`);
    }
    lists.forEach((l, i) => {
      const entries = [...l.matchAll(/<include>([^<]+)<\/include>/g)].map((m) => m[1].trim());
      inList(rel, entries, `resource <includes> #${i + 1}`, wanted("java"));
    });
  },

  // The .nupkg must reproduce the directory, so PackagePath is the skill
  // directory rather than the package root: a file unpacked to the root of the
  // nupkg would be a bare SKILL.md again.
  csharp() {
    const rel = "packages/csharp/src/NebulaToken/NebulaToken.csproj";
    const raw = manifest(rel);
    if (raw === null) return;
    const t = stripXmlComments(raw);
    const want = wanted("csharp");
    const packed = [...t.matchAll(/<None\s+Include="([^"]+)"[^>]*Pack="true"[^>]*PackagePath="([^"]*)"/g)]
      .map((m) => ({ include: m[1].replaceAll("\\", "/"), path: m[2].replaceAll("\\", "/").replace(/\/$/, "") }));
    const entry = packed.find((p) => p.include.endsWith(want));
    if (!entry) {
      inList(rel, packed.map((p) => p.include), "the packed <None> items", want);
    } else if (entry.path !== `skills/${skillDir("csharp")}`) {
      problems.push(`${rel}: the skill is packed to PackagePath="${entry.path}"; it must be "skills/${skillDir("csharp")}" so the .nupkg carries the skill directory a client can install`);
    }
  },

  // Composer archives the repository minus archive.exclude and minus the
  // export-ignore rules in the root .gitattributes. The manifest is the ROOT
  // composer.json: Packagist reads composer.json from a repository root only.
  // .gitattributes is the list that does the real trimming here — it is what
  // reduces a ten-language monorepo to the PHP package — so it is checked too.
  php() {
    const rel = "composer.json";
    const t = manifest(rel);
    if (t === null) return;
    let json;
    try {
      json = JSON.parse(t);
    } catch (e) {
      problems.push(`${rel} is not valid JSON (${e.message})`);
      return;
    }
    const excluded = json.archive?.exclude ?? [];
    if (excluded.some((e) => /skill/i.test(e))) {
      problems.push(`${rel}: "archive.exclude" excludes the agent skill`);
    }
    const attrs = ".gitattributes";
    const at = manifest(attrs);
    if (at === null) return;
    // The PHP skill now lives under packages/php/skills/, so the rules that
    // would drop it are the ones covering that path — not the root /skills
    // rule, which only export-ignores the index README.
    const kills = /^\/?packages(\/php(\/skills(\/nebula-token-php(\/SKILL\.md)?)?)?)?\/?$/i;
    for (const line of at.split("\n")) {
      const trimmed = line.trim();
      if (trimmed.startsWith("#") || !/export-ignore/.test(trimmed)) continue;
      const [pattern] = trimmed.split(/\s+/);
      if (kills.test(pattern) || /SKILL\.md$/i.test(pattern) || /^\*\*?\/?skills\/?$/i.test(pattern)) {
        problems.push(`${attrs}: "${trimmed}" export-ignores the agent skill out of the PHP dist archive`);
      }
    }
    notes.push(`php: composer archives the repository minus archive.exclude and .gitattributes export-ignore, neither of which drops ${skillPath("php")}`);
  },

  ruby() {
    const rel = "packages/ruby/nebula-token.gemspec";
    const t = manifest(rel);
    if (t === null) return;
    const files = t.match(/spec\.files\s*=\s*Dir\[([\s\S]*?)\]/)?.[1];
    if (files === undefined) {
      problems.push(`${rel}: \`spec.files\` is not the expected Dir[...] allow-list`);
    } else {
      inList(rel, rubyList(files), "`spec.files`", wanted("ruby"));
    }
  },

  elixir() {
    const rel = "packages/elixir/mix.exs";
    const t = manifest(rel);
    if (t === null) return;
    const files = t.match(/files:\s*\[([\s\S]*?)\]/)?.[1];
    if (files === undefined) {
      problems.push(`${rel}: no \`files\` allow-list`);
    } else {
      inList(rel, rubyList(files), "`files`", wanted("elixir"));
    }
  },

  // .pubignore is an exclude-list, so the assertion is that nothing excludes it.
  dart() {
    const rel = "packages/dart/.pubignore";
    const t = manifest(rel);
    if (t === null) return;
    const lines = t.split("\n").map((l) => l.trim()).filter((l) => l && !l.startsWith("#"));
    if (lines.some((l) => /skill/i.test(l))) {
      problems.push(`${rel}: excludes the agent skill from the pub.dev archive`);
    }
    notes.push(`dart: .pubignore is an exclude-list and does not exclude ${wanted("dart")}`);
  },

  // A Go module tarball is the module directory; there is no manifest list.
  go() {
    notes.push(`go: the module tarball carries every file in packages/go, ${wanted("go")} included`);
  },
};

for (const pkg of PACKAGES) CHECKS[pkg]();

// ------------------------------------------------------------------- report

if (problems.length) {
  console.error(`skill check FAILED — ${problems.length} problem(s)\n`);
  for (const p of problems) console.error(`  - ${p}`);
  console.error("\nA skill that does not ship, that ships in a shape nothing can install,");
  console.error("or that drifts from the code it documents, makes an agent generate");
  console.error("broken integrations at scale.");
  process.exit(1);
}

console.log("skill check OK");
console.log(`  ${PACKAGES.length} skills, one per package, at packages/<lang>/skills/nebula-token-<lang>/SKILL.md`);
console.log(`  ${found.length} SKILL.md files in the repository — exactly the ${PACKAGES.length} canonical ones, no mirror to drift`);
console.log(`  ${PACKAGES.length} frontmatter names match the directory a client installs them as`);
console.log(`  ${PACKAGES.length} skills state [N-21], [N-30], [N-35], [N-36], [N-39] and [N-14]/[N-46]`);
console.log(`  no sample sets a non-zero reuse grace window`);
console.log(`  no sample calls revokeToken and discards the result it can refuse with`);
console.log(`  7 manifests name the skill path in their inclusion list; 3 ecosystems ship it by default`);
for (const n of notes) console.log(`  ${n}`);
