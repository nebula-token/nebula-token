#!/usr/bin/env node
//
// scripts/check-marketplace.mjs — the ten skills are installable by standard tooling.
//
//   node scripts/check-marketplace.mjs
//
// Until .claude-plugin/marketplace.json existed, every install line this
// project published was a directory copy. That was not a style problem: an
// installer for agent skills exists, and we were invisible to it.
//
// Both consumers of that manifest resolve a skill the same way — "a plugin's
// skills load from the skills/ directory under its source" — so a marketplace
// entry with `source: "./packages/<lang>"` picks up the canonical skill at
// packages/<lang>/skills/nebula-token-<lang>/ with NO file moved and no second
// copy to drift:
//
//   npx skills add nebula-token/nebula-token --skill nebula-token-python
//   /plugin marketplace add nebula-token/nebula-token
//   /plugin install nebula-token-python@nebula-token
//
// Without the manifest, `skills add` finds nothing in any standard location
// (packages/*/skills/ is not one) and falls back to a recursive scan of the
// whole tree. That fallback happened to find all ten here, in a different
// order every time the tree changes shape, and it would just as happily find a
// stray SKILL.md left in a build directory. Discovery by declaration is the
// thing being asserted below; discovery by luck is what it replaces.
//
// The manifest is the second place in this repository that names all ten
// skills, and a second place is a place to drift. So this gate checks BOTH
// directions:
//
//   * every entry resolves to a real skill — no entry pointing at a package
//     that has no skill, no name that disagrees with the directory a client
//     installs it as or with the frontmatter `name` inside it;
//   * every skill in the tree appears in the manifest — a new language whose
//     entry was forgotten publishes a package nobody can install the standard
//     way, and nothing else in the repository would notice.
//
// Three further invariants are load-bearing and each fails silently:
//
//   * `strict: false` on every entry. The default is `true`, which makes
//     packages/<lang>/.claude-plugin/plugin.json the authority — a file that
//     does not exist and should not. Omitting the field breaks the install
//     with no local symptom whatsoever.
//   * No plugin.json under any source. With `strict: false`, a plugin.json
//     that declares components is documented as a conflict, and the plugin
//     fails to load.
//   * `source` must start with "./". The published schema requires the
//     pattern, and the `skills` CLI silently SKIPS any entry whose source
//     fails it — a manifest reading `"packages/python"` produces no error, no
//     warning, and no skill. (This is also why `metadata.pluginRoot` is not
//     used here: its documented shorthand is `"source": "formatter"`, which
//     that same rule rejects. Full sources need no second mechanism to be
//     resolved correctly, and a consumer that ignores `metadata` still gets
//     them right. If a future edit does add pluginRoot, this gate resolves
//     through it rather than quietly checking the wrong paths.)
//
// A trap worth knowing before you go looking for a bug: `claude plugin
// validate .` reports this manifest as invalid — `root: Unrecognized keys:
// "$schema", "description"`. That validator is stricter than the format it
// validates. Anthropic's own claude-plugins-official marketplace fails it the
// same way, on the same two keys, and the published schema this file declares
// lists both as valid root properties. `claude plugin marketplace add` and
// `claude plugin install nebula-token-python@nebula-token` both succeed
// against this repository, and the install pins to the commit SHA as intended.
// Do not delete `$schema` to silence `validate`; it is what gives an editor
// completion and errors on this file, and the runtime does not care.
//
// The manifest deliberately carries no `version` on its entries. Without one,
// an installed plugin pins to the git commit SHA it was fetched at, which is
// what we want while 1.0.0 is unreleased and no tag exists. A version here
// would also be an eleventh place to bump on release, unknown to
// scripts/version.mjs, and wrong the moment somebody forgets it.

import { readFileSync, existsSync, statSync } from "node:fs";
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { dirname, join, resolve, posix } from "node:path";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const MANIFEST = ".claude-plugin/marketplace.json";

/** One per language implementation. A closed set, like scripts/check-skills.mjs. */
const EXPECTED_PLUGINS = 10;

/** Schema URL the manifest declares, so an editor validates it as you type. */
const SCHEMA_URL = "https://json.schemastore.org/claude-code-marketplace.json";

/** The `owner/repo` shorthand both installers take. Documented ~12 times. */
const SOURCE_SLUG = "nebula-token/nebula-token";

const problems = [];
const notes = [];

/** Repo-relative POSIX path → absolute path, on any platform. */
const abs = (rel) => join(ROOT, ...rel.split("/"));

const isDir = (rel) => existsSync(abs(rel)) && statSync(abs(rel)).isDirectory();
const isFile = (rel) => existsSync(abs(rel)) && statSync(abs(rel)).isFile();

/** Hard stop: nothing below means anything if the file is absent or malformed. */
function load() {
  if (!isFile(MANIFEST)) {
    console.error(`marketplace check FAILED — ${MANIFEST} is missing\n`);
    console.error("Without it, `npx skills add` and `/plugin marketplace add` see no");
    console.error("skills in any standard location and fall back to a recursive scan.");
    process.exit(1);
  }
  const raw = readFileSync(abs(MANIFEST), "utf8");
  try {
    return JSON.parse(raw);
  } catch (e) {
    console.error(`marketplace check FAILED — ${MANIFEST} is not valid JSON\n`);
    console.error(`  - ${e.message}`);
    console.error("\nBoth consumers JSON.parse this file and swallow the error, so a typo");
    console.error("here disables every documented install command in silence.");
    process.exit(1);
  }
}

const manifest = load();

// ------------------------------------------------------- 0. it must be shipped
//
// A gitignored manifest passes every check below and reaches no user: neither
// `skills add` nor `/plugin marketplace add` sees the working tree, only what
// the clone contains.

try {
  execFileSync("git", ["check-ignore", "-q", "--", MANIFEST], { cwd: ROOT, stdio: "ignore" });
  problems.push(`${MANIFEST} is excluded by .gitignore — it would never reach a clone`);
} catch {
  notes.push("the manifest is not gitignored, so a clone carries it");
}

// ------------------------------------------------------ 1. the manifest itself
//
// Required by the published schema: name, owner, plugins. The name is
// public-facing — it is the right-hand side of `/plugin install <plugin>@<name>`
// — so it is also cross-checked against the documentation further down.

if (manifest.$schema !== SCHEMA_URL) {
  problems.push(
    `${MANIFEST}: $schema should be "${SCHEMA_URL}" (got ${JSON.stringify(manifest.$schema)}) — it is what validates this file in an editor before CI ever sees it`,
  );
}

const marketplaceName = manifest.name;
if (typeof marketplaceName !== "string" || !/^[a-z0-9]+(-[a-z0-9]+)*$/.test(marketplaceName)) {
  problems.push(
    `${MANIFEST}: \`name\` must be a kebab-case string (got ${JSON.stringify(marketplaceName)}) — users type it after the @ in \`/plugin install\``,
  );
}

if (typeof manifest.owner !== "object" || manifest.owner === null || Array.isArray(manifest.owner)) {
  problems.push(`${MANIFEST}: \`owner\` must be an object with at least a \`name\``);
} else if (typeof manifest.owner.name !== "string" || manifest.owner.name.trim() === "") {
  problems.push(`${MANIFEST}: \`owner.name\` is required and must be non-empty`);
}

if (!Array.isArray(manifest.plugins)) {
  console.error(`marketplace check FAILED — ${MANIFEST}: \`plugins\` must be an array\n`);
  process.exit(1);
}

if (manifest.plugins.length !== EXPECTED_PLUGINS) {
  problems.push(
    `${MANIFEST}: ${manifest.plugins.length} plugin entries, expected exactly ${EXPECTED_PLUGINS} — one per language implementation`,
  );
}

// `metadata.pluginRoot` prepends a base directory to every relative source. It
// is not used here (see the header), but it is resolved rather than assumed
// absent: a gate that ignored it would check paths nothing installs from.
let pluginRoot = "";
if (manifest.metadata !== undefined) {
  const pr = manifest.metadata?.pluginRoot;
  if (pr !== undefined) {
    if (typeof pr !== "string" || !pr.startsWith("./")) {
      problems.push(
        `${MANIFEST}: \`metadata.pluginRoot\` must be a string starting with "./" (got ${JSON.stringify(pr)}) — the \`skills\` CLI ignores the whole manifest otherwise`,
      );
    } else {
      pluginRoot = pr.slice(2).replace(/\/$/, "");
      notes.push(`metadata.pluginRoot is "${pr}", so sources resolve under ${pluginRoot}/`);
    }
  }
}

/** Repo-relative POSIX path a `source` resolves to, or null if unusable. */
const resolveSource = (source) => {
  if (typeof source !== "string" || !source.startsWith("./")) return null;
  const joined = posix.normalize(posix.join(pluginRoot, source.slice(2)));
  if (joined === ".." || joined.startsWith("../")) return null;
  return joined.replace(/\/$/, "");
};

// ---------------------------------------------- 2. every entry → a real skill

/** Repo-relative skill directory each entry claims, keyed by "<source>::<name>". */
const claimed = new Map();
const seenNames = new Set();

manifest.plugins.forEach((plugin, i) => {
  const at = `${MANIFEST}: plugins[${i}]`;

  const name = plugin?.name;
  if (typeof name !== "string" || !/^[a-z0-9]+(-[a-z0-9]+)*$/.test(name)) {
    problems.push(`${at}: \`name\` must be a kebab-case string (got ${JSON.stringify(name)})`);
    return;
  }
  if (seenNames.has(name)) {
    problems.push(`${at}: duplicate plugin name "${name}" — a name is an install identifier`);
    return;
  }
  seenNames.add(name);

  const where = `${MANIFEST}: "${name}"`;

  if (typeof plugin.description !== "string" || plugin.description.trim().length < 20) {
    problems.push(
      `${where}: needs a \`description\` saying what the skill is FOR — it is the only text a user sees when choosing between ten near-identical names`,
    );
  }

  if ("version" in plugin) {
    problems.push(
      `${where}: carries \`version\` — remove it. Without a version the plugin pins to the git commit SHA it was fetched at, which is what we want; with one, this file becomes an eleventh place to bump on release and scripts/version.mjs does not know about it`,
    );
  }

  const dir = resolveSource(plugin.source);
  if (dir === null) {
    problems.push(
      `${where}: \`source\` must be a repository-relative path starting with "./" and staying inside the repository (got ${JSON.stringify(plugin.source)}) — the \`skills\` CLI silently skips any entry that fails this, producing no error and no skill`,
    );
    return;
  }

  if (!isDir(dir)) {
    problems.push(`${where}: \`source\` "${plugin.source}" resolves to ${dir}/, which does not exist`);
    return;
  }

  // `strict` defaults to TRUE, which makes <source>/.claude-plugin/plugin.json
  // the authority. No package has one, and none should.
  const pluginJson = `${dir}/.claude-plugin/plugin.json`;
  if (plugin.strict !== false) {
    problems.push(
      `${where}: must set \`"strict": false\` — the default is true, which requires ${pluginJson}, a per-package manifest this layout exists to avoid`,
    );
  }
  if (isFile(pluginJson)) {
    problems.push(
      `${where}: ${pluginJson} exists — with \`strict: false\` a plugin.json that declares components is a documented conflict and the plugin fails to load`,
    );
  }

  // The whole point: the skill is read in place, under <source>/skills/.
  const skillDir = `${dir}/skills/${name}`;
  const skillMd = `${skillDir}/SKILL.md`;
  claimed.set(`${dir}::${name}`, skillMd);

  if (!isFile(skillMd)) {
    problems.push(
      `${where}: no skill at ${skillMd}. A plugin's skills load from the \`skills/\` directory under its \`source\`, so this entry installs nothing`,
    );
    return;
  }

  const front = readFileSync(abs(skillMd), "utf8").match(/^---\r?\n([\s\S]*?)\r?\n---/);
  if (!front) {
    problems.push(`${skillMd}: no YAML frontmatter — a client cannot identify the skill`);
    return;
  }
  const declared = front[1].match(/^name:\s*(\S+)\s*$/m)?.[1];
  if (declared !== name) {
    problems.push(
      `${skillMd}: frontmatter \`name\` is ${JSON.stringify(declared)} but the manifest entry and the directory both say "${name}" — the three must agree or the skill installs under an identity nothing references`,
    );
  }
});

// ---------------------------------------------- 3. every skill → a real entry
//
// The direction that stops the tree growing past the manifest. The file list
// comes from git, like scripts/check-skills.mjs, so a SKILL.md copied into
// target/, dist/ or a wheel by a local build is excluded by construction.

let tracked = [];
try {
  tracked = execFileSync("git", ["ls-files", "-co", "--exclude-standard", "--", "*SKILL.md"], {
    cwd: ROOT,
    encoding: "utf8",
  })
    .split("\n")
    .map((s) => s.trim())
    .filter(Boolean)
    .filter((f) => isFile(f));
} catch (e) {
  console.error(`check-marketplace: git could not list the skill files (${e.message})`);
  process.exit(2);
}

for (const rel of tracked) {
  const m = rel.match(/^(.*)\/skills\/([^/]+)\/SKILL\.md$/);
  if (!m) {
    problems.push(
      `${rel} is not at <source>/skills/<name>/SKILL.md, so no marketplace entry can expose it — see scripts/check-skills.mjs for the canonical layout`,
    );
    continue;
  }
  const [, dir, name] = m;
  if (!claimed.has(`${dir}::${name}`)) {
    problems.push(
      `${rel} exists but no marketplace entry claims it — add {"name":"${name}","source":"./${dir}","strict":false} to ${MANIFEST}, or the skill is unreachable via \`npx skills add\` and \`/plugin install\``,
    );
  }
}

// ------------------------------------- 4. the documented install lines are true
//
// Every install line in this repository is copy-pasteable, and every one of
// them names a skill or the marketplace. Renaming either without rewriting the
// docs leaves a dozen commands that cannot work — and nothing else here would
// notice, because a wrong `--skill` argument is valid Markdown, a valid flag,
// and a failed install.
//
// Three published forms are checked, all of which carry an identifier:
//
//   npx skills add <source> --skill <name>     any agent
//   /plugin install <name>@<marketplace>       Claude Code, interactive
//   claude plugin install <name>@<marketplace> Claude Code, headless
//
// `--all` is deliberately rejected in a published command line. It reads like
// "all ten skills" and is documented as shorthand for
// `--skill '*' --agent '*' -y`, but `--agent '*'` resolves to every agent the
// CLI supports — 75 of them — not the ones installed. Run in a repository it
// creates .adal/, .kimchi/, .pochi/ and fifty more beside .claude/. `--skill
// '*'` is the flag that means all ten and leaves the agents to detection.

let docs = [];
try {
  docs = execFileSync("git", ["ls-files", "-co", "--exclude-standard", "--", "*.md"], {
    cwd: ROOT,
    encoding: "utf8",
  })
    .split("\n")
    .map((s) => s.trim())
    .filter(Boolean)
    .filter((f) => isFile(f));
} catch {
  /* handled above */
}

let documented = 0;
for (const rel of docs) {
  const text = readFileSync(abs(rel), "utf8");

  // `/plugin install <name>@<marketplace>`, and the headless `claude plugin
  // install …` that this repository documents beside it. Both take the same
  // two identifiers, so both are worth exactly the same assertion.
  for (const [, lead, plugin, market] of text.matchAll(
    /(\/plugin|claude\s+plugin)\s+install\s+([A-Za-z0-9._-]+)@([A-Za-z0-9._-]+)/g,
  )) {
    documented++;
    const cmd = `${lead} install ${plugin}@${market}`;
    if (!seenNames.has(plugin)) {
      problems.push(`${rel}: documents \`${cmd}\`, but "${plugin}" is not a plugin in ${MANIFEST}`);
    }
    if (market !== marketplaceName) {
      problems.push(
        `${rel}: documents \`${cmd}\`, but the marketplace is named "${marketplaceName}" — that command fails for every reader`,
      );
    }
  }

  // `skills add <source> …`. Whole command lines first — one unambiguous,
  // linear pattern — then the arguments are picked out of the captured line.
  // Doing it in one regex needs `(\S+)…[^\n]*?--skill`, whose two halves both
  // match the same characters; that is the super-linear backtracking S8786
  // exists to catch, on input this repository controls but does not bound.
  for (const [line] of text.matchAll(/^[ \t>]*(?:npx +)?skills +add +[^\n]*/gm)) {
    const cmd = line.trim();

    // The argument to `--skill` is the skill directory name, which is the
    // plugin name — so a rename that misses the docs is the same defect as
    // above, in the route we lead with. `--skill '*'` names nothing: skip it.
    const name = /--skill +['"]?([A-Za-z0-9._-]+)/.exec(cmd)?.[1];
    if (name !== undefined) {
      documented++;
      if (!seenNames.has(name)) {
        problems.push(
          `${rel}: documents \`--skill ${name}\`, but "${name}" is not a plugin in ${MANIFEST} — \`skills add\` exits with "No matching skill found"`,
        );
      }
    }

    const source = /skills +add +(\S+)/.exec(cmd)?.[1];
    if (source !== undefined && !source.startsWith(".") && !source.startsWith("/") && source !== SOURCE_SLUG) {
      problems.push(
        `${rel}: documents \`skills add ${source}\`, but the repository is ${SOURCE_SLUG} — a remote source that is not this one installs somebody else's skill (line: ${cmd})`,
      );
    }

    // `--all` in a published command line. See the header: it is not "all ten".
    if (/[ \t]--all\b/.test(cmd)) {
      problems.push(
        `${rel}: publishes \`${cmd}\` — \`--all\` is \`--skill '*' --agent '*' -y\`, and \`--agent '*'\` is every agent the CLI supports, not every agent installed. It installs to all 75 agents the CLI supports, leaving fifty-odd new directories in the current scope. Use \`--skill '*'\``,
      );
    }
  }
}

// --------------------------------------------------------------------- report

if (problems.length) {
  console.error(`marketplace check FAILED — ${problems.length} problem(s)\n`);
  for (const p of problems) console.error(`  - ${p}`);
  console.error("\nA skill that the standard installer cannot find is a skill nobody installs.");
  console.error("The manifest and the tree have to describe the same ten things, in both");
  console.error("directions, or one of them is lying.");
  process.exit(1);
}

console.log("marketplace check OK");
console.log(`  ${MANIFEST} parses, declares ${SCHEMA_URL}, and is named "${marketplaceName}"`);
console.log(`  ${manifest.plugins.length} plugin entries, one per language implementation`);
console.log(`  ${claimed.size} sources exist and each carries skills/<name>/SKILL.md, read in place — no copy, no move`);
console.log(`  ${claimed.size} plugin names equal the skill directory name and its frontmatter \`name\``);
console.log(`  ${tracked.length} SKILL.md files in the repository — every one claimed by an entry`);
console.log(`  every entry sets strict:false, and no source carries a plugin.json to conflict with it`);
console.log(`  no entry carries a version, so an install pins to the commit SHA`);
console.log(
  `  ${documented} documented install commands (\`--skill\`, \`/plugin install\`, \`claude plugin install\`) name a real plugin, this marketplace and this repository`,
);
for (const n of notes) console.log(`  ${n}`);
