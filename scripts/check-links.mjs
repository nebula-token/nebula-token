#!/usr/bin/env node
//
// scripts/check-links.mjs — every relative link in the documentation resolves.
//
//   node scripts/check-links.mjs
//
// This checks links *within* the repository: a path that does not exist, or an
// anchor that names no heading. Those are the ones that break silently during a
// rewrite, and the ones no network flake can excuse. External URLs are checked
// separately by lychee in the docs job, with .lycheeignore carrying the reasons
// for each exemption.
//
// The file set comes from git (tracked plus untracked-but-not-ignored), so
// vendored dependencies, build output and node_modules are excluded by
// construction rather than by a skip list that rots.

import { readFileSync, existsSync, statSync } from "node:fs";
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { dirname, join, resolve, relative } from "node:path";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");

// javascript:S4036 reports that "git" is resolved through PATH. Left as it is,
// deliberately, and the reasoning is recorded in sonar-project.properties:
//
//   * execFileSync spawns the binary directly with a fixed argument vector and
//     NO shell, so the injection channel the rule ultimately guards against is
//     already closed here. Nothing below is interpolated into the arguments.
//   * The caller already trusts PATH completely: this script is started as
//     `node scripts/check-links.mjs` from a developer shell or a CI step, so
//     `node` itself was resolved the same way. Pinning git's path while node's
//     stays inherited raises no bar; it only looks like it does.
//   * There is no portable absolute path to pin. git lives in /usr/bin on the
//     CI image and under Program Files — or any portable-install directory — on
//     the Windows machines this repository is developed on. Hard-coding either,
//     or forcing a fixed PATH, would break `node scripts/check-links.mjs` as a
//     local gate on one of the two platforms, which is a certain cost against a
//     threat that requires an attacker who can already write to your PATH.
const files = execFileSync("git", ["ls-files", "-co", "--exclude-standard", "--", "*.md"], {
  cwd: ROOT,
  encoding: "utf8",
})
  .split("\n")
  .map((s) => s.trim())
  .filter(Boolean)
  // git lists files that are tracked but deleted in the working tree. A clean
  // checkout has none; a working tree mid-rename does, and they are not a
  // link defect.
  .filter((f) => existsSync(join(ROOT, f)));

if (files.length === 0) {
  console.error("check-links: git listed no markdown files");
  process.exit(2);
}

/**
 * GitHub's heading slug: lowercase, strip anything that is not a word
 * character, space or hyphen, then replace each remaining space with a hyphen.
 *
 * One space, one hyphen — runs are NOT collapsed. "Rotation & Reuse" loses the
 * ampersand but keeps both spaces around it, and so slugs to `rotation--reuse`.
 * Collapsing here would reject links that GitHub resolves perfectly well.
 */
function slug(heading) {
  return heading
    .trim()
    .toLowerCase()
    .replace(/[^\w\s-]/gu, "")
    .replace(/\s/g, "-");
}

const anchorCache = new Map();
function anchorsOf(absPath) {
  if (anchorCache.has(absPath)) return anchorCache.get(absPath);
  const set = new Set();
  try {
    const text = readFileSync(absPath, "utf8");
    let inFence = false;
    for (const line of text.split("\n")) {
      if (/^\s*(```|~~~)/.test(line)) { inFence = !inFence; continue; }
      if (inFence) continue;
      const h = line.match(/^#{1,6}\s+(.*?)\s*#*\s*$/);
      if (h) set.add(slug(h[1].replace(/[`*_]/g, "")));
      // Explicit HTML anchors, e.g. <a id="x"> or <a name="x">
      for (const m of line.matchAll(/<a\s[^>]*(?:id|name)="([^"]+)"/g)) set.add(m[1]);
    }
  } catch {
    /* reported elsewhere as a missing file */
  }
  anchorCache.set(absPath, set);
  return set;
}

/** Inline links, reference definitions, and raw HTML href/src. */
function linksIn(text) {
  const out = [];
  let inFence = false;
  const lines = text.split("\n");
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (/^\s*(```|~~~)/.test(line)) { inFence = !inFence; continue; }
    if (inFence) continue;
    const stripped = line.replace(/`[^`]*`/g, (m) => " ".repeat(m.length));
    for (const m of stripped.matchAll(/!?\[[^\]]*\]\(\s*<?([^)\s>]+)>?(?:\s+"[^"]*")?\s*\)/g)) {
      out.push({ target: m[1], line: i + 1 });
    }
    for (const m of stripped.matchAll(/^\s*\[[^\]]+\]:\s*<?([^\s>]+)>?/g)) {
      out.push({ target: m[1], line: i + 1 });
    }
    for (const m of stripped.matchAll(/<(?:a|img)\s[^>]*(?:href|src)="([^"]+)"/g)) {
      out.push({ target: m[1], line: i + 1 });
    }
  }
  return out;
}

const problems = [];
let checkedPaths = 0;
let checkedAnchors = 0;
let external = 0;

for (const file of files) {
  const abs = join(ROOT, file);
  let text;
  try {
    text = readFileSync(abs, "utf8");
  } catch (e) {
    problems.push(`${file}: unreadable (${e.message})`);
    continue;
  }

  for (const { target, line } of linksIn(text)) {
    if (/^[a-z][a-z0-9+.-]*:/i.test(target)) { external += 1; continue; } // http:, mailto:, ...
    if (target.startsWith("//")) { external += 1; continue; }

    const where = `${file}:${line}`;

    if (target.startsWith("#")) {
      const want = decodeURIComponent(target.slice(1));
      if (want && !anchorsOf(abs).has(want)) {
        problems.push(`${where}: no heading in this file matches anchor #${want}`);
      }
      checkedAnchors += 1;
      continue;
    }

    const [rawPath, anchor] = target.split("#");
    const cleanPath = decodeURIComponent(rawPath.split("?")[0]);
    if (!cleanPath) continue;

    const targetAbs = resolve(dirname(abs), cleanPath);
    // Nothing may point outside the repository.
    const rel = relative(ROOT, targetAbs).replaceAll("\\", "/");
    if (rel.startsWith("..")) {
      problems.push(`${where}: ${target} escapes the repository root`);
      continue;
    }
    if (!existsSync(targetAbs)) {
      problems.push(`${where}: ${target} does not exist (looked for ${rel || "."})`);
      continue;
    }
    checkedPaths += 1;

    if (anchor) {
      if (!statSync(targetAbs).isFile() || !cleanPath.endsWith(".md")) continue;
      const want = decodeURIComponent(anchor);
      if (!anchorsOf(targetAbs).has(want)) {
        problems.push(`${where}: ${rel} has no heading matching anchor #${want}`);
      }
      checkedAnchors += 1;
    }
  }
}

if (problems.length) {
  console.error(`link check FAILED — ${problems.length} broken link(s)\n`);
  for (const p of problems) console.error(`  ${p}`);
  console.error("\nA link in the documentation is a promise; a broken one is a defect.");
  process.exit(1);
}

console.log("link check OK");
console.log(`  ${files.length} markdown files`);
console.log(`  ${checkedPaths} relative paths resolved, ${checkedAnchors} anchors matched`);
console.log(`  ${external} external URLs deferred to lychee (see .lycheeignore)`);
