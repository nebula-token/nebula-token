#!/usr/bin/env node
//
// scripts/check-actions-pinned.mjs — every third-party action is pinned to a SHA.
//
//   node scripts/check-actions-pinned.mjs
//
// `uses: actions/checkout@v4` is a mutable reference. Whoever controls that tag
// controls what runs in a workflow that holds `id-token: write` and the
// publishing credentials for ten registries. Tags move, and they have been moved
// maliciously before. A 40-character commit SHA cannot be moved.
//
// The trailing comment is not decoration: it is the only way a human, or
// Dependabot, can tell what version a SHA is, so it is required too.
//
// This gate exists because the rule is invisible in review — a reviewer skimming
// a 400-line workflow will not notice the one line that says @v4.

import { readFileSync, readdirSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join, resolve } from "node:path";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const WORKFLOWS = join(ROOT, ".github", "workflows");

const problems = [];
let pinned = 0;
let local = 0;

// Explicit comparator rather than the parameterless sort() (javascript:S2871),
// which orders by UTF-16 code unit after coercing to string. This reproduces
// that ordering exactly — so the reported order is unchanged — while stating it.
const byCodeUnit = (a, b) => {
  if (a < b) return -1;
  return a > b ? 1 : 0;
};

const files = readdirSync(WORKFLOWS).filter((f) => /\.ya?ml$/.test(f)).sort(byCodeUnit);
if (files.length === 0) {
  console.error("check-actions-pinned: no workflows found");
  process.exit(2);
}

for (const file of files) {
  const text = readFileSync(join(WORKFLOWS, file), "utf8");
  text.split("\n").forEach((line, i) => {
    // Job containers and service containers are third-party code with the same
    // reach as an action, so they are held to the same standard: a digest.
    const img = line.match(/^\s*image:\s*(\S+)(.*)$/);
    if (img) {
      const where = `${file}:${i + 1}`;
      if (!/@sha256:[0-9a-f]{64}$/.test(img[1])) {
        problems.push(`${where}: container image ${img[1]} is a mutable tag; pin it by digest (@sha256:...)`);
      } else if (!/^\s*#\s*\S/.test(img[2])) {
        problems.push(`${where}: container image is pinned by digest but carries no comment saying which tag it was`);
      } else {
        pinned += 1;
      }
      return;
    }

    const m = line.match(/^\s*(?:-\s+)?uses:\s*(\S+)(.*)$/);
    if (!m) return;
    const [, ref, rest] = m;
    const where = `${file}:${i + 1}`;

    // Local composite actions and reusable workflows in this repository are
    // pinned by definition: they travel with the commit being built.
    if (ref.startsWith("./") || ref.startsWith(".github/")) { local += 1; return; }

    if (ref.startsWith("docker://")) {
      if (!/@sha256:[0-9a-f]{64}$/.test(ref)) {
        problems.push(`${where}: ${ref} is a mutable container tag; pin it by digest (@sha256:...)`);
      } else pinned += 1;
      return;
    }

    const at = ref.lastIndexOf("@");
    if (at === -1) {
      problems.push(`${where}: ${ref} has no ref at all`);
      return;
    }
    const version = ref.slice(at + 1);
    if (!/^[0-9a-f]{40}$/.test(version)) {
      problems.push(`${where}: ${ref} is pinned to the mutable ref "${version}"; use the full commit SHA with the version in a trailing comment`);
      return;
    }
    if (!/^\s*#\s*\S/.test(rest)) {
      problems.push(`${where}: ${ref.slice(0, at)} is pinned to a SHA but carries no "# vX.Y.Z" comment, so nobody can tell which version it is`);
      return;
    }
    pinned += 1;
  });
}

if (problems.length) {
  console.error(`action pinning check FAILED — ${problems.length} problem(s)\n`);
  for (const p of problems) console.error(`  ${p}`);
  console.error("\nResolve a tag to its commit with:");
  console.error("  git ls-remote https://github.com/OWNER/REPO refs/tags/vX.Y.Z");
  process.exit(1);
}

console.log("action pinning check OK");
console.log(`  ${files.length} workflows: ${pinned} third-party uses pinned to commit SHAs, ${local} local`);
