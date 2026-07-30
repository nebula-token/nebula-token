#!/usr/bin/env node
//
// scripts/docker-test.mjs — run the whole conformance matrix without installing
// ten toolchains.
//
//   node scripts/docker-test.mjs                 all ten languages
//   node scripts/docker-test.mjs go              one language
//   node scripts/docker-test.mjs go ruby         several
//   node scripts/docker-test.mjs --check         validate the harness, no daemon
//   node scripts/docker-test.mjs --list          what the harness covers
//
// This project's central claim is that ten independent implementations agree,
// enforced by two shared vector files rather than by prose. Checking that claim
// used to require ten toolchains on one machine, and nobody has ten toolchains:
// while 1.0.0 was being finished, four of the ten — Go, Rust, Ruby and Elixir —
// could not be executed on the maintainer's machine at all. An implementation
// nobody local can run is an implementation that drifts. So the harness in
// docker/compose.yml runs every suite in the official upstream image for its
// language, pinned by digest at the floor .github/runtime-matrix.json declares,
// with this repository bind-mounted read-only.
//
// Two properties are worth more than the convenience:
//
//   * a reviewer, a security auditor or a third-party porter can reproduce the
//     conformance claim in one command, on a machine with nothing installed but
//     Docker;
//   * --check validates the harness itself offline — digest pins, floors, and
//     that every command still matches the one .github/workflows/ci.yml runs —
//     so the harness cannot quietly drift away from CI and keep passing.
//
// Dependency-free by design, like the other scripts here: node, and nothing
// else. Docker is only needed to *run* the matrix, never to check it.

import { readFileSync, readdirSync, existsSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { dirname, join, resolve } from "node:path";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const COMPOSE = join(ROOT, "docker", "compose.yml");
const COMPOSE_REL = "docker/compose.yml";
const CI_REL = ".github/workflows/ci.yml";
const MATRIX_REL = ".github/runtime-matrix.json";

// --------------------------------------------------------------- compose.yml

/**
 * A deliberately small, line-oriented reader for docker/compose.yml.
 *
 * Not a YAML parser: this repository's scripts take no dependencies, and the
 * real YAML validation is `docker compose config`, which --check also runs when
 * the Docker CLI is present. What is needed here is the handful of fields the
 * harness's invariants are stated over — service name, image, x-floor,
 * working_dir, the mounts, and the command lines — plus the trailing comments,
 * which a YAML parser would throw away and which carry the pinning rationale.
 */
function parseCompose(text) {
  const services = [];
  let inServices = false;
  let cur = null;
  let section = null;
  let collecting = false;

  text.split("\n").forEach((line, i) => {
    const at = i + 1;

    if (/^services:\s*$/.test(line)) { inServices = true; return; }
    if (/^[A-Za-z]/.test(line)) { inServices = line.startsWith("services:"); cur = null; section = null; collecting = false; }
    if (!inServices || /^\s*$/.test(line)) return;

    // The command body is a block scalar indented eight spaces. Collect it
    // first: its lines can otherwise look like keys.
    if (collecting) {
      if (/^ {8}\S/.test(line)) { cur.command.push({ text: line.trim(), line: at }); return; }
      collecting = false;
    }

    const svc = line.match(/^ {2}([A-Za-z][\w-]*):\s*$/);
    if (svc) {
      cur = { name: svc[1], line: at, image: null, comment: null, floor: null, workingDir: null, volumes: [], tmpfs: [], command: [] };
      services.push(cur);
      section = null;
      return;
    }
    if (!cur) return;

    const img = line.match(/^ {4}image:\s*(\S+)\s*(?:#\s*(.+?))?\s*$/);
    if (img) { cur.image = img[1]; cur.comment = img[2] ?? null; section = null; return; }

    const floor = line.match(/^ {4}x-floor:\s*(\S+)\s+(\S+)\s*$/);
    if (floor) { cur.floor = { runtime: floor[1], version: floor[2] }; section = null; return; }

    const parity = line.match(/^ {4}x-ci-parity:\s*(\S+)\s*$/);
    if (parity) { cur.parity = parity[1]; section = null; return; }

    const wd = line.match(/^ {4}working_dir:\s*(\S+)\s*$/);
    if (wd) { cur.workingDir = wd[1]; section = null; return; }

    const key = line.match(/^ {4}([\w-]+):\s*$/);
    if (key) { section = ["volumes", "tmpfs", "command"].includes(key[1]) ? key[1] : null; return; }

    const item = line.match(/^ {6}-\s*(.+?)\s*$/);
    if (item && section === "volumes") { cur.volumes.push(item[1]); return; }
    if (item && section === "tmpfs") { cur.tmpfs.push(item[1]); return; }
    if (item && section === "command") {
      if (item[1] === "|") collecting = true; // the block scalar starts on the next line
    }
  });

  return services;
}

/** Compose escapes a literal `$` as `$$`; CI's shell does not. */
const unescape$ = (s) => s.replaceAll("$$", "$");

/**
 * Split a command line into the command and its trailing comment. The split is
 * on whitespace-`#`-whitespace, which is where a POSIX shell starts a comment
 * too — so `$${#files[@]}` is not mistaken for one.
 */
function splitComment(text) {
  const m = text.match(/^(.*?)\s#\s(.*)$/);
  return m ? { command: m[1].trim(), comment: m[2].trim() } : { command: text.trim(), comment: null };
}

const compose = existsSync(COMPOSE) ? readFileSync(COMPOSE, "utf8") : null;
if (compose === null) {
  console.error(`docker-test: ${COMPOSE_REL} is missing — there is no harness to run.`);
  process.exit(2);
}
const SERVICES = parseCompose(compose);
if (SERVICES.length === 0) {
  console.error(`docker-test: parsed no services out of ${COMPOSE_REL}. Has its shape changed?`);
  process.exit(2);
}

const byName = new Map(SERVICES.map((s) => [s.name, s]));
/** The tag from the trailing comment — `node:22` — for the table. */
const tagOf = (s) => (s.comment ?? "").split(/\s+[—-]\s+/)[0].trim() || "(no tag comment)";

// ------------------------------------------------------------------- --check

/**
 * .github/workflows/ci.yml split into job blocks, keyed by job id, comments
 * dropped.
 *
 * The parity check is scoped to the job whose id matches the service, not to the
 * whole workflow: `npm ci` also appears in the `gates` job, and accepting a match
 * there would let the TypeScript service stop running the TypeScript job's
 * commands without anything noticing. Comments are dropped for the same reason
 * check-examples.mjs drops them — a commented-out step would otherwise keep this
 * green.
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

/** Compare dotted numeric versions: -1, 0, 1. Mirrors check-runtime-matrix.mjs. */
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
 * check-runtime-matrix.mjs holds equal to the package manifest's own claim.
 * Channel names ("stable") are not versions and are skipped.
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

function check() {
  const problems = [];
  const rows = [];

  // 1. Every implementation is covered, and nothing else is. An eleventh
  //    language port that forgets the harness is a language nobody without that
  //    toolchain can ever verify.
  // Explicit comparator, not the parameterless sort() (javascript:S2871): the
  // default coerces to string and orders by UTF-16 code unit. This reproduces
  // that exactly, so the order these problems are reported in does not move.
  const byCodeUnit = (a, b) => {
    if (a < b) return -1;
    return a > b ? 1 : 0;
  };
  const packages = readdirSync(join(ROOT, "packages"), { withFileTypes: true })
    .filter((e) => e.isDirectory())
    .map((e) => e.name)
    .sort(byCodeUnit);
  for (const pkg of packages) {
    if (!byName.has(pkg)) {
      problems.push(`packages/${pkg} has no service in ${COMPOSE_REL} — the harness must cover every implementation, or that one can only ever be verified by whoever has its toolchain`);
    }
  }
  for (const s of SERVICES) {
    if (!packages.includes(s.name)) {
      problems.push(`${COMPOSE_REL}:${s.line}: service "${s.name}" has no packages/${s.name}`);
    }
  }

  // 2. The mounts. Stated once in the file as anchors, so this checks the
  //    anchors and that every service uses them.
  const repoAnchor = compose.match(/^x-repo:\s*&repo\s*"(.+)"\s*$/m)?.[1];
  if (repoAnchor !== "../:/repo:ro") {
    problems.push(`${COMPOSE_REL}: the &repo anchor must be "../:/repo:ro" — the repository ROOT (every conformance runner walks up to spec/test-vectors.json), READ-ONLY (a conformance run must not be able to edit the tree it judges). Found: ${repoAnchor ?? "no anchor"}`);
  }
  // "/work:exec", not "/work": Docker mounts a tmpfs `noexec` by default, and a
  // staged package tree gets executed from as well as read (node_modules/.bin,
  // vendor/bin/phpunit). Dropping the option does not degrade the harness, it
  // breaks it — npm ci fails EACCES on esbuild, PHPUnit exits 126 — so the
  // option is asserted rather than left to whoever edits the anchor next.
  const workAnchor = compose.match(/^x-work:\s*&work\s*"(.+)"\s*$/m)?.[1];
  if (workAnchor !== "/work:exec") {
    problems.push(`${COMPOSE_REL}: the &work anchor must be "/work:exec" — /work is the writable staging tree, and Docker's default tmpfs options include noexec, which makes every binary a package installs into its own tree (node_modules/.bin, vendor/bin/phpunit) unrunnable. Found: ${workAnchor ?? "no anchor"}`);
  }

  const matrix = JSON.parse(readFileSync(join(ROOT, MATRIX_REL), "utf8"));
  const jobs = ciJobs(readFileSync(join(ROOT, CI_REL), "utf8"));

  for (const s of SERVICES) {
    const where = `${COMPOSE_REL}:${s.line} (${s.name})`;

    // 3. Digest pins, with the tag in a comment — the rule
    //    scripts/check-actions-pinned.mjs enforces for workflows, applied here.
    if (!s.image) {
      problems.push(`${where}: no image`);
    } else if (!/@sha256:[0-9a-f]{64}$/.test(s.image)) {
      problems.push(`${where}: image ${s.image} is a mutable tag; pin it by digest (@sha256:...). Resolve one with: docker buildx imagetools inspect <image>:<tag>`);
    } else if (!s.comment) {
      problems.push(`${where}: image is pinned by digest but carries no comment saying which tag and toolchain version that digest is, so nobody can tell what it tests`);
    }

    // 4. The image is the DECLARED FLOOR, not the newest release. Raising a
    //    floor in .github/runtime-matrix.json must fail here until the image
    //    moves with it — otherwise the harness silently stops testing the
    //    version the manifests promise.
    if (!s.floor) {
      problems.push(`${where}: no x-floor. Add "x-floor: <runtime-matrix key> <version>" so the pin can be held equal to the declared floor.`);
    } else {
      const floor = declaredFloor(matrix, s.floor.runtime);
      if (floor === null) {
        problems.push(`${where}: x-floor names "${s.floor.runtime}", which is not a runtime in ${MATRIX_REL}`);
      } else if (cmp(floor, s.floor.version) !== 0) {
        problems.push(`${where}: x-floor says ${s.floor.version} but ${MATRIX_REL} now tests ${floor} lowest — this image no longer tests the declared floor. Repin it to ${floor} and update the comment.`);
      } else if (s.comment && !s.comment.includes(s.floor.version)) {
        problems.push(`${where}: the image comment (${s.comment}) does not mention ${s.floor.version}, so a reader cannot tell the digest is the floor`);
      }
    }

    // 5. The working directory, the mounts, the staging.
    if (s.workingDir !== `/work/packages/${s.name}`) {
      problems.push(`${where}: working_dir is ${s.workingDir ?? "unset"}; it must be /work/packages/${s.name} — the package, inside the writable staging tree`);
    }
    if (!s.volumes.includes("*repo")) {
      problems.push(`${where}: does not mount the repository via the shared *repo anchor`);
    }
    if (!s.tmpfs.includes("*work")) {
      problems.push(`${where}: does not mount /work as a tmpfs via the shared *work anchor — build output would have nowhere to go but the read-only mount`);
    }
    const first = s.command[0] ? splitComment(s.command[0].text).command : null;
    if (first !== `sh /repo/docker/stage.sh ${s.name}`) {
      problems.push(`${where}: the first command must be "sh /repo/docker/stage.sh ${s.name}"; /repo is read-only, so the package has to be staged into /work first. Found: ${first ?? "no command"}`);
    }

    // 6. Command parity with the job of the same name in CI. A harness running
    //    different commands from CI certifies something CI never checked, and the
    //    difference is invisible in review — which is why it is checked
    //    mechanically here.
    const job = jobs.get(s.name);
    if (!job) {
      problems.push(`${where}: ${CI_REL} has no job called "${s.name}", so there is nothing to hold this service's commands equal to`);
    }
    let asserted = 0;
    let exempt = 0;
    for (const { text, line } of job ? s.command.slice(1) : []) {
      const { command, comment } = splitComment(text);
      if (command === "" || command.startsWith("#")) continue;
      if (comment?.startsWith("not-in-ci:")) {
        if (comment.replace(/^not-in-ci:\s*/, "").length < 4) {
          problems.push(`${COMPOSE_REL}:${line}: "${command}" is exempt from the CI parity check but gives no reason`);
        }
        exempt += 1;
        continue;
      }
      const want = unescape$(command);
      if (!job.some((l) => l.includes(want))) {
        problems.push(`${COMPOSE_REL}:${line}: "${want}" appears in no step of the "${s.name}" job in ${CI_REL}. Either run what that job runs, or mark the line "# not-in-ci: <why>".`);
        continue;
      }
      asserted += 1;
    }
    // A service where nothing is checked against CI could be testing anything.
    // NO service is in that position today: .NET was, while its commands carried
    // a `-f` flag CI read from a matrix, and that flag is gone. The escape hatch
    // below is therefore currently unused, and kept for the next time an official
    // image forces a divergence — which has to be declared, not discovered by a
    // reader.
    //
    // Note what this check is and is not. It requires at least ONE command per
    // service to appear in CI; it does not require CI's commands to appear in the
    // service. Parity is one-directional, so a service reduced to `npm ci` still
    // passes. Widening it to both directions needs a declared exemption list for
    // the steps that are deliberately CI-only — cargo clippy, dart analyze, the
    // example compiles — and is tracked as work rather than claimed here.
    if (asserted === 0 && s.parity !== "explained") {
      problems.push(`${where}: no command is checked against ${CI_REL}, so this service could be testing anything. If every line genuinely has to differ, say so with "x-ci-parity: explained" and give each line a "# not-in-ci:" reason.`);
    }
    if (asserted > 0 && s.parity === "explained") {
      problems.push(`${where}: carries "x-ci-parity: explained" but ${asserted} command(s) do match ${CI_REL} — drop the field, it is now hiding a real check`);
    }

    rows.push({ name: s.name, tag: tagOf(s), floor: s.floor ? `${s.floor.runtime} ${s.floor.version}` : "?", asserted, exempt });
  }

  // 7. docker/stage.sh, which every service depends on.
  if (!existsSync(join(ROOT, "docker", "stage.sh"))) {
    problems.push("docker/stage.sh is missing — every service stages through it");
  }

  // 8. The real YAML validation, when the CLI is here. This needs no daemon:
  //    `docker compose config` parses and interpolates locally.
  const cli = spawnSync("docker", ["compose", "-f", COMPOSE, "config", "-q"], { encoding: "utf8" });
  if (cli.error?.code === "ENOENT") {
    console.log("note: the Docker CLI is not on PATH, so `docker compose config` was not run.");
    console.log("      Every other check above is offline and did run.");
  } else if (cli.status !== 0) {
    problems.push(`docker compose config rejected ${COMPOSE_REL}:\n${(cli.stderr || cli.stdout || "").trim()}`);
  }

  if (problems.length) {
    console.error(`docker harness check FAILED — ${problems.length} problem(s)\n`);
    for (const p of problems) console.error(`  - ${p}`);
    console.error("\nThe harness is the supported way to reproduce the conformance claim.");
    console.error("It only means that while it still runs what CI runs, at the floors the");
    console.error("manifests declare, against the vectors in this repository.");
    process.exit(1);
  }

  console.log("docker harness check OK");
  const w = Math.max(...rows.map((r) => r.name.length));
  for (const r of rows) {
    const exempt = r.exempt ? `, ${r.exempt} explained` : "";
    console.log(`  ${r.name.padEnd(w)}  ${r.tag.padEnd(38)} floor ${r.floor.padEnd(14)} ${r.asserted} command(s) matched against CI${exempt}`);
  }
  console.log(`\n  ${rows.length} services, every image digest-pinned at the floor in ${MATRIX_REL}`);
}

// -------------------------------------------------------------- the daemon

/**
 * Docker's own message for "the daemon is not running" names a socket or a
 * Windows npipe path and reads like a misconfiguration. It is not one, and it is
 * the single most common way this script fails, so it gets a real diagnosis
 * rather than a stack trace.
 */
function requireDocker() {
  const cli = spawnSync("docker", ["--version"], { encoding: "utf8" });
  if (cli.error?.code === "ENOENT") {
    fail([
      "the Docker CLI is not on PATH, so nothing was run.",
      "",
      "  Install Docker Engine (Linux) or Docker Desktop (macOS, Windows):",
      "    https://docs.docker.com/get-started/get-docker/",
      "",
      "  Podman also works, with `podman-compose` or a docker-compatible socket,",
      "  but it is not what CI uses and is not what this harness is tested with.",
    ]);
  }
  const version = (cli.stdout || "").trim();

  const plugin = spawnSync("docker", ["compose", "version"], { encoding: "utf8" });
  if (plugin.status !== 0) {
    fail([
      "the Docker Compose plugin is missing, so nothing was run.",
      "",
      `  Docker CLI: ${version}`,
      "  `docker compose version` failed. This harness needs Compose v2 or newer",
      "  (the plugin, not the old standalone `docker-compose` script):",
      "    https://docs.docker.com/compose/install/",
    ]);
  }

  const daemon = spawnSync("docker", ["version", "--format", "{{.Server.Version}}"], { encoding: "utf8" });
  if (daemon.status !== 0) {
    fail([
      "the Docker daemon is not reachable, so nothing was run.",
      "",
      `  Docker CLI:   ${version}`,
      `  Compose:      ${(plugin.stdout || "").trim()}`,
      "  Daemon probe: `docker version --format '{{.Server.Version}}'` exited " + daemon.status,
      "",
      ...(daemon.stderr || "").trim().split("\n").filter(Boolean).map((l) => `    ${l}`),
      "",
      "  That message names a socket or an npipe path, which reads like a broken",
      "  configuration. It almost never is: the CLI is installed and the engine",
      "  is not running.",
      "",
      "    macOS, Windows   start Docker Desktop and wait for \"Engine running\"",
      "    Linux            sudo systemctl start docker",
      "    Colima           colima start",
      "    remote/rootless  docker context ls — the selected context must point",
      "                     at a daemon you can actually reach",
      "",
      "  The harness itself can be validated with no daemon at all:",
      "    node scripts/docker-test.mjs --check",
    ]);
  }
  return { cli: version, daemon: (daemon.stdout || "").trim() };
}

function fail(lines) {
  const bar = "-".repeat(78);
  console.error(bar);
  console.error(`docker-test: ${lines[0]}`);
  console.error(bar);
  for (const l of lines.slice(1)) console.error(l);
  console.error(bar);
  process.exit(2);
}

// ------------------------------------------------------------------ running

const human = (ms) => {
  const s = Math.round(ms / 1000);
  return s < 60 ? `${s}s` : `${Math.floor(s / 60)}m ${String(s % 60).padStart(2, "0")}s`;
};

function run(names) {
  const { cli, daemon } = requireDocker();

  console.log(`docker-test: ${names.length} of ${SERVICES.length} conformance suites`);
  console.log(`  docker ${cli.replace(/^Docker version /, "")}, daemon ${daemon}`);
  console.log(`  ${COMPOSE_REL}: official images, pinned by digest at the floors in ${MATRIX_REL}`);
  console.log("  the repository is mounted read-only; no container can write to your tree");
  console.log("");

  const results = [];
  const started = Date.now();

  for (const name of names) {
    const s = byName.get(name);
    console.log(`${"=".repeat(78)}\n=== ${name}  (${tagOf(s)})\n${"=".repeat(78)}`);
    const t0 = Date.now();
    // Inherited stdio: the point of a conformance run is the output of the ten
    // suites, and swallowing it to keep the table tidy would hide the evidence.
    const r = spawnSync("docker", ["compose", "-f", COMPOSE, "run", "--rm", "--no-TTY", name], { stdio: "inherit" });
    const ms = Date.now() - t0;
    if (r.error) {
      results.push({ name, ok: false, ms, note: r.error.message });
    } else {
      results.push({ name, ok: r.status === 0, ms, note: r.status === 0 ? "" : `exit ${r.status}` });
    }
    console.log("");
  }

  const w = Math.max(...results.map((r) => r.name.length), 8);
  const tw = Math.max(...names.map((n) => tagOf(byName.get(n)).length), 5);
  console.log("=".repeat(78));
  console.log(`  ${"LANGUAGE".padEnd(w)}  ${"IMAGE".padEnd(tw)}  RESULT  TIME`);
  for (const r of results) {
    const tag = tagOf(byName.get(r.name));
    const note = r.note ? `  ${r.note}` : "";
    console.log(`  ${r.name.padEnd(w)}  ${tag.padEnd(tw)}  ${r.ok ? "PASS  " : "FAIL  "}  ${human(r.ms).padStart(7)}${note}`);
  }
  const failed = results.filter((r) => !r.ok);
  console.log("=".repeat(78));
  console.log(`  ${results.length - failed.length} passed, ${failed.length} failed in ${human(Date.now() - started)}`);

  if (failed.length) {
    console.log("");
    console.log(`  FAILED: ${failed.map((r) => r.name).join(", ")}`);
    console.log("  Re-run one, and get a shell in the same image to look around:");
    console.log(`    node scripts/docker-test.mjs ${failed[0].name}`);
    console.log(`    docker compose -f ${COMPOSE_REL} run --rm ${failed[0].name} bash`);
    console.log("  Inside that shell, stage the package first:");
    console.log(`    sh /repo/docker/stage.sh ${failed[0].name} && cd /work/packages/${failed[0].name}`);
    process.exit(1);
  }
  console.log(`  ${results.length === SERVICES.length ? "Every implementation agrees with the vectors in spec/." : "Run with no arguments for all ten."}`);
}

// --------------------------------------------------------------------- main

const args = process.argv.slice(2);
const flags = args.filter((a) => a.startsWith("-"));
const names = args.filter((a) => !a.startsWith("-"));

for (const f of flags) {
  if (!["--check", "--list", "--help", "-h"].includes(f)) {
    console.error(`docker-test: unknown option ${f}\n`);
    flags.push("--help");
  }
}

if (flags.includes("--help") || flags.includes("-h")) {
  // The header comment of this file is the documentation, so --help prints it
  // rather than a second copy that could disagree with it.
  const help = [];
  for (const line of readFileSync(fileURLToPath(import.meta.url), "utf8").split("\n").slice(1)) {
    if (!line.startsWith("//")) break;
    help.push(line.replace(/^\/\/ ?/, ""));
  }
  console.log(help.join("\n").trim());
  process.exit(flags.some((f) => !["--check", "--list", "--help", "-h"].includes(f)) ? 2 : 0);
}

if (flags.includes("--list")) {
  console.log(`${COMPOSE_REL} — ${SERVICES.length} services`);
  const w = Math.max(...SERVICES.map((s) => s.name.length));
  for (const s of SERVICES) {
    const floor = s.floor ? `floor ${s.floor.runtime} ${s.floor.version}` : "";
    console.log(`  ${s.name.padEnd(w)}  ${tagOf(s).padEnd(38)} ${floor}`);
  }
  process.exit(0);
}

if (flags.includes("--check")) {
  check();
  process.exit(0);
}

const unknown = names.filter((n) => !byName.has(n));
if (unknown.length) {
  console.error(`docker-test: no such language: ${unknown.join(", ")}`);
  console.error(`  known: ${SERVICES.map((s) => s.name).join(", ")}`);
  process.exit(2);
}

run(names.length ? names : SERVICES.map((s) => s.name));
