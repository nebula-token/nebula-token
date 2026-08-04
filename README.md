<div align="center">

<img src="assets/mark.svg" width="88" alt="NEBULA logo — an orbit with a token in rotation around a core that never leaves the server">

# NEBULA

**Opaque rotating refresh tokens — one specification, ten reference implementations.**

An implementation profile of the [OAuth 2.0 Security Best Current Practice (RFC 9700)](https://www.rfc-editor.org/rfc/rfc9700) refresh-token model: rotation on every use, replay (reuse) detection with family revocation, bounded lifetimes, and optional sender binding.

[Specification](SPECIFICATION.md) · [Integration guide](docs/INTEGRATION.md) · [Test vectors](spec/test-vectors.json) · [Behaviour vectors](spec/behavior-vectors.json) · [Security policy](SECURITY.md) · [Contributing](CONTRIBUTING.md)

</div>

---

## Why NEBULA?

Most refresh-token implementations get the threat model wrong. They make the token itself cryptographically elaborate — signed, encrypted, multi-layered — when the real danger is much simpler: **a stolen refresh token that keeps working for days.**

A refresh token is a long-lived credential. If an attacker exfiltrates one (XSS, malware, leaked logs, a compromised device), nothing *inside* the token helps — the token itself is the key. What limits the damage is server-side policy:

1. **Rotation** — every use of a refresh token invalidates it and issues a successor. A stolen token is only useful until its rightful owner refreshes.
2. **Reuse detection** — if an already-used token is presented again, two parties hold the same credential. That is theft. NEBULA revokes the entire session ("family") immediately, cutting off the attacker *and* surfacing the compromise.
3. **Revocability** — because state lives server-side, any token, session, or user can be killed instantly. Self-contained (stateless) tokens fundamentally cannot do this.

This is the model recommended by RFC 9700 and used in production by major identity providers. NEBULA packages it as one precise specification plus small, auditable, dependency-free implementations for the major backend languages.

## How it works

A NEBULA token is pure entropy — it carries no claims, no user data, no structure to attack:

```
nbl.{kid}.{selector}.{verifier}
      │       │           └─ 256-bit secret, base64url — proof of possession
      │       └─ 128-bit lookup key, base64url — O(1) DB access, safe to index
      └─ pepper key id — zero-downtime pepper rotation
```

The server stores only `HMAC-SHA-256(pepper, verifier)`; the pepper lives in your environment/KMS, never in the database. A full database dump yields nothing replayable. Lookups key on the non-secret selector; the verifier is checked in constant time. Two clocks bound every session: a fixed absolute deadline set at login, and a sliding idle deadline renewed on each refresh. Optionally, a family can be bound to a device identifier — a refresh from anywhere else burns the session.

There is deliberately **no cryptographic novelty** here: HMAC-SHA-256, CSPRNG output, and constant-time comparison, composed in the most boring way possible. Boring is the feature.

## One spec, one behavior, ten languages

[`SPECIFICATION.md`](SPECIFICATION.md) is the single normative definition — token format, the exact 10-step refresh algorithm, reuse/grace semantics, the six-method store contract, and the ten error codes. Its requirements are numbered `[N-1]`…`[N-53]`, so a test, a threat-model entry or a third-party conformance report can cite the exact sentence it depends on. Conformance is not a promise but an artefact: every implementation must pass the 46 shared [test vectors](spec/test-vectors.json) (hashing, canonical encoding, parsing) **and** the 38 scenarios of the machine-readable [behaviour suite](spec/behavior-vectors.json) — rotation, replay, grace window, expiry, sender binding, pepper rotation, concurrent-refresh conflicts, revocation. Behavior changes happen in the spec first, then in all implementations — never the other way around.

| Language | Package | Directory | Runtime deps |
|---|---|---|---|
| TypeScript | `nebula-token` | [`packages/typescript`](packages/typescript) | none |
| Python | `nebula-token` | [`packages/python`](packages/python) | none |
| Go | `github.com/nebula-token/nebula-token/packages/go` | [`packages/go`](packages/go) | none |
| Rust | `nebula-token` | [`packages/rust`](packages/rust) | 6 crates: `hmac`, `sha2`, `subtle` (RustCrypto), `base64`, `hex`, `rand` |
| Java | `dev.nebulatoken:nebula-token` | [`packages/java`](packages/java) | none |
| PHP | `nebula-token/nebula-token` | [`packages/php`](packages/php) | none |
| C# / .NET | `NebulaToken` | [`packages/csharp`](packages/csharp) | none |
| Dart | `nebula_token` | [`packages/dart`](packages/dart) | `crypto` |
| Ruby | `nebula-token` | [`packages/ruby`](packages/ruby) | none |
| Elixir | `nebula_token` | [`packages/elixir`](packages/elixir) | none (`jason` test-only) |

Kotlin and Scala are covered natively by the Java package (`dev.nebulatoken:nebula-token`) — it is plain JDK code with no framework assumptions.

**Third-party implementations:** none listed yet. Anyone may implement NEBULA and state that their implementation "conforms to NEBULA spec version 1" once it passes the published vectors in full — the claim is the implementer's, and this project neither certifies nor endorses it ([N-53]). What a listing here requires, and what it deliberately does not mean, is in [`GOVERNANCE.md`](GOVERNANCE.md) §7.

Each package ships the engine, the store contract, and an in-memory store for development. For production you implement the six-method store over your database (Redis, Postgres, DynamoDB, …); ready-to-apply schemas for PostgreSQL, MySQL and SQLite are in [`spec/schema/`](spec/schema), and the guidance that goes with them — the exact SQL per method, retention, transactions, consistency — is in [`docs/STORE.md`](docs/STORE.md).

## Agent skills

If an AI assistant writes the integration, give it the skill for your language. Ten are published — one per package — in the standard agent-skill format, and each carries the rules that are easy to get plausibly wrong: retry `CONFLICT` once, leave `reuseGraceSeconds` at 0 because raising it serves a replayed token and raises no `REUSE_DETECTED`, never use the in-memory store in production, attribute a failure with the `userId`/`familyId` it already carries, and never log the token.

Install one with the standard agent-skill installer, which targets Claude Code, Codex, Cursor, OpenCode and dozens of other clients:

```sh
npx skills add nebula-token/nebula-token --list                        # look first, install nothing
npx skills add nebula-token/nebula-token --skill nebula-token-python   # or any of the ten
npx skills add nebula-token/nebula-token --skill '*'                   # all ten, to the agents you have
```

That installs into the **project** — `.claude/skills/`, checked in and shared with your team. Add `-g` to install into your **personal** `~/.claude/skills/` instead; that is the choice people get wrong.

Claude Code also takes them as plugins, one per language:

```text
/plugin marketplace add nebula-token/nebula-token
/plugin install nebula-token-python@nebula-token
```

Both routes read the same files in place. Each skill lives inside the package it documents, in the directory shape a client installs — `packages/<language>/skills/nebula-token-<language>/SKILL.md` — and [`.claude-plugin/marketplace.json`](.claude-plugin/marketplace.json) points the installers straight at it, so nothing is copied, mirrored or generated. Every published artefact carries that same directory, which makes a dependency you have already installed a source of the skill too.

The fallbacks — from an installed package, from a clone, and from the release archive for offline and air-gapped machines — are in [`skills/README.md`](skills/README.md), with the path inside each registry's artefact. There is exactly one copy of each skill: `scripts/check-skills.mjs` fails the build if a second one appears, if a frontmatter `name` stops matching its directory, or if a manifest would publish an artefact without it, and `scripts/check-marketplace.mjs` fails it if the manifest and the tree stop naming the same ten skills in either direction.

## Quick taste (TypeScript)

```ts
import { NebulaEngine, MemoryRefreshTokenStore } from 'nebula-token';

const engine = new NebulaEngine({
  peppers: { k1: process.env.NEBULA_PEPPER_K1! }, // ≥ 32 bytes, from env/KMS
  activeKid: 'k1',
  store: new MemoryRefreshTokenStore(),           // implement RefreshTokenStore for prod
  // reuseGraceSeconds defaults to 0 — strict. A non-zero window can serve an
  // attacker a valid token with no REUSE_DETECTED event; leave it alone unless
  // lost-response retries are a measured problem.
});

// Login → start a token family. Timestamps are integer Unix seconds.
const { token, idleExpiresAt } = await engine.issue('usr_1', deviceId);

// Refresh endpoint → rotate.
const result = await engine.refresh(presentedToken, deviceId);

if (result.ok) {
  setRefreshCookie(result.token, result.idleExpiresAt);     // predecessor is now dead
} else if (result.error === 'CONFLICT') {
  respond409();  // a concurrent refresh won the CAS; the client retries once with
                 // the successor's cookie — never with the token that just lost
} else {
  if (result.error === 'REUSE_DETECTED' || result.error === 'DEVICE_MISMATCH') {
    alertSecurityTeam(result.error, result.userId, result.familyId); // family already revoked
  }
  respond401();  // every failure gets one generic response — the code stays in your logs
}
```

Every other language reads the same way — same names, same semantics, same error codes. The endpoints around this snippet, with the exact cookie attributes and the full error-code table, are in [`docs/INTEGRATION.md`](docs/INTEGRATION.md).

## Deployment checklist

Serve refresh tokens only over HTTPS in an `httpOnly`, `Secure`, `SameSite=Strict` cookie whose `Path` covers the refresh *and* logout endpoints and nothing else — never `localStorage`. Keep access tokens short-lived (5–15 min) so rotation happens often. Generate peppers with `openssl rand -base64 48`; rotate them periodically via `kid` with zero downtime. Rate-limit the refresh endpoint. Log and alert on `REUSE_DETECTED` and `DEVICE_MISMATCH` — they mean a credential was likely stolen. Garbage-collect records whose family has passed its absolute deadline; keep `rotated`/`revoked` rows until then, they are what makes reuse detection work.

The long form of each of those, with the reasoning: [`docs/INTEGRATION.md`](docs/INTEGRATION.md) for the HTTP layer, [`docs/STORE.md`](docs/STORE.md) for the store, [`docs/OPERATIONS.md`](docs/OPERATIONS.md) for metrics, key rotation, capacity and incident response.

## When to use NEBULA — and when not to

**Use NEBULA when** you build first-party authentication in your own backend and want refresh-token handling that matches what managed identity providers do internally: no per-user pricing, no vendor lock-in, session data in your own database (relevant for GDPR / data residency), identical behavior across every language in your stack.

**Do not use NEBULA when:** you already run a managed IdP (Auth0, Okta, Cognito — use its built-in rotation); you need full OAuth 2.0 / OIDC with third-party clients, scopes, and consent screens (you need an authorization server such as Keycloak or Ory, not a token library); you operate under FAPI 2.0 / open-banking requirements (you additionally need cryptographic sender-constraining — DPoP or mTLS — at the protocol layer; NEBULA's device binding is application-level); or your stack is a single language and its authorization-server framework already does this (OpenIddict, Spring Authorization Server, Fosite, Authlib — each is better integrated with its ecosystem than NEBULA will ever be, and the ten-language conformance guarantee is worth nothing to you).

### FAQ

**Why does it need a database?** Because instant revocation and reuse detection require server-side state — a stateless token cannot be revoked before it expires, which is exactly why RFC 9700 moved the industry away from stateless refresh tokens. NEBULA doesn't pick your database: it defines a six-method contract you implement over whatever you already run. Cost: one indexed lookup per refresh.

**Why not a JWT as refresh token?** A JWT proves who signed it, but cannot be un-signed: revocation requires a server-side denylist — at which point you have a database anyway, plus a signature scheme you no longer need. Claims belong in the short-lived *access* token; the refresh token is a credential, not an envelope.

**Why not self-host Ory, Keycloak or Supabase Auth?** If you need what those are — an identity provider that owns login, consent and the OAuth 2.0 protocol surface — run one, and take its rotation with it. The question only gets interesting when the refresh-token mechanism is all you need. Those engines are multi-language in the sense that any language can call their HTTP API: there is one implementation, behind a network hop, that you deploy, patch, monitor and keep available, and it wants to own your user table. NEBULA is multi-language in a different sense — ten *in-process* implementations that agree byte-for-byte, pinned by shared vectors. A refresh is an HMAC and one compare-and-set write against the database you already run: no service in the path, nothing extra that can be down, and session data that stays in your own schema. What NEBULA competes with is not an identity provider; it is the rotation logic you would otherwise write by hand — where the usual defect is the concurrent refresh: two parallel requests presenting the same token both observe it as active, both mint a successor, and the family forks into two independently valid lineages — which defeats reuse detection entirely. That is not an exotic race; it is a mobile client retrying, or two browser tabs refreshing together. Here it is a compare-and-set with a specified losing branch ([N-34] step 5, returning a retryable `CONFLICT` per [N-35]) rather than something left to the reader.

**What is genuinely new here?** Not the cryptography — deliberately. What did not exist before is a precise, testable, language-independent specification of the RFC 9700 rotation model: exact check order, exact reuse/grace semantics, shared conformance vectors, and ten implementations held to them by one executable suite rather than by ten hand-written ones.

## Security model, honestly stated

NEBULA protects against: token theft (bounded by rotation + reuse detection), database dumps (peppered hashes), token forgery (256-bit entropy), and timing side-channels (constant-time comparison, non-secret lookup keys). It cannot protect against a compromised server that can read the peppers and the store, or an attacker who fully controls the client after login — no token scheme can.

A consequence of the design worth spelling out: **the token layer is quantum-resistant by construction.** NEBULA uses no public-key cryptography anywhere, so Shor's algorithm — the quantum attack that breaks RSA and elliptic curves, and with them every RS256/ES256-signed token — has nothing to attack. The only applicable quantum speedup is Grover's search, which reduces the 256-bit verifier to an effective ~128 bits of security: still far beyond reach. And because validity lives in your database rather than in the math, "harvest now, decrypt later" does not apply — a recorded token is dead the moment it rotates, expires, or is revoked, regardless of future computing power. This statement covers the token layer only: the TLS channel and any asymmetric-signed access tokens deployed alongside it have their own post-quantum migrations ahead.

Vulnerabilities go through [SECURITY.md](SECURITY.md), never public issues.

## Maturity, stated plainly

A library on an authentication path should tell you what it has and has not been through. NEBULA's position, as of the 1.0 line:

- **No independent security audit.** None has been performed. [`SECURITY.md`](SECURITY.md) keeps the full list of what is missing — no formal verification of the rotation state machine, no fuzzing beyond the published vectors.
- **No production track record.** These implementations are new. Nobody can yet tell you how they behave at scale, because nobody has run them at scale.
- **What is real is the conformance.** Behaviour is not asserted in prose and hoped for in code: it is pinned by 46 test vectors and 38 executable behavioural scenarios that every implementation runs on every CI run, in all ten languages, with a runner that must assert the published case counts and fail on an empty section ([N-48]). Two implementations that pass agree at every point those artefacts observe: the accept/reject decision for the token strings the parsing vectors cover, the byte-level output of both keyed hashes, and — for each scenario, over whichever of them it asserts — the outcome code, the generation, the family and expiry relations, and the resulting multiset of record statuses in the store. That is a bounded claim rather than a universal one, and it is deliberately the one this project makes: the vectors do not observe timing, log output or store call ordering, and no differential harness yet drives all ten from one random transcript. It is also checkable — checkable by you, not just by our CI: `node scripts/docker-test.mjs` runs all ten suites in official images pinned by digest at the declared version floors, with nothing installed but Docker ([`docker/README.md`](docker/README.md)).
- **The surface is small on purpose.** Each implementation is one small package — dependency-free in eight of the ten — meant to be read in a sitting. The most useful thing you can do before adopting it is read it.

What is frozen and what may still move is spelled out in [`COMPATIBILITY.md`](COMPATIBILITY.md); how a third-party port may claim conformance ([N-53]) is in [`GOVERNANCE.md`](GOVERNANCE.md).

## Repository layout

```
SPECIFICATION.md           ← the normative definition (start here), requirements [N-1]…[N-53]
spec/test-vectors.json     ← 46 shared conformance cases: hashing and parsing (plus a constants block)
spec/behavior-vectors.json ← 38 normative behavioural scenarios — the machine-readable suite
spec/traceability.json     ← generated: which vectors and scenarios cover each requirement
spec/schema/*.sql          ← the store schema for PostgreSQL, MySQL and SQLite
packages/<language>/       ← one self-contained package per language
packages/*/examples/       ← production-style store templates (not published; compiled by CI, never executed)
packages/*/skills/         ← per-language agent skills, installable as they stand and shipped in every artefact
skills/README.md           ← the index of the ten skills: where each one lives and how to install it
docs/INTEGRATION.md        ← the HTTP layer end to end: endpoints, cookies, error codes, migration
docs/STORE.md              ← the six methods as SQL, retention, transactions, consistency
docs/OPERATIONS.md         ← metrics, alarms, pepper rotation, GC, capacity, incident response
docs/THREAT_MODEL.md       ← STRIDE analysis, with requirement and vector traceability
docs/COMPLIANCE.md         ← honest ASVS / NIST SP 800-63B mapping
docs/paper/                ← the accompanying paper (LaTeX source; the PDF is built by CI)
COMPATIBILITY.md           ← what 1.0 freezes, what may move, the support window
VERSIONING.md              ← spec_version vs package versions
RELEASING.md               ← how ten artefacts are published from one tag
GOVERNANCE.md              ← who decides what, and how a spec change happens
SECURITY.md                ← disclosure policy, and what this project has not done
SUPPORT.md                 ← where to ask what
docker/                    ← run the whole conformance matrix without installing ten toolchains
.github/workflows/ci.yml   ← full test matrix across all 10 languages, plus the repository gates
AGENTS.md                  ← instructions for coding agents (CLAUDE.md imports it)
```

## Contributing

Read [CONTRIBUTING.md](CONTRIBUTING.md). The short version: the spec is the source of truth, every implementation must pass the shared vectors, no new runtime dependencies, no novel cryptography. New language ports are very welcome; [`GOVERNANCE.md`](GOVERNANCE.md) describes how one gets listed and how a spec change is made. For questions rather than changes, [`SUPPORT.md`](SUPPORT.md) says where to ask what.

## License

**Apache License 2.0** — the full text is in [`LICENSE`](LICENSE). SPDX: `Apache-2.0`. One licence, not a choice: the explicit, irrevocable patent grant in §3 is what a legal review looks for before a dependency is allowed onto an authentication path, and a specification that invites independent implementations ought to provide it. This covers the specification text, the conformance vectors, and all ten reference implementations.

Practical consequence worth knowing before you vendor it: Apache-2.0 is compatible with GPLv3 and with LGPLv3, but the FSF considers it incompatible with **GPLv2-only** — a GPLv2-only project cannot combine NEBULA into its distribution.

© Matteo Teodori
