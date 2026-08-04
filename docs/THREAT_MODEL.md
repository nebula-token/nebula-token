# NEBULA Threat Model

This document enumerates the threats NEBULA is designed to mitigate, the ones it
explicitly does not address, and the residual risks an adopter must manage. It
follows a simplified STRIDE analysis over the refresh-token lifecycle.

Threats **T1–T5 follow the adversary capabilities defined in the paper**
([`paper/nebula.tex`](paper/nebula.tex), §Threat Model), in the same order, so the
two documents can be read side by side. T1–T4 are those capabilities verbatim;
T5 is the paper's fifth — arbitrary interleaving of requests — stated as the
threat it produces. T6 onward are the additional lifecycle threats that the
specification addresses but the paper's capability model does not name
separately.

Every mitigation cites the requirement that makes it normative. §Traceability at
the foot maps each threat to its requirements and to the scenarios in
[`spec/behavior-vectors.json`](../spec/behavior-vectors.json) that enforce them —
those are ids you can grep for, in a file a third-party port must pass.

## Assets

- **A1** — The refresh token in transit and at rest on the client.
- **A2** — The server-side token records (selector, verifier hash, metadata).
- **A3** — The peppers (HMAC keys) in the server environment/KMS.
- **A4** — The user session itself (the ability to mint access tokens).

## Trust boundaries

1. Client ↔ Server (public network).
2. Server application ↔ Token store (database).
3. Server application ↔ Secret storage (env/KMS).

## Adversary model

We assume the server process, its environment (A3), and the platform CSPRNG are
uncompromised, and that transport is TLS. The adversary may hold any combination
of the five capabilities T1–T5 below — including T5, the ability to make requests
interleave arbitrarily, which is a capability every real deployment hands them for
free. Denial of service against the backing store and full client compromise after
login are out of scope, as they are for any token scheme.

## Threats and mitigations

| # | Threat | STRIDE | Mitigation |
|---|---|---|---|
| **T1** | **Client-side token copy** — the adversary obtains a copy of any token in transit or at rest on the client (XSS, malware, a device backup, a leaked log). | S | **Rotation** ([N-26] step 10, [N-34]) bounds the useful window to one refresh cycle. **Reuse detection** ([N-30]) revokes the whole family the moment both parties present the same credential, in either interleaving: whoever refreshes second is the one who trips it. Optional **sender binding** ([N-32]) rejects the adversary's *first* use when the binding input is not available to them. The residual exposure is one refresh cycle, not the remaining token lifetime — see §Residual risk R2. |
| **T2** | **Database read** — the adversary reads a complete copy of the server-side token store, excluding the process environment and KMS. | I | Records hold only `HMAC-SHA-256(pepper, verifier)` ([N-10], [N-11]); the pepper lives outside the database ([N-23]). The raw verifier and the raw device identifier are never persisted, logged, or included in any error value ([N-14], [N-46]). The dump yields no presentable token and no recoverable device identifier. Selectors *are* recoverable — which is why revocation by token requires the verifier ([N-36]). |
| **T3** | **Arbitrary input to the refresh endpoint** — the adversary submits any string, in any volume, to `/refresh`. | S, T | Forgery without a record requires guessing both a stored selector and the 256-bit verifier that belongs to it; given a known selector, it requires supplying a verifier whose tag under the record's pepper equals the stored one — an **existential forgery against a MAC under an unknown key**, not a second preimage on an unkeyed hash ([N-43], [N-44]). The distinction is load-bearing: HMAC is keyed, the adversary does not hold the pepper ([N-23]), so the tag is not a function they can evaluate, and the reduction is to pepper secrecy rather than to any property of SHA-256 alone. Every non-conforming string is refused as `MALFORMED` before any database interaction ([N-6], [N-8]), and the selector's 128 bits make enumeration infeasible ([N-45]). Parsing never throws on any input, including invalid UTF-8 and unpaired surrogates ([N-8], [N-12]). Volume is the deployment's problem: rate limiting is normatively out of scope and belongs at the edge (§10 of the specification, R5 below). |
| **T4** | **Timing** — the adversary measures response timing to learn whether a selector exists or how much of a verifier is correct. | I | Database lookups key only on the non-secret selector ([N-45]), so no secret-dependent index traversal occurs. Secret-derived comparison is constant-time, does not short-circuit, and treats malformed operands as unequal rather than decoding them leniently ([N-31]). Rejections are returned as values, never as exceptions ([N-29]), removing exception-timing oracles. The fixed check order ([N-26], [N-28]) makes the *set* of observable outcomes identical across implementations. |
| **T5** | **Rotation race forking a family** — two concurrent refreshes of the same token both mint a successor, producing two lineages that never observe each other's replay. | T, R | `markRotated` is a compare-and-set ([N-17]) and the database arbitrates: exactly one `UPDATE … WHERE selector = ? AND status = ?` can match. The loser revokes the successor it inserted and returns `CONFLICT` without minting anything ([N-34] step 5). `revokeIfActive` ([N-18]) plays the same role on the grace path ([N-30] step 2). `CONFLICT` is transient and revokes nothing beyond the engine's own orphan ([N-35]). This is not an exotic race — it is two browser tabs. |
| **T6** | **Token tampering or malleability** — the adversary alters a token to obtain a second valid form of one credential. | T | Tokens are opaque randomness: there is nothing meaningful to modify. Non-canonical base64url encodings are **normatively rejected** ([N-7]): a 32-byte value has four 43-character spellings, and without the rule the same credential has four wire forms that a permissive and a strict decoder disagree about. The three non-canonical variants of a known verifier are published as vectors `p-30`, `p-31`, `p-32` in [`spec/test-vectors.json`](../spec/test-vectors.json). |
| **T7** | **Replay of a used token** — the adversary presents a token that has already been rotated. | R | The default is conclusive: revoke the family, return `REUSE_DETECTED` ([N-30]). The optional grace window admits exactly one legitimate counterexample — a lost response — under six preconditions, is anchored to the *original* rotation time and therefore not extendable, and converts to a theft verdict on any evidence that the successor was used. See T12 for what enabling it costs. |
| **T8** | **Indefinite session extension** — the adversary (or an over-eager client) keeps a session alive past the deadline set at login. | E | `familyExpiresAt` is fixed at login and MUST never be extended ([N-10]); rotation reuses the family's value ([N-34] step 1) and the sliding deadline is clamped to it ([N-33] step 3). A grace retry cannot mint past it either ([N-30] condition 6). This is enforced, not merely asserted: `expiry-02-absolute-never-extended` asserts the ceiling is unchanged after rotation, `expiry-05-idle-clamped-to-family` asserts the clamp, `grace-06-never-past-absolute-deadline` asserts the grace path respects it, and `expiry-01-absolute` asserts the family dies and is revoked. Every conforming implementation runs all four. |
| **T9** | **Pepper compromise or rotation forcing mass logout** — rotating the HMAC key invalidates every outstanding session. | D | The `kid` indirection separates minting from verification: verification uses the pepper named by the **record** ([N-27], [N-32]), minting uses the configured active pepper ([N-33]). Introducing a new pepper therefore invalidates nothing; sessions migrate at their next natural rotation, device bindings included. Deliberately retiring a pepper is the emergency lever: those sessions become `UNKNOWN_KID` and the users re-authenticate. The runbook, including when an old `kid` may finally be deleted, is in [`OPERATIONS.md`](OPERATIONS.md). |
| **T10** | **Oversized or malformed input as a DoS vector** — the adversary sends megabyte strings or pathological encodings. | D | The `MAX_TOKEN_LENGTH` check is performed **before any other parsing work** ([N-6] rule 1), so rejection is O(1) and allocation-light. No input may cause a raise, throw, panic or abort ([N-8]). This bounds per-request cost; it does not bound request volume, which is R5. |
| **T11** | **Revocation gaps** — a password change, a lost device or a compromise report leaves credentials working. | E | `revokeToken` ([N-36]), `revokeFamily` and `revokeAllForUser` ([N-37]) are first-class, indexed operations returning the number of records revoked. `revokeToken` is authenticated by the verifier, so a selector recovered from a log or a dump (T2) is not by itself a capability to terminate someone's session; the administrative paths take server-side identifiers and are authorised by the application. |
| **T12** | **Grace window abused for a silent takeover** — the adversary holding a rotated predecessor refreshes inside the grace window, before the legitimate client uses its successor. | S, R | **Partially mitigated, by design.** [N-30] states the trade-off normatively: for `reuseGraceSeconds` after a rotation, such an adversary is served a valid token, the legitimate client is then evicted with `REVOKED`, and **no `REUSE_DETECTED` event is raised**. The default is therefore 0 (`DEFAULT_REUSE_GRACE`, §1), deployments SHOULD leave it there unless lost-response retries are an observed problem, and those that enable it SHOULD alert on the `REVOKED` rate as the substitute signal. Sender binding ([N-32]) still applies on the grace path and is checked first. |
| **T13** | **Early deletion of rotated records** — a TTL, a nightly cleanup, or a "spent row" heuristic removes the evidence that reuse detection depends on. | R, D | [N-15] makes retention until `familyExpiresAt` normative for deployments as well as implementations. The failure is silent: a deleted predecessor turns a replay into `NOT_FOUND` — a routine outcome nobody alarms on — so the theft signal and the family revocation both disappear while everything still appears to work. This is the one threat in this table that **no vector can catch**, because it is a property of your store's operations, not of the engine. Mitigation is procedural: the GC predicate and the index for it are in [`STORE.md`](STORE.md) §4, and monitoring for a suspicious `NOT_FOUND` rate is in [`OPERATIONS.md`](OPERATIONS.md). |

## Quantum adversary

The token layer is quantum-resistant by construction. There is no public-key
cryptography in NEBULA, so Shor's algorithm — which breaks RSA/ECC and thereby
every asymmetric-signed token format — has no target. Grover's search halves
brute-force exponents: the 256-bit verifier retains ~128 bits of quantum security
and HMAC-SHA-256 ~128 bits of preimage resistance, both considered post-quantum
safe. The corresponding statement for the pepper holds only when the pepper
carries close to 256 bits of entropy, which is why [N-23] asks for it.
"Harvest now, decrypt later" does not apply: validity is a row in the store, not
a mathematical property, so a captured token is inert once rotated, expired, or
revoked. Scope: this covers the token layer only — TLS transport and any
asymmetric-signed access tokens deployed alongside NEBULA require their own
post-quantum migration.

## Explicit non-goals (residual risk for the adopter)

- **R1 — Compromised server.** An attacker who can read A3 *and* write A2 can
  mint valid records. No token scheme survives full server compromise.
- **R2 — Compromised client after login.** An attacker with persistent control of
  the client receives each rotated token as the legitimate app would. Rotation
  and reuse detection bound the *aftermath* of a one-off theft (T1); they do
  nothing against an adversary who keeps stealing. Sender binding raises the bar
  in proportion to how strongly the binding input is tied to the device — strong
  for a keystore-held identifier on a native platform, weak on the web, where
  cryptographic sender-constraining (DPoP, mTLS) is the real answer.
- **R3 — Transport security.** NEBULA assumes HTTPS and defines no transport.
  Cookie attributes, CSRF defence and the endpoint shapes are in
  [`INTEGRATION.md`](INTEGRATION.md).
- **R4 — Store availability and consistency.** Reuse detection depends on the
  store being reachable and read-after-write consistent. Store errors must fail
  closed ([N-20]); the consistency analysis, including which staleness windows
  are self-healing and which are not, is in [`STORE.md`](STORE.md) §6.
- **R5 — Denial of service against the endpoint or the store.** Rate limiting is
  a non-goal of the specification (§10) and MUST be provided at the edge.
- **R6 — Access-token compromise.** NEBULA issues no access token and validates
  none. An access token stolen after a successful refresh remains valid for its
  own lifetime, whatever happens to the refresh family; keeping that lifetime
  short (5–15 minutes) is what bounds it.

## Security-relevant events

Alert on `REUSE_DETECTED` and `DEVICE_MISMATCH` — both mean a credential was very
likely stolen, and [N-39] requires the failure result to carry `userId` and
`familyId` so the event can be attributed without a second lookup of a token you
were told never to log. Monitor the rates of `VERIFIER_MISMATCH` (online
guessing), `NOT_FOUND` (enumeration, or a GC misconfiguration per T13), `CONFLICT`
(client retry storms), and `REVOKED` (the substitute signal under T12). Do not
return these codes to the caller: [N-42] asks for one generic response at the
boundary, with the specific code logged server-side. The single defensible
exception is `CONFLICT`, which the client must act on and which reveals nothing —
the engine reaches it only after the verifier has been proved
([`INTEGRATION.md`](INTEGRATION.md) §4). Thresholds and dashboards are in
[`OPERATIONS.md`](OPERATIONS.md).

## Traceability

Requirement ids are defined in [`SPECIFICATION.md`](../SPECIFICATION.md).
Scenario ids are the `id` fields of
[`spec/behavior-vectors.json`](../spec/behavior-vectors.json); `p-*` ids are
parsing cases in [`spec/test-vectors.json`](../spec/test-vectors.json). Every
conforming implementation executes all of them ([N-47], [N-48]).

The table below is the threat-side view. The requirement-side view — which
vectors and scenarios cover each `[N-*]`, and which requirements are verified by
review rather than by execution — is generated from the vector files themselves
and published as [`spec/traceability.json`](../spec/traceability.json).

| Threat | Requirements | Covering scenarios |
|---|---|---|
| T1 Client-side token copy | [N-26], [N-30], [N-32], [N-34], [N-39] | `rotate-01-basic`, `rotate-02-generation-accounting`, `reuse-01-replay-revokes-family`, `reuse-02-strict-mode-default`, `device-01-wrong-device-burns-family` |
| T2 Database read | [N-10], [N-11], [N-13], [N-14], [N-46] | `privacy-01-no-raw-secrets-persisted`, `revoke-01-token-requires-verifier-proof` |
| T3 Arbitrary input | [N-5], [N-6], [N-8], [N-12], [N-26], [N-43], [N-44] | `parse-01-malformed-never-throws`, `proof-01-verifier-mismatch`, `lookup-01-not-found`, `kid-04-unknown-kid-in-token`, `device-05-invalid-unicode-is-a-mismatch-not-a-crash` |
| T4 Timing | [N-28], [N-29], [N-31], [N-45] | `proof-01-verifier-mismatch`, `order-01-rotated-plus-wrong-verifier`, `order-02-revoked-plus-wrong-verifier` — these pin the *outcome* and the check order; timing itself is not vector-testable and is reviewed in code ([N-31]) |
| T5 Rotation race | [N-17], [N-18], [N-22], [N-34], [N-35] | `conflict-01-lost-rotation-cas`, `conflict-02-lost-grace-cas` |
| T6 Tampering / malleability | [N-6], [N-7] | `p-23`, `p-30`, `p-31`, `p-32` (test vectors), `parse-01-malformed-never-throws` |
| T7 Replay of a used token | [N-30], [N-34] | `reuse-01-replay-revokes-family`, `reuse-02-strict-mode-default`, `grace-01-retry-succeeds`, `grace-02-window-not-extendable`, `grace-03-denied-when-successor-used`, `order-04-reuse-beats-expiry` |
| T8 Indefinite session extension | [N-10], [N-26], [N-30], [N-33] | `expiry-01-absolute`, `expiry-02-absolute-never-extended`, `expiry-03-idle`, `expiry-04-idle-renews-on-each-refresh`, `expiry-05-idle-clamped-to-family`, `grace-06-never-past-absolute-deadline`, `order-05-idle-expiry-beats-device` |
| T9 Pepper compromise / rotation | [N-27], [N-32], [N-33] | `kid-01-pepper-rotation-preserves-sessions`, `kid-02-device-binding-survives-pepper-rotation`, `kid-03-retired-pepper-yields-unknown-kid` |
| T10 Oversized / malformed as DoS | [N-6], [N-8], [N-29] | `parse-01-malformed-never-throws`, `p-28` (test vectors) |
| T11 Revocation gaps | [N-19], [N-36], [N-37] | `revoke-01-token-requires-verifier-proof`, `revoke-02-token-works-after-rotation`, `revoke-03-family-and-user` |
| T12 Grace-window takeover | [N-30], [N-39] | `grace-01-retry-succeeds`, `grace-03-denied-when-successor-used`, `grace-04-device-mismatch-burns-family`, `grace-05-missing-device-burns-family`, `reuse-02-strict-mode-default` |
| T13 Early deletion of records | [N-15] | **None — not vector-testable.** Retention is a property of your store's operations. Enforce it procedurally: [`STORE.md`](STORE.md) §4 and [`OPERATIONS.md`](OPERATIONS.md) |

Two entries above deliberately admit a gap rather than paper over it: timing
(T4) is a property of the compiled code and is verified by review of [N-31], not
by a vector; and retention (T13) is a property of your operations and cannot be
verified from inside the library at all. Everything else in the table is
executable.
