# NEBULA Specification, Version 1

**Status:** Stable
**Spec version:** 1 (`spec_version = 1`)
**Conformance:** The key words MUST, MUST NOT, REQUIRED, SHALL, SHALL NOT, SHOULD, SHOULD NOT, RECOMMENDED, MAY and OPTIONAL are to be interpreted as described in [RFC 2119](https://www.rfc-editor.org/rfc/rfc2119) and [RFC 8174](https://www.rfc-editor.org/rfc/rfc8174) when, and only when, they appear in all capitals.

This document is the single normative definition of NEBULA. Every implementation in this repository — and any third-party implementation claiming conformance — MUST implement exactly the behavior described here and MUST pass the shared conformance artifacts in [`spec/test-vectors.json`](spec/test-vectors.json) and [`spec/behavior-vectors.json`](spec/behavior-vectors.json).

NEBULA is an implementation profile of the refresh-token recommendations in [RFC 9700 (OAuth 2.0 Security Best Current Practice)](https://www.rfc-editor.org/rfc/rfc9700): opaque tokens, rotation on every use, replay (reuse) detection with family revocation, bounded lifetimes, and optional sender binding.

Requirements in this document are individually identified as **[N-*n*]** so that tests, threat-model entries and third-party conformance reports can cite them. The mapping from requirement to test is published in [`spec/traceability.json`](spec/traceability.json).

---

## 1. Constants

| Name | Value |
|---|---|
| `PREFIX` | `"nbl"` |
| `SELECTOR_BYTES` | 16 |
| `VERIFIER_BYTES` | 32 |
| `SELECTOR_CHARS` | 22 (base64url of 16 bytes, unpadded) |
| `VERIFIER_CHARS` | 43 (base64url of 32 bytes, unpadded) |
| `MAX_KID_LENGTH` | 64 bytes |
| `MAX_TOKEN_LENGTH` | 512 bytes |
| `MIN_PEPPER_LENGTH` | 32 bytes |
| `DEFAULT_ABSOLUTE_TTL` | 2 592 000 s (30 days) |
| `DEFAULT_IDLE_TTL` | 604 800 s (7 days) |
| `DEFAULT_REUSE_GRACE` | 0 s (strict) |

**[N-1]** All lengths in this specification are measured in **bytes of the UTF-8 encoding** of the value, never in characters, Unicode scalar values, UTF-16 code units, or grapheme clusters. Because a conforming token is US-ASCII by construction (§2), byte length and character length coincide for every token that can be issued; the byte rule is what governs rejection of non-conforming input.

**[N-2]** All timestamps are Unix time in **seconds** (integer). Implementations MUST represent them in a signed integer type of at least 64 bits.

**[N-3]** Implementations MUST allow clock injection, so that conformance tests can drive time deterministically.

**[N-4]** Implementations MUST expose every constant in this table as a public, named value of the package.

## 2. Token format

```
nbl.{kid}.{selector}.{verifier}
```

**[N-5]** A token MUST match the following ABNF ([RFC 5234](https://www.rfc-editor.org/rfc/rfc5234)):

```abnf
token      = %s"nbl" "." kid "." selector "." verifier
kid        = 1*64 b64url
selector   = 22 b64url
verifier   = 43 b64url
b64url     = ALPHA / DIGIT / "-" / "_"
```

- `kid` — pepper key identifier. Chosen by the operator. Opaque to this specification.
- `selector` — base64url (RFC 4648 §5, **unpadded**) of `SELECTOR_BYTES` CSPRNG bytes. The public lookup key.
- `verifier` — base64url (RFC 4648 §5, **unpadded**) of `VERIFIER_BYTES` CSPRNG bytes. The secret.

**[N-6]** A token MUST be rejected as `MALFORMED` when any of the following holds, and implementations MUST perform the length check before any other parsing work:

1. its length exceeds `MAX_TOKEN_LENGTH` bytes;
2. it does not split into exactly four parts on `.` (U+002E), or any part is empty;
3. part 1 is not exactly `PREFIX`;
4. any part contains a byte outside the `b64url` set — this includes padding (`=`), whitespace of any kind, and the standard-base64 characters `+` and `/`;
5. `kid` exceeds `MAX_KID_LENGTH` bytes;
6. `selector` is not exactly `SELECTOR_CHARS` characters, or `verifier` is not exactly `VERIFIER_CHARS` characters;
7. the `verifier` does not base64url-decode to exactly `VERIFIER_BYTES` bytes;
8. the `verifier` is not **canonical**.

**[N-7] Canonical encoding.** A base64url string is canonical iff re-encoding its decoded bytes reproduces the input string exactly. Implementations MUST enforce this by decoding and re-encoding, or by an equivalent check on the trailing bits.

> **Why this is normative.** A 32-byte value has four distinct 43-character base64url encodings, because the final character carries four significant bits and two unused ones. Without [N-7] the same credential has four wire forms; a permissive decoder in one implementation and a strict one in another disagree on whether a presented string is a valid token. The vectors in `spec/test-vectors.json` include all three non-canonical variants of a known verifier.

**[N-8]** Parsing MUST NOT raise, throw, panic, or abort on any input, including the empty string, a null/nil reference where the language permits one, invalid UTF-8 byte sequences, and inputs at or beyond `MAX_TOKEN_LENGTH`. Every rejection MUST be reported as the `MALFORMED` value.

**[N-9]** Parsing MUST NOT be influenced by locale, culture, or case-folding settings.

## 3. Server-side record

**[N-10]** One record per issued token, with at minimum these fields (names MAY follow language conventions; semantics MUST NOT change):

| Field | Type | Meaning |
|---|---|---|
| `selector` | string | Primary key. The only token-derived value that may be indexed. |
| `verifierHash` | string | Lowercase hex of `HMAC-SHA-256(pepper[kid], verifier_bytes)`. |
| `kid` | string | Pepper id used for `verifierHash` **and** `deviceIdHash`. |
| `familyId` | string | Lowercase hex of 16 CSPRNG bytes, fixed at login, shared across rotations. |
| `generation` | int | 0 at issue, +1 per rotation. |
| `userId` | string | Owner. |
| `deviceIdHash` | string \| null | Lowercase hex of `HMAC-SHA-256(pepper[kid], "device:" ‖ deviceId)`, or null when unbound. |
| `createdAt` | int | Issue time of this record. |
| `familyExpiresAt` | int | Absolute deadline. Fixed at login. MUST never be extended. |
| `idleExpiresAt` | int | Sliding deadline: `min(now + idleTtl, familyExpiresAt)`. |
| `status` | enum | `active` \| `rotated` \| `revoked`. |
| `rotatedAt` | int \| null | Set on first rotation. On a grace retry (§6.3) it MUST keep its original value. |
| `replacedBySelector` | string \| null | Selector of the successor record. |

**[N-11] Hash input encoding.** The HMAC key is the pepper encoded as **UTF-8**. The HMAC message for `verifierHash` is the raw decoded verifier bytes. The HMAC message for `deviceIdHash` is the UTF-8 encoding of the string `"device:"` concatenated with the device identifier. Implementations MUST NOT apply any other text encoding, normalisation form, case transformation, or trimming to either input.

Some runtimes give a string value a **declared encoding** alongside its bytes. Where the bytes of such a value are already a valid UTF-8 encoding, those bytes **are** the input required above, and an implementation MUST use them as they are: it MUST NOT decide acceptance on the declared encoding, and MUST NOT transcode from it, which the preceding sentence already forbids as "any other text encoding". Deciding on the tag rather than on the bytes makes one implementation refuse an identifier — and, in `refresh`, revoke a family ([N-32]) — where the others rotate. Bytes that are not a valid UTF-8 encoding have no UTF-8 encoding to speak of and are governed by [N-12] and by §5 ([N-24]) instead. See erratum E-1.

It follows that a pepper which **has no UTF-8 encoding** — most commonly a string carrying an unpaired surrogate, which arrives trivially from a JSON secrets file or a lenient UTF-16 decode — is not a usable HMAC key, and [N-11] cannot define one for it. Such a pepper MUST fail construction (§5, [N-24]) rather than being encoded by substitution. Substituting a replacement character is non-conforming and observably so: it yields a one-byte key on runtimes that substitute `?` and a three-byte key on those that substitute U+FFFD, so the same configured pepper would produce different `verifierHash` and `deviceIdHash` values in different languages. Failing at construction surfaces the defect at deployment instead of silently splitting a mixed-language deployment. This mirrors [N-12], which resolves the same encoding question for the attacker-reachable device identifier.

**[N-12]** Some runtimes admit string values that are not valid Unicode — most commonly an unpaired surrogate, which arrives trivially through JSON input. Such a device identifier has no UTF-8 encoding, so [N-11] cannot define a hash for it. Implementations MUST therefore treat it as follows, and MUST NOT raise, throw or panic in either case:

- in `refresh`, where the value is attacker-controlled, it MUST be treated as a sender-binding failure — `DEVICE_MISMATCH` when the record is bound, and ignored when it is not;
- in `issue`, where the value is supplied by the application, it MUST be rejected through the native error channel ([N-20]) as an invalid argument, so the defect surfaces at the call site rather than minting an unusable binding.

`revokeToken` is not listed because it accepts no device identifier at all
([N-36]): revocation is authenticated by the verifier proof and deliberately
performs no sender-binding check.

Deriving a hash from a replacement character, or from any byte sequence that is not the UTF-8 encoding of the input, is non-conforming: it would make the same identifier hash differently across languages.

**[N-13]** Hex output MUST be **lowercase**. Comparisons of hex material MUST be performed per [N-31].

**[N-14]** The raw verifier and the raw device identifier MUST NEVER be persisted, logged, or included in any error value, exception message, or debug/`repr`/`toString` representation of any type defined by this specification.

**[N-15] Retention.** A record MUST be retained, with its `status` and `replacedBySelector` intact, until at least its `familyExpiresAt`. Implementations and deployments MUST NOT delete or expire `rotated` or `revoked` records before that time.

> **Why this is normative.** Reuse detection is the act of finding a `rotated` record. A store that deletes rotated rows early — a Redis TTL applied at rotation, or a nightly `DELETE WHERE status <> 'active'` — silently converts every replay from `REUSE_DETECTED` into `NOT_FOUND`, disabling the single property this specification exists to provide. Records MAY be deleted once `now ≥ familyExpiresAt`.

## 4. Store contract

**[N-16]** Implementations MUST define a store interface with exactly these six capabilities. The synchrony of the interface (blocking, promise/future-returning, or coroutine) MUST follow the idiom of the target ecosystem; the semantics below MUST NOT change.

```
findBySelector(selector)                                        -> record | null
insert(record)                                                  -> void
markRotated(selector, fromStatus, rotatedAt, replacedBySelector) -> bool
revokeIfActive(selector)                                        -> bool
revokeFamily(familyId)                                          -> int
revokeUser(userId)                                              -> int
```

**[N-17] `markRotated` is a compare-and-set.** It MUST apply its write **if and only if** the stored record's current `status` equals `fromStatus`, and MUST return whether the write was applied. In SQL this is
`UPDATE … SET status='rotated', rotated_at=?, replaced_by_selector=? WHERE selector=? AND status=?`
with the affected-row count returned. Returning `true` unconditionally is non-conforming.

**[N-18] `revokeIfActive` is a compare-and-set.** It MUST set `status = revoked` if and only if the current status is `active`, and MUST return whether it did.

**[N-19]** `revokeFamily` and `revokeUser` MUST set `status = revoked` for every record of the family or user respectively, and MUST return the number of records they changed. They MUST be idempotent.

**[N-20] Two failure channels.** Protocol outcomes (§7) are returned as values. Infrastructure failures — the store being unreachable, a timeout, a constraint violation — MUST be reported through the language's native error channel (exception, `Err`, returned `error`), MUST NOT be converted into a protocol outcome, and MUST NOT be swallowed. An engine operation whose store call fails MUST fail closed: it MUST NOT return a success result, and it MUST NOT report a revocation that did not take place.

**[N-21]** Every package MUST ship an in-memory store for development and tests. It MUST be safe to use concurrently from the runtime's normal request-concurrency model, and it MUST be documented as unsuitable for production.

**[N-22] Atomicity.** A store SHOULD execute the rotation write pair (`insert` of the successor followed by `markRotated` of the predecessor) inside one transaction. Where it does not, the engine's compensation in §6.4 step 5 applies.

## 5. Engine configuration

| Option | Constraint |
|---|---|
| `peppers` | Map `kid → secret`. Each `kid` MUST match the `kid` production of §2 and MUST NOT exceed `MAX_KID_LENGTH`; each secret MUST have a UTF-8 encoding ([N-11]) and MUST be at least `MIN_PEPPER_LENGTH` bytes **of that encoding** ([N-1]); violation MUST fail construction. |
| `activeKid` | MUST exist in `peppers`; violation MUST fail construction. |
| `store` | The store implementation. |
| `absoluteTtlSeconds` | Default `DEFAULT_ABSOLUTE_TTL`. MUST be > 0. |
| `idleTtlSeconds` | Default `DEFAULT_IDLE_TTL`. MUST be > 0. |
| `reuseGraceSeconds` | Default `DEFAULT_REUSE_GRACE`. MUST be ≥ 0. See §6.3 for the security trade-off. |
| clock | Injectable "now" function/interface. |

**[N-23]** A pepper is a cryptographic key, not a passphrase. It SHOULD carry at least 256 bits of entropy and SHOULD be generated by a CSPRNG (`openssl rand -base64 48`) and held in an environment variable, secret manager, or KMS. `MIN_PEPPER_LENGTH` is a floor against obvious misconfiguration, not a sufficient condition for security.

**[N-24]** Configuration MUST be copied at construction. Mutating the caller's `peppers` map after the engine is built MUST NOT change engine behavior.

## 6. Operations

### 6.1 Issue (login)

**[N-25]** `issue(userId, deviceId?)`:

1. `familyId` ← lowercase hex of 16 CSPRNG bytes; `familyExpiresAt` ← `now + absoluteTtl`.
2. Mint (§6.5) a generation-0 record; `deviceIdHash` ← device hash with the **active** pepper if `deviceId` is present, else null. Absence of a device identifier MUST be distinguishable from an empty-string device identifier.
3. `insert` the record. If the insert fails, the operation MUST fail and MUST NOT return a token ([N-20]).
4. Return the token string plus family metadata. Timestamps in the result MUST be integer Unix seconds ([N-2]).

### 6.2 Refresh (rotation)

**[N-26]** `refresh(token, deviceId?)` MUST perform these checks **in this order**, returning the first failure:

| # | Check | Failure |
|---|---|---|
| 1 | Parse (§2) | `MALFORMED` |
| 2 | `peppers[token.kid]` exists | `UNKNOWN_KID` |
| 3 | `findBySelector` returns a record | `NOT_FOUND` |
| 4 | Verifier proof against `peppers[record.kid]`, constant-time ([N-31]) | `VERIFIER_MISMATCH` |
| 5 | `status = rotated` → reuse handling (§6.3) | — |
| 6 | `status = revoked` | `REVOKED` |
| 7 | `now < familyExpiresAt`, else revoke family | `EXPIRED_ABSOLUTE` |
| 8 | `now < idleExpiresAt`, else revoke family | `EXPIRED_IDLE` |
| 9 | Sender binding (§6.4), else revoke family | `DEVICE_MISMATCH` |
| 10 | Rotate (§6.4) | `CONFLICT` on a lost compare-and-set |

**[N-27]** If `peppers[record.kid]` is absent at step 4 — the token's kid resolved but the record was written under a pepper that has since been retired — the result MUST be `UNKNOWN_KID`.

**[N-28]** The ordering in [N-26] is normative and observable. It fixes which error is returned when several conditions hold at once, so that clients, gateways and monitoring behave identically across implementations. In particular: a `rotated` record presented with a wrong verifier MUST return `VERIFIER_MISMATCH` and MUST NOT revoke the family — otherwise knowledge of a selector alone would let anyone destroy a session.

**[N-29]** Errors MUST be returned as values (result types, discriminated unions, sentinel returns) and MUST NOT be raised or thrown for control flow. This is distinct from [N-20]: infrastructure failures do use the native error channel.

### 6.3 Reuse handling

**[N-30]** When a `rotated` record is presented, a **grace retry** applies if and only if ALL of the following hold:

1. `reuseGraceSeconds > 0`;
2. `record.rotatedAt ≠ null`;
3. `now − record.rotatedAt ≤ reuseGraceSeconds`;
4. `record.replacedBySelector ≠ null`;
5. the successor record exists and its `status` is `active`;
6. `now < record.familyExpiresAt`.

Then:

1. Apply the sender-binding check (§6.4); on failure revoke the family and return `DEVICE_MISMATCH`.
2. `revokeIfActive(successor.selector)`. If it returns `false`, another retry won the race: return `CONFLICT` without minting anything.
3. Rotate the presented record again (§6.4) with `fromStatus = rotated`, **preserving its original `rotatedAt`** and updating `replacedBySelector` to the new successor.

Otherwise the presentation is a theft signal: revoke the entire family and return `REUSE_DETECTED`.

Condition 6 exists so that a grace retry can never mint a token past the family's absolute deadline.

> **Security trade-off of a non-zero grace window — normative guidance.** The window exists for exactly one legitimate case: a client that sent a refresh and never received the response. It is not free. For `reuseGraceSeconds` after a rotation, an adversary holding the rotated predecessor who acts *before* the legitimate client uses its successor is served a valid token; the legitimate client is then evicted with `REVOKED`, and **no `REUSE_DETECTED` event is raised**. Deployments therefore MUST treat `reuseGraceSeconds` as a reliability-versus-detectability trade-off, SHOULD keep it at the smallest value their clients need, and SHOULD leave it at the default of 0 unless lost-response retries are an observed problem. Deployments that enable it SHOULD additionally alert on the `REVOKED` rate.

### 6.4 Sender binding and rotation

**[N-31] Constant-time comparison.** Comparison of any secret-derived material MUST be constant-time with respect to content, MUST NOT short-circuit, and MUST NOT raise on any input. Operands that are not exactly 64 lowercase hexadecimal characters MUST compare unequal rather than being decoded leniently, truncated, case-folded, or trimmed.

**[N-32] Sender binding.** If `record.deviceIdHash ≠ null`, the presented `deviceId` MUST be hashed with `peppers[record.kid]` — the **record's** pepper, not the active one — and compared per [N-31]. A missing device identifier where the record is bound MUST fail. Failure MUST revoke the family and return `DEVICE_MISMATCH`.

**[N-33] Minting.**

1. `selector` ← base64url of `SELECTOR_BYTES` CSPRNG bytes; `verifier` ← `VERIFIER_BYTES` CSPRNG bytes.
2. `verifierHash` ← lowercase hex `HMAC-SHA-256(peppers[activeKid], verifier)`; `kid` ← `activeKid`.
3. `idleExpiresAt` ← `min(now + idleTtl, familyExpiresAt)`.
4. On rotation of a bound family, `deviceIdHash` ← device hash of the presented `deviceId` with the **active** pepper, migrating the binding forward across pepper rotation.
5. Token string ← `nbl.{activeKid}.{selector}.{base64url(verifier)}`.

**[N-34] Rotation** of a record with a given `fromStatus`:

1. Mint the successor ([N-33]) with `generation + 1`, the same `familyId`, and the same `familyExpiresAt`.
2. `insert` the successor.
3. `applied` ← `markRotated(record.selector, fromStatus, rotatedAt, successor.selector)`, where `rotatedAt` is `now` for a fresh rotation and the record's **original** `rotatedAt` for a grace retry.
4. If `applied`, return success with the new token, `userId`, `familyId`, `generation`, and the successor's expiry timestamps.
5. If not `applied`, a concurrent refresh won. The engine MUST revoke the successor it just inserted (`revokeIfActive`) and MUST return `CONFLICT`. It MUST NOT return a token.

> **Why step 3 is a compare-and-set.** Without it, two concurrent refreshes of the same active token both observe `status = active`, both mint a successor, and the family forks into two independently valid lineages — defeating reuse detection entirely. This is not an exotic race: it is the ordinary behavior of a mobile client retrying, or of two browser tabs refreshing together.

**[N-35]** `CONFLICT` is a transient outcome. Clients SHOULD retry the refresh once; the retry meets the ordinary reuse path. `CONFLICT` MUST NOT revoke anything beyond the successor the engine itself inserted.

### 6.5 Revocation

**[N-36]** `revokeToken(token)` is an **authenticated** operation. It MUST perform steps 1–4 of [N-26] — parse, pepper lookup, record lookup, constant-time verifier proof — and MUST return the corresponding failure when any of them fails. On success it revokes the whole family of the record and returns the number of records revoked. It MUST succeed regardless of the record's `status`, so that a client can log out with a token that has already been rotated or revoked.

It takes **no device identifier** and MUST NOT perform the sender-binding check of [N-32].

> **Why the verifier is required.** §3 designates the selector as a public lookup key: it is safe to index, appears in logs, and is recoverable from a database dump that this specification otherwise renders inert. If revocation accepted a selector alone, anyone who read one could terminate that session — an unauthenticated denial of service against an arbitrary user. Administrative revocation paths, which are authenticated by the application, are served by [N-37].

> **Why sender binding is deliberately absent.** The verifier proof already
> authenticates the caller, and an adversary holding the verifier could simply
> *use* the token — revoking it is strictly less harmful than refreshing it, so
> a second factor buys nothing here. It would, however, cost something real: a
> user whose device identifier legitimately changed — an application
> reinstalled, an operating system upgrade that regenerated the identifier —
> could no longer terminate their own possibly-compromised session. For
> revocation the safe direction is to revoke, not to refuse.

**[N-37]** `revokeFamily(familyId)` and `revokeAllForUser(userId)` revoke by server-side identifier and require no token. They are intended for administrative and incident-response paths — password change, "log out all devices", compromise response — and the caller is responsible for authorising them. Both return the number of records revoked and MUST be idempotent.

## 7. Error codes

**[N-38]** Exactly these names, exactly these semantics:

| Code | Meaning |
|---|---|
| `MALFORMED` | The presented string is not a NEBULA token (§2). |
| `UNKNOWN_KID` | No pepper is configured for the required key identifier. |
| `NOT_FOUND` | No record exists for the selector. |
| `VERIFIER_MISMATCH` | The proof of possession failed. |
| `REUSE_DETECTED` | A rotated token was replayed. The family has been revoked. |
| `REVOKED` | The record was revoked. |
| `EXPIRED_ABSOLUTE` | The family passed its fixed deadline. The family has been revoked. |
| `EXPIRED_IDLE` | The sliding deadline passed. The family has been revoked. |
| `DEVICE_MISMATCH` | Sender binding failed. The family has been revoked. |
| `CONFLICT` | A concurrent refresh won the compare-and-set. Nothing was rotated. Retryable. |

**[N-39]** `REUSE_DETECTED` and `DEVICE_MISMATCH` SHOULD be surfaced to security monitoring; `EXPIRED_*`, `NOT_FOUND` and `VERIFIER_MISMATCH` rates SHOULD be monitored. To make this possible without a second lookup, a failure result MUST carry the `userId` and `familyId` of the affected record whenever the engine resolved one — that is, for every code except `MALFORMED`, `UNKNOWN_KID` and `NOT_FOUND`.

This obligation is on **every** operation that returns a failure, not on `refresh` alone. In particular `revokeToken` ([N-36]) resolves its record at step 3 and only then proves the verifier at step 4, so a `VERIFIER_MISMATCH` from `revokeToken` MUST carry both fields: an unauthenticated attempt to terminate a session is precisely the event [N-39] exists to make attributable, and the selector alone does not identify the victim. Conversely, the three exempt codes MUST NOT carry them from any operation — a value invented for a record that was never resolved would misattribute the event.

**[N-40] Extensibility.** Where the language supports it, the error type MUST be declared open to future additions (Rust `#[non_exhaustive]`, and an equivalent documented policy elsewhere), so that a future minor version can add a code without breaking exhaustive matches. Consumers MUST treat an unrecognised code as a refusal.

**[N-41]** Human-readable messages accompanying a code are non-normative, are not part of the compatibility promise, and MAY change in any release. Only the codes are stable.

**[N-42] Client-visible surface.** The distinct codes exist for the server's logs, not for the client. A deployment SHOULD collapse every failure to a single generic response (for example `401` with no detail) at the transport boundary, and log the specific code server-side. Returning the code verbatim to an unauthenticated caller reveals whether a selector exists.

## 8. Cryptographic requirements

**[N-43]** Randomness MUST come from the platform CSPRNG. Failure to obtain randomness MUST propagate per [N-20]; it MUST NOT be silently replaced by a weaker source.

**[N-44]** The only keyed primitive is HMAC-SHA-256. No custom constructions, encodings, or ciphers.

**[N-45]** Database lookups MUST key only on the selector, never on secret-derived material.

**[N-46]** Implementations MUST NOT log, or include in any error value, the token, the verifier, the pepper, or the raw device identifier ([N-14]). The selector MAY be logged as a correlation identifier.

> **Constant-time comparison is [N-31]**, and it belongs to this section as much
> as to the one it is stated in. It is written in §6.4 beside the sender-binding
> rule that is its second consumer, but it governs both comparisons of
> secret-derived material in this specification: the verifier proof of [N-26]
> step 4 and the device comparison of [N-32]. Anyone auditing the cryptographic
> obligations from this section must read it there.

> **Note (non-normative) — post-quantum posture.** NEBULA uses no public-key cryptography, so Shor's algorithm has no target anywhere in this specification. The applicable quantum attack is Grover search: against the 256-bit verifier it costs approximately 2^128 queries, conventionally regarded as post-quantum safe. The corresponding statement for the pepper holds only when the pepper carries close to 256 bits of entropy, which is why [N-23] recommends it — a SHOULD, so the margin at the HMAC layer is a deployment obligation rather than a conformance property. Because token validity is server-side state rather than a mathematical property, recorded tokens cannot be "decrypted later": they die on rotation, expiry, or revocation. This concerns the token layer only; transport and any co-deployed asymmetric tokens carry their own migration obligations.

## 9. Conformance

**[N-47]** An implementation is conformant iff it passes, in full:

1. every vector in [`spec/test-vectors.json`](spec/test-vectors.json) — the `constants`, `verifier_hashing`, `device_hashing` and `parsing` sections;
2. every scenario in [`spec/behavior-vectors.json`](spec/behavior-vectors.json), executed against an injected clock and a store that records its calls.

**[N-48]** A conformance runner MUST assert that the number of cases it executed equals the number of cases published in each section, and MUST fail if any section is absent or empty. Silently iterating zero cases is a conformance failure, not a pass.

**[N-49]** `spec/behavior-vectors.json` is the normative behavioral suite. It is data, not prose: each scenario carries an `id`, a sequence of operations against a fixed clock, and the expected outcome and resulting record states. A third-party port demonstrates conformance by running it, not by re-deriving it. Requirement-to-scenario traceability is published in `spec/traceability.json`.

## 10. Non-goals

NEBULA deliberately does not define: claims or user data inside the token (use short-lived access tokens); transport (use HTTPS + `httpOnly` cookies); storage engines; key management beyond the `kid` indirection; rate limiting (which deployments MUST provide at the edge — see [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) R5); session enumeration or session metadata, which are application concerns layered on `familyId`.

NEBULA does not protect against a compromised server that can read the peppers and the store, nor against an adversary in persistent control of a client after login.

## 11. Change control and compatibility

**[N-50]** This document, `spec/test-vectors.json` and `spec/behavior-vectors.json` are versioned together by `spec_version`. Version 1 is frozen: within `spec_version = 1`, no requirement identified above may change meaning, no error code may be removed or redefined, and no wire form may be added or withdrawn. Errata that correct an internal contradiction without changing conforming behavior are published in `spec/ERRATA.md`.

**[N-51]** The `nbl` prefix is reserved by this specification. A future incompatible wire format MUST use a different prefix, so that the two can coexist on one endpoint and be distinguished before any database interaction. Implementations MUST reject a token whose prefix they do not implement as `MALFORMED` ([N-6] rule 3).

**[N-52]** Package versions follow Semantic Versioning independently of `spec_version`. A package's major version MUST NOT change merely because the spec did not; a package MUST document which `spec_version` it implements. The relationship, the support window and the release process are defined in [`VERSIONING.md`](VERSIONING.md), [`COMPATIBILITY.md`](COMPATIBILITY.md) and [`RELEASING.md`](RELEASING.md).

**[N-53]** A third party may state "conforms to NEBULA spec version 1" for an implementation that passes §9 in full. The claim is the implementer's own; this project neither certifies nor endorses it. The process for listing an implementation is in [`CONTRIBUTING.md`](CONTRIBUTING.md).
