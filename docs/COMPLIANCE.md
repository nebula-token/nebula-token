# Compliance mapping

An honest, specific mapping from NEBULA to the session-management controls of
OWASP ASVS and NIST SP 800-63B, plus short notes on PCI DSS and GDPR.

**Nothing here is a certification, and no library can make a system compliant.**
NEBULA is one component on the authentication path. It can satisfy a control
outright, satisfy the mechanical half of one and leave the policy to you, or have
nothing to do with it. This document says which, per control, including the two
places where NEBULA's own guidance deliberately deviates from a control's letter.

Verdicts used below:

| | Meaning |
|---|---|
| **Satisfies** | The control is met by conforming behaviour of the library, with no work by the adopter beyond using it. |
| **Partial** | The library provides the mechanism; the adopter chooses the values or wires the flow. Both halves are required. |
| **Adopter** | Outside the library entirely. Usually documented in [`INTEGRATION.md`](INTEGRATION.md). |
| **N/A** | The control addresses a design NEBULA does not use. |
| **Deviates** | NEBULA's documented guidance does not follow the control's letter, for a stated reason. Read these two; do not let them surprise an assessor. |

**On version numbers.** Control identifiers move between standard revisions. The
ASVS rows below are numbered per **ASVS 4.0.3, chapter V3 (Session Management)**;
ASVS 5.0 reorganised and renumbered session management, so if you are being
assessed against 5.0, match by control *text*, not by the numbers here. The NIST
rows are per **SP 800-63B Rev. 3, §7**; the reauthentication limits are stable
across the Rev. 4 session-management material, but verify the citation against
the revision your programme actually uses before quoting it in evidence.

---

## 1. OWASP ASVS — V3 Session Management

Control text is paraphrased; consult the standard for the normative wording.

| Control | In substance | Verdict | How |
|---|---|---|---|
| **3.1.1** | Session tokens never appear in URL parameters | **Adopter** | NEBULA prescribes no transport. [`INTEGRATION.md`](INTEGRATION.md) puts the token in an `httpOnly` cookie or a request body, never a query string. |
| **3.2.1** | A new session token is generated on authentication | **Satisfies** | `issue` mints a fresh family with a new `familyId` and a new selector/verifier pair at login ([N-25]). Session fixation is impossible: there is no way to make the engine adopt a caller-supplied token. |
| **3.2.2** | Session tokens carry sufficient entropy (≥64 bits) | **Satisfies** | 256-bit verifier plus a 128-bit selector, both from the platform CSPRNG ([N-43]); four times the requirement in the secret alone. |
| **3.2.3** | Tokens are stored in the browser by a secure method | **Adopter** | `httpOnly; Secure; SameSite=Strict`, path-scoped, never `localStorage` — [`INTEGRATION.md`](INTEGRATION.md) §3. |
| **3.2.4** | Tokens are generated with approved cryptographic algorithms | **Satisfies** | Platform CSPRNG for all token material; HMAC-SHA-256 as the only keyed primitive ([N-43], [N-44]). Failure to obtain randomness propagates as an error rather than falling back ([N-20]). |
| **3.3.1** | Logout invalidates the session token; the back button cannot resume it | **Satisfies** | `revokeToken` revokes the entire family server-side ([N-36]); validity is a row, so an invalidated token is dead everywhere at once. Works even on an already-rotated token, so a stale client still logs out. |
| **3.3.2** | Re-authentication occurs periodically and after inactivity | **Partial** | NEBULA enforces both clocks — an absolute deadline fixed at login that MUST never be extended, and a sliding idle deadline clamped to it ([N-10], [N-33]). Choosing values that match your assurance level, and running the re-authentication flow when they expire, is yours. See §2 for the AAL numbers. |
| **3.3.3** | The user can terminate all other sessions after a password change | **Partial** | `revokeAllForUser` is a first-class operation returning the number of records revoked ([N-37]). Calling it from your password-change flow, and offering the choice in the UI, is yours. |
| **3.3.4** | Users can view and log out of individual active sessions and devices | **Adopter** | Session enumeration is an explicit non-goal (specification §10). `familyId` is the stable join key for your own session table — one row per login, carrying IP, user agent and device label — and `revokeFamily(familyId)` terminates the one the user picked. |
| **3.4.1** | Cookie-based tokens set `Secure` | **Adopter** | Documented; [`INTEGRATION.md`](INTEGRATION.md) §3. |
| **3.4.2** | Cookie-based tokens set `HttpOnly` | **Adopter** | Documented; the single most valuable attribute here, since it downgrades an XSS from theft to use-while-open. |
| **3.4.3** | Cookie-based tokens use `SameSite` | **Adopter** | `SameSite=Strict` recommended, with the `Lax` caveat and a CSRF fallback. |
| **3.4.4** | Cookie-based tokens use the `__Host-` prefix | **Deviates** | `__Host-` requires `Path=/`, which is incompatible with scoping the refresh cookie to the refresh endpoints. NEBULA's guidance is `__Secure-` plus a narrow `Path`, trading the prefix's host-only guarantee for a much smaller exposure surface — the credential is not attached to every request on the origin. If your assessor requires 3.4.4 literally, you can satisfy both by serving auth on a dedicated host (`auth.example.com`) and using `__Host-` with `Path=/` there. |
| **3.4.5** | The cookie path is the most precise value possible | **Satisfies (as guidance)** | The recommended `Path` covers exactly the refresh and logout endpoints and nothing else. |
| **3.5.1** | Users can revoke tokens granted to linked applications | **N/A** | NEBULA is a first-party credential mechanism with no delegation, scopes or consent (specification §10). If you need those, you need an authorization server. |
| **3.5.2** | Session tokens are used rather than static API secrets | **Satisfies** | The credential rotates on every use and expires under two clocks; there is no static secret on the client. |
| **3.5.3** | Stateless tokens resist tampering, replay, enveloping and key substitution | **N/A by design** | NEBULA tokens are not stateless and carry no cryptographic structure to attack. Validity is server-side state, which answers the control's concern more strongly than the control asks: replay is *detected* ([N-30]) rather than merely prevented, and there is no signature scheme to substitute. |
| **3.6.1 / 3.6.2** | Re-authentication of federated identity within limits (L3) | **Adopter** | NEBULA performs no authentication and holds no IdP relationship. Its absolute deadline is the lever that forces a return to your IdP. |
| **3.7.1** | A valid session — or re-authentication — is required before sensitive operations | **Adopter** | Step-up authentication is an application flow. `generation` and `createdAt` on the record let you tell how long ago the session was *established*, which is the input such a policy usually needs. |

Two ASVS-adjacent points worth putting in front of an assessor before they ask:

- **Reuse detection is not an ASVS control.** Nothing in V3 requires it. It is an
  RFC 9700 requirement, and it is the reason this library exists; present it as a
  strengthening measure, with the threat model's traceability table as evidence.
- **Rate limiting (V11 / V2.2.1-adjacent) is explicitly out of scope** and must be
  at the edge (specification §10, R5 in [`THREAT_MODEL.md`](THREAT_MODEL.md)).
  Assessors ask about brute force on the refresh endpoint; the honest answer is
  that a 256-bit verifier makes guessing pointless, and that request-volume
  control is nonetheless your gateway's job.

## 2. NIST SP 800-63B — session management (§7)

| Requirement | In substance | Verdict | How |
|---|---|---|---|
| §7.1 | Session secrets have at least 64 bits of entropy, generated by an approved RNG | **Satisfies** | 256-bit verifier from the platform CSPRNG ([N-43]). |
| §7.1 | Session secrets are not stored in a way that allows an attacker to reuse them; the verifier stores only a hash | **Satisfies** | Only `HMAC-SHA-256(pepper, verifier)` is stored, with the key held outside the database ([N-10], [N-11], [N-23]). A database dump is inert. |
| §7.1 | **Session secrets are non-persistent** — not retained across an application restart or device reboot | **Deviates** | A refresh token in a cookie with a `Max-Age` is by construction persistent; that is what "stay signed in" means. This is a real tension in the standard for any remember-me design, not a NEBULA quirk. Two ways out: issue the cookie as a session cookie (no `Max-Age`), which makes the family last only as long as the browser is open; or document the deviation, cite the compensating controls — rotation on every use, replay detection, two enforced clocks, instant revocation — and set the deadlines per §7.2 below. |
| §7.1 | Session secrets are invalidated at logout | **Satisfies** | `revokeToken` revokes the family ([N-36]); nothing survives it. |
| §7.1.1 | Browser cookies are transmitted over an authenticated protected channel, marked `Secure` and `HttpOnly`, and scoped as narrowly as possible | **Adopter** | Documented in [`INTEGRATION.md`](INTEGRATION.md) §3; NEBULA sets no cookies itself. |
| §7.2 | Reauthentication at the interval required by the AAL, and after the inactivity limit | **Partial** | The two clocks map directly onto the two limits — see the table below. What NEBULA cannot do is enforce *how* the user reauthenticates; at AAL3 the standard requires an authenticator, and a refresh token is not one. |
| §7.2 | At AAL2 and above, session termination on inactivity is enforced by the verifier, not the client | **Satisfies** | The idle deadline is a column in your database, evaluated server-side on every refresh ([N-26] step 8). A client cannot extend it, and neither can a replayed token. |

### Configuring for an assurance level

| AAL | Reauthentication limit | Inactivity limit | `absoluteTtlSeconds` | `idleTtlSeconds` | Still yours |
|---|---|---|---|---|---|
| AAL1 | 30 days | — | `2592000` (the default) | your choice (default `604800`) | — |
| AAL2 | 12 hours | 30 minutes | `43200` | `1800` | Reauthentication must use an authenticator, not the refresh token |
| AAL3 | 12 hours | 15 minutes | `43200` | `900` | As AAL2, plus the AAL3 authenticator requirements, which are entirely outside NEBULA |

Two consequences of the arithmetic, worth stating before an assessor finds them:

- **Your access-token lifetime adds to the effective inactivity window.** A user
  who goes idle one second after a refresh holds a working access token for its
  full remaining life. To honour a 30-minute inactivity limit you need
  `idleTtlSeconds = 1800` *and* an access-token lifetime short enough that the sum
  stays within the limit — or server-side access-token validation that consults
  the same idle deadline.
- **Short deadlines multiply rotations.** AAL2 settings with a 5-minute access
  token produce a rotation every 5 minutes for 12 hours: 145 rows per session
  instead of 8 641 over 30 days at the same 5-minute cadence — far fewer in total, because the absolute TTL
  falls from 30 days to 12 hours. The capacity arithmetic is in
  [`OPERATIONS.md`](OPERATIONS.md) §5; higher assurance is *cheaper* to store, not
  more expensive.

## 3. PCI DSS

PCI DSS v4.0 requires re-authentication after 15 minutes of inactivity for
sessions with access to the cardholder data environment (requirement 8.2.8, with
the related session-management items in 8.6). NEBULA's contribution is
mechanical: set `idleTtlSeconds = 900`, and keep the access-token lifetime short
enough that the idle window is not silently extended by it — the same arithmetic
as AAL2 above. Everything else in requirement 8 — MFA, account lockout, credential
policy — is outside this library.

## 4. GDPR and data protection

- **Data minimisation (Art. 5(1)(c)).** A NEBULA record holds a user identifier,
  hashes, integers and a status. The raw device identifier is never persisted
  ([N-14]), so a store dump cannot re-identify devices; the token carries no
  claims and no personal data at all.
- **The records are still personal data.** They link a person to login times,
  session counts and device presence. Put the table in your record of processing,
  and state the retention period — it is exactly `absoluteTtlSeconds`, enforced
  by the GC job.
- **Erasure (Art. 17).** Deleting a user's rows is unproblematic: [N-15] forbids
  deleting rows *early for security reasons*, and there is nothing to protect once
  the account is gone. Revoke first (`revokeAllForUser`), then delete, so no
  credential outlives the record of it.
- **Residency and processors.** State lives in your database, in your region,
  under your control. There is no NEBULA service, no telemetry, and no third
  party in the credential path — which is usually the shortest answer to a
  transfer-impact question about a managed identity provider.

## 5. What NEBULA does not address at all

Authentication itself (passwords, MFA, WebAuthn, account recovery), authorisation
and scopes, access-token minting or validation, audit logging of user actions,
consent and cookie banners, encryption at rest for your database, key management
beyond the `kid` indirection, rate limiting, and session enumeration UI. Several
of these sit inside the same ASVS chapters as the controls above; none is a gap
in NEBULA, and all of them are gaps in a system that has *only* NEBULA.

## 6. Evidence you can hand an assessor

| Artefact | What it demonstrates |
|---|---|
| [`SPECIFICATION.md`](../SPECIFICATION.md) | The behaviour is specified, not emergent. Every requirement carries an id you can cite in a finding or a response. |
| [`spec/test-vectors.json`](../spec/test-vectors.json), [`spec/behavior-vectors.json`](../spec/behavior-vectors.json) | 46 conformance cases and 38 normative behavioural scenarios, executed in CI against every implementation, with a runner that must assert the case counts and fail on an empty section ([N-47], [N-48]). |
| [`THREAT_MODEL.md`](THREAT_MODEL.md) | A threat table where every entry maps to requirement ids and to executable scenario ids — including the two entries that admit no vector can cover them. |
| [`spec/traceability.json`](../spec/traceability.json) | The requirement-side view of the same coverage, generated from the vector files: which scenarios exercise each `[N-*]`, and which requirements are verified by review instead. An assessor asking "how do you know?" can be handed this file. |
| [`SECURITY.md`](../SECURITY.md) | A disclosure policy with response times, and an explicit list of what the project has *not* done: no independent audit, no formal verification, no fuzzing beyond the vectors, no production track record. |
| [`COMPATIBILITY.md`](../COMPATIBILITY.md) | What is frozen, what may move, the deprecation policy and the support window. |
| [`OPERATIONS.md`](OPERATIONS.md) | Runbooks for key rotation, retention, incident response and global logout — the operational evidence assessors ask for after the code review. |

The last row of that table is the one to lead with. A control framework asks
whether you understand your own weaknesses; the most credible thing you can show
is the document that lists them.
