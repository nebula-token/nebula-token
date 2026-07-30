# Security policy

NEBULA sits on an authentication path. Reports are taken seriously and answered
quickly.

---

## Reporting a vulnerability

**Do not open a public issue, pull request, or discussion.**

**Preferred — GitHub private vulnerability reporting.** On the repository's
Security tab, choose *Report a vulnerability*. This gives us a private fork to
develop the fix in and a direct path to requesting a CVE, and it needs no key
exchange.

**Alternative — email.** `security@nebulatoken.dev`. If you want the report
encrypted, ask for the current PGP key in a first message containing no details
and we will send the fingerprint out of band. No key file is published in this
repository: a fingerprint you fetched over the same channel you are worried
about proves nothing, and a stale committed key is worse than none.

Please include: the affected implementation(s) and version(s), the requirement
identifier from `SPECIFICATION.md` you believe is violated if you know it, a
proof of concept or reproduction steps, and your assessment of impact.

### What to expect

| | |
|---|---|
| Acknowledgement | within **72 hours** |
| Initial assessment, with a severity and a plan | within **7 days** |
| Fix released | target **90 days**, sooner for anything actively exploitable |
| Credit | in the advisory and the changelog, under whatever name you choose, or none |

These are targets held by a single maintainer, not a staffed rota: there is
nobody to cover a holiday, and the 90-day figure assumes ten coordinated
releases from one CI run. They are what we aim at, stated so you can plan
your own disclosure around them.

We will keep you informed at each step, and we will say plainly if we disagree
that a report is a vulnerability — with the reasoning, so you can push back.

We operate no bug bounty. We are grateful anyway.

## Scope

**In scope**

- Token forgery, verifier recovery, or any acceptance of a token the
  specification says must be refused.
- Bypass of rotation, reuse detection, family revocation, expiry, or sender
  binding.
- Timing side-channels in verifier or device comparison.
- Any divergence of an implementation from `SPECIFICATION.md` with a security
  consequence — including a divergence *between* two conforming implementations.
- Defects in the specification itself: a requirement that is unsafe, ambiguous
  in a security-relevant way, or that permits a conforming-but-vulnerable
  implementation.
- Secret material reaching a log, an error value, or a debug representation.
- Anything that makes an operation fail open rather than closed.

**Out of scope**

- Vulnerabilities in a store implementation you wrote. The contract is documented
  in `docs/STORE.md`; we will happily discuss it, but it is not our artefact.
- Compromise of the peppers, the process environment, or the host.
- Denial of service against your database, and the absence of rate limiting,
  which §10 of the specification and the threat model (R5) explicitly place at
  the edge.
- Use of the in-memory store in production. It is documented as unsuitable ([N-21]).
- Reports that a stolen token works before its next use. That is the bearer
  property the design bounds rather than eliminates; see `docs/THREAT_MODEL.md`.

## Supported versions

| Version | Supported |
|---|---|
| 1.x (latest patch) | Yes |
| Anything older | No |

Only the most recent patch of the current minor line receives fixes. See
[`COMPATIBILITY.md`](COMPATIBILITY.md) §6.

## How a fix is shipped

A vulnerability in a specification this small is rarely confined to one language,
so the default is that **all ten packages are released together**, on one day,
even where a language is unaffected. The remediation instruction is then a single
version number rather than a per-language matrix.

1. Work happens in a private fork, branched from the affected release tag — not
   on `main`, where the commit itself would disclose the issue.
2. A CVE is requested through GitHub's CNA and the advisory is drafted while the
   fix is in review, not after.
3. All ten registries are published from one tagged CI run
   ([`RELEASING.md`](RELEASING.md)).
4. The advisory goes public once the last registry has the artefact. The reporter
   is notified before it does.
5. If a fix is not ready and the issue is being actively exploited, we publish
   mitigation guidance first and the fix when it exists.

## Coordinated disclosure

We follow coordinated disclosure with a **90-day** default. We will move faster
when a fix is ready sooner, and we will ask for more time only with a reason and
a date. If you intend to disclose on your own schedule, tell us — we would rather
plan around it than be surprised by it.

We will not ask you to sign anything, and we will not treat a good-faith report
as unauthorised access.

## What this project has not done

Stated plainly, because a security policy that lists only strengths is not
useful:

- No independent third-party security audit has been performed.
- No formal verification of the rotation state machine exists.
- The parsers have not been fuzzed beyond the published vectors.
- The implementations have no production deployment history.

None of these is scheduled: they are stated so that an adopter can weigh them,
not as a promise that they will be closed. Every implementation is a single
small module meant to be read in one sitting — please do read it.
