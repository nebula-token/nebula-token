# Integrating NEBULA into an HTTP API

NEBULA defines the credential and the state machine. It defines no transport, no
endpoint shapes, no cookies and no access tokens ([`SPECIFICATION.md`](../SPECIFICATION.md)
§10). This document is the missing half: a complete, opinionated worked example
of the three endpoints, the exact cookie attributes, the mapping from the ten
error codes to what a client sees, and how to migrate from a non-rotating or
JWT-based refresh setup.

The example is TypeScript because that is the reference implementation. Every
other language reads the same way — same method names, same result shapes, same
codes.

---

## 1. The shape of the thing

Two credentials with different jobs:

| | Access token | Refresh token (NEBULA) |
|---|---|---|
| Lifetime | 5–15 minutes | days to weeks, bounded by two clocks |
| Sent to | every API request | one endpoint, nothing else |
| Stored by the client | in memory | `httpOnly` cookie (web) or the platform keystore (native) |
| Contains | your claims | nothing; it is 256 bits of entropy |
| Revocable | no — it expires | yes, instantly |
| Issued by | your code | `engine.issue` / `engine.refresh` |

The access token's short lifetime is what bounds the damage of a theft NEBULA
cannot see (R6 in [`THREAT_MODEL.md`](THREAT_MODEL.md)). The refresh token's
narrow exposure — one path, one cookie, never readable from JavaScript — is what
makes the rotation model worth having. Weakening either one weakens the other.

Three endpoints, all `POST`/`DELETE`, all rate-limited at the edge:

```
POST   /auth/session          login     → sets the refresh cookie, returns an access token
POST   /auth/session/refresh  rotate    → replaces the refresh cookie, returns an access token
DELETE /auth/session          logout    → revokes the family, clears the cookie
```

The paths are nested deliberately: the cookie is scoped to `/auth/session`, and
RFC 6265 path-matching means the browser sends it to `/auth/session` **and**
`/auth/session/refresh`, and to nothing else. A cookie scoped to
`/auth/session/refresh` would not reach the logout endpoint, which is the most
common way this design goes wrong — logout then silently fails to revoke, and the
stolen token stays alive to its natural deadline.

## 2. Setting up the engine

```ts
import { NebulaEngine } from 'nebula-token';
import { PostgresRefreshTokenStore } from './refresh-token-store.js'; // your six methods

export const engine = new NebulaEngine({
  peppers: { k1: process.env.NEBULA_PEPPER_K1! },  // openssl rand -base64 48
  activeKid: 'k1',
  store: new PostgresRefreshTokenStore(pool),
  absoluteTtlSeconds: 60 * 60 * 24 * 30,           // 30 days — the ceiling, fixed at login
  idleTtlSeconds: 60 * 60 * 24 * 7,                // 7 days — sliding, renewed on each refresh
  // reuseGraceSeconds is 0 by default. Read [N-30] before raising it: a non-zero
  // window can serve an attacker a valid token with no REUSE_DETECTED event.
});
```

One engine per process, built at startup. Construction validates the peppers and
throws for a caller mistake ([N-23], §5); a failure here should stop the process,
not be caught.

## 3. The cookie, attribute by attribute

```
Set-Cookie: __Secure-nbl=nbl.k1.<selector>.<verifier>;
            HttpOnly; Secure; SameSite=Strict; Path=/auth/session; Max-Age=604800
```

| Attribute | Value | Why |
|---|---|---|
| `HttpOnly` | always | JavaScript must not be able to read the token. This is the single attribute that turns an XSS from "session stolen" into "session used while the page is open". |
| `Secure` | always | Refuses to travel over plaintext. Required by the `__Secure-` prefix. |
| `SameSite` | `Strict` | The refresh endpoint is a state-changing `POST` authenticated by a cookie: without this it is CSRF-able. `Strict` is right because refresh is never a cross-site navigation. Use `Lax` only if a top-level cross-site navigation must land on an authenticated page; never `None` unless you have a first-party CSRF defence and know why. |
| `Path` | `/auth/session` | Scopes the credential to the only endpoints that consume it, so it is not attached to every request on your origin, and does not leak into request logs of unrelated handlers. |
| `Max-Age` | `idleExpiresAt − now` | From the result, not a constant. The cookie then dies exactly when the token stops being usable, so the browser stops sending a dead credential. It can never outlive the family, because [N-33] clamps `idleExpiresAt` to `familyExpiresAt`. |
| name prefix | `__Secure-` | Guarantees the cookie was set over HTTPS with `Secure`. **Not `__Host-`**: that prefix requires `Path=/`, which is incompatible with scoping the cookie to the refresh path. Path scoping is worth more here than the prefix. |
| `Domain` | omit | An omitted `Domain` gives a host-only cookie. Setting it shares the credential with every subdomain, including the one someone will spin up for a marketing page. |

```ts
import type { Response } from 'express';

const COOKIE = '__Secure-nbl';
const COOKIE_PATH = '/auth/session';

function setRefreshCookie(res: Response, token: string, idleExpiresAt: number): void {
  const maxAge = Math.max(0, idleExpiresAt - Math.floor(Date.now() / 1000));
  res.append(
    'Set-Cookie',
    `${COOKIE}=${token}; HttpOnly; Secure; SameSite=Strict; Path=${COOKIE_PATH}; Max-Age=${maxAge}`,
  );
}

function clearRefreshCookie(res: Response): void {
  res.append('Set-Cookie', `${COOKIE}=; HttpOnly; Secure; SameSite=Strict; Path=${COOKIE_PATH}; Max-Age=0`);
}
```

**Native and mobile clients** have no cookie jar worth trusting. Store the token
in the platform keystore (Keychain, EncryptedSharedPreferences, `flutter_secure_storage`)
and send it in the request body of the refresh call. Everything else in this
document is unchanged — and device binding is genuinely strong there, because the
identifier can itself live in the keystore.

## 4. The three endpoints

```ts
import express from 'express';
import { engine } from './engine.js';

const app = express();
const ACCESS_TTL = 15 * 60;

/** POST /auth/session — login. Credential verification is yours; this is the token half. */
app.post('/auth/session', async (req, res) => {
  const user = await verifyPassword(req.body.email, req.body.password); // your code
  if (!user) return res.status(401).json({ error: 'invalid_credentials' });

  const deviceId = deviceIdOf(req);                    // see §5; undefined = unbound family
  const { token, familyId, expiresAt, idleExpiresAt } = await engine.issue(user.id, deviceId);

  await recordSession(familyId, user.id, req.ip, req.get('user-agent'), expiresAt); // your table
  setRefreshCookie(res, token, idleExpiresAt);
  res.json({ accessToken: mintAccessToken(user.id, ACCESS_TTL), expiresIn: ACCESS_TTL });
});

/** POST /auth/session/refresh — rotate. The only endpoint that consumes a refresh token. */
app.post('/auth/session/refresh', async (req, res) => {
  const presented = req.cookies?.[COOKIE];
  if (!presented) return res.status(401).end();

  const deviceId = deviceIdOf(req);
  const result = await engine.refresh(presented, deviceId);

  // [N-35]: CONFLICT means a concurrent refresh won the compare-and-set and
  // nothing was rotated — the winner's successor is already on its way to this
  // same client. Do NOT re-present `presented` here: the winner has rotated it,
  // so at the default grace of 0 a retry is a replay, and it burns the family
  // (§7). Answer 409, leave the cookie alone, let the client retry once.
  if (!result.ok && result.error === 'CONFLICT') {
    logRefreshFailure(result);
    return res.status(409).end();                       // cookie deliberately untouched
  }

  if (!result.ok) {
    logRefreshFailure(result);                          // §6 — the code goes here, not to the client
    clearRefreshCookie(res);
    return res.status(401).end();                       // [N-42]: one generic response
  }

  setRefreshCookie(res, result.token, result.idleExpiresAt);
  res.json({ accessToken: mintAccessToken(result.userId, ACCESS_TTL), expiresIn: ACCESS_TTL });
});

/** DELETE /auth/session — logout. Revokes the whole family, not just this token. */
app.delete('/auth/session', async (req, res) => {
  const presented = req.cookies?.[COOKIE];
  clearRefreshCookie(res);                              // clear it whatever happens next
  if (!presented) return res.status(204).end();

  const result = await engine.revokeToken(presented);   // proves the verifier ([N-36])
  if (result.ok) await closeSession(result.familyId);   // your own metadata table
  res.status(204).end();                                // never tell the caller which branch ran
});
```

Three things in that code are not decoration:

**Logout revokes the family, not the record.** `revokeToken` kills every
generation of the session ([N-36]), and it works even if the presented token has
already been rotated or revoked — a client that logs out with a stale cookie
still logs out. It requires the verifier, so a selector recovered from a log is
not a capability to end someone else's session.

**Logout returns 204 in every branch.** A missing cookie, a garbage cookie and a
successful revocation are indistinguishable to the caller.

**`CONFLICT` is the one failure that must not clear the cookie, and must not be
retried with the same token.** [N-35] says the client SHOULD retry once, and the
retry it means is the *client's*: by then the winner's `Set-Cookie` has landed,
so the retry presents the successor and succeeds. A retry inside the handler
presents the token that just lost — which the winner has already rotated.
Measured against the reference implementation: two concurrent refreshes at the
default `reuseGraceSeconds = 0` give `[ok, CONFLICT]`, and re-presenting the
loser's token turns that `CONFLICT` into `REUSE_DETECTED` — the family is revoked, the
winner's brand-new token dies with it, and a security event fires that no
attacker caused. Clearing the cookie on `CONFLICT` does the same damage more
quietly — it can erase the successor the winner's response just set.

So: `409`, no body, cookie untouched. It is the one code that carries no
information about whether the selector exists, because the engine only reaches it
after the verifier has already been proved. A server-side retry is safe *only*
with `reuseGraceSeconds > 0`, where the retry takes the grace path and consumes
the unused successor ([N-30] step 2) — and that window has its own cost ([N-30],
T12 in [`THREAT_MODEL.md`](THREAT_MODEL.md)), which is not worth buying to avoid
one `409`.

## 5. Device binding, honestly

`deviceIdOf(req)` is your decision, and the value of binding depends entirely on
it ([N-32]):

- **Native app:** a random UUID minted at first launch and held in the platform
  keystore. Strong: an attacker who exfiltrates the refresh token does not get
  this, so their *first* use fails and the family burns.
- **Web:** there is no device identifier a browser will honestly give you. A
  random id in a second `httpOnly` cookie binds to the *cookie jar*, which is
  weak (an attacker who can steal one cookie can usually steal two) but not
  worthless: it defeats a token pasted into a different browser. Fingerprinting
  is worse than nothing — it changes on a browser update and evicts real users.
- **Nothing:** pass `undefined` and leave the family unbound. This is a
  respectable choice on the web; rotation and reuse detection do not depend on it.

Rules that come out of the specification: absence of a device identifier is not
the same as an empty string ([N-25] step 2, scenario `device-04-empty-string-is-a-binding`);
a bound family refreshed *without* an identifier fails closed and burns the family
([N-32]); and the same identifier must be presented on every refresh, so whatever
you choose has to be as durable as the session itself.

## 6. The ten error codes at the boundary

Every failure but one returns the same thing to the client. The distinctions
exist for your logs. `CONFLICT` is the exception, because it is the only code the
client must *act* on differently — and the only one that says nothing about
whether a selector exists.

| Code | Client sees | Client action | Log level | Alarm |
|---|---|---|---|---|
| `MALFORMED` | `401`, no body | Clear the cookie, go to login | debug | on a sudden spike (probing) |
| `UNKNOWN_KID` | `401`, no body | Go to login | **warn** | yes — this is normally a config error or a pepper retired too early |
| `NOT_FOUND` | `401`, no body | Go to login | info | on rate — enumeration, or a GC job deleting rows early (T13) |
| `VERIFIER_MISMATCH` | `401`, no body | Go to login | **warn** | on rate — online guessing against a known selector |
| `REUSE_DETECTED` | `401`, no body | Go to login; consider telling the user | **security event** | **yes, always** ([N-39]) |
| `REVOKED` | `401`, no body | Go to login | info | on rate, if `reuseGraceSeconds > 0` — it is the substitute signal for a grace-window takeover ([N-30]) |
| `EXPIRED_ABSOLUTE` | `401`, no body | Go to login | info | no — routine |
| `EXPIRED_IDLE` | `401`, no body | Go to login | info | no — routine |
| `DEVICE_MISMATCH` | `401`, no body | Go to login | **security event** | **yes, always** ([N-39]) |
| `CONFLICT` | `409`, no body, cookie left intact | Retry **once**, through the single-flight gate, with the cookie as it then stands — never by re-presenting the token that lost | debug | on rate — a retry storm or a client without single-flight |

**Why one generic response.** [N-42] is explicit: the codes are for the server's
logs, not for the client. `NOT_FOUND` versus `VERIFIER_MISMATCH` tells an
unauthenticated caller whether a selector exists — which is exactly the oracle the
selector/verifier split was designed to deny them (T2, T4 in the threat model).
Returning the code verbatim also invites clients to branch on it, which freezes
your error surface into an API contract that [N-41] explicitly does not promise.

**What to log instead.** [N-39] requires the failure result to carry `userId` and
`familyId` whenever the engine resolved a record — every code except `MALFORMED`,
`UNKNOWN_KID` and `NOT_FOUND` — so a security event can be attributed without a
second lookup of a token you were told never to log ([N-14]).

```ts
function logRefreshFailure(r: { error: string; userId?: string; familyId?: string }): void {
  const security = r.error === 'REUSE_DETECTED' || r.error === 'DEVICE_MISMATCH';
  logger[security ? 'error' : 'info']('nebula.refresh.failed', {
    code: r.error,
    userId: r.userId,      // undefined for MALFORMED / UNKNOWN_KID / NOT_FOUND
    familyId: r.familyId,
    // never the token, the verifier, the pepper or the raw device id ([N-46])
  });
}
```

Treat an unrecognised code as a refusal ([N-40]): a future minor version may add
one, and your `switch` is not exhaustive forever.

## 7. Client-side rules

**Single-flight the refresh.** A page with five components that each notice a 401
must issue *one* refresh, not five. Five concurrent refreshes of the same token
produce one success and four `CONFLICT`s ([N-34] step 5) — measured against the
reference implementation, and the *safe* outcome rather than a harmless one. The
four losers hold a token the winner has already rotated, so anything that
re-presents it is a replay: at the default `reuseGraceSeconds = 0` that is
`REUSE_DETECTED`, the family is revoked, and the session the winner just renewed
dies with it. Single-flight is not tidiness; it is what keeps a routine race off
the reuse path. Keep one in-flight promise and let everyone await it.

```ts
let inFlight: Promise<string> | null = null;

export function refreshAccessToken(): Promise<string> {
  inFlight ??= attempt(true).finally(() => { inFlight = null; });
  return inFlight;
}

async function attempt(mayRetry: boolean): Promise<string> {
  const r = await fetch('/auth/session/refresh', { method: 'POST', credentials: 'same-origin' });
  // 409 is CONFLICT: a concurrent refresh won, the cookie now carries its
  // successor, and [N-35] allows exactly one retry — which sends that cookie,
  // never the token that lost. Any other failure is final.
  if (r.status === 409 && mayRetry) return attempt(false);
  if (!r.ok) throw new Error('reauthenticate');
  return (await r.json()).accessToken as string;
}
```

**Refresh proactively, not reactively.** Refreshing at ~75% of the access token's
life avoids a user-visible 401 round trip and keeps the refresh cadence
predictable, which makes the row-growth arithmetic in
[`OPERATIONS.md`](OPERATIONS.md) predictable too.

**Never retry a 401 from `/auth/session/refresh`.** It means the family is gone.
Retrying turns one failed session into a request loop against your login page.
`409` is the single exception, and it is retried once, never twice.

**Do not put the refresh token in a response body on the web.** If JavaScript can
read it, `HttpOnly` bought you nothing.

## 8. Rate limiting and CSRF

Rate limiting is a non-goal of the specification and MUST be at the edge (R5 in
the threat model). Two limits, not one: per-IP on `/auth/session/refresh` to blunt
enumeration, and per-`familyId` to catch a single credential being hammered — the
result carries `familyId` even on failure ([N-39]), so the second limit is
available to you without a lookup.

CSRF: `SameSite=Strict` is the primary defence and is sufficient for a same-site
SPA. If you must relax it to `Lax`, add one of the standard first-party defences —
a double-submit token, or an `Origin` check on the refresh handler. The cost of
getting this wrong is a silent, attacker-triggered rotation: they cannot read the
response, but they can burn the user's session.

## 9. Migrating an existing system

The migration is the same shape in both cases below: **upgrade on use**. You stop
minting the old credential immediately, keep accepting it for a bounded window,
and mint a NEBULA family the first time each user refreshes. No mass logout, no
flag day.

Dispatch is unambiguous and cheap, because [N-51] reserves the `nbl` prefix:

```ts
async function refreshAny(presented: string, deviceId?: string) {
  if (presented.startsWith('nbl.')) return engine.refresh(presented, deviceId);
  return legacyRefresh(presented, deviceId);   // deleted at the end of phase 2
}
```

Try NEBULA first, always. A legacy validator that runs first and is lenient about
what it accepts can be handed a NEBULA token and do something unpredictable with
it.

### From a non-rotating opaque refresh token

| Phase | What changes | How you know it worked |
|---|---|---|
| 0 | Apply `spec/schema/`, deploy the store adapter, wire the engine. Nothing issues NEBULA yet. | The table exists and is empty. |
| 1 | Login issues NEBULA only. `/refresh` accepts both; a legacy token is validated as before, then exchanged: `engine.issue(userId, deviceId)`, set the new cookie, and delete the legacy row in the same transaction. | The legacy-branch share of refreshes decays toward zero. |
| 2 | After the legacy token's maximum lifetime has elapsed since the start of phase 1 — or on an announced cutover date, whichever is later — delete the legacy branch, the legacy table and its code. | The legacy branch counter has been flat at zero for a full lifetime. |

The one thing to get right: **delete the legacy row as part of the exchange.** If
it survives, the old credential still works, and you have added rotation to a
system that also accepts a non-rotating token — the weakest link is what an
attacker will use.

### From JWT refresh tokens

Same three phases, with one difference that dictates the timetable: **you cannot
revoke an outstanding JWT.** Nothing you deploy shortens the life of a JWT already
in the wild; the migration window is fixed by the largest `exp` you have issued.

- Before phase 1, if you can, cut the refresh JWT's lifetime to the shortest your
  clients tolerate. Every day you take off the JWT lifetime is a day off the
  migration.
- During phase 1, if you need immediate revocation for the legacy branch, add a
  denylist keyed by `jti`. This is a temporary structure; it dies with phase 2.
  (It is also the argument for the whole migration: once you have a denylist you
  have a database on the refresh path, which is the cost people adopt JWTs to
  avoid.)
- The claims in your refresh JWT do not move to NEBULA. A NEBULA record carries a
  `userId` and nothing else ([N-10]); put claims in the short-lived access token,
  and put session metadata in your own table keyed by `familyId`, which is stable
  for the life of the session ([`COMPATIBILITY.md`](../COMPATIBILITY.md) §4).
- Rollback plan: keeping the legacy branch alive is the rollback. Because phase 1
  changes only what you *mint*, reverting to minting JWTs is a config change until
  the day you delete the branch.

### After the cutover

- Alarm on `REUSE_DETECTED` from day one. On a rotating system it is a real
  signal; if it fires constantly, look first for a client without single-flight
  (§7) and for a load balancer replaying requests, not for an attacker.
- Watch `NOT_FOUND`. A high rate right after migration usually means legacy
  cookies are still being presented after the branch was deleted.
- Expect a step change in row count: rotation writes a row per refresh. Do the
  arithmetic in [`OPERATIONS.md`](OPERATIONS.md) *before* phase 1, not after.

## 10. Checklist

- [ ] Refresh cookie: `HttpOnly`, `Secure`, `SameSite=Strict`, `Path` scoped to a
      prefix that covers refresh **and** logout, `Max-Age` from the result, no
      `Domain`, `__Secure-` prefix.
- [ ] Access token 5–15 minutes, held in memory, minted on login and on every
      successful refresh.
- [ ] `CONFLICT` answered with `409`, the cookie left intact, and retried exactly
      once **by the client** through its single-flight gate ([N-35]) — never by
      re-presenting the losing token server-side. Every other failure is one
      generic `401` with no body ([N-42]).
- [ ] `REUSE_DETECTED` and `DEVICE_MISMATCH` raise security events carrying
      `userId` and `familyId` ([N-39]); no token, verifier, pepper or raw device
      id is ever logged ([N-46]).
- [ ] Logout calls `revokeToken` (family-wide, verifier-proved) and returns the
      same response in every branch.
- [ ] Client single-flights refresh and never retries a 401 from it.
- [ ] Rate limits at the edge, per-IP and per-`familyId`.
- [ ] Store adapter tested against the behaviour vectors
      ([`STORE.md`](STORE.md) §8), reads served by the primary
      ([`STORE.md`](STORE.md) §6).
- [ ] GC job deleting only `family_expires_at <= now` ([N-15]).
