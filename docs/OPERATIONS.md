# Operating NEBULA

Everything you need after the code is correct: what to measure, what to wake
someone for, how to rotate a pepper without logging anyone out, how big the table
gets, why restoring a backup can re-arm a stolen token, and what to do when one
is stolen.

This document assumes the deployment described in
[`INTEGRATION.md`](INTEGRATION.md) and a store built per [`STORE.md`](STORE.md).

---

## 1. Metrics to emit

Six counters and two gauges cover it. Names are suggestions; the labels are the
part that matters.

| Metric | Type | Labels | Source |
|---|---|---|---|
| `nebula_issue_total` | counter | `bound` (whether a device id was supplied) | one per successful `issue` |
| `nebula_refresh_total` | counter | `result` = `ok` or one of the ten codes | one per `refresh`, including retries |
| `nebula_revoke_total` | counter | `path` = `token` / `family` / `user` | one per revocation call |
| `nebula_revoked_records_total` | counter | `path` | the **count returned** by the revocation ([N-19]) |
| `nebula_store_errors_total` | counter | `op` | store failures reaching the engine ([N-20]) |
| `nebula_gc_deleted_total` | counter | — | rows deleted by the GC job |
| `nebula_records` | gauge | `status` | periodic `SELECT status, count(*) … GROUP BY status` |
| `nebula_oldest_live_family_seconds` | gauge | — | `now − min(family_expires_at)` over undeleted rows; the GC's health |

Emit the outcome label from the engine's own result, never from an HTTP status —
the boundary collapses all ten codes into one `401` ([N-42]), so the status code
carries none of the information you need.

Also emit `familyId` and `userId` as structured log fields on every failure that
carries them ([N-39]), and **never** the token, verifier, pepper or raw device
identifier ([N-14], [N-46]).

## 2. What to alarm on

The rates below are all "per successful refresh", which normalises for traffic
and for time of day.

### Page someone

| Signal | Why | First move |
|---|---|---|
| Any `REUSE_DETECTED` | A rotated token was replayed. Two parties held one credential ([N-30]). The family is already revoked; the alarm exists so a human looks. | §7 |
| Any `DEVICE_MISMATCH` | A bound family was refreshed from somewhere else ([N-32]). The family is already revoked. | §7 |
| `nebula_store_errors_total` > 0 sustained | The engine fails closed ([N-20]), so a store outage is an authentication outage. Every session in the world stops refreshing. | Treat as a database incident, not an auth incident |
| `UNKNOWN_KID` above a trickle | A pepper is missing from a deployed instance, or one was retired too early (§3). Every affected user is being logged out. | Compare the deployed pepper set across instances |

`REUSE_DETECTED` and `DEVICE_MISMATCH` are security events by [N-39]. Route them
to wherever your security events go, not only to the application log — and give
the alarm a threshold of one, not a rate. The whole point of the design is that
this event is rare and meaningful.

### Watch, don't page

| Signal | What it usually means |
|---|---|
| `CONFLICT` rate rising | Clients refreshing concurrently and losing the compare-and-set ([N-34] step 5). Almost always a client missing single-flight ([`INTEGRATION.md`](INTEGRATION.md) §7), a proxy retrying `POST`s, or a mobile client retrying on a flaky network. Harmless per request, and it doubles the write volume of every affected refresh (each loser inserts and then revokes a successor). It stops being harmless if anything re-presents the token that lost: at the default grace of 0 that is a replay, and it revokes the family. If `CONFLICT` and `REUSE_DETECTED` rise together, that is the bug — see [`INTEGRATION.md`](INTEGRATION.md) §4. |
| `VERIFIER_MISMATCH` rate rising | Online guessing against a known selector, or an adapter bug — a truncated or case-mangled `verifier_hash` column fails closed exactly like a wrong verifier ([N-31]). Check one row by hand before assuming an attack. |
| `NOT_FOUND` rate rising | Enumeration, stale clients after a migration, or — the dangerous one — a GC job deleting rows before `family_expires_at`, which silently converts every replay into `NOT_FOUND` and disables reuse detection (T13 in [`THREAT_MODEL.md`](THREAT_MODEL.md)). Verify §4 before looking for an attacker. |
| `REVOKED` rate rising | Routine if you revoke a lot. **Not routine if `reuseGraceSeconds > 0`**: [N-30] states that a grace-window takeover evicts the legitimate client with `REVOKED` and raises no `REUSE_DETECTED`, so this rate is your only signal for it. |
| `EXPIRED_ABSOLUTE`, `EXPIRED_IDLE` | Routine. They should track your TTLs and your traffic shape; a step change means a config change or a client that stopped refreshing. |
| `MALFORMED` | Routine background noise from scanners. A spike is probing, not a bug. |

## 3. Pepper rotation

Rotation costs nothing and logs nobody out. Do it on a schedule — annually is
defensible — so that the emergency version of the procedure is not the first time
you run it.

### Planned rotation

```bash
openssl rand -base64 48        # ≥ 32 bytes required; aim for ~256 bits of entropy ([N-23])
```

1. **Add the new pepper under a new `kid`.** Deploy with `peppers = { k1, k2 }`
   and `activeKid` still `k1`. Nothing changes behaviourally; this step exists so
   that no instance can ever be asked to verify a `kid` it does not have.
2. **Verify every instance has both** before continuing. A rolling deploy with
   mixed pepper sets and a switched `activeKid` produces `UNKNOWN_KID` for real
   users.
3. **Switch `activeKid` to `k2`.** Deploy. From this moment new records are
   written under `k2`; outstanding records still verify under `k1`, because
   verification always uses the pepper named by the *record* ([N-27], [N-32]),
   and each session migrates at its next natural rotation ([N-33] step 4 carries
   the device binding across with it).
4. **Watch the migration.**

   ```sql
   SELECT kid, status, count(*), max(family_expires_at)
     FROM refresh_tokens GROUP BY kid, status;
   ```

5. **Retire `k1` when — and only when — no record under it can still succeed.**

   ```sql
   -- Must return 0 before you remove k1 from the configuration.
   SELECT count(*) FROM refresh_tokens
    WHERE kid = 'k1' AND status = 'active'
      AND family_expires_at > :now AND idle_expires_at > :now;
   ```

   Rows that are `revoked`, or past either deadline, cannot produce a success
   under any pepper, so they do not hold the retirement back. Neither do
   `rotated` rows — with one exception: if `reuseGraceSeconds > 0`, a row rotated
   within the last `reuseGraceSeconds` can still serve a grace retry ([N-30]), so
   run the query no sooner than that many seconds after the last rotation under
   `k1`. The worst-case wait is bounded either way: `absoluteTtlSeconds` after
   the moment you switched `activeKid`, because no record under `k1` was minted
   after that.

   Removing the pepper earlier does not corrupt anything, but every affected user
   is logged out with `UNKNOWN_KID` ([N-27]) — the failure is safe, visible, and
   entirely avoidable by waiting.

6. **Destroy the retired key material** once the query has returned 0 for a full
   day. Keep it marked inactive in the KMS in the meantime; do not leave it in
   the application's configuration, where a rollback would silently re-arm it.

### Emergency rotation

If a pepper may have leaked, be clear about what that actually means before
declaring a mass-logout incident:

- A pepper alone lets nobody mint or present a token. Records live in the
  database; the verifier is 256 random bits and HMAC-SHA-256 is preimage
  resistant, so pepper + full dump still yields no presentable token (T2).
- What the pepper genuinely protects is the **device-identifier hash**, whose
  input may be low-entropy and therefore guessable by dictionary once the key is
  known ([N-11]).
- What the `kid` gives you is an **instant global kill switch**: remove it from
  the configuration and every session under it stops verifying, at once, with no
  write to the database.

So: rotate promptly using steps 1–3, then jump straight to removing the old
`kid`, accepting the forced re-login. If the compromise might extend to the store
itself, do §7's global revocation as well — a pepper you retire stops old records
from verifying, but says nothing about records an attacker with write access may
have inserted under the *new* one.

## 4. The garbage-collection job

One statement, one predicate, one index.

```sql
DELETE FROM refresh_tokens WHERE family_expires_at <= :now;
```

- **Never a different predicate.** Not `status <> 'active'`, not `rotated_at <
  …`, not a TTL applied at rotation. [N-15] requires every record to survive
  until `family_expires_at` with its `status` and `replaced_by_selector` intact,
  because finding a `rotated` row *is* reuse detection. Deleting early disables
  the property this library exists to provide, and nothing fails visibly when you
  do (T13).
- **Expiry does not shorten retention.** A family that died of idle timeout on
  day 7 still keeps its rows until `family_expires_at` on day 30. The only lever
  on retention is `absoluteTtlSeconds`.
- **The index is not optional.** `idx_rt_gc` on `family_expires_at` is in all
  three files under [`spec/schema/`](../spec/schema/); without it this delete is a
  full scan of your largest table, every run.
- **Batch it.** Delete in chunks of 10 000 with a short pause between chunks
  (`LIMIT` on MySQL and SQLite; `ctid IN (SELECT … LIMIT n)` on PostgreSQL) so a
  single run cannot bloat the undo log or stall replication.
- **Run it often.** Hourly beats nightly: the work per run is proportional to the
  interval, and a small hourly delete is invisible where a nightly one is a spike.
- **Alarm on it.** If `nebula_gc_deleted_total` is flat at zero while
  `nebula_oldest_live_family_seconds` grows past `absoluteTtlSeconds`, the job is
  not running — which is a disk problem, not a security problem, and the safe
  failure direction.

## 5. Capacity and row growth

Rotation writes a row per refresh. That is the cost of the model, and it is worth
being precise about it before you are surprised by it.

```
rows per family  =  1 + (rotations per day × days the session stays active)
rows retained    =  rows per family, until family_expires_at   ([N-15])
rotations/day    =  86 400 / refresh interval in seconds
```

The refresh interval is the access-token lifetime for a client that refreshes on
expiry. A client that refreshes proactively at ~75% of that lifetime
([`INTEGRATION.md`](INTEGRATION.md) §7) refreshes a third more often, so multiply
every row count below by 1.33 — or size on the proactive number directly, which
is the honest thing to do if that is what your client does.

Rows per family over a 30-day absolute TTL, for a session that stays active
throughout:

| Access-token lifetime | Rotations / day | Rows per family |
|---|---|---|
| 5 min | 288 | 8 641 |
| 15 min | 96 | 2 881 |
| 60 min | 24 | 721 |
| 4 h | 6 | 181 |

Worked example — 100 000 users, 1.5 devices each, 15-minute access tokens,
30-day absolute TTL, and the pessimistic assumption that every session is active
every day:

```
families            150 000
rows                150 000 × 2 881          ≈ 432 million
storage at ~300 B   432e6 × 300 B            ≈ 130 GB  (row + indexes; measure yours)
write rate          150 000 × 96 / 86 400    ≈ 167 refreshes/s
                                             ≈ 334 writes/s (one INSERT + one UPDATE each)
GC rate at steady state                       = the insert rate, by definition
```

Three levers, in order of effect:

1. **Access-token lifetime.** Doubling it halves every number above. Going from 5
   to 15 minutes removes two thirds of the table. The security cost is the window
   in which a stolen *access* token still works (R6 in the threat model) — a
   trade you should make deliberately, not by accident.
2. **`absoluteTtlSeconds`.** It is the retention window as well as the session
   ceiling; halving it halves the table. It also halves the worst case for pepper
   retirement (§3).
3. **Idle timeout.** It does not reduce retention, but it stops rotations for
   inactive sessions, which is where the pessimistic assumption above is wrong for
   most real populations. Measure your own active-days distribution before sizing.

Partitioning by `family_expires_at` (monthly range partitions, drop the whole
partition instead of deleting rows) turns GC into a metadata operation and is
worth it above a few hundred million rows. It changes no application code.

## 6. Backups, restores, and replica promotion

**A restore of the token store re-arms revoked and rotated tokens.** This is the
operational hazard most likely to undo the entire design, and it does so
silently.

A point-in-time restore to time *T* rewinds every row's `status` to what it was
at *T*:

- Records rotated after *T* become `active` again. A token an attacker stole and
  had spent is a working credential once more, and the reuse-detection evidence
  that would have caught them is gone.
- Revocations performed after *T* are undone. Every session you killed — for a
  password change, a lost laptop, an incident — is live again.
- Records minted after *T* no longer exist, so every legitimate user who
  refreshed since *T* is logged out with `NOT_FOUND`. The people you did *not*
  want to disturb are the only ones inconvenienced.

Therefore: **treat the token table as non-restorable state.** If you restore the
database that contains it, immediately revoke everything in it, in the same
maintenance window, before traffic returns:

```sql
UPDATE refresh_tokens SET status = 'revoked' WHERE status <> 'revoked';
```

Everyone re-authenticates once; nobody carries a resurrected credential. Prefer
this to `TRUNCATE`: it is nearly as cheap, and it keeps the rows as evidence
until their natural deadline, which is what [N-15] asks for.

Related cases, same mechanism:

- **Replica promotion under lag** is a point-in-time restore to `now − lag`.
  Rotations and revocations inside the lag window are lost. Your effective
  revocation window is your replication lag — write that number down.
- **A restored copy in a lower environment** is a live credential store if it is
  configured with production peppers. It should not be, and the table should not
  be copied into an analytics warehouse: the hashes are inert without the pepper
  but the selectors and the family graph map every session you have.
- **Restoring across a pepper rotation.** A restore to before a rotation whose old
  `kid` you have already destroyed yields `UNKNOWN_KID` for those rows — which,
  given the paragraph above, is where you were headed anyway.

## 7. Incident response

### A `REUSE_DETECTED` fired for one user

The engine has already revoked the family ([N-30]); nothing is on fire while you
investigate.

1. **Attribute it.** The failure result carries `userId` and `familyId` ([N-39]);
   your own session table gives the IP and user agent of each generation.
2. **Decide whether it is systemic before it is malicious.** A burst of
   `REUSE_DETECTED` across many users at once is far more often a client without
   single-flight, a proxy replaying `POST`s, or a database restore (§6) than a
   mass theft. Check the `CONFLICT` rate in the same window first: if the two
   move together, something is re-presenting a token that lost the
   compare-and-set ([`INTEGRATION.md`](INTEGRATION.md) §4), and you are looking
   at your own retry logic rather than at an attacker. One user, once, at an odd
   hour, from a new network is the other thing.
3. **Widen the blast radius if the vector is unknown.** `revokeAllForUser`
   ([N-37]) ends every session of that user; a password reset ends the ability to
   start a new one.
4. **Tell the user.** They are the only party who knows whether the second device
   was theirs.

### A `DEVICE_MISMATCH` fired

Same procedure, with one extra hypothesis: check whether the device identifier
itself changed legitimately — a reinstalled app that regenerated its keystore id,
or a web deployment that rotated the cookie carrying it. A wave of
`DEVICE_MISMATCH` immediately after a client release is a client bug, and it is
burning real users' sessions.

### Suspected database disclosure

The dump is inert as a source of tokens (T2): verifier hashes are HMAC outputs
under a pepper held elsewhere, and no raw verifier or device identifier is stored
([N-14]). What the attacker does have is the selector and the family graph — a
map of who has how many sessions and when. Selectors alone cannot revoke anything
either, because `revokeToken` proves the verifier ([N-36]).

Still: rotate the pepper (§3) — it protects the low-entropy device hashes — and
if the attacker may also have had *write* access, revoke everything (§6's
statement), because a record inserted by an attacker is a valid session and no
part of this design can tell you which one it is.

### Suspected server or pepper compromise

R1 in the threat model: an adversary who can read the peppers *and* write the
store can mint sessions. Nothing in this library helps. Rotate peppers, revoke
everything, force re-authentication, and rotate every other secret the host held.

### Global logout, as a procedure

```sql
UPDATE refresh_tokens SET status = 'revoked' WHERE status <> 'revoked';
```

Batch it like the GC job on a large table. The alternative — retiring the active
`kid` — is faster and writes nothing, but leaves the table full of rows that look
`active`, which will confuse the next person to read it. Prefer the explicit
statement, and use the `kid` lever only when you need the kill switch *now*.

Expect the fallout to be visible: a spike in `UNKNOWN_KID` or `REVOKED`, then a
login spike, then a return to baseline. Tell support before you run it.

## 8. A minimal dashboard

Four panels answer nearly every operational question:

1. **Refresh outcomes**, stacked by `result`. Healthy looks like a wall of `ok`
   with a thin fringe of `EXPIRED_*`.
2. **Security events**: `REUSE_DETECTED` + `DEVICE_MISMATCH`, count, with a
   threshold line at 1.
3. **Table health**: `nebula_records` by status, `nebula_gc_deleted_total` per
   run, `nebula_oldest_live_family_seconds` against `absoluteTtlSeconds`.
4. **Store health**: `nebula_store_errors_total` and refresh latency p99. The
   engine fails closed, so this panel is the one that predicts an authentication
   outage.
