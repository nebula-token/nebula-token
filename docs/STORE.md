# Implementing a production store

The store contract ([`SPECIFICATION.md`](../SPECIFICATION.md) §4, [N-16]) is six
methods over a single table or keyspace. The in-memory store shipped with every
package is a development and test fixture ([N-21]); it is per-process, so reuse
detection does not survive a restart and does not work behind more than one
instance.

This document is the reference for people writing the other implementation. It
covers the schema, the exact statement behind each method, how the engine turns a
lost compare-and-set into `CONFLICT`, what the store must retain and for how
long, transaction boundaries, and what breaks under a store that is not
read-after-write consistent.

Two facts govern everything below:

1. **Two of the six methods are compare-and-set operations.** `markRotated`
   ([N-17]) and `revokeIfActive` ([N-18]) must apply their write *if and only if*
   the current status matches, and must report whether they did. A store that
   returns `true` unconditionally is not merely imprecise — it re-opens the race
   the specification exists to close.
2. **Rotated and revoked rows are evidence.** Reuse detection is the act of
   finding a `rotated` record ([N-15]). A store that deletes them early converts
   every replay from `REUSE_DETECTED` into `NOT_FOUND`.

---

## 1. Schema

The DDL is not in this document. It lives in three real files, one per engine,
which are the only copies:

| Engine | File |
|---|---|
| PostgreSQL 12+ | [`spec/schema/postgres.sql`](../spec/schema/postgres.sql) |
| MySQL 8.0.16+ / MariaDB 10.5+ | [`spec/schema/mysql.sql`](../spec/schema/mysql.sql) |
| SQLite 3.37+ | [`spec/schema/sqlite.sql`](../spec/schema/sqlite.sql) |

They define the same thirteen columns of [N-10] with the same semantics, four
indexes (primary key on `selector`, plus `family_id`, `user_id` and
`family_expires_at`), and CHECK constraints for the invariants the engine
maintains — including the two shape rules that catch a miswritten adapter
immediately:

- an `active` row has `rotated_at IS NULL` and `replaced_by_selector IS NULL`;
- a `rotated` row has both set ([N-34] step 3), because that pair is exactly what
  the grace path in [N-30] reads.

Three column decisions are load-bearing and are explained in the files
themselves: timestamps are `BIGINT` Unix seconds and never a timezone-aware type
([N-2]); hash columns are `TEXT`/`VARCHAR` and never `CHAR`, because a
blank-padded value fails the constant-time hex comparison of [N-31] and would
reject every token in the table; and on MySQL every token-derived column is
`ascii_bin`, because the server default collation is case-insensitive and
selectors are case-sensitive base64url.

If your engine is not one of the three, port `postgres.sql` — it is the most
explicit — and keep the constraint names, so an error in production reads the
same everywhere.

## 2. The six methods, as SQL

Placeholders are shown in PostgreSQL style. Use parameter binding, always: token
material must never be interpolated into a statement.

| Contract method | Statement | Result |
|---|---|---|
| `findBySelector` | `SELECT <13 columns> FROM refresh_tokens WHERE selector = $1` | row or nothing |
| `insert` | `INSERT INTO refresh_tokens (<13 columns>) VALUES ($1 … $13)` | nothing; a duplicate-key violation is an infrastructure error ([N-20]) |
| `markRotated` | `UPDATE refresh_tokens SET status = 'rotated', rotated_at = $2, replaced_by_selector = $3 WHERE selector = $1 AND status = $4` | **affected rows = 1 → `true`, 0 → `false`** |
| `revokeIfActive` | `UPDATE refresh_tokens SET status = 'revoked' WHERE selector = $1 AND status = 'active'` | **affected rows = 1 → `true`, 0 → `false`** |
| `revokeFamily` | `UPDATE refresh_tokens SET status = 'revoked' WHERE family_id = $1 AND status <> 'revoked'` | affected rows, as an integer |
| `revokeUser` | `UPDATE refresh_tokens SET status = 'revoked' WHERE user_id = $1 AND status <> 'revoked'` | affected rows, as an integer |

Four details that adapters get wrong:

**`markRotated` takes `fromStatus` as a parameter, not a literal.** It is
`'active'` on an ordinary rotation and `'rotated'` on a grace retry ([N-34] step
3), because a grace retry re-rotates a record that is already `rotated`. An
adapter that hard-codes `AND status = 'active'` silently turns every grace retry
into a `CONFLICT`.

**Derive the answer from the affected-row count, not from whether the statement
ran.** Every driver exposes the count: `rowCount` in node-postgres,
`cursor.rowcount` in DB-API, `RowsAffected()` on Go's `sql.Result`,
`PreparedStatement.executeUpdate()` in JDBC, `PDOStatement::rowCount()`,
`ExecuteNonQueryAsync` in ADO.NET, `num_rows` on `Postgrex.Result`,
`cmd_tuples` on Ruby's `PG::Result`. If your driver cannot report it, use
`UPDATE … RETURNING selector` (or the engine's equivalent) and count the rows
you got back.

**Then return a boolean, not the count itself.** [N-17] and [N-18] define these
two methods as returning whether the write applied, and `count == 1` is that
answer — `res.cmd_tuples == 1`, `cur.rowcount == 1`. Returning the bare count
is a portability trap rather than a shortcut: in a language where `0` is truthy
— Ruby is the one among the ten — a lost compare-and-set then reads as a win,
both concurrent refreshes mint a successor, and the family forks into two
independently valid lineages with reuse detection silently off for it. That is
the exact failure [N-17] exists to close. The shipped adapters get this right
(`examples/pg_store.rb`, `examples/sqlite_store.py`); copy their shape.

**The `AND status <> 'revoked'` guard on the two bulk revocations is what makes
the count portable.** [N-19] asks for the number of records *changed*. PostgreSQL
reports rows *matched*, MySQL reports rows *changed*, and without the guard the
same call returns 2 on one engine and 0 on the other for an already-revoked
family. With the guard both return the same number, and the operation stays
idempotent as [N-19] requires. (Verified on PostgreSQL 16 and MySQL 8.4 — see
§8.)

**`revokeIfActive` is not "revoke".** It must refuse a record that is `rotated`
or already `revoked`. The engine relies on that refusal in two places: to clean
up the successor it inserted after losing a rotation race ([N-34] step 5), and to
let exactly one concurrent grace retry consume an unused successor ([N-30] step
2).

## 3. How a lost compare-and-set becomes `CONFLICT`

The store never produces an error code. It reports a boolean; the engine decides.
The whole of the concurrency design is in the two sequences below.

**Ordinary rotation ([N-34]).** Two requests present the same active token — two
browser tabs, or a mobile client that retried.

```
request A                          request B
─────────────────────────────────  ─────────────────────────────────
findBySelector(S)   → active       findBySelector(S)   → active
insert(successor A')               insert(successor B')
markRotated(S,'active',…,A') → true
                                   markRotated(S,'active',…,B') → false
                                   revokeIfActive(B')        ← clean up
return token A'                    return CONFLICT
```

Because the `WHERE` clause carries `AND status = 'active'`, exactly one of the two
`UPDATE`s can match: the database, not the application, arbitrates. The loser
revokes the orphan successor it inserted and returns `CONFLICT` — never a token
([N-34] step 5). Without the status predicate both writes succeed, the family
forks into two independently valid lineages, and reuse detection is dead: neither
lineage ever sees a replay.

**Grace retry ([N-30]).** Two retries of the same lost response arrive together.
Each finds the predecessor `rotated` and its successor `active`; each tries to
consume that successor with `revokeIfActive`. Exactly one wins; the loser returns
`CONFLICT` before minting anything.

`CONFLICT` is transient and carries no security meaning ([N-35]): nothing was
rotated, and nothing beyond the engine's own orphan successor was revoked. What
matters is *what the retry presents*. The loser's token is now `rotated`, so
re-presenting it meets the ordinary reuse path — at the default grace of 0,
`REUSE_DETECTED`, and the family goes with it. The retry [N-35] intends is the
client's, which sends the successor the winner has already handed it and simply
succeeds. That distinction is the difference between a `409` and a forced
re-login for a routine race, and it is why the handler in
[`INTEGRATION.md`](INTEGRATION.md) §4 never retries in place.

The two behaviours are pinned by the scenarios `conflict-01-lost-rotation-cas`
and `conflict-02-lost-grace-cas` in
[`spec/behavior-vectors.json`](../spec/behavior-vectors.json), which drive the
lost compare-and-set deterministically rather than hoping to observe a race.

## 4. Retention: what you must not delete, and why

**[N-15] is a requirement on your deployment, not only on your code.** A record
MUST be retained, with its `status` and `replaced_by_selector` intact, until at
least its `family_expires_at`. Records MAY be deleted once
`now >= family_expires_at`.

The failure mode is silent, which is what makes it worth a section. Reuse
detection works by finding a `rotated` row. If that row is gone, the engine takes
the `NOT_FOUND` branch at step 3 of [N-26] — a routine outcome that no
sensible deployment alarms on. The stolen token stops working, so nothing looks
broken; what disappears is the *signal* that a theft occurred, and with it the
family revocation that evicts the attacker from the rest of the session.

Three ways to arrive there, all of them things people do on purpose:

- **A TTL applied at rotation.** In Redis, `EXPIRE rt:{selector} 60` after
  rotation looks like good hygiene. It deletes the evidence one minute after it
  becomes evidence. Set the TTL from `family_expires_at - now` at *insert* time,
  and never shorten it.
- **A nightly `DELETE WHERE status <> 'active'`.** This deletes every rotated
  predecessor in the system every night. It is the single most effective way to
  disable NEBULA while leaving every test passing.
- **A `rotated_at`-based cleanup**, on the reasoning that a rotated row is spent.
  It is spent as a credential and live as evidence.

The only correct predicate is the one in the schema files:

```sql
DELETE FROM refresh_tokens WHERE family_expires_at <= $1;   -- $1 = now
```

`<=` and not `<`: at exactly `family_expires_at` the family is already dead,
because [N-26] step 7 tests `now < family_expires_at`.

This predicate needs the `idx_rt_gc` index on `family_expires_at`. Without it the
GC job is a sequential scan of what is, in most deployments, the largest table in
the database — every run, forever. Every package's `SKILL.md` recommends running
this job; the index is what makes the recommendation affordable. Sizing, batching
and scheduling are in [`OPERATIONS.md`](OPERATIONS.md).

## 5. Transaction boundaries and isolation

**What must be atomic.** Every rotation performs `insert(successor)` followed by
`markRotated(predecessor)`. [N-22] says these SHOULD be one transaction. If the
process dies between them you are left with an orphan `active` successor that no
client holds: harmless (nobody can present a token nobody received) but it
accumulates, and it is indistinguishable in the table from a live token. The
grace path is the same shape: `revokeIfActive(successor)` followed by a
re-rotation.

**Where to put the boundary.** At the call site, around the whole engine
operation, not inside the store methods:

```
BEGIN;
  result = await engine.refresh(token, deviceId);
COMMIT;   -- ROLLBACK if the engine threw
```

This works because the engine performs no I/O other than store calls, and it
keeps the store adapter free of transaction logic — the same adapter then works
inside a caller's larger transaction.

**Which isolation level.** `READ COMMITTED` is what the compare-and-set is
specified against, and it is the PostgreSQL and Oracle default. Under it — and
under MySQL/MariaDB's default `REPEATABLE READ`, which re-reads the latest
committed version for an `UPDATE` — the loser's statement matches zero rows and
the engine reports `CONFLICT`. Safety never rests on the isolation level: it
rests on the `WHERE … AND status = ?` predicate, which no level can make two
writers both satisfy. What the level changes is the *shape* of the loser's
outcome.

Three consequences worth stating:

- **You do not need `SERIALIZABLE`.** If you use it, be ready for serialization
  failures on the rotation of a hot session and retry them as you would any
  other; the engine will not see them as `CONFLICT`, it will see them as an
  infrastructure error ([N-20]) and fail closed.
- **PostgreSQL's `REPEATABLE READ` is not MySQL's.** PostgreSQL implements it as
  snapshot isolation, so the losing compare-and-set does not return zero rows —
  it aborts with `could not serialize access due to concurrent update`
  (SQLSTATE `40001`). Verified on PostgreSQL 17 and MariaDB 10.4, the two
  behaving exactly as described here. Nothing forks either way, but on
  PostgreSQL you get an infrastructure error where you expected a `CONFLICT`, so
  either stay on `READ COMMITTED` for these statements or add the
  serialization-failure retry the level obliges you to have anyway.
- **`SELECT … FOR UPDATE` is an alternative, not an addition.** Locking the row
  in `findBySelector` and holding it to the end of the transaction serialises
  rotations of one token, which also closes the race. It costs a lock held across
  the engine's HMAC work, and it turns the loser's outcome from a fast `CONFLICT`
  into a wait. Prefer the compare-and-set. Never do both under `SERIALIZABLE`
  without measuring — you will have built a queue.

**Do not wrap `revokeUser` in the request transaction.** "Log out everywhere" for
a user with many sessions can touch thousands of rows; run it on its own
connection, outside the request transaction, and let it commit on its own.

## 6. Stores that are not read-after-write consistent

NEBULA assumes that a write performed by one request is visible to the next
request that reads the same key. Deployments break this assumption routinely, and
usually by accident: a read replica for `SELECT`s, a multi-region cluster with
asynchronous replication, DynamoDB's default eventually-consistent read, a Redis
replica serving reads while the primary takes writes.

What each of the six methods does under staleness:

| Path | Under a stale read | Consequence |
|---|---|---|
| `findBySelector` after `insert` (login, then an immediate refresh) | row not yet visible | `NOT_FOUND` — the user is logged out one second after logging in |
| `findBySelector` after `markRotated` | predecessor still reads `active` | the engine tries an ordinary rotation and the compare-and-set at the primary fails → `CONFLICT`. **No fork**, but not free: the client is holding a token the primary has already rotated, so once replication catches up the next presentation of it is a replay (§3) |
| `findBySelector` after `revokeFamily` | record still reads `active` | a revoked token is accepted until replication catches up. **Not self-healing** |
| grace path reading the successor | successor not yet visible, or reads `active` after being consumed | a legitimate retry is judged a replay (`REUSE_DETECTED`), or two retries are both served |

The pattern is that the compare-and-set writes are safe because they execute at
the primary and re-evaluate their predicate there; the *reads* are what carry the
risk, and the one that matters for security is revocation visibility — the window
in which a token you have already killed still works is exactly your replication
lag.

Therefore: **route every NEBULA read to the primary**, or to a store that
guarantees read-after-write for the key you just wrote.

- **PostgreSQL/MySQL replicas:** do not send `findBySelector` to a replica. If
  your ORM does read/write splitting automatically, pin these queries.
- **DynamoDB:** `ConsistentRead: true` on `GetItem`, and conditional writes
  (`ConditionExpression: status = :from`) for the two compare-and-sets — that is
  the same mechanism, expressed differently.
- **Redis:** read from the primary. `READONLY` replica reads are asynchronous;
  Redis Cluster does not give you read-your-writes on a replica.
- **Cassandra/Scylla:** `LOCAL_QUORUM` reads and writes at minimum, and use
  lightweight transactions (`IF status = 'active'`) for the compare-and-sets.
  Their cost is real; if it is unacceptable, this is not the right store for a
  credential.

If you cannot get read-after-write consistency, you can still run NEBULA — you
are choosing a revocation window equal to your replication lag, and you should
write that number down in your threat model rather than discover it during an
incident.

## 7. Redis and other key-value stores

The contract is not SQL-specific; it needs three capabilities: a keyed lookup, a
conditional write, and two secondary indexes.

```
rt:{selector}          → hash of the thirteen record fields
                         TTL = family_expires_at - now, set at INSERT and never shortened
family:{family_id}     → set of selectors,  same TTL
user:{user_id}         → set of selectors,  TTL refreshed as families are added
```

- `findBySelector` → `HGETALL rt:{selector}`.
- `insert` → `HSET` + `SADD` to both sets, in one `MULTI/EXEC`.
- `markRotated` / `revokeIfActive` → **a Lua script**, not `WATCH`-based
  optimistic locking and certainly not read-then-write. The script reads the
  status field, compares it to the expected one, writes only on a match, and
  returns 1 or 0. Redis executes a script atomically, which is exactly the
  compare-and-set semantics [N-17] and [N-18] require.
- `revokeFamily` / `revokeUser` → iterate the set inside a Lua script, set
  `status` on each member whose status is not already `revoked`, and return the
  count.

The `user:{user_id}` set is unbounded in a way the SQL index is not: it
accumulates a selector per rotation for as long as the user exists. Prune it
when its members' families expire, or store families rather than selectors and
resolve one level deeper.

## 8. What is actually verified, and what is not

Stated precisely, because the previous version of this document claimed more than
was true.

**Verified by the repository's test suites, on every CI run:**

- Engine behaviour against the 38 scenarios of
  [`spec/behavior-vectors.json`](../spec/behavior-vectors.json) and the 46 cases
  of [`spec/test-vectors.json`](../spec/test-vectors.json), in every language.
  This includes both compare-and-set outcomes, driven deterministically by the
  runner's `failNextCas` operation.
- Those scenarios run against each package's **in-memory** store ([N-21]). The
  in-memory store implements the same six-method contract, so what is verified is
  the *engine's* use of the contract — the sequences in §3 above — not any SQL.
  Which scenario covers which requirement is published in
  [`spec/traceability.json`](../spec/traceability.json).

**Verified by hand against real servers, not by CI:**

- The three schema files apply cleanly: `spec/schema/postgres.sql` on PostgreSQL
  16 and 17, `spec/schema/mysql.sql` on MySQL 8.4 and MariaDB 10.4 (below the
  10.5 floor the file states, so that floor is conservative),
  `spec/schema/sqlite.sql` on SQLite 3.44.
- The statements in §2 produce the affected-row counts stated there, including
  the matched-versus-changed difference — unguarded, `revokeFamily` on an
  already-revoked family reported 2 on PostgreSQL and 0 on MariaDB, and the
  guarded form reported 0 on both — and the CHECK constraints reject the
  malformed rows they are meant to reject. On MySQL, clearing `sql_mode`
  reproduces the truncation the schema header warns about: a 26-character
  selector is stored as its first 22.
- The isolation-level difference in §5: the losing compare-and-set returns zero
  rows under `READ COMMITTED` and under MariaDB's `REPEATABLE READ`, and raises
  SQLSTATE `40001` under PostgreSQL's.

None of this runs in CI, because CI has no database. Re-run it yourself before
trusting a version this list does not name.

**Compiled but never executed:**

- The per-package example adapters under `packages/*/examples/`. CI compiles,
  analyses or loads every one of them (`scripts/check-examples.mjs` fails the
  build if a package's template stops being built by some job), so they cannot
  silently fall behind the store contract. But no test *runs* them, and none has
  ever been pointed at a real database: a template that compiles can still be
  wrong.
- Any store you write. Nothing in this repository can test your adapter for you.

**So test your adapter.** The cheapest sufficient test is the one the packages
already run: point the behaviour-vector runner at your store instead of the
in-memory one. If your language's runner is not reusable, the minimum set is six
assertions — `markRotated` returns `false` on a second attempt with the same
`fromStatus`; `markRotated` returns `true` with `fromStatus = 'rotated'` on a
rotated record; `revokeIfActive` returns `false` on a rotated record and on a
revoked one; `revokeFamily` returns a count and is idempotent; `insert` of a
duplicate selector raises rather than overwriting; and a row survives a GC run
performed one second before its `family_expires_at`.

## 9. Checklist

- [ ] Schema applied from `spec/schema/`, indexes and CHECK constraints included.
- [ ] Every query parameterised; no token material in a statement string.
- [ ] Lookups key only on `selector` ([N-45]); nothing secret-derived is indexed.
- [ ] `markRotated` and `revokeIfActive` return the affected-row count as a
      boolean, and `markRotated` uses the caller's `fromStatus`.
- [ ] `revokeFamily` / `revokeUser` return a count and carry the
      `status <> 'revoked'` guard.
- [ ] Store failures propagate as infrastructure errors ([N-20]); nothing is
      swallowed, nothing returns a protocol code.
- [ ] Rotation writes are in one transaction ([N-22]).
- [ ] Reads go to the primary, or the consistency window is documented.
- [ ] GC deletes only `family_expires_at <= now` ([N-15]), and the
      `family_expires_at` index exists.
- [ ] The adapter is tested against the behaviour vectors, not only by hand.

Operational concerns beyond correctness — metrics, alarms, pepper rotation, row
growth, backup hazards — are in [`OPERATIONS.md`](OPERATIONS.md).
