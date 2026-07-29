// Production-style SQL store for NEBULA — driver-agnostic Dart example.
//
// The store is written against a tiny abstract `SqlExecutor` whose methods
// return futures, which is what every server-side Dart driver actually offers:
// `package:postgres` has no blocking API at all, and `waitFor` — the last way to
// turn a Future into a value — was removed in Dart 3. Implement `SqlExecutor`
// over your driver (postgres, mysql_client, sqlite3 wrapped in `Future.value`)
// and you get a spec-conforming store. Keeps this example dependency-free
// (schema: docs/STORE.md).
//
// Best practices demonstrated: parameterized queries only; lookups keyed on the
// non-secret selector ([N-45]); rotated/revoked rows kept until the family's
// absolute deadline, because they are what powers reuse detection ([N-15]);
// deleteExpired for GC.
//
// The two mutating methods are compare-and-sets ([N-17], [N-18]): the status
// predicate lives in the WHERE clause and the affected-row count is the return
// value. `UPDATE … WHERE selector=?` alone — no status predicate, no row count —
// is non-conforming, and it silently re-opens the race in which two concurrent
// refreshes both mint a successor and fork the family.
//
// Wrap each refresh request in one transaction so the successor insert and the
// predecessor's markRotated commit atomically ([N-22]). Let driver errors
// propagate: they must reach the caller as errors, never be folded into a
// protocol outcome ([N-20]).

import 'package:nebula_token/nebula_token.dart';

/// Minimal driver abstraction.
abstract interface class SqlExecutor {
  /// Runs a statement; completes with the affected row count.
  Future<int> execute(String sql, List<Object?> params);

  /// Runs a query; completes with the first row as a map keyed by column name,
  /// or null when no row matches.
  Future<Map<String, Object?>?> queryRow(String sql, List<Object?> params);
}

const String _cols =
    'selector, verifier_hash, kid, family_id, generation, user_id, device_id_hash, '
    'created_at, family_expires_at, idle_expires_at, status, rotated_at, replaced_by_selector';

class SqlRefreshTokenStore implements RefreshTokenStore {
  SqlRefreshTokenStore(this.db);

  final SqlExecutor db;

  @override
  Future<TokenRecord?> findBySelector(String selector) async {
    final Map<String, Object?>? row = await db.queryRow(
      'SELECT $_cols FROM refresh_tokens WHERE selector = ?',
      <Object?>[selector],
    );
    if (row == null) return null;
    return TokenRecord(
      selector: row['selector']! as String,
      verifierHash: row['verifier_hash']! as String,
      kid: row['kid']! as String,
      familyId: row['family_id']! as String,
      generation: row['generation']! as int,
      userId: row['user_id']! as String,
      deviceIdHash: row['device_id_hash'] as String?,
      createdAt: row['created_at']! as int,
      familyExpiresAt: row['family_expires_at']! as int,
      idleExpiresAt: row['idle_expires_at']! as int,
      status: TokenStatus.values.byName(row['status']! as String),
      rotatedAt: row['rotated_at'] as int?,
      replacedBySelector: row['replaced_by_selector'] as String?,
    );
  }

  @override
  Future<void> insert(TokenRecord r) async {
    await db.execute(
      'INSERT INTO refresh_tokens ($_cols) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)',
      <Object?>[
        r.selector,
        r.verifierHash,
        r.kid,
        r.familyId,
        r.generation,
        r.userId,
        r.deviceIdHash,
        r.createdAt,
        r.familyExpiresAt,
        r.idleExpiresAt,
        r.status.name,
        r.rotatedAt,
        r.replacedBySelector,
      ],
    );
  }

  /// Compare-and-set ([N-17]): the write applies only while the row still holds
  /// [fromStatus], and the affected-row count reports whether it did.
  @override
  Future<bool> markRotated(
    String selector,
    TokenStatus fromStatus,
    int rotatedAt,
    String replacedBySelector,
  ) async {
    final int n = await db.execute(
      "UPDATE refresh_tokens SET status='rotated', rotated_at=?, replaced_by_selector=? "
      'WHERE selector=? AND status=?',
      <Object?>[rotatedAt, replacedBySelector, selector, fromStatus.name],
    );
    return n == 1;
  }

  /// Compare-and-set ([N-18]): revoke only while the row is still active.
  @override
  Future<bool> revokeIfActive(String selector) async {
    final int n = await db.execute(
      "UPDATE refresh_tokens SET status='revoked' WHERE selector=? AND status='active'",
      <Object?>[selector],
    );
    return n == 1;
  }

  /// Idempotent, and returns how many rows it changed ([N-19]) — hence the
  /// `status <> 'revoked'` predicate: re-revoking a dead family must report 0.
  @override
  Future<int> revokeFamily(String familyId) => db.execute(
    "UPDATE refresh_tokens SET status='revoked' "
    "WHERE family_id=? AND status <> 'revoked'",
    <Object?>[familyId],
  );

  @override
  Future<int> revokeUser(String userId) => db.execute(
    "UPDATE refresh_tokens SET status='revoked' "
    "WHERE user_id=? AND status <> 'revoked'",
    <Object?>[userId],
  );

  /// Operational helper: GC families past their absolute deadline ([N-15]).
  /// Never delete on rotation — that turns every replay into NOT_FOUND and
  /// disables the one property NEBULA exists to provide.
  Future<int> deleteExpired(int now) => db.execute(
    'DELETE FROM refresh_tokens WHERE family_expires_at <= ?',
    <Object?>[now],
  );
}

void main() {
  // This example is a template: implement SqlExecutor with your DB driver, then
  //   final engine = NebulaEngine(..., store: SqlRefreshTokenStore(db));
  //   final issued = await engine.issue(userId, deviceId);
  //   final result = await engine.refresh(presented, deviceId);
  // Schema and operational guidance: docs/STORE.md
}
