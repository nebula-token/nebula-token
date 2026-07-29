// No package declaration on purpose.
//
// This file is a TEMPLATE to copy into your own project, not a shipped type. It
// lives in examples/, which is outside src/main/java so Maven never compiles it
// into the jar, and a `package dev.nebulatoken.examples;` line here would be
// three things at once: a claim on a namespace this project does not publish, a
// path/package mismatch (java:S1598) that every IDE reports, and one more line
// you would have to edit after pasting it. Copy the class into your own package
// and add your own declaration; nothing below changes.
//
// CI compiles it exactly as you would: `javac -cp target/classes examples/*.java`.

import dev.nebulatoken.RefreshTokenStore;
import dev.nebulatoken.TokenRecord;
import dev.nebulatoken.TokenStatus;

import javax.sql.DataSource;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.Locale;

/**
 * Production-style SQL store for NEBULA -- JDBC example (PostgreSQL flavoured).
 *
 * <p>What this template demonstrates:
 *
 * <ul>
 *   <li><b>The compare-and-set methods are real compare-and-sets</b> ([N-17],
 *       [N-18]): the {@code AND status = ?} in the WHERE clause is the whole
 *       mechanism, and the affected-row count is the answer. Dropping either
 *       lets two concurrent refreshes fork one family into two live lineages.</li>
 *   <li><b>Both failure channels</b> ([N-20]): protocol answers are the returned
 *       {@code boolean}/{@code int}; a {@link SQLException} is rethrown, never
 *       converted into {@code false} or {@code 0}. Reporting "the CAS lost" for
 *       a statement that never reached the database is how an engine ends up
 *       claiming a revocation that did not happen.</li>
 *   <li>{@link PreparedStatement} only -- token material is never concatenated
 *       into SQL -- and lookups keyed on the non-secret selector ([N-45]).</li>
 *   <li>Rotated and revoked rows kept until the family's absolute deadline: they
 *       are what reuse detection reads ([N-15]). {@link #deleteExpired(long)} is
 *       the only GC that is safe.</li>
 * </ul>
 *
 * <p>Wrap each refresh request in one transaction
 * ({@code setAutoCommit(false)} &rarr; {@code engine.refresh} &rarr;
 * {@code commit}) so the successor insert and the predecessor's
 * {@code markRotated} commit atomically ([N-22]).
 *
 * <p>Schema: {@code docs/STORE.md}. This file lives in {@code examples/} and is
 * not compiled into the published artifact.
 */
public final class JdbcRefreshTokenStore implements RefreshTokenStore {

    private static final String COLS =
            "selector, verifier_hash, kid, family_id, generation, user_id, device_id_hash, "
          + "created_at, family_expires_at, idle_expires_at, status, rotated_at, replaced_by_selector";

    private final DataSource ds;

    public JdbcRefreshTokenStore(DataSource ds) {
        this.ds = ds;
    }

    @Override
    public TokenRecord findBySelector(String selector) {
        String sql = "SELECT " + COLS + " FROM refresh_tokens WHERE selector = ?";
        try (Connection c = ds.getConnection(); PreparedStatement ps = c.prepareStatement(sql)) {
            ps.setString(1, selector);
            try (ResultSet rs = ps.executeQuery()) {
                if (!rs.next()) return null;
                Long rotatedAt = rs.getObject("rotated_at") == null ? null : rs.getLong("rotated_at");
                return new TokenRecord(
                        rs.getString("selector"), rs.getString("verifier_hash"), rs.getString("kid"),
                        rs.getString("family_id"), rs.getInt("generation"), rs.getString("user_id"),
                        rs.getString("device_id_hash"), rs.getLong("created_at"),
                        rs.getLong("family_expires_at"), rs.getLong("idle_expires_at"),
                        TokenStatus.valueOf(rs.getString("status").toUpperCase(Locale.ROOT)),
                        rotatedAt, rs.getString("replaced_by_selector"));
            }
        } catch (SQLException e) {
            throw new IllegalStateException("refresh_tokens lookup failed", e);
        }
    }

    @Override
    public void insert(TokenRecord r) {
        String sql = "INSERT INTO refresh_tokens (" + COLS + ") VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)";
        try (Connection c = ds.getConnection(); PreparedStatement ps = c.prepareStatement(sql)) {
            ps.setString(1, r.selector());
            ps.setString(2, r.verifierHash());
            ps.setString(3, r.kid());
            ps.setString(4, r.familyId());
            ps.setInt(5, r.generation());
            ps.setString(6, r.userId());
            ps.setString(7, r.deviceIdHash());
            ps.setLong(8, r.createdAt());
            ps.setLong(9, r.familyExpiresAt());
            ps.setLong(10, r.idleExpiresAt());
            ps.setString(11, status(r.status()));
            ps.setObject(12, r.rotatedAt());
            ps.setString(13, r.replacedBySelector());
            ps.executeUpdate();
        } catch (SQLException e) {
            throw new IllegalStateException("refresh_tokens insert failed", e);
        }
    }

    /** Compare-and-set ([N-17]): the {@code AND status = ?} is not optional. */
    @Override
    public boolean markRotated(String selector, TokenStatus fromStatus, long rotatedAt,
                               String replacedBySelector) {
        return 1 == update(
                "UPDATE refresh_tokens SET status='rotated', rotated_at=?, replaced_by_selector=? "
                        + "WHERE selector=? AND status=?",
                ps -> {
                    ps.setLong(1, rotatedAt);
                    ps.setString(2, replacedBySelector);
                    ps.setString(3, selector);
                    ps.setString(4, status(fromStatus));
                });
    }

    /** Compare-and-set ([N-18]). */
    @Override
    public boolean revokeIfActive(String selector) {
        return 1 == update(
                "UPDATE refresh_tokens SET status='revoked' WHERE selector=? AND status='active'",
                ps -> ps.setString(1, selector));
    }

    @Override
    public int revokeFamily(String familyId) {
        return update("UPDATE refresh_tokens SET status='revoked' "
                        + "WHERE family_id=? AND status <> 'revoked'",
                ps -> ps.setString(1, familyId));
    }

    @Override
    public int revokeUser(String userId) {
        return update("UPDATE refresh_tokens SET status='revoked' "
                        + "WHERE user_id=? AND status <> 'revoked'",
                ps -> ps.setString(1, userId));
    }

    /**
     * Operational helper: GC families past their absolute deadline. Note the
     * predicate -- deleting anything before {@code family_expires_at}, in
     * particular "tidying up" rotated rows, silently disables reuse detection
     * ([N-15]).
     */
    public int deleteExpired(long now) {
        return update("DELETE FROM refresh_tokens WHERE family_expires_at <= ?",
                ps -> ps.setLong(1, now));
    }

    private static String status(TokenStatus status) {
        return status.name().toLowerCase(Locale.ROOT);
    }

    @FunctionalInterface
    private interface Binder {
        void bind(PreparedStatement ps) throws SQLException;
    }

    private int update(String sql, Binder binder) {
        try (Connection c = ds.getConnection(); PreparedStatement ps = c.prepareStatement(sql)) {
            binder.bind(ps);
            return ps.executeUpdate();
        } catch (SQLException e) {
            // [N-20] fail closed: never report "the compare-and-set lost" for a
            // statement that never ran.
            throw new IllegalStateException("refresh_tokens update failed", e);
        }
    }
}
