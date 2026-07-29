// Production-style SQL store for NEBULA — ADO.NET example (driver-agnostic).
//
// Works with Npgsql (PostgreSQL), Microsoft.Data.SqlClient and Microsoft.Data.Sqlite:
// inject any DbDataSource. Best practices demonstrated: parameterized commands only;
// lookups keyed on the non-secret selector ([N-45]); the two mutating operations
// written as real compare-and-set statements ([N-17], [N-18]); rotated/revoked rows
// kept until the family's absolute deadline, because they are what powers reuse
// detection ([N-15]); DeleteExpired for periodic GC.
//
// Wrap one refresh request in a single DbTransaction at the call site so the insert of
// the successor and the markRotated of the predecessor commit atomically ([N-22]).
//
// Infrastructure failures are left to propagate ([N-20]): a faulted task reaches the
// caller, and the engine returns neither a token nor a revocation count for work that
// did not happen. Never catch and translate them into a protocol outcome.
//
// Schema: docs/STORE.md. This file lives in examples/ and is not part of the published
// package.

using System.Data.Common;

namespace NebulaToken.Examples;

public sealed class AdoNetRefreshTokenStore : IRefreshTokenStore
{
    private const string Cols =
        "selector, verifier_hash, kid, family_id, generation, user_id, device_id_hash, " +
        "created_at, family_expires_at, idle_expires_at, status, rotated_at, replaced_by_selector";

    private readonly DbDataSource _db;

    public AdoNetRefreshTokenStore(DbDataSource db) => _db = db;

    public async Task<TokenRecord?> FindBySelectorAsync(
        string selector, CancellationToken cancellationToken = default)
    {
        await using var cmd = _db.CreateCommand($"SELECT {Cols} FROM refresh_tokens WHERE selector = @s");
        AddParam(cmd, "@s", selector);

        await using var reader = await cmd.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false);
        if (!await reader.ReadAsync(cancellationToken).ConfigureAwait(false)) return null;

        return new TokenRecord
        {
            Selector = reader.GetString(0),
            VerifierHash = reader.GetString(1),
            Kid = reader.GetString(2),
            FamilyId = reader.GetString(3),
            Generation = reader.GetInt32(4),
            UserId = reader.GetString(5),
            DeviceIdHash = reader.IsDBNull(6) ? null : reader.GetString(6),
            CreatedAt = reader.GetInt64(7),
            FamilyExpiresAt = reader.GetInt64(8),
            IdleExpiresAt = reader.GetInt64(9),
            Status = ParseStatus(reader.GetString(10)),
            RotatedAt = reader.IsDBNull(11) ? null : reader.GetInt64(11),
            ReplacedBySelector = reader.IsDBNull(12) ? null : reader.GetString(12),
        };
    }

    public async Task InsertAsync(TokenRecord rec, CancellationToken cancellationToken = default)
    {
        await using var cmd = _db.CreateCommand(
            $"INSERT INTO refresh_tokens ({Cols}) VALUES (@a,@b,@c,@d,@e,@f,@g,@h,@i,@j,@k,@l,@m)");
        AddParam(cmd, "@a", rec.Selector);
        AddParam(cmd, "@b", rec.VerifierHash);
        AddParam(cmd, "@c", rec.Kid);
        AddParam(cmd, "@d", rec.FamilyId);
        AddParam(cmd, "@e", rec.Generation);
        AddParam(cmd, "@f", rec.UserId);
        AddParam(cmd, "@g", (object?)rec.DeviceIdHash ?? DBNull.Value);
        AddParam(cmd, "@h", rec.CreatedAt);
        AddParam(cmd, "@i", rec.FamilyExpiresAt);
        AddParam(cmd, "@j", rec.IdleExpiresAt);
        AddParam(cmd, "@k", Wire(rec.Status));
        AddParam(cmd, "@l", (object?)rec.RotatedAt ?? DBNull.Value);
        AddParam(cmd, "@m", (object?)rec.ReplacedBySelector ?? DBNull.Value);
        await cmd.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// [N-17]: the <c>AND status = @f</c> is the compare-and-set. Without it two
    /// concurrent refreshes of one token both succeed and the family forks into two
    /// independently valid lineages, which silently disables reuse detection.
    /// </summary>
    public async Task<bool> MarkRotatedAsync(
        string selector,
        TokenStatus fromStatus,
        long rotatedAt,
        string replacedBySelector,
        CancellationToken cancellationToken = default)
    {
        var affected = await ExecAsync(
            "UPDATE refresh_tokens SET status='rotated', rotated_at=@r, replaced_by_selector=@n " +
            "WHERE selector=@s AND status=@f",
            cancellationToken,
            ("@r", rotatedAt), ("@n", replacedBySelector), ("@s", selector), ("@f", Wire(fromStatus)))
            .ConfigureAwait(false);
        return affected == 1;
    }

    /// <summary>[N-18]: compare-and-set on <c>active</c>.</summary>
    public async Task<bool> RevokeIfActiveAsync(string selector, CancellationToken cancellationToken = default)
    {
        var affected = await ExecAsync(
            "UPDATE refresh_tokens SET status='revoked' WHERE selector=@s AND status='active'",
            cancellationToken,
            ("@s", selector)).ConfigureAwait(false);
        return affected == 1;
    }

    /// <summary>
    /// [N-19]: returns the number of records actually changed, which is what makes it
    /// idempotent — a second call reports 0 rather than repeating the first count.
    /// </summary>
    public Task<int> RevokeFamilyAsync(string familyId, CancellationToken cancellationToken = default) =>
        ExecAsync(
            "UPDATE refresh_tokens SET status='revoked' WHERE family_id=@f AND status<>'revoked'",
            cancellationToken,
            ("@f", familyId));

    public Task<int> RevokeUserAsync(string userId, CancellationToken cancellationToken = default) =>
        ExecAsync(
            "UPDATE refresh_tokens SET status='revoked' WHERE user_id=@u AND status<>'revoked'",
            cancellationToken,
            ("@u", userId));

    /// <summary>
    /// Operational helper: GC families past their absolute deadline. Deleting anything
    /// before <c>family_expires_at</c> converts every replay from REUSE_DETECTED into
    /// NOT_FOUND ([N-15]).
    /// </summary>
    public Task<int> DeleteExpiredAsync(long now, CancellationToken cancellationToken = default) =>
        ExecAsync("DELETE FROM refresh_tokens WHERE family_expires_at <= @t", cancellationToken, ("@t", now));

    private async Task<int> ExecAsync(
        string sql, CancellationToken cancellationToken, params (string Name, object Value)[] args)
    {
        await using var cmd = _db.CreateCommand(sql);
        foreach (var (name, value) in args) AddParam(cmd, name, value);
        return await cmd.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
    }

    private static void AddParam(DbCommand cmd, string name, object value)
    {
        var p = cmd.CreateParameter();
        p.ParameterName = name;
        p.Value = value;
        cmd.Parameters.Add(p);
    }

    // The wire spelling of the status column is the spec's lowercase name, not the C#
    // enum name, so a row written by any other NEBULA implementation reads back here.
    private static string Wire(TokenStatus status) => status switch
    {
        TokenStatus.Active => "active",
        TokenStatus.Rotated => "rotated",
        TokenStatus.Revoked => "revoked",
        _ => throw new ArgumentOutOfRangeException(nameof(status), status, null),
    };

    private static TokenStatus ParseStatus(string value) => value switch
    {
        "active" => TokenStatus.Active,
        "rotated" => TokenStatus.Rotated,
        "revoked" => TokenStatus.Revoked,
        _ => throw new InvalidOperationException($"[NEBULA] unknown status \"{value}\" in refresh_tokens"),
    };
}
