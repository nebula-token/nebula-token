using System.Collections.Concurrent;

namespace NebulaToken;

/// <summary>
/// Reference in-memory store ([N-21]) — development and tests ONLY.
/// </summary>
/// <remarks>
/// <para>
/// <b>Not for production.</b> State is per-process and lost on restart, so reuse
/// detection does not survive a deploy and does not work behind more than one
/// instance — exactly the two situations it exists to catch. Implement
/// <see cref="IRefreshTokenStore"/> over your database instead; see
/// <c>examples/AdoNetRefreshTokenStore.cs</c> and <c>docs/STORE.md</c>.
/// </para>
/// <para>
/// <b>Concurrency.</b> Unlike single-threaded runtimes, .NET serves requests on a
/// thread pool, so the compare-and-set methods of [N-17] and [N-18] have to be
/// genuinely atomic here. Each is a read / build-modified-copy /
/// <see cref="ConcurrentDictionary{TKey,TValue}.TryUpdate"/> loop:
/// <see cref="TokenRecord"/> is immutable and compares by reference, so
/// <c>TryUpdate</c> only applies the swap if nobody else changed the row in between.
/// Editing the stored object's fields in place would look like it works and would
/// silently lose the race.
/// </para>
/// </remarks>
public sealed class MemoryRefreshTokenStore : IRefreshTokenStore
{
    private readonly ConcurrentDictionary<string, TokenRecord> _rows = new(StringComparer.Ordinal);

    public Task<TokenRecord?> FindBySelectorAsync(
        string selector, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ArgumentNullException.ThrowIfNull(selector);
        return Task.FromResult(_rows.TryGetValue(selector, out var record) ? record : null);
    }

    public Task InsertAsync(TokenRecord record, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ArgumentNullException.ThrowIfNull(record);

        // A real store has a primary key on `selector`; refusing the duplicate here
        // rather than overwriting keeps that failure mode visible in development.
        if (!_rows.TryAdd(record.Selector, record))
        {
            throw new InvalidOperationException($"[NEBULA] duplicate selector {record.Selector}");
        }
        return Task.CompletedTask;
    }

    /// <inheritdoc />
    public Task<bool> MarkRotatedAsync(
        string selector,
        TokenStatus fromStatus,
        long rotatedAt,
        string replacedBySelector,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ArgumentNullException.ThrowIfNull(selector);
        ArgumentNullException.ThrowIfNull(replacedBySelector);

        while (true)
        {
            if (!_rows.TryGetValue(selector, out var current)) return Task.FromResult(false);
            if (current.Status != fromStatus) return Task.FromResult(false);

            if (_rows.TryUpdate(selector, current.AsRotated(rotatedAt, replacedBySelector), current))
            {
                return Task.FromResult(true);
            }
            // Another writer swapped the row first: re-read and re-evaluate the guard.
        }
    }

    /// <inheritdoc />
    public Task<bool> RevokeIfActiveAsync(string selector, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ArgumentNullException.ThrowIfNull(selector);

        while (true)
        {
            if (!_rows.TryGetValue(selector, out var current)) return Task.FromResult(false);
            if (current.Status != TokenStatus.Active) return Task.FromResult(false);
            if (_rows.TryUpdate(selector, current.AsRevoked(), current)) return Task.FromResult(true);
        }
    }

    public Task<int> RevokeFamilyAsync(string familyId, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ArgumentNullException.ThrowIfNull(familyId);
        return Task.FromResult(RevokeWhere(r => string.Equals(r.FamilyId, familyId, StringComparison.Ordinal)));
    }

    public Task<int> RevokeUserAsync(string userId, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ArgumentNullException.ThrowIfNull(userId);
        return Task.FromResult(RevokeWhere(r => string.Equals(r.UserId, userId, StringComparison.Ordinal)));
    }

    /// <summary>Test helper: every record currently stored. Not part of the store contract.</summary>
    public IReadOnlyList<TokenRecord> All() => _rows.Values.ToList();

    /// <summary>
    /// Test helper: drop records whose family deadline has passed. Records MUST be kept,
    /// status and <c>replacedBySelector</c> intact, until <c>familyExpiresAt</c> — an
    /// early sweep of rotated rows silently converts every replay from REUSE_DETECTED
    /// into NOT_FOUND ([N-15]).
    /// </summary>
    public int DeleteExpired(long now)
    {
        var removed = 0;
        foreach (var (selector, record) in _rows)
        {
            if (now >= record.FamilyExpiresAt && _rows.TryRemove(selector, out _)) removed++;
        }
        return removed;
    }

    /// <summary>Revoke every matching row that is not already revoked, counting the writes ([N-19]).</summary>
    private int RevokeWhere(Func<TokenRecord, bool> matches)
    {
        var changed = 0;
        foreach (var selector in _rows.Keys)
        {
            while (true)
            {
                if (!_rows.TryGetValue(selector, out var current)) break;
                if (!matches(current) || current.Status == TokenStatus.Revoked) break;
                if (_rows.TryUpdate(selector, current.AsRevoked(), current))
                {
                    changed++;
                    break;
                }
            }
        }
        return changed;
    }
}
