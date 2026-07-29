using System.Security.Cryptography;
using System.Text;

namespace NebulaToken;

/// <summary>
/// NEBULA engine — SPECIFICATION.md §5–§6.
/// </summary>
/// <remarks>
/// Thread-safe and stateless beyond its configuration: all mutable state lives in the
/// <see cref="IRefreshTokenStore"/>. One instance per process is the expected usage.
/// </remarks>
public sealed class NebulaEngine
{
    /// <summary>Engine configuration (§5). Copied at construction ([N-24]).</summary>
    public sealed class Config
    {
        /// <summary>
        /// Map kid → pepper secret. Each kid matches the <c>kid</c> production of §2;
        /// each secret is at least <see cref="Nebula.MinPepperLength"/> <b>bytes</b>.
        /// A pepper is a key, not a passphrase — generate it with a CSPRNG and hold it
        /// in an environment variable, secret manager or KMS ([N-23]).
        /// </summary>
        public required IReadOnlyDictionary<string, string> Peppers { get; init; }

        /// <summary>kid used for newly minted tokens. MUST exist in <see cref="Peppers"/>.</summary>
        public required string ActiveKid { get; init; }

        public required IRefreshTokenStore Store { get; init; }

        public long AbsoluteTtlSeconds { get; init; } = Nebula.DefaultAbsoluteTtl;

        public long IdleTtlSeconds { get; init; } = Nebula.DefaultIdleTtl;

        /// <summary>See [N-30] for the security trade-off before raising this above 0.</summary>
        public long ReuseGraceSeconds { get; init; } = Nebula.DefaultReuseGrace;

        /// <summary>Injectable clock, unix seconds ([N-3]).</summary>
        public Func<long>? Clock { get; init; }
    }

    private readonly Dictionary<string, string> _peppers;
    private readonly string _activeKid;
    private readonly IRefreshTokenStore _store;
    private readonly long _absoluteTtl;
    private readonly long _idleTtl;
    private readonly long _reuseGrace;
    private readonly Func<long> _clock;

    /// <exception cref="NebulaConfigException">The configuration violates §5.</exception>
    public NebulaEngine(Config config)
    {
        ArgumentNullException.ThrowIfNull(config);
        if (config.Peppers is null) throw new NebulaConfigException("Peppers is required");
        if (config.Store is null) throw new NebulaConfigException("Store is required");

        // [N-24] copy — and StringComparer.Ordinal, because a culture-aware kid lookup
        // could map two distinct kids onto one pepper ([N-9]).
        _peppers = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var (kid, secret) in config.Peppers)
        {
            if (!IsValidKid(kid))
            {
                throw new NebulaConfigException(
                    $"kid \"{kid}\" must be 1-{Nebula.MaxKidLength} characters from [A-Za-z0-9_-]");
            }
            // [N-11]: the HMAC key is the pepper encoded as UTF-8, so a string that has
            // no UTF-8 encoding — an unpaired surrogate, which arrives trivially from a
            // JSON secrets file or a lenient UTF-16 decode — is not a usable key.
            // Encoding.UTF8 would silently substitute U+FFFD here, Java substitutes '?'
            // and Python refuses; three different HMAC keys for the same configured
            // value. §5 resolves it by failing construction everywhere. The message
            // never quotes the secret ([N-14]).
            if (secret is null || !Nebula.IsWellFormedUnicode(secret))
            {
                throw new NebulaConfigException(
                    $"pepper \"{kid}\" must be a string with a UTF-8 encoding (no unpaired surrogate)");
            }
            // [N-1]: bytes of that UTF-8 encoding, not characters. A 16-character CJK
            // passphrase is 48 UTF-8 bytes and passes; a 31-character ASCII one is 31
            // bytes and does not.
            if (Encoding.UTF8.GetByteCount(secret) < Nebula.MinPepperLength)
            {
                // [N-14]: the pepper itself never appears in the message.
                throw new NebulaConfigException(
                    $"pepper \"{kid}\" must be at least {Nebula.MinPepperLength} bytes");
            }
            _peppers[kid] = secret;
        }

        if (config.ActiveKid is null || !_peppers.ContainsKey(config.ActiveKid))
        {
            throw new NebulaConfigException($"ActiveKid \"{config.ActiveKid}\" not present in Peppers");
        }

        if (config.AbsoluteTtlSeconds <= 0)
            throw new NebulaConfigException("AbsoluteTtlSeconds must be positive");
        if (config.IdleTtlSeconds <= 0)
            throw new NebulaConfigException("IdleTtlSeconds must be positive");
        if (config.ReuseGraceSeconds < 0)
            throw new NebulaConfigException("ReuseGraceSeconds must be non-negative");

        _activeKid = config.ActiveKid;
        _store = config.Store;
        _absoluteTtl = config.AbsoluteTtlSeconds;
        _idleTtl = config.IdleTtlSeconds;
        _reuseGrace = config.ReuseGraceSeconds;
        _clock = config.Clock ?? (() => DateTimeOffset.UtcNow.ToUnixTimeSeconds());
    }

    // ── Operations ───────────────────────────────────────────────────────────

    /// <summary>Issue the first token of a new family ([N-25]). Call at login.</summary>
    /// <param name="userId">Owner of the session.</param>
    /// <param name="deviceId">
    /// Sender-binding identifier, or <see langword="null"/> for an unbound family.
    /// <see langword="null"/> and <c>""</c> are distinct: the empty string is a real
    /// binding ([N-25]).
    /// </param>
    /// <param name="cancellationToken">Cancellation for the store write.</param>
    /// <exception cref="NebulaConfigException">
    /// <paramref name="deviceId"/> is not valid Unicode. At issue the value comes from
    /// the application, so the defect surfaces at the call site rather than minting a
    /// binding nothing can ever satisfy ([N-12]).
    /// </exception>
    public async Task<IssueResult> IssueAsync(
        string userId,
        string? deviceId = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(userId);
        if (deviceId is not null && !Nebula.IsWellFormedUnicode(deviceId))
        {
            throw new NebulaConfigException("deviceId is not valid Unicode (unpaired surrogate)");
        }

        var now = _clock();
        var familyId = Nebula.RandomHex(16);
        var familyExpiresAt = now + _absoluteTtl;
        var deviceIdHash = deviceId is null ? null : Nebula.HashDeviceId(ActivePepper, deviceId);

        var (token, record) = Mint(userId, familyId, 0, deviceIdHash, familyExpiresAt, now);

        // [N-25] step 3 / [N-20]: a faulted insert propagates. No token is returned
        // for state that was not written.
        await _store.InsertAsync(record, cancellationToken).ConfigureAwait(false);

        return new IssueResult(token, userId, familyId, 0, familyExpiresAt, record.IdleExpiresAt);
    }

    /// <summary>
    /// Exchange a refresh token for its successor ([N-26]).
    /// </summary>
    /// <remarks>
    /// The check order below is normative and observable ([N-28]): it fixes which error
    /// wins when several conditions hold at once.
    /// </remarks>
    public async Task<RefreshResult> RefreshAsync(
        string? token,
        string? deviceId = null,
        CancellationToken cancellationToken = default)
    {
        // 1. Parse
        var parsed = Nebula.ParseToken(token);
        if (parsed is null) return RefreshResult.Failure(ErrorCode.Malformed);

        // 2. Pepper lookup by the TOKEN's kid
        if (!_peppers.ContainsKey(parsed.Kid)) return RefreshResult.Failure(ErrorCode.UnknownKid);

        // 3. Record lookup — keyed only on the selector ([N-45])
        var record = await _store.FindBySelectorAsync(parsed.Selector, cancellationToken).ConfigureAwait(false);
        if (record is null) return RefreshResult.Failure(ErrorCode.NotFound);

        // 4. Verifier proof against the pepper of the RECORD's kid ([N-27], [N-31])
        if (!_peppers.TryGetValue(record.Kid, out var recordPepper))
        {
            return RefreshResult.Failure(ErrorCode.UnknownKid);
        }
        if (!Nebula.ConstantTimeEqualHex(Nebula.HashVerifier(recordPepper, parsed.Verifier), record.VerifierHash))
        {
            // [N-28] deliberately no family revocation here: knowledge of a selector
            // alone must never be sufficient to destroy a session.
            return RefreshResult.Failure(ErrorCode.VerifierMismatch, record);
        }

        var now = _clock();

        // 5. Reuse
        if (record.Status == TokenStatus.Rotated)
        {
            return await HandleReuseAsync(record, recordPepper, deviceId, now, cancellationToken)
                .ConfigureAwait(false);
        }

        // 6. Revoked
        if (record.Status == TokenStatus.Revoked) return RefreshResult.Failure(ErrorCode.Revoked, record);

        // 7-8. Expiry
        if (now >= record.FamilyExpiresAt)
        {
            await _store.RevokeFamilyAsync(record.FamilyId, cancellationToken).ConfigureAwait(false);
            return RefreshResult.Failure(ErrorCode.ExpiredAbsolute, record);
        }
        if (now >= record.IdleExpiresAt)
        {
            await _store.RevokeFamilyAsync(record.FamilyId, cancellationToken).ConfigureAwait(false);
            return RefreshResult.Failure(ErrorCode.ExpiredIdle, record);
        }

        // 9. Sender binding — pepper of the RECORD's kid ([N-32])
        if (record.DeviceIdHash is not null && !DeviceMatches(record, recordPepper, deviceId))
        {
            await _store.RevokeFamilyAsync(record.FamilyId, cancellationToken).ConfigureAwait(false);
            return RefreshResult.Failure(ErrorCode.DeviceMismatch, record);
        }

        // 10. Rotate
        return await RotateAsync(record, deviceId, now, TokenStatus.Active, now, cancellationToken)
            .ConfigureAwait(false);
    }

    /// <summary>
    /// Revoke the family a token belongs to ([N-36]).
    /// </summary>
    /// <remarks>
    /// Authenticated: the verifier is proved exactly as in <see cref="RefreshAsync"/>,
    /// because §3 designates the selector as a <i>public</i> lookup key — it is safe to
    /// index and to log, and it is recoverable from a database dump. If revocation
    /// accepted a selector alone, anyone who read one could terminate that session, an
    /// unauthenticated denial of service. Administrative paths are served by
    /// <see cref="RevokeFamilyAsync"/> and <see cref="RevokeAllForUserAsync"/> ([N-37]).
    /// Succeeds whatever the record's status, so a client can still log out with a token
    /// that was already rotated or revoked.
    /// <para>
    /// Takes no device identifier and performs no sender-binding check ([N-36] specifies
    /// steps 1-4 of [N-26] and no sender-binding step), because logout must keep working
    /// for a client that can no longer produce its device identifier. The operation is
    /// already authenticated by the verifier proof.
    /// </para>
    /// </remarks>
    public async Task<RevokeResult> RevokeTokenAsync(
        string? token,
        CancellationToken cancellationToken = default)
    {
        var parsed = Nebula.ParseToken(token);
        if (parsed is null) return RevokeResult.Failure(ErrorCode.Malformed);
        if (!_peppers.ContainsKey(parsed.Kid)) return RevokeResult.Failure(ErrorCode.UnknownKid);

        var record = await _store.FindBySelectorAsync(parsed.Selector, cancellationToken).ConfigureAwait(false);
        if (record is null) return RevokeResult.Failure(ErrorCode.NotFound);

        if (!_peppers.TryGetValue(record.Kid, out var recordPepper))
        {
            return RevokeResult.Failure(ErrorCode.UnknownKid);
        }
        if (!Nebula.ConstantTimeEqualHex(Nebula.HashVerifier(recordPepper, parsed.Verifier), record.VerifierHash))
        {
            // [N-39]: the record was resolved above, so this refusal is attributable.
            // An unauthenticated attempt to terminate somebody's session is exactly the
            // event an operator needs to see, and the selector alone will not identify
            // the victim.
            return RevokeResult.Failure(ErrorCode.VerifierMismatch, record);
        }

        // No sender-binding step ([N-36]): revocation takes no device identifier.
        var revoked = await _store.RevokeFamilyAsync(record.FamilyId, cancellationToken).ConfigureAwait(false);
        return RevokeResult.Success(record, revoked);
    }

    /// <summary>
    /// Revoke a whole family by its server-side identifier ([N-37]). Requires no token;
    /// the caller is responsible for authorising it. Idempotent.
    /// </summary>
    /// <returns>The number of records revoked.</returns>
    public Task<int> RevokeFamilyAsync(string familyId, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(familyId);
        return _store.RevokeFamilyAsync(familyId, cancellationToken);
    }

    /// <summary>
    /// Revoke every session of a user ([N-37]) — password change, "log out all devices",
    /// compromise response. Idempotent.
    /// </summary>
    /// <returns>The number of records revoked.</returns>
    public Task<int> RevokeAllForUserAsync(string userId, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(userId);
        return _store.RevokeUserAsync(userId, cancellationToken);
    }

    // ── Private ──────────────────────────────────────────────────────────────

    private async Task<RefreshResult> HandleReuseAsync(
        TokenRecord record,
        string recordPepper,
        string? deviceId,
        long now,
        CancellationToken cancellationToken)
    {
        // [N-30] preconditions 1-4 and 6. Precondition 5 needs a store read and is
        // checked immediately below. Condition 6 (now < familyExpiresAt) is what stops
        // a grace retry from minting a token past the family's absolute deadline.
        var withinGrace = _reuseGrace > 0
            && record.RotatedAt is not null
            && now - record.RotatedAt.Value <= _reuseGrace
            && record.ReplacedBySelector is not null
            && now < record.FamilyExpiresAt;

        if (withinGrace)
        {
            var successor = await _store
                .FindBySelectorAsync(record.ReplacedBySelector!, cancellationToken)
                .ConfigureAwait(false);

            if (successor is { Status: TokenStatus.Active })
            {
                // Sender binding first ([N-30] step 1).
                if (record.DeviceIdHash is not null && !DeviceMatches(record, recordPepper, deviceId))
                {
                    await _store.RevokeFamilyAsync(record.FamilyId, cancellationToken).ConfigureAwait(false);
                    return RefreshResult.Failure(ErrorCode.DeviceMismatch, record);
                }

                // Compare-and-set: exactly one concurrent retry may consume the unused
                // successor. The loser rotates nothing and reports CONFLICT ([N-30] step 2).
                if (!await _store.RevokeIfActiveAsync(successor.Selector, cancellationToken).ConfigureAwait(false))
                {
                    return RefreshResult.Failure(ErrorCode.Conflict, record);
                }

                // Preserve the original rotatedAt: the window is anchored to the first
                // rotation and cannot be walked forward by repeated retries ([N-30]).
                return await RotateAsync(
                        record, deviceId, now, TokenStatus.Rotated, record.RotatedAt!.Value, cancellationToken)
                    .ConfigureAwait(false);
            }
        }

        // Otherwise the presentation is a theft signal.
        await _store.RevokeFamilyAsync(record.FamilyId, cancellationToken).ConfigureAwait(false);
        return RefreshResult.Failure(ErrorCode.ReuseDetected, record);
    }

    private async Task<RefreshResult> RotateAsync(
        TokenRecord record,
        string? deviceId,
        long now,
        TokenStatus fromStatus,
        long rotatedAt,
        CancellationToken cancellationToken)
    {
        // Re-hash with the ACTIVE pepper — this is what migrates a device binding
        // forward across a pepper rotation ([N-33] step 4). Unreachable with an
        // invalid-Unicode deviceId: a bound record has already failed the binding
        // check above, and an unbound one keeps its null hash.
        var deviceIdHash = record.DeviceIdHash is not null && deviceId is not null
            ? Nebula.HashDeviceId(ActivePepper, deviceId)
            : record.DeviceIdHash;

        var (token, successor) = Mint(
            record.UserId, record.FamilyId, record.Generation + 1, deviceIdHash, record.FamilyExpiresAt, now);

        await _store.InsertAsync(successor, cancellationToken).ConfigureAwait(false);

        var applied = await _store
            .MarkRotatedAsync(record.Selector, fromStatus, rotatedAt, successor.Selector, cancellationToken)
            .ConfigureAwait(false);

        if (!applied)
        {
            // [N-34] step 5: a concurrent refresh won the compare-and-set. Clean up the
            // orphan successor we just inserted and report a retryable conflict — never
            // a token. Without this the family forks into two live lineages, which is
            // the ordinary behaviour of two browser tabs refreshing together.
            await _store.RevokeIfActiveAsync(successor.Selector, cancellationToken).ConfigureAwait(false);
            return RefreshResult.Failure(ErrorCode.Conflict, record);
        }

        return RefreshResult.Success(token, successor);
    }

    /// <summary>Mint a token and its record ([N-33]).</summary>
    private (string Token, TokenRecord Record) Mint(
        string userId,
        string familyId,
        int generation,
        string? deviceIdHash,
        long familyExpiresAt,
        long now)
    {
        // [N-43] platform CSPRNG. RandomNumberGenerator throws rather than degrading to
        // a weaker source, which is the propagation [N-43] requires.
        var selectorBytes = RandomNumberGenerator.GetBytes(Nebula.SelectorBytes);
        var verifier = RandomNumberGenerator.GetBytes(Nebula.VerifierBytes);
        var selector = Nebula.Base64UrlEncode(selectorBytes);

        var record = new TokenRecord
        {
            Selector = selector,
            VerifierHash = Nebula.HashVerifier(ActivePepper, verifier),
            Kid = _activeKid,
            FamilyId = familyId,
            Generation = generation,
            UserId = userId,
            DeviceIdHash = deviceIdHash,
            CreatedAt = now,
            FamilyExpiresAt = familyExpiresAt,
            IdleExpiresAt = Math.Min(now + _idleTtl, familyExpiresAt),
        };

        var token = $"{Nebula.Prefix}.{_activeKid}.{selector}.{Nebula.Base64UrlEncode(verifier)}";
        return (token, record);
    }

    /// <summary>Sender binding ([N-32]) against the record's own pepper.</summary>
    private static bool DeviceMatches(TokenRecord record, string recordPepper, string? deviceId)
    {
        // A missing device identifier where the record is bound must fail ([N-32]).
        if (deviceId is null || record.DeviceIdHash is null) return false;

        // [N-12]: on the attacker-reachable path an invalid device identifier is a
        // binding failure, never an exception.
        if (!Nebula.IsWellFormedUnicode(deviceId)) return false;

        return Nebula.ConstantTimeEqualHex(Nebula.HashDeviceId(recordPepper, deviceId), record.DeviceIdHash);
    }

    private static bool IsValidKid(string? kid)
    {
        if (string.IsNullOrEmpty(kid) || kid.Length > Nebula.MaxKidLength) return false;
        foreach (var c in kid)
        {
            var ok = (c >= 'A' && c <= 'Z')
                  || (c >= 'a' && c <= 'z')
                  || (c >= '0' && c <= '9')
                  || c == '-' || c == '_';
            if (!ok) return false;
        }
        // ASCII by the check above, so character count == UTF-8 byte count ([N-1]).
        return true;
    }

    private string ActivePepper => _peppers[_activeKid];
}
