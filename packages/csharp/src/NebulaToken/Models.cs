namespace NebulaToken;

/// <summary>Record status (§3).</summary>
public enum TokenStatus
{
    Active,
    Rotated,
    Revoked,
}

/// <summary>
/// Protocol outcomes ([N-38]). Names map 1:1 to the spec strings modulo C# casing;
/// <see cref="ErrorCodeExtensions.ToSpecName"/> yields the canonical spec spelling.
/// </summary>
/// <remarks>
/// <para>
/// <b>Extensibility policy ([N-40]).</b> C# has no <c>non_exhaustive</c>, so this is
/// the documented equivalent: a future minor version MAY add a member to this enum,
/// and that addition is not a breaking change. Consumers MUST NOT assume a
/// <c>switch</c> over it is exhaustive — always include a default arm and treat an
/// unrecognised code as a refusal.
/// </para>
/// </remarks>
public enum ErrorCode
{
    /// <summary>The presented string is not a NEBULA token (§2).</summary>
    Malformed,

    /// <summary>No pepper is configured for the required key identifier.</summary>
    UnknownKid,

    /// <summary>No record exists for the selector.</summary>
    NotFound,

    /// <summary>The proof of possession failed.</summary>
    VerifierMismatch,

    /// <summary>A rotated token was replayed. The family has been revoked.</summary>
    ReuseDetected,

    /// <summary>The record was revoked.</summary>
    Revoked,

    /// <summary>The family passed its fixed deadline. The family has been revoked.</summary>
    ExpiredAbsolute,

    /// <summary>The sliding deadline passed. The family has been revoked.</summary>
    ExpiredIdle,

    /// <summary>Sender binding failed. The family has been revoked.</summary>
    DeviceMismatch,

    /// <summary>
    /// A concurrent refresh won the compare-and-set. Nothing was rotated.
    /// Retryable exactly once; the retry meets the ordinary reuse path ([N-35]).
    /// </summary>
    Conflict,
}

/// <summary>Canonical spec spellings of <see cref="ErrorCode"/> ([N-38]).</summary>
public static class ErrorCodeExtensions
{
    /// <summary>
    /// The spec name of a code — the form to log and to compare against the
    /// conformance vectors, e.g. <c>REUSE_DETECTED</c>.
    /// </summary>
    public static string ToSpecName(this ErrorCode code) => code switch
    {
        ErrorCode.Malformed => "MALFORMED",
        ErrorCode.UnknownKid => "UNKNOWN_KID",
        ErrorCode.NotFound => "NOT_FOUND",
        ErrorCode.VerifierMismatch => "VERIFIER_MISMATCH",
        ErrorCode.ReuseDetected => "REUSE_DETECTED",
        ErrorCode.Revoked => "REVOKED",
        ErrorCode.ExpiredAbsolute => "EXPIRED_ABSOLUTE",
        ErrorCode.ExpiredIdle => "EXPIRED_IDLE",
        ErrorCode.DeviceMismatch => "DEVICE_MISMATCH",
        ErrorCode.Conflict => "CONFLICT",
        // [N-40]: a code added by a future minor version reaches here. It is still
        // a refusal, so name it rather than throwing.
        _ => "UNRECOGNISED",
    };
}

/// <summary>
/// Server-side record — one row per issued token ([N-10]).
/// </summary>
/// <remarks>
/// Immutable: the mutating operations of §4 are compare-and-set writes, and a store
/// that swaps a whole record for a modified copy can implement them atomically
/// (see <see cref="MemoryRefreshTokenStore"/>) where one that edits fields in place
/// cannot. Reference equality is deliberately left in place — value equality would
/// let a concurrent, coincidentally-identical row satisfy a compare-and-set.
/// </remarks>
public sealed class TokenRecord
{
    /// <summary>Primary key. The only token-derived value that may be indexed ([N-45]).</summary>
    public required string Selector { get; init; }

    /// <summary>Lowercase hex of HMAC-SHA-256(pepper[<see cref="Kid"/>], verifier bytes).</summary>
    public required string VerifierHash { get; init; }

    /// <summary>Pepper id used for <see cref="VerifierHash"/> <b>and</b> <see cref="DeviceIdHash"/>.</summary>
    public required string Kid { get; init; }

    /// <summary>Lowercase hex of 16 CSPRNG bytes, fixed at login, shared across rotations.</summary>
    public required string FamilyId { get; init; }

    /// <summary>0 at issue, +1 per rotation.</summary>
    public required int Generation { get; init; }

    public required string UserId { get; init; }

    /// <summary>
    /// Lowercase hex of HMAC-SHA-256(pepper[<see cref="Kid"/>], "device:" ‖ deviceId),
    /// or <see langword="null"/> when unbound.
    /// </summary>
    public required string? DeviceIdHash { get; init; }

    /// <summary>Unix seconds ([N-2]).</summary>
    public required long CreatedAt { get; init; }

    /// <summary>Unix seconds ([N-2]). Absolute deadline, fixed at login, never extended.</summary>
    public required long FamilyExpiresAt { get; init; }

    /// <summary>Unix seconds ([N-2]). <c>min(now + idleTtl, familyExpiresAt)</c>.</summary>
    public required long IdleExpiresAt { get; init; }

    public TokenStatus Status { get; init; } = TokenStatus.Active;

    /// <summary>
    /// Set on first rotation. A grace retry MUST keep the original value, which is
    /// what stops the window from being walked forward ([N-30]).
    /// </summary>
    public long? RotatedAt { get; init; }

    public string? ReplacedBySelector { get; init; }

    /// <summary>The same record in the <c>rotated</c> state.</summary>
    public TokenRecord AsRotated(long rotatedAt, string replacedBySelector) =>
        Copy(TokenStatus.Rotated, rotatedAt, replacedBySelector);

    /// <summary>
    /// The same record in the <c>revoked</c> state, keeping <see cref="RotatedAt"/>
    /// and <see cref="ReplacedBySelector"/> — reuse detection reads them, and [N-15]
    /// requires them intact until <see cref="FamilyExpiresAt"/>.
    /// </summary>
    public TokenRecord AsRevoked() => Copy(TokenStatus.Revoked, RotatedAt, ReplacedBySelector);

    private TokenRecord Copy(TokenStatus status, long? rotatedAt, string? replacedBySelector) => new()
    {
        Selector = Selector,
        VerifierHash = VerifierHash,
        Kid = Kid,
        FamilyId = FamilyId,
        Generation = Generation,
        UserId = UserId,
        DeviceIdHash = DeviceIdHash,
        CreatedAt = CreatedAt,
        FamilyExpiresAt = FamilyExpiresAt,
        IdleExpiresAt = IdleExpiresAt,
        Status = status,
        RotatedAt = rotatedAt,
        ReplacedBySelector = replacedBySelector,
    };
}

/// <summary>
/// Storage contract ([N-16]) — exactly six capabilities. Implement over PostgreSQL,
/// SQL Server, Redis, EF Core, … ; see <c>examples/AdoNetRefreshTokenStore.cs</c>.
/// </summary>
/// <remarks>
/// <para>
/// <b>Asynchronous by contract.</b> [N-16] requires the synchrony of the interface to
/// follow the idiom of the ecosystem. Every real ADO.NET or EF Core store is async, and
/// a blocking contract would force <c>GetAwaiter().GetResult()</c> inside each one —
/// which deadlocks or starves the thread pool under ASP.NET load. The semantics below
/// are unchanged from the specification.
/// </para>
/// <para>
/// <b>Two failure channels ([N-20]).</b> Protocol outcomes are the return values below.
/// Infrastructure failures — store unreachable, timeout, constraint violation — MUST
/// fault the returned task, MUST NOT be converted into a protocol outcome, and MUST NOT
/// be swallowed. A faulted task propagates out of the engine, so the caller always fails
/// closed: never a token for state that was not written, never a revocation that did
/// not happen.
/// </para>
/// </remarks>
public interface IRefreshTokenStore
{
    /// <summary>The record for a selector, or <see langword="null"/>.</summary>
    Task<TokenRecord?> FindBySelectorAsync(string selector, CancellationToken cancellationToken = default);

    /// <summary>Persist a newly minted record.</summary>
    Task InsertAsync(TokenRecord record, CancellationToken cancellationToken = default);

    /// <summary>
    /// Compare-and-set ([N-17]). Apply the rotation write <b>if and only if</b> the
    /// stored record's status is still <paramref name="fromStatus"/>, and report
    /// whether it was applied.
    /// </summary>
    /// <remarks>
    /// SQL: <c>UPDATE … SET status='rotated', rotated_at=@r, replaced_by_selector=@n
    /// WHERE selector=@s AND status=@f</c> → affected rows == 1.
    /// Returning <see langword="true"/> unconditionally is non-conforming: it re-opens
    /// the race in which two concurrent refreshes both mint a successor and fork the
    /// family into two independently valid lineages.
    /// </remarks>
    Task<bool> MarkRotatedAsync(
        string selector,
        TokenStatus fromStatus,
        long rotatedAt,
        string replacedBySelector,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Compare-and-set ([N-18]): set <c>revoked</c> if and only if the current status
    /// is <c>active</c>, and report whether it did.
    /// </summary>
    Task<bool> RevokeIfActiveAsync(string selector, CancellationToken cancellationToken = default);

    /// <summary>Revoke every record of the family. Returns how many changed ([N-19]). Idempotent.</summary>
    Task<int> RevokeFamilyAsync(string familyId, CancellationToken cancellationToken = default);

    /// <summary>Revoke every record of the user. Returns how many changed ([N-19]). Idempotent.</summary>
    Task<int> RevokeUserAsync(string userId, CancellationToken cancellationToken = default);
}

/// <summary>Result of <see cref="NebulaEngine.IssueAsync"/> (§6.1). Timestamps are unix seconds ([N-2]).</summary>
public sealed record IssueResult(
    string Token,
    string UserId,
    string FamilyId,
    int Generation,
    long ExpiresAt,
    long IdleExpiresAt)
{
    /// <summary>
    /// [N-14]: the compiler-generated record <c>ToString</c> prints every member, so
    /// <c>logger.LogInformation("{Result}", issued)</c> would put the raw verifier —
    /// the whole secret — into the log. Redacting here is the only place that can
    /// stop it, because the caller never opts in.
    /// </summary>
    public override string ToString() =>
        $"IssueResult {{ Token = <redacted>, UserId = {UserId}, FamilyId = {FamilyId}, " +
        $"Generation = {Generation}, ExpiresAt = {ExpiresAt}, IdleExpiresAt = {IdleExpiresAt} }}";
}

/// <summary>
/// Outcome of <see cref="NebulaEngine.RefreshAsync"/> (§6.2). Errors are returned as
/// values, never thrown ([N-29]).
/// </summary>
/// <remarks>
/// <see cref="UserId"/> and <see cref="FamilyId"/> are populated on failure whenever the
/// engine resolved a record — every code except <see cref="ErrorCode.Malformed"/>,
/// <see cref="ErrorCode.UnknownKid"/> and <see cref="ErrorCode.NotFound"/> — so a
/// REUSE_DETECTED or DEVICE_MISMATCH event can be attributed to a session without a
/// second lookup of a token you were told never to log ([N-39]).
/// </remarks>
public sealed record RefreshResult(
    bool Ok,
    string? Token,
    string? UserId,
    string? FamilyId,
    int Generation,
    long ExpiresAt,
    long IdleExpiresAt,
    ErrorCode? Error)
{
    /// <summary>Redacted for the same reason as <see cref="IssueResult.ToString"/> ([N-14]).</summary>
    public override string ToString() => Ok
        ? $"RefreshResult {{ Ok = true, Token = <redacted>, UserId = {UserId}, FamilyId = {FamilyId}, " +
          $"Generation = {Generation}, ExpiresAt = {ExpiresAt}, IdleExpiresAt = {IdleExpiresAt} }}"
        : $"RefreshResult {{ Ok = false, Error = {Error?.ToSpecName()}, UserId = {UserId}, FamilyId = {FamilyId} }}";

    internal static RefreshResult Success(string token, TokenRecord successor) =>
        new(true, token, successor.UserId, successor.FamilyId, successor.Generation,
            successor.FamilyExpiresAt, successor.IdleExpiresAt, null);

    /// <summary>Failure before any record was resolved: nothing to attribute ([N-39]).</summary>
    internal static RefreshResult Failure(ErrorCode error) =>
        new(false, null, null, null, 0, 0, 0, error);

    /// <summary>Failure with the affected record attributed ([N-39]).</summary>
    internal static RefreshResult Failure(ErrorCode error, TokenRecord record) =>
        new(false, null, record.UserId, record.FamilyId, 0, 0, 0, error);
}

/// <summary>Outcome of <see cref="NebulaEngine.RevokeTokenAsync"/> (§6.5).</summary>
/// <remarks>
/// <see cref="UserId"/> and <see cref="FamilyId"/> are populated on failure whenever the
/// engine resolved a record, exactly as in <see cref="RefreshResult"/> — [N-39] governs
/// every operation that returns a failure, not <see cref="NebulaEngine.RefreshAsync"/>
/// alone. <see cref="NebulaEngine.RevokeTokenAsync"/> resolves its record before it
/// proves the verifier, so a VERIFIER_MISMATCH there is attributable and carries both;
/// MALFORMED, UNKNOWN_KID and NOT_FOUND never do.
/// </remarks>
public sealed record RevokeResult(
    bool Ok,
    string? UserId,
    string? FamilyId,
    int Revoked,
    ErrorCode? Error)
{
    internal static RevokeResult Success(TokenRecord record, int revoked) =>
        new(true, record.UserId, record.FamilyId, revoked, null);

    /// <summary>Failure before any record was resolved: nothing to attribute ([N-39]).</summary>
    internal static RevokeResult Failure(ErrorCode error) => new(false, null, null, 0, error);

    /// <summary>Failure with the affected record attributed ([N-39]).</summary>
    internal static RevokeResult Failure(ErrorCode error, TokenRecord record) =>
        new(false, record.UserId, record.FamilyId, 0, error);
}

/// <summary>
/// Caller mistakes: an invalid engine configuration (§5) or a device identifier that
/// is not valid Unicode supplied by the application ([N-12]).
/// </summary>
/// <remarks>
/// Derives from <see cref="ArgumentException"/> so existing argument-validation
/// handlers keep working. This is the native error channel of [N-20], deliberately
/// distinct from the protocol outcomes of [N-29]. Messages never contain a pepper,
/// a verifier or a raw device identifier ([N-14]).
/// </remarks>
public sealed class NebulaConfigException : ArgumentException
{
    public NebulaConfigException(string message) : base($"[NEBULA] {message}") { }

    public NebulaConfigException(string message, Exception innerException)
        : base($"[NEBULA] {message}", innerException) { }
}
