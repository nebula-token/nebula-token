using System.Diagnostics.CodeAnalysis;
using System.Text.Json;
using System.Text.Json.Serialization;
using Xunit;
using Xunit.Abstractions;
using Xunit.Sdk;

namespace NebulaToken.Tests;

/// <summary>
/// Runner for the normative behavioral suite, <c>spec/behavior-vectors.json</c>
/// ([N-47], [N-49]).
/// </summary>
/// <remarks>
/// The scenarios are data. Only this runner is language-specific, which is what stops
/// the ten ports from drifting apart the way ten hand-written suites did. Nothing
/// behavioural belongs here: if a case is missing, it belongs in the vectors.
/// </remarks>
public class BehaviorVectorsTests
{
    private static readonly BehaviorVectors Vectors = LoadVectors();

    /// <summary>
    /// Conditions this runtime satisfies. A .NET <c>string</c> is a sequence of UTF-16
    /// code units and can hold an unpaired surrogate, so the invalid-Unicode scenario
    /// applies here and is executed rather than skipped.
    /// </summary>
    private static readonly HashSet<string> SatisfiedConditions =
        new(StringComparer.Ordinal) { "runtime-admits-invalid-unicode-strings" };

    /// <summary>32 zero bytes, canonically encoded: well-formed, and never the real secret.</summary>
    private static readonly string ForgedVerifier = new('A', Nebula.VerifierChars);

    /// <summary>A well-formed selector that is never stored.</summary>
    private static readonly string ForgedSelector = new('A', Nebula.SelectorChars);

    private readonly ITestOutputHelper _output;

    public BehaviorVectorsTests(ITestOutputHelper output) => _output = output;

    public static TheoryData<string> ApplicableScenarios()
    {
        var data = new TheoryData<string>();
        foreach (var scenario in Vectors.Scenarios.Where(Applies)) data.Add(scenario.Id);
        return data;
    }

    [Theory]
    [MemberData(nameof(ApplicableScenarios))]
    public Task BehaviorScenario(string id) =>
        RunScenarioAsync(Vectors.Scenarios.Single(s => s.Id == id));

    /// <summary>
    /// [N-48]/[N-49]: the suite must be executed in full. Every unconditional scenario
    /// runs; a conditional one may be skipped only where this runtime does not satisfy
    /// its condition, and is then reported by id.
    /// </summary>
    /// <remarks>
    /// The count is taken from <see cref="ApplicableScenarios"/> — the member data xUnit
    /// actually feeds the theory — and never recomputed from the vector file. [N-48] is
    /// about the number of cases <i>executed</i>, so an assertion derived from the file
    /// alone proves only that the file is self-consistent: it stays green while the data
    /// source quietly yields a subset, which is precisely the failure the requirement
    /// exists to catch.
    /// </remarks>
    [Fact]
    public void ExecutesEveryPublishedScenario()
    {
        Assert.Equal(Nebula.SpecVersion, Vectors.SpecVersion);
        Assert.NotEmpty(Vectors.Scenarios);
        Assert.Equal(Vectors.Counts.Scenarios, Vectors.Scenarios.Count);

        var skipped = Vectors.Scenarios.Where(s => !Applies(s)).ToList();
        foreach (var scenario in skipped)
        {
            _output.WriteLine(
                $"skipped {scenario.Id}: condition \"{scenario.Condition}\" not satisfied by this runtime");
            // Only a conditional scenario may ever be skipped.
            Assert.False(string.IsNullOrEmpty(scenario.Condition));
        }

        var fed = ApplicableScenarios().Select(row => (string)row[0]!).ToList();

        _output.WriteLine($"executed {fed.Count} scenario(s), skipped {skipped.Count}");
        Assert.Equal(Vectors.Counts.Scenarios, fed.Count + skipped.Count);
        Assert.True(
            fed.Count >= Vectors.Counts.Unconditional,
            $"the theory is fed {fed.Count} scenarios, but {Vectors.Counts.Unconditional} are unconditional");

        // Ids, not just a count: a data source that substituted one scenario for another
        // would keep the count intact.
        Assert.Equal(
            Vectors.Scenarios.Where(Applies).Select(s => s.Id).OrderBy(id => id, StringComparer.Ordinal),
            fed.OrderBy(id => id, StringComparer.Ordinal));
        Assert.Equal(fed.Count, fed.Distinct(StringComparer.Ordinal).Count());
    }

    private static bool Applies(Scenario scenario) =>
        scenario.Condition is null || SatisfiedConditions.Contains(scenario.Condition);

    // ── Execution ────────────────────────────────────────────────────────────

    // csharpsquid:S3776 measures cognitive complexity 100 against a threshold of
    // 15, and the measurement is right. The switch below is an interpreter for
    // the step vocabulary published in spec/behavior-vectors.json under
    // `runner.ops`: one case per entry, in the same order, so a reviewer can
    // read the runner and the vector format side by side. That correspondence is
    // what makes a conformance runner auditable, and a dispatch over a published
    // op vocabulary is branchy by construction.
    //
    // Per-op methods were considered and rejected: the ops share one mutable
    // scenario state (engine, store, bindings, issuedSecrets, issuedTokens,
    // deviceIds, now), "reconfigure" reassigns `engine` and "advance" reassigns
    // `now` — neither of which an extracted static method can do without a
    // context object threaded through all ten. The parts that lift cleanly
    // already are: Build, ResolveToken, DeviceOf, CheckSuccess, Merge.
    [SuppressMessage(
        "Major Code Smell",
        "S3776:Cognitive Complexity of methods should not be too high",
        Justification =
            "Dispatch over the published behavior-vector op vocabulary; the one-to-one "
            + "correspondence with spec/behavior-vectors.json is the auditable property. "
            + "See sonar-project.properties.")]
    private static async Task RunScenarioAsync(Scenario scenario)
    {
        var cfg = Merge(Vectors.Defaults, scenario.Config);
        var store = new ControllableStore();
        var bindings = new Dictionary<string, Binding>(StringComparer.Ordinal);
        var issuedSecrets = new List<string>();
        var issuedTokens = new List<string>();
        var deviceIds = new HashSet<string>(StringComparer.Ordinal);
        var now = cfg.Now!.Value;

        NebulaEngine Build(IEnumerable<string> kids, string activeKid) => new(new NebulaEngine.Config
        {
            Peppers = kids.ToDictionary(k => k, k => Vectors.Peppers[k], StringComparer.Ordinal),
            ActiveKid = activeKid,
            Store = store,
            AbsoluteTtlSeconds = cfg.AbsoluteTtlSeconds!.Value,
            IdleTtlSeconds = cfg.IdleTtlSeconds!.Value,
            ReuseGraceSeconds = cfg.ReuseGraceSeconds!.Value,
            Clock = () => now,
        });

        var engine = Build(cfg.Peppers!, cfg.ActiveKid!);

        for (var i = 0; i < scenario.Steps.Count; i++)
        {
            var step = scenario.Steps[i];
            var expect = step.Expect;

            switch (step.Op)
            {
                case "issue":
                {
                    var deviceId = DeviceOf(step);
                    var result = await engine.IssueAsync(step.UserId!, deviceId);
                    if (expect?.Ok == false) throw Fail(scenario, i, "expected issue to fail");

                    CheckSuccess(
                        scenario, i, expect, bindings,
                        result.Token, result.Generation, result.FamilyId,
                        result.ExpiresAt, result.IdleExpiresAt);

                    if (step.Bind is not null)
                    {
                        bindings[step.Bind] = new Binding(result.Token, result.FamilyId, result.ExpiresAt);
                    }
                    issuedTokens.Add(result.Token);
                    issuedSecrets.Add(result.Token.Split('.')[3]);
                    if (!string.IsNullOrEmpty(deviceId)) deviceIds.Add(deviceId);
                    break;
                }

                case "refresh":
                {
                    var result = await engine.RefreshAsync(
                        ResolveToken(scenario, i, step.Token, bindings), DeviceOf(step));

                    if (expect?.Ok == true || (expect?.Ok is null && expect?.Error is null))
                    {
                        if (!result.Ok)
                        {
                            throw Fail(scenario, i, $"expected success, got {result.Error?.ToSpecName()}");
                        }
                        CheckSuccess(
                            scenario, i, expect, bindings,
                            result.Token!, result.Generation, result.FamilyId!,
                            result.ExpiresAt, result.IdleExpiresAt);

                        if (step.Bind is not null)
                        {
                            bindings[step.Bind] = new Binding(result.Token!, result.FamilyId!, result.ExpiresAt);
                        }
                        issuedTokens.Add(result.Token!);
                        issuedSecrets.Add(result.Token!.Split('.')[3]);
                    }
                    else
                    {
                        if (result.Ok) throw Fail(scenario, i, $"expected {expect?.Error}, got success");
                        if (result.Error?.ToSpecName() != expect?.Error)
                        {
                            throw Fail(scenario, i,
                                $"expected {expect?.Error}, got {result.Error?.ToSpecName()}");
                        }
                        CheckAttribution(scenario, i, expect, result.UserId, result.FamilyId);
                    }
                    break;
                }

                case "revokeToken":
                {
                    var result = await engine.RevokeTokenAsync(
                        ResolveToken(scenario, i, step.Token, bindings));

                    if (expect?.Ok == false)
                    {
                        if (result.Ok) throw Fail(scenario, i, $"expected {expect.Error}, got success");
                        if (result.Error?.ToSpecName() != expect.Error)
                        {
                            throw Fail(scenario, i,
                                $"expected {expect.Error}, got {result.Error?.ToSpecName()}");
                        }
                        // [N-39] governs every failure result, RevokeTokenAsync's included.
                        CheckAttribution(scenario, i, expect, result.UserId, result.FamilyId);
                    }
                    else
                    {
                        if (!result.Ok)
                        {
                            throw Fail(scenario, i, $"expected success, got {result.Error?.ToSpecName()}");
                        }
                        if (expect?.Revoked is not null && result.Revoked != expect.Revoked)
                        {
                            throw Fail(scenario, i, $"expected {expect.Revoked} revoked, got {result.Revoked}");
                        }
                    }
                    break;
                }

                case "revokeFamilyOf":
                {
                    var revoked = await engine.RevokeFamilyAsync(bindings[step.Of!].FamilyId);
                    if (expect?.Revoked is not null && revoked != expect.Revoked)
                    {
                        throw Fail(scenario, i, $"expected {expect.Revoked} revoked, got {revoked}");
                    }
                    break;
                }

                case "revokeUser":
                {
                    var revoked = await engine.RevokeAllForUserAsync(step.UserId!);
                    if (expect?.Revoked is not null && revoked != expect.Revoked)
                    {
                        throw Fail(scenario, i, $"expected {expect.Revoked} revoked, got {revoked}");
                    }
                    break;
                }

                case "advance":
                    now += step.Seconds!.Value;
                    break;

                case "reconfigure":
                    // A new engine over the SAME store: a pepper rotation is a
                    // configuration change, never a data migration.
                    engine = Build(step.Peppers!, step.ActiveKid!);
                    break;

                case "failNextCas":
                    store.FailNextCas(step.Method!);
                    break;

                case "expectStatusCounts":
                {
                    var actual = new Dictionary<string, int>(StringComparer.Ordinal)
                    {
                        ["active"] = 0,
                        ["rotated"] = 0,
                        ["revoked"] = 0,
                    };
                    foreach (var record in store.Inner.All())
                    {
                        actual[record.Status.ToString().ToLowerInvariant()]++;
                    }
                    foreach (var (status, want) in step.Counts!)
                    {
                        if (actual[status] != want)
                        {
                            throw Fail(scenario, i,
                                $"expected {want} {status}, got {actual[status]} (active={actual["active"]}, " +
                                $"rotated={actual["rotated"]}, revoked={actual["revoked"]})");
                        }
                    }
                    break;
                }

                case "expectNoRawSecrets":
                {
                    var dump = JsonSerializer.Serialize(store.Inner.All());
                    foreach (var secret in issuedSecrets)
                    {
                        if (dump.Contains(secret, StringComparison.Ordinal))
                        {
                            throw Fail(scenario, i, "a raw verifier reached the store ([N-14])");
                        }
                    }
                    foreach (var token in issuedTokens)
                    {
                        if (dump.Contains(token, StringComparison.Ordinal))
                        {
                            throw Fail(scenario, i, "a whole token reached the store ([N-14])");
                        }
                    }
                    foreach (var deviceId in deviceIds)
                    {
                        if (dump.Contains(deviceId, StringComparison.Ordinal))
                        {
                            throw Fail(scenario, i, "a raw device identifier reached the store ([N-14])");
                        }
                    }
                    break;
                }

                default:
                    throw Fail(scenario, i, $"unknown op \"{step.Op}\"");
            }
        }
    }

    /// <summary>
    /// [N-39] attribution, tri-state. <c>true</c> demands the field, <c>false</c> demands
    /// its absence — the exclusion list (MALFORMED, UNKNOWN_KID, NOT_FOUND) is a
    /// requirement too, and a truthy-only check could never observe it. Absent means the
    /// scenario does not assert it. A .NET result type always carries the properties, so
    /// "absent" reads as <see langword="null"/> — the value the engine leaves when no
    /// record was resolved.
    /// </summary>
    private static void CheckAttribution(
        Scenario scenario, int index, Expect? expect, string? userId, string? familyId)
    {
        if (expect?.HasUserId is { } wantUserId && (userId is not null) != wantUserId)
        {
            throw Fail(scenario, index,
                $"expected userId {(wantUserId ? "present" : "absent")} ([N-39])");
        }
        if (expect?.HasFamilyId is { } wantFamilyId && (familyId is not null) != wantFamilyId)
        {
            throw Fail(scenario, index,
                $"expected familyId {(wantFamilyId ? "present" : "absent")} ([N-39])");
        }
    }

    // Nine parameters (csharpsquid:S107), and every one is a field of the vector
    // step or of the result being checked against it. A carrier type here would
    // be a class whose only job is to be unpacked one line later, and it would
    // hide which vector fields this check actually reads.
    [SuppressMessage(
        "Major Code Smell",
        "S107:Methods should not have too many parameters",
        Justification =
            "Each parameter is a field of the vector step or of the result under test; "
            + "bundling them would hide which fields the check reads. "
            + "See sonar-project.properties.")]
    private static void CheckSuccess(
        Scenario scenario,
        int index,
        Expect? expect,
        IReadOnlyDictionary<string, Binding> bindings,
        string token,
        int generation,
        string familyId,
        long expiresAt,
        long idleExpiresAt)
    {
        if (expect is null) return;

        if (expect.Generation is not null && generation != expect.Generation)
        {
            throw Fail(scenario, index, $"expected generation {expect.Generation}, got {generation}");
        }
        if (expect.Kid is not null)
        {
            var kid = token.Split('.')[1];
            if (kid != expect.Kid) throw Fail(scenario, index, $"expected kid {expect.Kid}, got {kid}");
        }
        if (expect.SameFamilyAs is not null && familyId != bindings[expect.SameFamilyAs].FamilyId)
        {
            throw Fail(scenario, index, "familyId changed across rotation");
        }
        if (expect.SameExpiresAtAs is not null)
        {
            var other = bindings[expect.SameExpiresAtAs].ExpiresAt;
            if (expiresAt != other)
            {
                throw Fail(scenario, index, $"absolute deadline moved: {other} -> {expiresAt}");
            }
        }
        if (expect.IdleEqualsExpires == true && idleExpiresAt != expiresAt)
        {
            throw Fail(scenario, index, $"idleExpiresAt {idleExpiresAt} should be clamped to {expiresAt}");
        }
    }

    private static string? ResolveToken(
        Scenario scenario, int index, TokenRef? tokenRef, IReadOnlyDictionary<string, Binding> bindings)
    {
        if (tokenRef?.Literal is not null) return tokenRef.Literal;
        if (tokenRef?.Ref is null) throw Fail(scenario, index, "step has no token reference");

        if (!bindings.TryGetValue(tokenRef.Ref, out var bound))
        {
            throw Fail(scenario, index, $"unknown binding \"{tokenRef.Ref}\"");
        }
        if (tokenRef.Forge is null) return bound.Token;

        var parts = bound.Token.Split('.');
        switch (tokenRef.Forge)
        {
            case "verifier": parts[3] = ForgedVerifier; break;
            case "unknownKid": parts[1] = "zz"; break;
            case "unknownSelector": parts[2] = ForgedSelector; break;
            default: throw Fail(scenario, index, $"unknown forge \"{tokenRef.Forge}\"");
        }
        return string.Join('.', parts);
    }

    private static string? DeviceOf(Step step) =>
        step.DeviceIdKind == "lone-surrogate" ? ((char)0xD800).ToString() : step.DeviceId;

    private static VectorConfig Merge(VectorConfig defaults, VectorConfig? overrides) => new(
        overrides?.Now ?? defaults.Now,
        overrides?.AbsoluteTtlSeconds ?? defaults.AbsoluteTtlSeconds,
        overrides?.IdleTtlSeconds ?? defaults.IdleTtlSeconds,
        overrides?.ReuseGraceSeconds ?? defaults.ReuseGraceSeconds,
        overrides?.ActiveKid ?? defaults.ActiveKid,
        overrides?.Peppers ?? defaults.Peppers);

    private static XunitException Fail(Scenario scenario, int index, string message) =>
        new($"[{scenario.Id}] step {index} ({string.Join(", ", scenario.Requirements)}): {message}");

    private static BehaviorVectors LoadVectors()
    {
        var options = new JsonSerializerOptions { PropertyNamingPolicy = JsonNamingPolicy.CamelCase };
        return JsonSerializer.Deserialize<BehaviorVectors>(SpecVectors.Read("behavior-vectors.json"), options)
               ?? throw new InvalidOperationException("behavior-vectors.json is empty");
    }

    // ── Store wrapper ────────────────────────────────────────────────────────

    /// <summary>
    /// Wraps the reference store so a scenario can force one compare-and-set to lose.
    /// That is how CONFLICT is provoked deterministically, instead of by racing threads
    /// and hoping — the genuine race is covered separately in EngineTests.
    /// </summary>
    private sealed class ControllableStore : IRefreshTokenStore
    {
        public MemoryRefreshTokenStore Inner { get; } = new();

        private bool _failMarkRotated;
        private bool _failRevokeIfActive;

        public void FailNextCas(string method)
        {
            switch (method)
            {
                case "markRotated": _failMarkRotated = true; break;
                case "revokeIfActive": _failRevokeIfActive = true; break;
                default: throw new ArgumentOutOfRangeException(nameof(method), method, "not a compare-and-set");
            }
        }

        public Task<TokenRecord?> FindBySelectorAsync(string selector, CancellationToken cancellationToken = default)
            => Inner.FindBySelectorAsync(selector, cancellationToken);

        public Task InsertAsync(TokenRecord record, CancellationToken cancellationToken = default)
            => Inner.InsertAsync(record, cancellationToken);

        public Task<bool> MarkRotatedAsync(
            string selector,
            TokenStatus fromStatus,
            long rotatedAt,
            string replacedBySelector,
            CancellationToken cancellationToken = default)
        {
            if (_failMarkRotated)
            {
                _failMarkRotated = false;
                return Task.FromResult(false);
            }
            return Inner.MarkRotatedAsync(selector, fromStatus, rotatedAt, replacedBySelector, cancellationToken);
        }

        public Task<bool> RevokeIfActiveAsync(string selector, CancellationToken cancellationToken = default)
        {
            if (_failRevokeIfActive)
            {
                _failRevokeIfActive = false;
                return Task.FromResult(false);
            }
            return Inner.RevokeIfActiveAsync(selector, cancellationToken);
        }

        public Task<int> RevokeFamilyAsync(string familyId, CancellationToken cancellationToken = default)
            => Inner.RevokeFamilyAsync(familyId, cancellationToken);

        public Task<int> RevokeUserAsync(string userId, CancellationToken cancellationToken = default)
            => Inner.RevokeUserAsync(userId, cancellationToken);
    }

    private sealed record Binding(string Token, string FamilyId, long ExpiresAt);

    // ── Vector shapes ────────────────────────────────────────────────────────

    internal sealed record BehaviorVectors(
        [property: JsonPropertyName("spec_version")] int SpecVersion,
        VectorCounts Counts,
        Dictionary<string, string> Peppers,
        VectorConfig Defaults,
        List<Scenario> Scenarios);

    internal sealed record VectorCounts(int Scenarios, int Unconditional);

    /// <summary>Nullable throughout: a scenario's <c>config</c> is a partial override.</summary>
    internal sealed record VectorConfig(
        long? Now,
        long? AbsoluteTtlSeconds,
        long? IdleTtlSeconds,
        long? ReuseGraceSeconds,
        string? ActiveKid,
        List<string>? Peppers);

    internal sealed record Scenario(
        string Id,
        string Title,
        List<string> Requirements,
        string? Condition,
        VectorConfig? Config,
        List<Step> Steps);

    internal sealed record TokenRef(string? Ref, string? Literal, string? Forge);

    internal sealed record Expect(
        bool? Ok,
        string? Error,
        int? Generation,
        string? Kid,
        string? SameFamilyAs,
        string? SameExpiresAtAs,
        bool? IdleEqualsExpires,
        bool? HasUserId,
        bool? HasFamilyId,
        int? Revoked);

    internal sealed record Step(
        string Op,
        string? UserId,
        // Nullable rather than defaulted: absence of a device identifier must stay
        // distinguishable from an empty-string one ([N-25]).
        string? DeviceId,
        string? DeviceIdKind,
        TokenRef? Token,
        string? Bind,
        string? Of,
        long? Seconds,
        string? Method,
        List<string>? Peppers,
        string? ActiveKid,
        Dictionary<string, int>? Counts,
        Expect? Expect);
}
