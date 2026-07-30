using System.Text.Json;
using Xunit;

namespace NebulaToken.Tests;

/// <summary>
/// Language-specific tests: properties that cannot be expressed as portable behavior
/// vectors. Every cross-language behaviour lives in <c>spec/behavior-vectors.json</c>
/// and is exercised by <see cref="BehaviorVectorsTests"/>; nothing here duplicates it.
/// </summary>
public class EngineTests
{
    private const string Pepper = "pepper-one-0123456789abcdef0123456789ab";
    private const long Start = 1_700_000_000;

    /// <summary>A well-formed stored hash: exactly 64 lowercase hex characters.</summary>
    private static readonly string Hash = new('a', 64);

    private sealed class Clock
    {
        public long Now { get; set; } = Start;
    }

    private static (NebulaEngine Engine, MemoryRefreshTokenStore Store, Clock Clock) Make(
        long absoluteTtl = Nebula.DefaultAbsoluteTtl,
        long idleTtl = Nebula.DefaultIdleTtl,
        long reuseGrace = Nebula.DefaultReuseGrace)
    {
        var store = new MemoryRefreshTokenStore();
        var clock = new Clock();
        var engine = new NebulaEngine(new NebulaEngine.Config
        {
            Peppers = new Dictionary<string, string> { ["k1"] = Pepper },
            ActiveKid = "k1",
            Store = store,
            AbsoluteTtlSeconds = absoluteTtl,
            IdleTtlSeconds = idleTtl,
            ReuseGraceSeconds = reuseGrace,
            Clock = () => clock.Now,
        });
        return (engine, store, clock);
    }

    // ── Constant-time comparison ([N-31]) ────────────────────────────────────

    /// <summary>
    /// [N-31]: operands that are not exactly 64 lowercase hex characters compare
    /// unequal. A lenient hex decode stops at the first invalid character and compares
    /// decoded prefixes — and <see cref="Convert.FromHexString(string)"/>, the obvious
    /// BCL choice, additionally accepts upper case. Every negative case below would
    /// then compare EQUAL, and a stored hash that an ETL job upper-cased, a CHAR column
    /// space-padded or a migration truncated would keep verifying.
    /// </summary>
    [Fact]
    public void ConstantTimeEqualHexRejectsAnythingButSixtyFourLowercaseHexChars()
    {
        Assert.Equal(64, Hash.Length);
        Assert.True(Nebula.ConstantTimeEqualHex(Hash, Hash));
        Assert.False(Nebula.ConstantTimeEqualHex(Hash, new string('b', 64)));

        var unequal = new (string? A, string? B, string Why)[]
        {
            ("abc", "abd", "odd-length prefixes"),
            (Hash, Hash + "   ", "space-padded CHAR column"),
            (Hash, Hash + "\n", "trailing newline"),
            (Hash, Hash + "zzzz", "junk suffix"),
            (Hash, Hash.ToUpperInvariant(), "case is not folded"),
            (Hash.ToUpperInvariant(), Hash.ToUpperInvariant(), "two upper-cased operands are still invalid"),
            (Hash[..63], Hash[..63], "truncated column: identical, but not 64 characters"),
            ("", "", "empty is never equal"),
            (" " + Hash[1..], Hash, "leading space is not trimmed"),
            (null, Hash, "null operand"),
            (Hash, null, "null operand"),
        };

        foreach (var (a, b, why) in unequal)
        {
            Assert.False(Nebula.ConstantTimeEqualHex(a, b), why);
        }
    }

    [Fact]
    public void ConstantTimeEqualHexNeverThrows()
    {
        var hostile = new string?[]
        {
            null, "", " ", "zz", new string(' ', 64), new string((char)0xD800, 64),
            new string('g', 64), Hash.ToUpperInvariant(),
        };
        foreach (var value in hostile)
        {
            Assert.False(Nebula.ConstantTimeEqualHex(value, Hash));
            Assert.False(Nebula.ConstantTimeEqualHex(Hash, value));
        }
    }

    [Fact]
    public async Task AStoredHashCorruptedAfterTheFactFailsClosedInsteadOfVerifying()
    {
        var (engine, store, _) = Make();
        var issued = await engine.IssueAsync("u1");
        var row = store.All()[0];

        // The same record, but the column was upper-cased by an ETL job.
        const string otherSelector = "xxxxxxxxxxxxxxxxxxxxxx";
        await store.InsertAsync(new TokenRecord
        {
            Selector = otherSelector,
            VerifierHash = row.VerifierHash.ToUpperInvariant(),
            Kid = row.Kid,
            FamilyId = row.FamilyId,
            Generation = row.Generation,
            UserId = row.UserId,
            DeviceIdHash = row.DeviceIdHash,
            CreatedAt = row.CreatedAt,
            FamilyExpiresAt = row.FamilyExpiresAt,
            IdleExpiresAt = row.IdleExpiresAt,
        });

        var parts = issued.Token.Split('.');
        parts[2] = otherSelector;
        var result = await engine.RefreshAsync(string.Join('.', parts));

        Assert.False(result.Ok);
        Assert.Equal(ErrorCode.VerifierMismatch, result.Error);
    }

    // ── Concurrency ([N-17], [N-18], [N-34]) ─────────────────────────────────

    /// <summary>
    /// The race [N-34] exists to close: two refreshes of one token both observe
    /// <c>active</c>, both mint a successor, and without the compare-and-set the family
    /// forks into two independently valid lineages — which silently disables reuse
    /// detection for the rest of the session.
    /// </summary>
    /// <remarks>
    /// The store gates every racer at its <c>findBySelector</c> until all of them have
    /// read the record, so the interleaving is forced rather than hoped for. Without the
    /// gate the thread pool is free to run the tasks one after another, and the losers
    /// would report REUSE_DETECTED instead of CONFLICT.
    /// </remarks>
    [Theory]
    [InlineData(2)]
    [InlineData(8)]
    public async Task ConcurrentRefreshesOfOneTokenLeaveExactlyOneActiveRecord(int racers)
    {
        var store = new GatedStore(racers);
        var engine = new NebulaEngine(new NebulaEngine.Config
        {
            Peppers = new Dictionary<string, string> { ["k1"] = Pepper },
            ActiveKid = "k1",
            Store = store,
        });

        var issued = await engine.IssueAsync("u1");
        store.GateOn(issued.Token.Split('.')[2]);

        // Dedicated threads: the racers block on the barrier, and a pool that grows
        // one thread per second would turn this into a timeout rather than a race.
        var results = await Task.WhenAll(Enumerable.Range(0, racers).Select(_ =>
            Task.Factory
                .StartNew(() => engine.RefreshAsync(issued.Token), TaskCreationOptions.LongRunning)
                .Unwrap()));

        Assert.Single(results.Where(r => r.Ok));
        Assert.All(results.Where(r => !r.Ok), r => Assert.Equal(ErrorCode.Conflict, r.Error));

        var rows = store.Inner.All();
        Assert.Single(rows.Where(r => r.Status == TokenStatus.Active));
        Assert.Single(rows.Where(r => r.Status == TokenStatus.Rotated));
        // Every loser cleaned up the orphan successor it had already inserted ([N-34.5]).
        Assert.Equal(racers - 1, rows.Count(r => r.Status == TokenStatus.Revoked));

        // [N-35]: CONFLICT revoked nothing beyond those orphans, so the winner's token
        // is live and the presented one is now an ordinary rotated predecessor.
        var winner = results.Single(r => r.Ok);
        Assert.True((await engine.RefreshAsync(winner.Token)).Ok);
    }

    // ── Store failures fail closed ([N-20]) ──────────────────────────────────

    [Fact]
    public async Task AFailingInsertMustNotHandBackATokenForStateThatWasNeverWritten()
    {
        var engine = BuildOver(new ExplodingStore("insert"));
        var thrown = await Assert.ThrowsAsync<InvalidOperationException>(() => engine.IssueAsync("u1"));
        Assert.Equal("database is on fire", thrown.Message);
    }

    [Fact]
    public async Task AFailingRevokeFamilyMustNotBeReportedAsASuccessfulRevocation()
    {
        var engine = BuildOver(new ExplodingStore("revokeFamily"));
        var issued = await engine.IssueAsync("u1");
        Assert.True((await engine.RefreshAsync(issued.Token)).Ok);

        // The replay must attempt a family revocation. The failure propagates instead
        // of being swallowed into a confident REUSE_DETECTED that never happened.
        await Assert.ThrowsAsync<InvalidOperationException>(() => engine.RefreshAsync(issued.Token));
    }

    [Fact]
    public async Task AFailingRotationWriteMustNotReturnAToken()
    {
        var engine = BuildOver(new ExplodingStore("markRotated"));
        var issued = await engine.IssueAsync("u1");
        await Assert.ThrowsAsync<InvalidOperationException>(() => engine.RefreshAsync(issued.Token));
    }

    // ── Configuration (§5, [N-23], [N-24]) ───────────────────────────────────

    public static TheoryData<string, string, long, long, long> InvalidConfigurations() => new()
    {
        { "k1", "short", Nebula.DefaultAbsoluteTtl, Nebula.DefaultIdleTtl, 0 },
        { "k1", Pepper, 0, Nebula.DefaultIdleTtl, 0 },
        { "k1", Pepper, -1, Nebula.DefaultIdleTtl, 0 },
        { "k1", Pepper, Nebula.DefaultAbsoluteTtl, 0, 0 },
        { "k1", Pepper, Nebula.DefaultAbsoluteTtl, -5, 0 },
        { "k1", Pepper, Nebula.DefaultAbsoluteTtl, Nebula.DefaultIdleTtl, -1 },
        { "k.1", Pepper, Nebula.DefaultAbsoluteTtl, Nebula.DefaultIdleTtl, 0 },
        { "k 1", Pepper, Nebula.DefaultAbsoluteTtl, Nebula.DefaultIdleTtl, 0 },
        { "ké", Pepper, Nebula.DefaultAbsoluteTtl, Nebula.DefaultIdleTtl, 0 },
        { "", Pepper, Nebula.DefaultAbsoluteTtl, Nebula.DefaultIdleTtl, 0 },
    };

    [Theory]
    [MemberData(nameof(InvalidConfigurations))]
    public void ConstructorRejectsAnInvalidConfiguration(
        string kid, string pepper, long absoluteTtl, long idleTtl, long reuseGrace)
    {
        Assert.Throws<NebulaConfigException>(() => new NebulaEngine(new NebulaEngine.Config
        {
            Peppers = new Dictionary<string, string> { [kid] = pepper },
            ActiveKid = kid,
            Store = new MemoryRefreshTokenStore(),
            AbsoluteTtlSeconds = absoluteTtl,
            IdleTtlSeconds = idleTtl,
            ReuseGraceSeconds = reuseGrace,
        }));
    }

    [Fact]
    public void ConstructorRejectsAKidPastMaxKidLengthAndAnUnknownActiveKid()
    {
        var store = new MemoryRefreshTokenStore();
        var tooLong = new string('k', Nebula.MaxKidLength + 1);

        Assert.Throws<NebulaConfigException>(() => new NebulaEngine(new NebulaEngine.Config
        {
            Peppers = new Dictionary<string, string> { [tooLong] = Pepper },
            ActiveKid = tooLong,
            Store = store,
        }));

        Assert.Throws<NebulaConfigException>(() => new NebulaEngine(new NebulaEngine.Config
        {
            Peppers = new Dictionary<string, string> { ["k1"] = Pepper },
            ActiveKid = "nope",
            Store = store,
        }));

        // Exactly MAX_KID_LENGTH is the boundary and must be accepted.
        _ = new NebulaEngine(new NebulaEngine.Config
        {
            Peppers = new Dictionary<string, string> { [new string('k', Nebula.MaxKidLength)] = Pepper },
            ActiveKid = new string('k', Nebula.MaxKidLength),
            Store = store,
        });
    }

    /// <summary>[N-1]: MIN_PEPPER_LENGTH counts UTF-8 bytes, never characters.</summary>
    [Fact]
    public void MinPepperLengthCountsBytesNotCharacters()
    {
        var store = new MemoryRefreshTokenStore();
        var wide = string.Concat(Enumerable.Repeat("日", 16)); // 16 characters, 48 UTF-8 bytes
        Assert.Equal(16, wide.Length);

        _ = new NebulaEngine(new NebulaEngine.Config
        {
            Peppers = new Dictionary<string, string> { ["k1"] = wide },
            ActiveKid = "k1",
            Store = store,
        });

        Assert.Throws<NebulaConfigException>(() => new NebulaEngine(new NebulaEngine.Config
        {
            Peppers = new Dictionary<string, string> { ["k1"] = new string('a', Nebula.MinPepperLength - 1) },
            ActiveKid = "k1",
            Store = store,
        }));
    }

    /// <summary>
    /// [N-11]: a pepper with no UTF-8 encoding is not a usable HMAC key, so it must fail
    /// construction rather than be encoded by substitution — <see cref="System.Text.Encoding.UTF8"/>
    /// would silently key the HMAC with U+FFFD, and the other nine would each substitute
    /// something different for the same configured value.
    /// </summary>
    /// <remarks>
    /// A <c>[Fact]</c> over a local array rather than a theory: an unpaired
    /// surrogate cannot survive a round trip through attribute metadata, so
    /// <c>InlineData</c> is not a place to put one.
    /// </remarks>
    [Fact]
    public void APepperWithNoUtf8EncodingIsRejected()
    {
        var store = new MemoryRefreshTokenStore();
        var illFormed = new[]
        {
            "\uD800",   // a high surrogate with nothing after it
            "\uDC00",   // a low surrogate with nothing before it
            "\uD800a",  // a high surrogate followed by a non-surrogate
        };

        foreach (var suffix in illFormed)
        {
            // Appended to a pepper that is already long enough, so only the encoding
            // check can be refusing it.
            var ex = Assert.Throws<NebulaConfigException>(() => new NebulaEngine(new NebulaEngine.Config
            {
                Peppers = new Dictionary<string, string> { ["k1"] = Pepper + suffix },
                ActiveKid = "k1",
                Store = store,
            }));

            // [N-14]: the message names the kid and never the secret.
            Assert.DoesNotContain(Pepper, ex.Message, StringComparison.Ordinal);
        }
    }

    /// <summary>[N-24]: the configuration is copied, so a later mutation cannot weaken it.</summary>
    [Fact]
    public async Task ThePepperMapIsCopiedAtConstruction()
    {
        var store = new MemoryRefreshTokenStore();
        var peppers = new Dictionary<string, string> { ["k1"] = Pepper };
        var engine = new NebulaEngine(new NebulaEngine.Config
        {
            Peppers = peppers,
            ActiveKid = "k1",
            Store = store,
        });

        peppers["k1"] = "x"; // would otherwise key the HMAC with a one-byte secret
        peppers.Clear();

        var issued = await engine.IssueAsync("u1");
        var parsed = Nebula.ParseToken(issued.Token);
        Assert.NotNull(parsed);
        Assert.Equal(Nebula.HashVerifier(Pepper, parsed!.Verifier), store.All()[0].VerifierHash);
        Assert.True((await engine.RefreshAsync(issued.Token)).Ok);
    }

    // ── Device identifiers ([N-11], [N-12], [N-14]) ──────────────────────────

    /// <summary>
    /// [N-12]: at issue the value comes from the application, so an unpaired surrogate
    /// is a caller error on the native channel — not a binding nothing can satisfy.
    /// </summary>
    [Fact]
    public async Task IssueRejectsADeviceIdThatIsNotValidUnicodeAtTheCallSite()
    {
        var (engine, _, _) = Make();
        var lone = ((char)0xD800).ToString();
        var thrown = await Assert.ThrowsAsync<NebulaConfigException>(() => engine.IssueAsync("u1", lone));
        Assert.DoesNotContain(lone, thrown.Message, StringComparison.Ordinal); // [N-14]
    }

    /// <summary>[N-11]: no normalisation, trimming or case folding on either operand.</summary>
    [Fact]
    public void HashDeviceIdAppliesNoNormalisationTrimmingOrCaseFolding()
    {
        // "Cafe-acute" precomposed (NFC) vs decomposed (NFD): the same text, two code
        // point sequences. They MUST hash differently - an implementation that
        // normalised would conflate them and disagree with every other port. Written as
        // escapes so the distinction survives an editor that normalises source files.
        const string nfc = "Caf\u00E9";
        const string nfd = "Cafe\u0301";
        Assert.NotEqual(nfc, nfd);
        Assert.NotEqual(Nebula.HashDeviceId(Pepper, nfc), Nebula.HashDeviceId(Pepper, nfd));

        // The pepper is the HMAC key and is equally un-normalised.
        Assert.NotEqual(Nebula.HashDeviceId(nfc + Pepper, "x"), Nebula.HashDeviceId(nfd + Pepper, "x"));

        Assert.NotEqual(Nebula.HashDeviceId(Pepper, "x"), Nebula.HashDeviceId(Pepper, " x"));
        Assert.NotEqual(Nebula.HashDeviceId(Pepper, "x"), Nebula.HashDeviceId(Pepper, "X"));
    }

    [Fact]
    public void HashDeviceIdRefusesInvalidUnicodeRatherThanHashingAReplacementCharacter()
    {
        // Encoding.UTF8 substitutes U+FFFD for a lone surrogate rather than throwing,
        // and hashing that substitute is precisely what [N-12] calls non-conforming:
        // the same identifier would then hash differently across languages. Refusing is
        // the only conforming answer - and it must stay distinguishable from hashing
        // U+FFFD itself, which is an ordinary, valid device identifier.
        Assert.Throws<NebulaConfigException>(() => Nebula.HashDeviceId(Pepper, "\uD800"));
        Assert.Throws<NebulaConfigException>(() => Nebula.HashDeviceId(Pepper, "a\uDC00b"));
        Assert.Throws<NebulaConfigException>(() => Nebula.HashDeviceId(Pepper, "\uD800a"));

        Assert.True(Nebula.IsWellFormedUnicode("\uFFFD"));
        Assert.Matches("^[0-9a-f]{64}$", Nebula.HashDeviceId(Pepper, "\uFFFD"));

        // A well-formed surrogate pair is valid Unicode and must hash normally.
        const string astral = "\uD83D\uDE00";
        Assert.True(Nebula.IsWellFormedUnicode(astral));
        Assert.Matches("^[0-9a-f]{64}$", Nebula.HashDeviceId(Pepper, astral));
    }

    // ── Secret hygiene ([N-14], [N-46]) ──────────────────────────────────────

    [Fact]
    public async Task NoRawSecretAppearsInAnythingTheEngineStores()
    {
        var (engine, store, _) = Make();
        var issued = await engine.IssueAsync("u1", "devA");
        var dump = JsonSerializer.Serialize(store.All());

        Assert.DoesNotContain(issued.Token.Split('.')[3], dump, StringComparison.Ordinal);
        Assert.DoesNotContain(issued.Token, dump, StringComparison.Ordinal);
        Assert.DoesNotContain("devA", dump, StringComparison.Ordinal);
        Assert.DoesNotContain(Pepper, dump, StringComparison.Ordinal);

        var row = store.All()[0];
        Assert.Matches("^[0-9a-f]{64}$", row.VerifierHash);
        Assert.Matches("^[0-9a-f]{64}$", row.DeviceIdHash!);
        Assert.Matches("^[0-9a-f]{32}$", row.FamilyId);
    }

    /// <summary>
    /// C#-specific: a positional <c>record</c> gets a compiler-generated
    /// <c>ToString</c> that prints every member, so
    /// <c>logger.LogInformation("{Result}", issued)</c> would otherwise write the whole
    /// token — verifier included — to the log ([N-14], [N-46]).
    /// </summary>
    [Fact]
    public async Task ResultToStringNeverPrintsTheToken()
    {
        var (engine, _, _) = Make();
        var issued = await engine.IssueAsync("u1");
        var refreshed = await engine.RefreshAsync(issued.Token);
        var parsed = Nebula.ParseToken(issued.Token);

        Assert.DoesNotContain(issued.Token.Split('.')[3], issued.ToString(), StringComparison.Ordinal);
        Assert.DoesNotContain(refreshed.Token!.Split('.')[3], refreshed.ToString(), StringComparison.Ordinal);
        Assert.DoesNotContain("Verifier = System.Byte", parsed!.ToString(), StringComparison.Ordinal);
        Assert.Contains("<redacted>", issued.ToString(), StringComparison.Ordinal);
    }

    // ── Result shape ([N-2], [N-39]) ─────────────────────────────────────────

    /// <summary>
    /// [N-2]: unix seconds in a signed 64-bit type, not <see cref="DateTime"/>. A
    /// deadline past 2038 must survive, which an <c>int</c> would not.
    /// </summary>
    [Fact]
    public async Task TimestampsAreIntegerUnixSecondsInASixtyFourBitType()
    {
        var (engine, _, clock) = Make(absoluteTtl: 3600, idleTtl: 600);
        clock.Now = 4_102_444_800; // 2100-01-01, past the 32-bit epoch cliff

        var issued = await engine.IssueAsync("u1");
        Assert.Equal(clock.Now + 3600, issued.ExpiresAt);
        Assert.Equal(clock.Now + 600, issued.IdleExpiresAt);

        var refreshed = await engine.RefreshAsync(issued.Token);
        Assert.True(refreshed.Ok);
        Assert.Equal(issued.ExpiresAt, refreshed.ExpiresAt);
        Assert.True(refreshed.ExpiresAt > int.MaxValue, "a 32-bit timestamp would have wrapped here");
    }

    [Fact]
    public async Task FailuresCarryUserIdAndFamilyIdOnceARecordIsResolved()
    {
        var (engine, _, _) = Make();
        var issued = await engine.IssueAsync("u1");
        await engine.RefreshAsync(issued.Token);

        var replay = await engine.RefreshAsync(issued.Token);
        Assert.Equal(ErrorCode.ReuseDetected, replay.Error);
        Assert.Equal("u1", replay.UserId);
        Assert.Equal(issued.FamilyId, replay.FamilyId);

        // Before a record is resolved there is nothing to attribute ([N-39]).
        var malformed = await engine.RefreshAsync("garbage");
        Assert.Equal(ErrorCode.Malformed, malformed.Error);
        Assert.Null(malformed.UserId);
        Assert.Null(malformed.FamilyId);
    }

    [Fact]
    public void EveryErrorCodeHasADistinctSpecName()
    {
        var codes = Enum.GetValues<ErrorCode>();
        var names = codes.Select(c => c.ToSpecName()).ToList();
        Assert.Equal(10, codes.Length); // [N-38]: exactly ten codes in spec version 1
        Assert.Equal(names.Count, names.Distinct(StringComparer.Ordinal).Count());
        Assert.Contains("CONFLICT", names);
    }

    // ── Store hygiene ────────────────────────────────────────────────────────

    [Fact]
    public async Task TheInMemoryStoreRefusesADuplicateSelectorRatherThanOverwriting()
    {
        var store = new MemoryRefreshTokenStore();
        var row = new TokenRecord
        {
            Selector = "AAAAAAAAAAAAAAAAAAAAAA",
            VerifierHash = Hash,
            Kid = "k1",
            FamilyId = "f",
            Generation = 0,
            UserId = "u1",
            DeviceIdHash = null,
            CreatedAt = 0,
            FamilyExpiresAt = 1,
            IdleExpiresAt = 1,
        };
        await store.InsertAsync(row);
        await Assert.ThrowsAsync<InvalidOperationException>(() => store.InsertAsync(row));
    }

    /// <summary>
    /// [N-15]: dropping a rotated row early converts every replay from REUSE_DETECTED
    /// into NOT_FOUND, disabling the one property this specification exists to provide.
    /// </summary>
    [Fact]
    public async Task DeleteExpiredOnlyRemovesRecordsPastTheFamilyDeadline()
    {
        var (engine, store, _) = Make(absoluteTtl: 100, idleTtl: 100);
        var issued = await engine.IssueAsync("u1");
        Assert.True((await engine.RefreshAsync(issued.Token)).Ok);

        Assert.Equal(0, store.DeleteExpired(Start + 99));
        Assert.Equal(2, store.All().Count);
        Assert.Equal(2, store.DeleteExpired(Start + 100));
    }

    [Fact]
    public async Task CancellationPropagatesThroughTheStoreContract()
    {
        var (engine, _, _) = Make();
        using var cts = new CancellationTokenSource();
        await cts.CancelAsync();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(
            () => engine.IssueAsync("u1", null, cts.Token));
    }

    // ── Helpers ──────────────────────────────────────────────────────────────

    private static NebulaEngine BuildOver(IRefreshTokenStore store) => new(new NebulaEngine.Config
    {
        Peppers = new Dictionary<string, string> { ["k1"] = Pepper },
        ActiveKid = "k1",
        Store = store,
    });

    /// <summary>Fails one named method through the native error channel ([N-20]).</summary>
    private sealed class ExplodingStore : IRefreshTokenStore
    {
        private readonly MemoryRefreshTokenStore _inner = new();
        private readonly string _failOn;

        public ExplodingStore(string failOn) => _failOn = failOn;

        private Task<T> Guard<T>(string method, Func<Task<T>> run) =>
            method == _failOn
                ? Task.FromException<T>(new InvalidOperationException("database is on fire"))
                : run();

        public Task<TokenRecord?> FindBySelectorAsync(string selector, CancellationToken cancellationToken = default)
            => Guard("findBySelector", () => _inner.FindBySelectorAsync(selector, cancellationToken));

        public Task InsertAsync(TokenRecord record, CancellationToken cancellationToken = default)
            => Guard("insert", async () =>
            {
                await _inner.InsertAsync(record, cancellationToken);
                return true;
            });

        public Task<bool> MarkRotatedAsync(
            string selector, TokenStatus fromStatus, long rotatedAt, string replacedBySelector,
            CancellationToken cancellationToken = default)
            => Guard("markRotated",
                () => _inner.MarkRotatedAsync(selector, fromStatus, rotatedAt, replacedBySelector, cancellationToken));

        public Task<bool> RevokeIfActiveAsync(string selector, CancellationToken cancellationToken = default)
            => Guard("revokeIfActive", () => _inner.RevokeIfActiveAsync(selector, cancellationToken));

        public Task<int> RevokeFamilyAsync(string familyId, CancellationToken cancellationToken = default)
            => Guard("revokeFamily", () => _inner.RevokeFamilyAsync(familyId, cancellationToken));

        public Task<int> RevokeUserAsync(string userId, CancellationToken cancellationToken = default)
            => Guard("revokeUser", () => _inner.RevokeUserAsync(userId, cancellationToken));
    }

    /// <summary>
    /// Holds every racer at <c>findBySelector</c> until all of them have read the same
    /// active record, so the compare-and-set is the only thing that can pick a winner.
    /// </summary>
    private sealed class GatedStore : IRefreshTokenStore
    {
        public MemoryRefreshTokenStore Inner { get; } = new();

        private readonly Barrier _barrier;
        private string? _gatedSelector;

        public GatedStore(int racers) => _barrier = new Barrier(racers);

        public void GateOn(string selector) => _gatedSelector = selector;

        public async Task<TokenRecord?> FindBySelectorAsync(
            string selector, CancellationToken cancellationToken = default)
        {
            var record = await Inner.FindBySelectorAsync(selector, cancellationToken);
            if (selector == _gatedSelector && record is { Status: TokenStatus.Active })
            {
                Assert.True(_barrier.SignalAndWait(TimeSpan.FromSeconds(30)), "racers did not converge");
            }
            return record;
        }

        public Task InsertAsync(TokenRecord record, CancellationToken cancellationToken = default)
            => Inner.InsertAsync(record, cancellationToken);

        public Task<bool> MarkRotatedAsync(
            string selector, TokenStatus fromStatus, long rotatedAt, string replacedBySelector,
            CancellationToken cancellationToken = default)
            => Inner.MarkRotatedAsync(selector, fromStatus, rotatedAt, replacedBySelector, cancellationToken);

        public Task<bool> RevokeIfActiveAsync(string selector, CancellationToken cancellationToken = default)
            => Inner.RevokeIfActiveAsync(selector, cancellationToken);

        public Task<int> RevokeFamilyAsync(string familyId, CancellationToken cancellationToken = default)
            => Inner.RevokeFamilyAsync(familyId, cancellationToken);

        public Task<int> RevokeUserAsync(string userId, CancellationToken cancellationToken = default)
            => Inner.RevokeUserAsync(userId, cancellationToken);
    }
}
