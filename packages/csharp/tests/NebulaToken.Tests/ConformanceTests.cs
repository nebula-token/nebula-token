using System.Text.Json;
using Xunit;

namespace NebulaToken.Tests;

/// <summary>
/// Shared conformance vectors — <c>spec/test-vectors.json</c> ([N-47]).
/// </summary>
/// <remarks>
/// [N-48]: every section asserts that the number of cases it executed equals the
/// number published in the <c>counts</c> block. Silently iterating zero cases is a
/// conformance failure, not a pass — which is exactly what a mistyped property name
/// or a moved vector file would otherwise look like.
/// </remarks>
public class ConformanceTests
{
    private static readonly JsonElement Vectors = SpecVectors.Load("test-vectors.json");

    [Fact]
    public void SpecVersionMatchesPublishedVectors()
    {
        Assert.Equal(Nebula.SpecVersion, Vectors.GetProperty("spec_version").GetInt32());
    }

    [Fact]
    public void ConstantsMatchSpecification()
    {
        var c = Vectors.GetProperty("constants");
        Assert.Equal(Nebula.Prefix, c.GetProperty("prefix").GetString());
        Assert.Equal(Nebula.SelectorBytes, c.GetProperty("selector_bytes").GetInt32());
        Assert.Equal(Nebula.VerifierBytes, c.GetProperty("verifier_bytes").GetInt32());
        Assert.Equal(Nebula.SelectorChars, c.GetProperty("selector_chars").GetInt32());
        Assert.Equal(Nebula.VerifierChars, c.GetProperty("verifier_chars").GetInt32());
        Assert.Equal(Nebula.MaxKidLength, c.GetProperty("max_kid_length").GetInt32());
        Assert.Equal(Nebula.MaxTokenLength, c.GetProperty("max_token_length").GetInt32());
        Assert.Equal(Nebula.MinPepperLength, c.GetProperty("min_pepper_length").GetInt32());
        Assert.Equal(Nebula.DefaultAbsoluteTtl, c.GetProperty("default_absolute_ttl_seconds").GetInt64());
        Assert.Equal(Nebula.DefaultIdleTtl, c.GetProperty("default_idle_ttl_seconds").GetInt64());
        Assert.Equal(Nebula.DefaultReuseGrace, c.GetProperty("default_reuse_grace_seconds").GetInt64());

        // [N-4]/[N-48]: every published constant is compared, not only the ones this
        // file happened to remember. A constant added to the vectors fails here.
        const int asserted = 11;
        Assert.Equal(asserted, c.EnumerateObject().Count());
    }

    [Fact]
    public void VerifierHashingVectors()
    {
        var executed = 0;
        foreach (var v in Vectors.GetProperty("verifier_hashing").EnumerateArray())
        {
            var id = v.GetProperty("id").GetString();
            var verifier = Base64UrlDecode(v.GetProperty("verifier_b64url").GetString()!);
            var actual = Nebula.HashVerifier(v.GetProperty("pepper").GetString()!, verifier);
            Assert.Equal(v.GetProperty("expected_hmac_sha256_hex").GetString(), actual);
            Assert.True(actual == actual.ToLowerInvariant(), $"{id}: hex must be lowercase ([N-13])");
            executed++;
        }
        Assert.Equal(Vectors.GetProperty("counts").GetProperty("verifier_hashing").GetInt32(), executed);
    }

    [Fact]
    public void DeviceHashingVectors()
    {
        var executed = 0;
        foreach (var v in Vectors.GetProperty("device_hashing").EnumerateArray())
        {
            var actual = Nebula.HashDeviceId(
                v.GetProperty("pepper").GetString()!,
                v.GetProperty("device_id").GetString()!);
            Assert.Equal(v.GetProperty("expected_hmac_sha256_hex").GetString(), actual);
            executed++;
        }
        Assert.Equal(Vectors.GetProperty("counts").GetProperty("device_hashing").GetInt32(), executed);
    }

    [Fact]
    public void ParsingVectors()
    {
        var executed = 0;
        foreach (var v in Vectors.GetProperty("parsing").EnumerateArray())
        {
            var id = v.GetProperty("id").GetString();
            var note = v.GetProperty("note").GetString();
            var parsed = Nebula.ParseToken(v.GetProperty("token").GetString());

            if (v.GetProperty("valid").GetBoolean())
            {
                Assert.True(parsed is not null, $"{id} should parse: {note}");
                Assert.Equal(v.GetProperty("kid").GetString(), parsed!.Kid);
                Assert.Equal(v.GetProperty("selector").GetString(), parsed.Selector);
                Assert.Equal(Nebula.VerifierBytes, parsed.Verifier.Length);
            }
            else
            {
                Assert.True(parsed is null, $"{id} should be MALFORMED: {note}");
            }
            executed++;
        }
        Assert.Equal(Vectors.GetProperty("counts").GetProperty("parsing").GetInt32(), executed);
    }

    /// <summary>
    /// [N-8]: parsing is total. C# is statically typed, so the "non-string types"
    /// clause has no analogue; <see langword="null"/> and every degenerate string
    /// shape do.
    /// </summary>
    [Fact]
    public void ParsingNeverThrows()
    {
        var hostile = new string?[]
        {
            null,
            string.Empty,
            " ",
            ".",
            new string('.', 1000),
            "nbl." + new string('k', 10_000),
            $"nbl.k1.{new string(' ', 22)}.{new string('A', 43)}",
            $"nbl.k1.{new string('A', 22)}.{new string('A', 43)}\0",
            "nbl\0.k1.AAECAwQFBgcICQoLDA0ODw.AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8",
            // A lone surrogate: valid in a .NET string, not valid Unicode. UTF-8 byte
            // counting must tolerate it rather than throw ([N-8], [N-12]).
            $"nbl.{(char)0xD800}.AAECAwQFBgcICQoLDA0ODw.AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8",
            ((char)0xDC00).ToString(),
            // 600 non-ASCII characters — 1800 UTF-8 bytes, so the byte-length gate of
            // [N-6.1] must reject it even though the character count is under 512.
            new string((char)0xFFFD, 600),
        };

        foreach (var input in hostile)
        {
            var parsed = Nebula.ParseToken(input);
            Assert.Null(parsed);
        }
    }

    /// <summary>Local decoder: the library's is internal, and the vectors are pre-validated.</summary>
    private static byte[] Base64UrlDecode(string value)
    {
        var padded = value.Replace('-', '+').Replace('_', '/');
        return Convert.FromBase64String(padded.PadRight(padded.Length + (4 - padded.Length % 4) % 4, '='));
    }
}

/// <summary>
/// Locates the normative vector files.
/// </summary>
/// <remarks>
/// Walks up from the test assembly (which lives under
/// <c>packages/csharp/tests/NebulaToken.Tests/bin/&lt;config&gt;/&lt;tfm&gt;</c>) until it finds
/// the repository's <c>spec/</c> directory. No absolute path is hardcoded and the
/// vectors are never copied into the package: one file, ten implementations, no
/// opportunity for a stale duplicate to drift.
/// </remarks>
internal static class SpecVectors
{
    public static JsonElement Load(string fileName)
    {
        for (var dir = new DirectoryInfo(AppContext.BaseDirectory); dir is not null; dir = dir.Parent)
        {
            var candidate = Path.Combine(dir.FullName, "spec", fileName);
            if (File.Exists(candidate))
            {
                return JsonDocument.Parse(File.ReadAllText(candidate)).RootElement;
            }
        }
        throw new FileNotFoundException(
            $"could not locate spec/{fileName} above {AppContext.BaseDirectory}");
    }

    public static string Read(string fileName)
    {
        for (var dir = new DirectoryInfo(AppContext.BaseDirectory); dir is not null; dir = dir.Parent)
        {
            var candidate = Path.Combine(dir.FullName, "spec", fileName);
            if (File.Exists(candidate)) return File.ReadAllText(candidate);
        }
        throw new FileNotFoundException(
            $"could not locate spec/{fileName} above {AppContext.BaseDirectory}");
    }
}
