using System.Security.Cryptography;
using System.Text;

namespace NebulaToken;

/// <summary>
/// NEBULA — Opaque Rotating Refresh Tokens.
/// C# implementation of SPECIFICATION.md (spec version 1).
/// Spec constants (§1) and the pure primitives (§2, §6.4). BCL only.
/// </summary>
/// <remarks>
/// Requirement identifiers in comments ([N-*]) refer to SPECIFICATION.md.
/// </remarks>
public static class Nebula
{
    // ── Spec constants (§1), all public and named ([N-4]) ────────────────────

    /// <summary>Version of SPECIFICATION.md this package implements ([N-52]).</summary>
    public const int SpecVersion = 1;

    public const string Prefix = "nbl";
    public const int SelectorBytes = 16;
    public const int VerifierBytes = 32;
    public const int SelectorChars = 22;
    public const int VerifierChars = 43;

    /// <summary>Maximum <c>kid</c> length, in UTF-8 bytes ([N-1]).</summary>
    public const int MaxKidLength = 64;

    /// <summary>Maximum token length, in UTF-8 bytes ([N-1]).</summary>
    public const int MaxTokenLength = 512;

    /// <summary>Minimum pepper length, in UTF-8 bytes ([N-1], [N-23]).</summary>
    public const int MinPepperLength = 32;

    public const long DefaultAbsoluteTtl = 60L * 60 * 24 * 30;
    public const long DefaultIdleTtl = 60L * 60 * 24 * 7;
    public const long DefaultReuseGrace = 0;

    /// <summary>HMAC-SHA-256 output, in lowercase hex characters.</summary>
    private const int HashHexChars = 64;

    /// <summary>A parsed wire token. <see cref="Verifier"/> is a secret ([N-14]).</summary>
    public sealed record ParsedToken(string Kid, string Selector, byte[] Verifier)
    {
        /// <summary>
        /// [N-14]: the compiler-generated record <c>ToString</c> would print every
        /// member, so overriding it is what keeps the secret out of an interpolated
        /// log line. (<c>byte[]</c> would print as its type name today, but that is
        /// an implementation detail worth not depending on.)
        /// </summary>
        public override string ToString() =>
            $"ParsedToken {{ Kid = {Kid}, Selector = {Selector}, Verifier = <redacted> }}";
    }

    // ── Parsing (§2) ─────────────────────────────────────────────────────────

    /// <summary>
    /// Parse a wire token (§2, [N-5]..[N-9]).
    /// </summary>
    /// <returns>The parsed parts, or <see langword="null"/> for any malformation.</returns>
    /// <remarks>
    /// Total by construction ([N-8]): it returns <see langword="null"/> for every
    /// input including <see langword="null"/>, the empty string, strings holding
    /// unpaired surrogates and strings past <see cref="MaxTokenLength"/>. It never
    /// throws.
    /// </remarks>
    public static ParsedToken? ParseToken(string? token)
    {
        if (string.IsNullOrEmpty(token)) return null;

        // [N-6.1] length first, before any other parsing work, and measured in
        // UTF-8 bytes ([N-1]) — `token.Length` counts UTF-16 code units and would
        // disagree with every other implementation in this family on non-ASCII
        // input. Encoding.UTF8 uses replacement fallback, so an unpaired surrogate
        // is counted rather than thrown on ([N-8]).
        if (Encoding.UTF8.GetByteCount(token) > MaxTokenLength) return null;

        var parts = token.Split('.');
        if (parts.Length != 4) return null;                                     // [N-6.2]

        var kid = parts[1];
        var selector = parts[2];
        var verifierB64 = parts[3];

        // Ordinal everywhere: [N-9] forbids locale- or culture-sensitive parsing,
        // and a culture-aware comparison can treat distinct strings as equal.
        if (!string.Equals(parts[0], Prefix, StringComparison.Ordinal)) return null;  // [N-6.3]

        // [N-6.2]/[N-6.5]/[N-6.6] exact lengths. The alphabet check below is what
        // makes character length and byte length coincide here.
        if (kid.Length == 0 || kid.Length > MaxKidLength) return null;
        if (selector.Length != SelectorChars) return null;
        if (verifierB64.Length != VerifierChars) return null;

        // [N-6.4] alphabet: rejects padding, whitespace of any kind, '+', '/' and
        // anything non-ASCII.
        if (!IsBase64Url(kid) || !IsBase64Url(selector) || !IsBase64Url(verifierB64)) return null;

        if (!TryBase64UrlDecode(verifierB64, out var verifier)) return null;
        if (verifier.Length != VerifierBytes) return null;                      // [N-6.7]

        // [N-7] canonical encoding: 32 bytes have four distinct 43-character
        // base64url spellings and only one is canonical. Without this the same
        // credential has four wire forms.
        if (!string.Equals(Base64UrlEncode(verifier), verifierB64, StringComparison.Ordinal)) return null;

        return new ParsedToken(kid, selector, verifier);
    }

    /// <summary>
    /// True iff every character is in the <c>b64url</c> production of §2.
    /// </summary>
    /// <remarks>
    /// An explicit ASCII range test rather than a <c>Regex</c>: `^`/`$` anchors are
    /// a known trap here (in several dialects `$` also matches before a trailing
    /// newline, which would accept "…{verifier}\n" as well-formed), and character
    /// classes are the one place a regex engine can be talked into culture
    /// sensitivity ([N-9]).
    /// </remarks>
    private static bool IsBase64Url(string value)
    {
        foreach (var c in value)
        {
            var ok = (c >= 'A' && c <= 'Z')
                  || (c >= 'a' && c <= 'z')
                  || (c >= '0' && c <= '9')
                  || c == '-' || c == '_';
            if (!ok) return false;
        }
        return true;
    }

    // ── Hashing (§3) ─────────────────────────────────────────────────────────

    /// <summary>
    /// <c>verifierHash</c> = lowercase hex HMAC-SHA-256(pepper, verifier) ([N-11], [N-13]).
    /// The HMAC key is the pepper encoded as UTF-8; the message is the raw
    /// decoded verifier bytes.
    /// </summary>
    public static string HashVerifier(string pepper, ReadOnlySpan<byte> verifier)
    {
        ArgumentNullException.ThrowIfNull(pepper);
        return ToLowerHex(HMACSHA256.HashData(Encoding.UTF8.GetBytes(pepper), verifier));
    }

    /// <summary>
    /// <c>deviceIdHash</c> = lowercase hex HMAC-SHA-256(pepper, "device:" ‖ deviceId) ([N-11]).
    /// No normalisation, trimming or case folding is applied to either operand.
    /// </summary>
    /// <exception cref="NebulaConfigException">
    /// The device identifier is not valid Unicode, so [N-11] cannot define a hash
    /// for it ([N-12]). Callers on the attacker-reachable path must pre-check with
    /// <see cref="IsWellFormedUnicode"/> and treat the failure as a binding
    /// mismatch instead.
    /// </exception>
    public static string HashDeviceId(string pepper, string deviceId)
    {
        ArgumentNullException.ThrowIfNull(pepper);
        ArgumentNullException.ThrowIfNull(deviceId);
        if (!IsWellFormedUnicode(deviceId))
        {
            // [N-14]: the identifier itself never appears in the message.
            throw new NebulaConfigException("deviceId is not valid Unicode (unpaired surrogate)");
        }
        return ToLowerHex(HMACSHA256.HashData(
            Encoding.UTF8.GetBytes(pepper),
            Encoding.UTF8.GetBytes("device:" + deviceId)));
    }

    /// <summary>
    /// True iff the string is valid Unicode, i.e. contains no unpaired surrogate.
    /// </summary>
    /// <remarks>
    /// A .NET string is a UTF-16 code unit sequence and can hold a lone surrogate —
    /// which arrives trivially through JSON. Such a value has no UTF-8 encoding, so
    /// hashing it would silently hash U+FFFD instead and make the same identifier
    /// hash differently across languages ([N-12]).
    /// </remarks>
    public static bool IsWellFormedUnicode(string value)
    {
        ArgumentNullException.ThrowIfNull(value);
        var i = 0;
        while (i < value.Length)
        {
            var c = value[i];
            if (char.IsHighSurrogate(c))
            {
                if (i + 1 >= value.Length || !char.IsLowSurrogate(value[i + 1])) return false;
                i += 2; // a well-formed pair; skip both halves
            }
            else if (char.IsLowSurrogate(c))
            {
                return false; // a low surrogate with no high surrogate before it
            }
            else
            {
                i++;
            }
        }
        return true;
    }

    // ── Constant-time comparison (§6.4) ──────────────────────────────────────

    /// <summary>
    /// Constant-time comparison of two hex digests ([N-31]). Never throws.
    /// </summary>
    /// <remarks>
    /// Operands that are not exactly 64 <b>lowercase</b> hex characters compare
    /// unequal. The guard is deliberate rather than defensive: a lenient hex decode
    /// (<see cref="Convert.FromHexString(string)"/> accepts upper case, and a
    /// hand-rolled one typically stops at the first invalid character and compares
    /// decoded prefixes) would keep verifying a stored hash that an ETL job
    /// upper-cased, a CHAR column space-padded, or a truncating migration cut
    /// short. All of those must fail closed.
    /// </remarks>
    public static bool ConstantTimeEqualHex(string? aHex, string? bHex)
    {
        if (aHex is null || bHex is null) return false;
        if (aHex.Length != HashHexChars || bHex.Length != HashHexChars) return false;
        if (!IsLowerHex(aHex) || !IsLowerHex(bHex)) return false;

        Span<byte> a = stackalloc byte[HashHexChars / 2];
        Span<byte> b = stackalloc byte[HashHexChars / 2];
        DecodeLowerHex(aHex, a);
        DecodeLowerHex(bHex, b);
        return CryptographicOperations.FixedTimeEquals(a, b);
    }

    private static bool IsLowerHex(string value)
    {
        foreach (var c in value)
        {
            if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) return false;
        }
        return true;
    }

    /// <summary>Decode a string already validated by <see cref="IsLowerHex"/>.</summary>
    private static void DecodeLowerHex(string hex, Span<byte> destination)
    {
        for (var i = 0; i < destination.Length; i++)
        {
            destination[i] = (byte)((Nibble(hex[i * 2]) << 4) | Nibble(hex[i * 2 + 1]));
        }
        static int Nibble(char c) => c <= '9' ? c - '0' : c - 'a' + 10;
    }

    // ── base64url, RFC 4648 §5, unpadded ─────────────────────────────────────

    /// <summary>
    /// Encode unpadded base64url. Used both to build tokens and, in
    /// <see cref="ParseToken"/>, to enforce canonical encoding ([N-7]).
    /// </summary>
    internal static string Base64UrlEncode(ReadOnlySpan<byte> data) =>
        Convert.ToBase64String(data).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    /// <summary>
    /// Decode unpadded base64url. Never throws.
    /// </summary>
    /// <remarks>
    /// .NET 8 has no <c>Base64Url</c> helper (it arrived in .NET 9), so this stays
    /// hand-rolled for both target frameworks rather than forking behaviour per
    /// TFM. The BCL base64 parser underneath is lenient — it skips whitespace and
    /// accepts non-canonical trailing bits — but every caller here has already
    /// pinned the exact length and the exact alphabet and re-checks canonicality
    /// afterwards, so none of that leniency is reachable ([N-6.4], [N-7]).
    /// </remarks>
    internal static bool TryBase64UrlDecode(string data, out byte[] result)
    {
        var padded = data.Replace('-', '+').Replace('_', '/');
        padded = padded.PadRight(padded.Length + (4 - padded.Length % 4) % 4, '=');

        var buffer = new byte[padded.Length / 4 * 3];
        if (!Convert.TryFromBase64String(padded, buffer, out var written))
        {
            result = Array.Empty<byte>();
            return false;
        }
        result = buffer.AsSpan(0, written).ToArray();
        return true;
    }

    /// <summary>
    /// Lowercase hex ([N-13]). <c>ToLowerInvariant</c>, never <c>ToLower</c>: the
    /// Turkish dotless-i rule would otherwise make the output locale-dependent.
    /// </summary>
    private static string ToLowerHex(ReadOnlySpan<byte> data) =>
        Convert.ToHexString(data).ToLowerInvariant();

    internal static string RandomHex(int byteCount) =>
        ToLowerHex(RandomNumberGenerator.GetBytes(byteCount));
}
