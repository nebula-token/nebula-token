package dev.nebulatoken;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Base64;
import java.util.HexFormat;

/**
 * NEBULA -- Opaque Rotating Refresh Tokens.
 * Java implementation of SPECIFICATION.md (spec version 1).
 *
 * <p>This class holds the spec constants (&sect;1) and the pure primitives
 * (&sect;2, &sect;6.4) they govern. JDK standard library only.
 *
 * <p>Requirement identifiers in comments ([N-*]) refer to SPECIFICATION.md.
 */
public final class Nebula {

    // --- Spec constants (§1, [N-4]) -----------------------------------------

    /** Version of SPECIFICATION.md this package implements ([N-52]). */
    public static final int SPEC_VERSION = 1;
    public static final String PREFIX = "nbl";
    public static final int SELECTOR_BYTES = 16;
    public static final int VERIFIER_BYTES = 32;
    public static final int SELECTOR_CHARS = 22;
    public static final int VERIFIER_CHARS = 43;
    public static final int MAX_KID_LENGTH = 64;
    public static final int MAX_TOKEN_LENGTH = 512;
    public static final int MIN_PEPPER_LENGTH = 32;
    public static final long DEFAULT_ABSOLUTE_TTL = 60L * 60 * 24 * 30;
    public static final long DEFAULT_IDLE_TTL = 60L * 60 * 24 * 7;
    public static final long DEFAULT_REUSE_GRACE = 0L;

    /** HMAC-SHA-256 output width, in lowercase hex characters. */
    private static final int HASH_HEX_CHARS = 64;

    private static final Base64.Encoder B64E = Base64.getUrlEncoder().withoutPadding();
    private static final Base64.Decoder B64D = Base64.getUrlDecoder();
    private static final HexFormat HEX = HexFormat.of(); // lowercase ([N-13])

    private Nebula() {}

    /**
     * A parsed wire token (&sect;2).
     *
     * <p>{@code verifier} holds the 32 raw secret bytes: never persist, log, or
     * put it in an error message ([N-14]). {@code toString} below deliberately
     * omits it.
     *
     * <p>{@code equals} and {@code hashCode} are written out rather than left to
     * the compiler: a record advertises value semantics, and the generated pair
     * would compare {@code verifier} by array <em>identity</em>, so two parses of
     * the same token string would not be equal. Two details are deliberate:
     *
     * <ul>
     *   <li>{@code equals} compares the verifier with
     *       {@link MessageDigest#isEqual}, which does not short-circuit. A
     *       {@code Arrays.equals} here would make the comparison time depend on
     *       how many leading bytes of a secret an attacker guessed right
     *       ([N-31]).</li>
     *   <li>{@code hashCode} deliberately omits {@code verifier}. The contract
     *       only requires equal objects to agree on a hash, which they do; not
     *       deriving an int from 32 secret bytes keeps the material out of hash
     *       buckets and heap dumps ([N-14]).</li>
     * </ul>
     */
    public record ParsedToken(String kid, String selector, byte[] verifier) {
        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (!(o instanceof ParsedToken other)) return false;
            return java.util.Objects.equals(kid, other.kid)
                    && java.util.Objects.equals(selector, other.selector)
                    && MessageDigest.isEqual(verifier, other.verifier);
        }

        @Override
        public int hashCode() {
            return java.util.Objects.hash(kid, selector);
        }

        @Override
        public String toString() {
            return "ParsedToken[kid=" + kid + ", selector=" + selector + ", verifier=<redacted>]";
        }
    }

    /**
     * Parse a wire token (&sect;2, [N-5]..[N-9]).
     *
     * <p>Total by construction: every rejection is a {@code null} return, and no
     * input -- including {@code null}, the empty string, lone surrogates, or a
     * megabyte of dots -- can make this method throw ([N-8]).
     *
     * @return the parsed token, or {@code null} if it is MALFORMED
     */
    public static ParsedToken parseToken(String token) {
        if (token == null || token.isEmpty()) return null;

        // [N-6.1] length in UTF-8 BYTES, before any other parsing work.
        if (utf8Length(token) > MAX_TOKEN_LENGTH) return null;

        // Limit -1 keeps trailing empty fields, so "nbl.k1.sel." is four parts
        // with an empty verifier rather than three ([N-6.2]).
        String[] parts = token.split("\\.", -1);
        if (parts.length != 4) return null;

        String prefix = parts[0];
        String kid = parts[1];
        String selector = parts[2];
        String verifierB64 = parts[3];

        if (!PREFIX.equals(prefix)) return null;                                 // [N-6.3] case-sensitive
        if (kid.isEmpty() || selector.isEmpty() || verifierB64.isEmpty()) return null; // [N-6.2]

        // [N-6.5]/[N-6.6] exact lengths. Character count equals byte count here
        // because the alphabet check below admits ASCII only.
        if (kid.length() > MAX_KID_LENGTH) return null;
        if (selector.length() != SELECTOR_CHARS) return null;
        if (verifierB64.length() != VERIFIER_CHARS) return null;

        // [N-6.4] alphabet: rejects '=', '+', '/', whitespace and everything
        // non-ASCII. Deliberately a character scan and not a regex: `$` matches
        // before a trailing newline in several dialects (vector p-24 exists for
        // exactly that bug), and no scan of an explicit ASCII range can be
        // perturbed by locale or case-folding settings ([N-9]).
        if (!isB64Url(kid) || !isB64Url(selector) || !isB64Url(verifierB64)) return null;

        byte[] verifier;
        try {
            verifier = B64D.decode(verifierB64);
        } catch (IllegalArgumentException e) {
            return null; // unreachable after the alphabet check; [N-8] forbids trusting that
        }
        if (verifier.length != VERIFIER_BYTES) return null;                      // [N-6.7]

        // [N-7] canonical encoding. Base64.getUrlDecoder() ignores the two unused
        // trailing bits, so three further 43-character spellings of these same 32
        // bytes decode happily; re-encoding is what rejects them ([N-6.8]).
        if (!B64E.encodeToString(verifier).equals(verifierB64)) return null;

        return new ParsedToken(kid, selector, verifier);
    }

    /** verifierHash = lowercase hex HMAC-SHA-256(pepper, verifier) ([N-11], [N-13]). */
    public static String hashVerifier(String pepper, byte[] verifier) {
        return HEX.formatHex(hmacSha256(pepper, verifier));
    }

    /**
     * deviceIdHash = lowercase hex HMAC-SHA-256(pepper, "device:" + deviceId)
     * ([N-11]). No normalisation, trimming or case folding is applied to either
     * operand.
     *
     * @throws NebulaConfigException if {@code deviceId} is not valid Unicode.
     *     A lone surrogate has no UTF-8 encoding, so [N-11] cannot define a hash
     *     for it. Callers on the attacker-reachable path must pre-check with
     *     {@link #isWellFormedUnicode} and treat the value as a binding failure
     *     instead ([N-12]).
     */
    public static String hashDeviceId(String pepper, String deviceId) {
        if (deviceId == null || !isWellFormedUnicode(deviceId)) {
            throw new NebulaConfigException("deviceId is not valid Unicode (unpaired surrogate)");
        }
        return HEX.formatHex(hmacSha256(pepper, ("device:" + deviceId).getBytes(StandardCharsets.UTF_8)));
    }

    /**
     * Constant-time comparison of two hex digests ([N-31]).
     *
     * <p>Operands that are not exactly 64 lowercase hex characters compare
     * unequal. The guard is the point of the method: {@code HexFormat.parseHex}
     * would accept upper case and reject the rest by throwing, and a lenient
     * decoder would compare truncated prefixes -- so a stored hash that an ETL
     * job upper-cased, a {@code CHAR(70)} column space-padded, or a migration
     * truncated would keep verifying instead of failing closed.
     *
     * <p>Never throws, whatever it is handed.
     */
    public static boolean constantTimeEqualHex(String aHex, String bHex) {
        if (!isLowerHex64(aHex) || !isLowerHex64(bHex)) return false;
        // Equal, guarded lengths: MessageDigest.isEqual does not short-circuit.
        return MessageDigest.isEqual(HEX.parseHex(aHex), HEX.parseHex(bHex));
    }

    /**
     * True iff the string is valid Unicode, i.e. contains no unpaired surrogate.
     *
     * <p>Java strings are UTF-16 code-unit sequences and can hold one; it arrives
     * trivially through JSON input ([N-12]).
     */
    public static boolean isWellFormedUnicode(String s) {
        if (s == null) return false;
        // A while loop, not a for loop: the step is 2 code units for a surrogate
        // pair and 1 otherwise, so the advance belongs with the branch that
        // decided it rather than in a header that a second `i++` contradicts.
        int i = 0;
        while (i < s.length()) {
            char c = s.charAt(i);
            if (Character.isHighSurrogate(c)) {
                if (!isSurrogatePairAt(s, i)) return false;
                i += 2; // a well-formed pair
            } else if (Character.isLowSurrogate(c)) {
                return false; // a low surrogate with no high surrogate before it
            } else {
                i += 1;
            }
        }
        return true;
    }

    // --- Internals ----------------------------------------------------------

    /** The `b64url` production of the §2 ABNF: ALPHA / DIGIT / "-" / "_". */
    static boolean isB64Url(String s) {
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            boolean ok = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')
                    || (c >= '0' && c <= '9') || c == '-' || c == '_';
            if (!ok) return false;
        }
        return true;
    }

    /**
     * UTF-8 byte length ([N-1]) without allocating the encoded form -- a hostile
     * caller must not be able to trade a long string for a large array here.
     * An unpaired surrogate has no encoding; it is counted as the 3 bytes its
     * replacement character occupies, which only ever over-counts.
     */
    static int utf8Length(String s) {
        int n = 0;
        // As in isWellFormedUnicode: each branch states both what the code point
        // costs in UTF-8 bytes and how many UTF-16 code units it occupied.
        int i = 0;
        while (i < s.length()) {
            char c = s.charAt(i);
            if (c < 0x80) {
                n += 1;
                i += 1;
            } else if (c < 0x800) {
                n += 2;
                i += 1;
            } else if (isSurrogatePairAt(s, i)) {
                n += 4;
                i += 2;
            } else {
                n += 3;
                i += 1;
            }
        }
        return n;
    }

    /** Whether a well-formed surrogate pair starts at {@code i}. */
    private static boolean isSurrogatePairAt(String s, int i) {
        return Character.isHighSurrogate(s.charAt(i))
                && i + 1 < s.length()
                && Character.isLowSurrogate(s.charAt(i + 1));
    }

    private static boolean isLowerHex64(String s) {
        if (s == null || s.length() != HASH_HEX_CHARS) return false;
        for (int i = 0; i < HASH_HEX_CHARS; i++) {
            char c = s.charAt(i);
            if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) return false;
        }
        return true;
    }

    /** The only keyed primitive in NEBULA ([N-44]). Key is the pepper as UTF-8 ([N-11]). */
    static byte[] hmacSha256(String pepper, byte[] data) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(pepper.getBytes(StandardCharsets.UTF_8), "HmacSHA256"));
            return mac.doFinal(data);
        } catch (java.security.GeneralSecurityException e) {
            // A JRE without HmacSHA256 is not a protocol outcome: fail closed
            // through the native error channel ([N-20]). The message carries no
            // key material ([N-46]).
            throw new IllegalStateException("HmacSHA256 unavailable", e);
        }
    }

    static String b64url(byte[] data) {
        return B64E.encodeToString(data);
    }

    static String hex(byte[] data) {
        return HEX.formatHex(data);
    }
}
