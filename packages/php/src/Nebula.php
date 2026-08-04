<?php

declare(strict_types=1);

namespace NebulaToken;

/**
 * NEBULA — Opaque Rotating Refresh Tokens.
 * PHP reference implementation of SPECIFICATION.md (spec version 1).
 *
 * Spec constants (§1) and the pure primitives of §2 and §6.4. Standard library
 * only. Requirement identifiers in comments ([N-*]) refer to SPECIFICATION.md.
 */
final class Nebula
{
    /** Version of SPECIFICATION.md this package implements ([N-52]). */
    public const SPEC_VERSION = 1;

    // §1 constants — every one of them public and named ([N-4]).
    public const PREFIX = 'nbl';
    public const SELECTOR_BYTES = 16;
    public const VERIFIER_BYTES = 32;
    public const SELECTOR_CHARS = 22;
    public const VERIFIER_CHARS = 43;
    public const MAX_KID_LENGTH = 64;
    public const MAX_TOKEN_LENGTH = 512;
    public const MIN_PEPPER_LENGTH = 32;
    public const DEFAULT_ABSOLUTE_TTL = 60 * 60 * 24 * 30;
    public const DEFAULT_IDLE_TTL = 60 * 60 * 24 * 7;
    public const DEFAULT_REUSE_GRACE = 0;

    /** HMAC-SHA-256 output, in lowercase hex characters. */
    private const HASH_HEX_CHARS = 64;

    /**
     * The `b64url` production of §2, anchored with \A…\z and never ^…$: PCRE's
     * `$` also matches immediately before a trailing newline, which would let
     * "…{verifier}\n" through as well-formed (vector p-24).
     */
    private const B64URL = '/\A[A-Za-z0-9_-]+\z/';

    private const LOWER_HEX_64 = '/\A[0-9a-f]{64}\z/';

    private function __construct()
    {
        // Static holder: constants and pure functions only, never instantiated.
    }

    public static function b64urlEncode(string $data): string
    {
        return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
    }

    /** Strict, unpadded base64url decode ([N-6.4]). Returns null on any deviation. */
    public static function b64urlDecode(string $data): ?string
    {
        // The alphabet guard is what rejects '=', '+', '/' and whitespace:
        // base64_decode() in strict mode still tolerates padding.
        if (preg_match(self::B64URL, $data) !== 1) {
            return null;
        }
        $decoded = base64_decode(strtr($data, '-_', '+/'), true);

        return $decoded === false ? null : $decoded;
    }

    /**
     * Parse a wire token (§2, [N-5]..[N-9]).
     *
     * Total by construction: it accepts `mixed`, and every rejection is the
     * `null` return — never an exception, whatever the input ([N-8]). PHP
     * strings are byte strings, so invalid UTF-8 is refused by the alphabet
     * check like any other out-of-set byte, and no locale or case-folding
     * setting can influence any comparison below ([N-9]).
     *
     * php:S1142 counts the returns and wants at most three. Every one of them is
     * a numbered sub-clause of [N-6]: the grammar is a fixed list of rejections,
     * and each `return null` below is annotated with the clause it enforces.
     * Collapsing them behind accumulated boolean state would hide which clause
     * rejected a token, which is the one thing this function exists to make
     * obvious. Suppressed, not restructured.
     */
    public static function parseToken(mixed $token): ?ParsedToken // NOSONAR(php:S1142)
    {
        if (!is_string($token)) {
            return null;
        }
        // [N-6.1] byte length, before any other parsing work. strlen() counts
        // bytes, which is the unit the spec measures in ([N-1]).
        if (strlen($token) > self::MAX_TOKEN_LENGTH) {
            return null;
        }

        $parts = explode('.', $token);
        if (count($parts) !== 4) {                                    // [N-6.2]
            return null;
        }
        [$prefix, $kid, $selector, $verifierB64] = $parts;

        if ($prefix !== self::PREFIX) {                               // [N-6.3] case-sensitive
            return null;
        }
        if ($kid === '' || $selector === '' || $verifierB64 === '') { // [N-6.2]
            return null;
        }
        // [N-6.5]/[N-6.6] exact lengths, in bytes.
        if (strlen($kid) > self::MAX_KID_LENGTH) {
            return null;
        }
        if (strlen($selector) !== self::SELECTOR_CHARS || strlen($verifierB64) !== self::VERIFIER_CHARS) {
            return null;
        }
        // [N-6.4] alphabet: rejects padding, whitespace, '+', '/', non-ASCII.
        if (preg_match(self::B64URL, $kid) !== 1 || preg_match(self::B64URL, $selector) !== 1) {
            return null;
        }

        $verifier = self::b64urlDecode($verifierB64);
        if ($verifier === null || strlen($verifier) !== self::VERIFIER_BYTES) { // [N-6.7]
            return null;
        }
        // [N-7] canonical encoding: 32 bytes have four 43-character spellings
        // and only the minimal one is a token. Re-encoding is the check.
        if (self::b64urlEncode($verifier) !== $verifierB64) {
            return null;
        }

        return new ParsedToken($kid, $selector, $verifier);
    }

    /**
     * True iff the byte string is well-formed UTF-8 ([N-12]).
     *
     * PHP strings are byte strings, so — unlike a UTF-8-only string type — they
     * can carry the WTF-8 encoding of an unpaired surrogate, or any other
     * invalid sequence, straight from a JSON body. Such a value has no UTF-8
     * encoding and therefore no hash under [N-11]. PCRE's /u check rejects
     * surrogate encodings and overlong forms as well as truncated sequences.
     */
    public static function isWellFormedUtf8(string $s): bool
    {
        return preg_match('//u', $s) === 1;
    }

    /** verifierHash = lowercase hex HMAC-SHA-256(pepper, verifier) ([N-11], [N-13]). */
    public static function hashVerifier(
        #[\SensitiveParameter] string $pepper,
        #[\SensitiveParameter] string $verifier,
    ): string
    {
        // The key is the pepper's bytes and the message is the raw decoded
        // verifier: no text transcoding happens on either operand ([N-11]).
        return hash_hmac('sha256', $verifier, $pepper);
    }

    /**
     * deviceIdHash = lowercase hex HMAC-SHA-256(pepper, "device:" . deviceId) ([N-11]).
     *
     * Throws for a device identifier that is not well-formed UTF-8; callers on
     * the attacker-reachable path must pre-check with {@see isWellFormedUtf8}
     * and treat the failure as a binding mismatch instead ([N-12]).
     */
    public static function hashDeviceId(
        #[\SensitiveParameter] string $pepper,
        #[\SensitiveParameter] string $deviceId,
    ): string
    {
        if (!self::isWellFormedUtf8($deviceId)) {
            // [N-14] the message names no value: the raw device id must not
            // appear in an exception message.
            throw new NebulaConfigException('deviceId is not valid UTF-8');
        }

        // No normalisation, trimming or case folding is applied ([N-11]).
        return hash_hmac('sha256', 'device:' . $deviceId, $pepper);
    }

    /**
     * Constant-time comparison of two hex digests ([N-31]).
     *
     * Operands that are not exactly 64 lowercase hex characters compare
     * unequal. The guard is deliberate: hex2bin() would decode leniently and
     * compare decoded prefixes, so a stored hash truncated by a short column,
     * space-padded by CHAR(n), or upper-cased by an ETL job would keep
     * verifying instead of failing closed. Nothing here raises, and hash_equals
     * does not short-circuit.
     */
    public static function constantTimeEqualHex(string $aHex, string $bHex): bool
    {
        if (strlen($aHex) !== self::HASH_HEX_CHARS || strlen($bHex) !== self::HASH_HEX_CHARS) {
            return false;
        }
        if (preg_match(self::LOWER_HEX_64, $aHex) !== 1 || preg_match(self::LOWER_HEX_64, $bHex) !== 1) {
            return false;
        }

        return hash_equals($aHex, $bHex);
    }
}
