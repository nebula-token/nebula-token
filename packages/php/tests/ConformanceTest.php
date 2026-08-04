<?php

declare(strict_types=1);

namespace NebulaToken\Tests;

use NebulaToken\Nebula;
use PHPUnit\Framework\TestCase;
use stdClass;

/**
 * Shared conformance vectors — spec/test-vectors.json (SPECIFICATION.md [N-47]).
 *
 * The vectors are read from the repository, never copied into the package, so
 * this suite cannot drift from the other nine implementations.
 */
final class ConformanceTest extends TestCase
{
    /** @return array<string, mixed> */
    private static function vectors(): array
    {
        // Walk up from this file until the repository's spec/ directory shows
        // up: the package must stay relocatable, so no path is hardcoded.
        $dir = __DIR__;
        while (!is_file($dir . '/spec/test-vectors.json')) {
            $parent = dirname($dir);
            self::assertNotSame($parent, $dir, 'could not locate spec/test-vectors.json above ' . __DIR__);
            $dir = $parent;
        }
        $raw = file_get_contents($dir . '/spec/test-vectors.json');
        self::assertNotFalse($raw);

        return json_decode($raw, true, 512, JSON_THROW_ON_ERROR);
    }

    /**
     * php:S3415 reads the arguments as swapped, because the second one is a
     * class constant and its heuristic assumes a constant is always the
     * *expected* value. Here it is the opposite way round, deliberately and
     * throughout this file: the published vector is the expected value — it is
     * the normative artefact every port is measured against — and the library
     * constant is the actual, because the library is what is under test. Swapping
     * them would invert what a failure message means, and would break step with
     * the Java and Ruby conformance suites, which assert this in the same order.
     */
    public function testSpecVersionMatchesThePublishedVectors(): void
    {
        self::assertSame(self::vectors()['spec_version'], Nebula::SPEC_VERSION); // NOSONAR(php:S3415)
    }

    public function testConstantsMatchSpec(): void
    {
        $published = self::vectors()['constants'];
        $compared = [
            'prefix' => Nebula::PREFIX,
            'selector_bytes' => Nebula::SELECTOR_BYTES,
            'verifier_bytes' => Nebula::VERIFIER_BYTES,
            'selector_chars' => Nebula::SELECTOR_CHARS,
            'verifier_chars' => Nebula::VERIFIER_CHARS,
            'max_kid_length' => Nebula::MAX_KID_LENGTH,
            'max_token_length' => Nebula::MAX_TOKEN_LENGTH,
            'min_pepper_length' => Nebula::MIN_PEPPER_LENGTH,
            'default_absolute_ttl_seconds' => Nebula::DEFAULT_ABSOLUTE_TTL,
            'default_idle_ttl_seconds' => Nebula::DEFAULT_IDLE_TTL,
            'default_reuse_grace_seconds' => Nebula::DEFAULT_REUSE_GRACE,
        ];

        // [N-48]: every constant the spec publishes is compared, not only the
        // ones this file happened to remember.
        self::assertSame(
            [],
            array_keys(array_diff_key($published, $compared)),
            'a published constant was never asserted',
        );
        foreach ($compared as $name => $value) {
            self::assertSame($published[$name], $value, $name);
        }
    }

    public function testVerifierHashingVectors(): void
    {
        $vectors = self::vectors();
        self::assertNotEmpty($vectors['verifier_hashing'], 'section absent or empty ([N-48])');

        $n = 0;
        foreach ($vectors['verifier_hashing'] as $v) {
            $verifier = Nebula::b64urlDecode($v['verifier_b64url']);
            self::assertNotNull($verifier, $v['id']);
            self::assertSame(
                $v['expected_hmac_sha256_hex'],
                Nebula::hashVerifier($v['pepper'], $verifier),
                $v['id'] . ': ' . $v['note'],
            );
            $n++;
        }
        self::assertSame($vectors['counts']['verifier_hashing'], $n, 'executed count must equal published count ([N-48])');
    }

    public function testDeviceHashingVectors(): void
    {
        $vectors = self::vectors();
        self::assertNotEmpty($vectors['device_hashing'], 'section absent or empty ([N-48])');

        $n = 0;
        foreach ($vectors['device_hashing'] as $v) {
            self::assertSame(
                $v['expected_hmac_sha256_hex'],
                Nebula::hashDeviceId($v['pepper'], $v['device_id']),
                $v['id'] . ': ' . $v['note'],
            );
            if (isset($v['device_id_bytes'])) {
                // [N-11] keys the HMAC on the UTF-8 encoding of the identifier,
                // not on however the runtime happens to hold it. A PHP string
                // *is* a byte string, so the decoded bytes go straight in with
                // nothing converting them; a runner whose strings carry an
                // encoding separate from their bytes has more to do. Either way
                // the case's one expected hash must come out, which is the
                // portable statement of the rule — and the assertion that a
                // runtime cannot decide a device identifier on anything but its
                // bytes.
                $fromBytes = hex2bin($v['device_id_bytes']);
                self::assertNotFalse($fromBytes, $v['id'] . ': device_id_bytes must be hex');
                self::assertSame(
                    $v['device_id'],
                    $fromBytes,
                    $v['id'] . ': device_id_bytes must be the UTF-8 encoding of device_id',
                );
                self::assertSame(
                    $v['expected_hmac_sha256_hex'],
                    Nebula::hashDeviceId($v['pepper'], $fromBytes),
                    $v['id'] . ' from bytes',
                );
            }
            $n++;
        }
        self::assertSame($vectors['counts']['device_hashing'], $n, 'executed count must equal published count ([N-48])');
    }

    public function testParsingVectors(): void
    {
        $vectors = self::vectors();
        self::assertNotEmpty($vectors['parsing'], 'section absent or empty ([N-48])');

        $n = 0;
        foreach ($vectors['parsing'] as $v) {
            $parsed = Nebula::parseToken($v['token']);
            if ($v['valid']) {
                self::assertNotNull($parsed, $v['id'] . ' should parse: ' . $v['note']);
                self::assertSame($v['kid'], $parsed->kid, $v['id']);
                self::assertSame($v['selector'], $parsed->selector, $v['id']);
                self::assertSame(Nebula::VERIFIER_BYTES, strlen($parsed->verifier), $v['id']);
            } else {
                self::assertNull($parsed, $v['id'] . ' should be MALFORMED (' . $v['rule'] . '): ' . $v['note']);
            }
            $n++;
        }
        self::assertSame($vectors['counts']['parsing'], $n, 'executed count must equal published count ([N-48])');
    }

    public function testParsingIsTotal(): void
    {
        // [N-8]: no input may raise. PHP's string type is a byte string, so
        // invalid UTF-8 reaches the parser routinely; `mixed` covers the
        // non-string values a loosely typed caller can hand over.
        $hostile = [
            null, 42, 4.5, true, false, [], new stdClass(),
            '', ' ', '.', str_repeat('.', 1000),
            'nbl.' . str_repeat('k', 10_000),
            'nbl.k1.' . str_repeat(' ', 22) . '.' . str_repeat('A', 43),
            "nbl.k1.\xED\xA0\x80\xED\xA0\x80\xED\xA0\x80\xED\xA0\x80\xED\xA0\x80\xED\xA0\x80\xED\xA0\x80.\xff",
            "\xff\xfe",
            "nbl.k1.AAECAwQFBgcICQoLDA0ODw.AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8\0",
        ];
        foreach ($hostile as $input) {
            self::assertNull(Nebula::parseToken($input), 'hostile input must parse to null, not raise');
        }
    }
}
