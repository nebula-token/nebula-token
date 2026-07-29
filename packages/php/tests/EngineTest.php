<?php

declare(strict_types=1);

namespace NebulaToken\Tests;

use Closure;
use NebulaToken\ErrorCode;
use NebulaToken\MemoryRefreshTokenStore;
use NebulaToken\Nebula;
use NebulaToken\NebulaConfigException;
use NebulaToken\NebulaEngine;
use NebulaToken\NebulaStoreException;
use NebulaToken\RefreshTokenStore;
use NebulaToken\TokenRecord;
use NebulaToken\TokenStatus;
use PHPUnit\Framework\TestCase;
use RuntimeException;

/**
 * Language-specific tests: properties that cannot be expressed as portable
 * behavior vectors. All cross-language behavior lives in
 * spec/behavior-vectors.json and is exercised by BehaviorVectorsTest.
 */
final class EngineTest extends TestCase
{
    private const PEPPER = 'pepper-one-0123456789abcdef0123456789ab';
    private const HASH = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';

    private int $now = 1_700_000_000;

    private function clock(): Closure
    {
        return fn (): int => $this->now;
    }

    private function makeEngine(RefreshTokenStore $store, int $grace = 0): NebulaEngine
    {
        return new NebulaEngine(
            peppers: ['k1' => self::PEPPER],
            activeKid: 'k1',
            store: $store,
            reuseGraceSeconds: $grace,
            clock: $this->clock(),
        );
    }

    // ── Constant-time comparison ([N-31]) ───────────────────────────────────

    public function testConstantTimeEqualHexRejectsAnythingButSixtyFourLowercaseHexChars(): void
    {
        self::assertTrue(Nebula::constantTimeEqualHex(self::HASH, self::HASH));
        self::assertFalse(Nebula::constantTimeEqualHex(self::HASH, str_repeat('b', 64)));

        // hex2bin() decodes leniently and would compare decoded prefixes, so
        // every case below would otherwise compare EQUAL to the stored hash.
        self::assertFalse(Nebula::constantTimeEqualHex('abc', 'abd'), 'odd-length prefixes');
        self::assertFalse(Nebula::constantTimeEqualHex(self::HASH, self::HASH . '   '), 'space-padded CHAR column');
        self::assertFalse(Nebula::constantTimeEqualHex(self::HASH, self::HASH . "\n"), 'trailing newline');
        self::assertFalse(Nebula::constantTimeEqualHex(self::HASH, self::HASH . 'zzzz'), 'junk suffix');
        self::assertFalse(Nebula::constantTimeEqualHex(self::HASH, strtoupper(self::HASH)), 'case is not folded');
        self::assertFalse(Nebula::constantTimeEqualHex(strtoupper(self::HASH), strtoupper(self::HASH)), 'uppercase both');
        self::assertFalse(
            Nebula::constantTimeEqualHex(substr(self::HASH, 0, 63), substr(self::HASH, 0, 63)),
            'truncated column',
        );
        self::assertFalse(Nebula::constantTimeEqualHex('', ''), 'empty is never equal');
    }

    public function testConstantTimeEqualHexNeverRaises(): void
    {
        // PHP's own type system rejects the non-string operands the reference
        // has to guard against, so the hostile set here is byte strings —
        // including one that is not valid UTF-8.
        $hostile = ['', ' ', 'zz', str_repeat(' ', 64), str_repeat('g', 64), "\xff\xfe", self::HASH . "\0"];
        foreach ($hostile as $a) {
            self::assertFalse(Nebula::constantTimeEqualHex($a, self::HASH));
            self::assertFalse(Nebula::constantTimeEqualHex(self::HASH, $a));
        }
    }

    public function testStoredHashCorruptedAfterTheFactFailsClosed(): void
    {
        $store = new MemoryRefreshTokenStore();
        $engine = $this->makeEngine($store);
        $issued = $engine->issue('u1');
        $row = $store->all()[0];

        // Same record, but the column was upper-cased by an ETL job.
        $store->insert(new TokenRecord(
            selector: str_repeat('x', 22),
            verifierHash: strtoupper($row->verifierHash),
            kid: $row->kid,
            familyId: $row->familyId,
            generation: $row->generation,
            userId: $row->userId,
            deviceIdHash: null,
            createdAt: $row->createdAt,
            familyExpiresAt: $row->familyExpiresAt,
            idleExpiresAt: $row->idleExpiresAt,
        ));

        $parts = explode('.', $issued->token);
        $parts[2] = str_repeat('x', 22);
        $res = $engine->refresh(implode('.', $parts));

        self::assertFalse($res->ok);
        self::assertSame(ErrorCode::VerifierMismatch, $res->error);
    }

    // ── Concurrency ([N-17], [N-34], [N-35]) ────────────────────────────────

    public function testAConcurrentRefreshLosesTheCompareAndSetInsteadOfForkingTheFamily(): void
    {
        // PHP serves one request per process, so the race is reproduced by
        // interleaving deterministically: a competing refresh runs to
        // completion between this one's insert and its markRotated.
        $store = new InterleavingStore();
        $engine = $this->makeEngine($store);
        $issued = $engine->issue('u1');

        $winner = null;
        $store->beforeNextMarkRotated(function () use ($engine, $issued, &$winner): void {
            $winner = $engine->refresh($issued->token);
        });
        $loser = $engine->refresh($issued->token);

        self::assertNotNull($winner);
        self::assertTrue($winner->ok, 'the refresh that got its write in first must succeed');
        self::assertFalse($loser->ok, 'a token must never be returned on a lost compare-and-set');
        self::assertSame(ErrorCode::Conflict, $loser->error);

        $active = array_values(array_filter(
            $store->inner()->all(),
            static fn (TokenRecord $r): bool => $r->status === TokenStatus::Active,
        ));
        self::assertCount(1, $active, 'the family must not fork into two live lineages');
        self::assertSame(Nebula::parseToken($winner->token)->selector, $active[0]->selector);
    }

    public function testABurstOfConcurrentRefreshesLeavesExactlyOneActiveRecord(): void
    {
        // Every racer reads the record before any write lands, which is exactly
        // what a pinned read reproduces; only the store's CAS separates them.
        $store = new RacingStore();
        $engine = $this->makeEngine($store);
        $issued = $engine->issue('u1');
        $store->pinReadsOf(Nebula::parseToken($issued->token)->selector);

        $results = [];
        for ($i = 0; $i < 16; $i++) {
            $results[] = $engine->refresh($issued->token);
        }

        $ok = array_filter($results, static fn ($r): bool => $r->ok);
        self::assertCount(1, $ok, 'exactly one refresh may win');
        foreach ($results as $r) {
            if (!$r->ok) {
                self::assertSame(ErrorCode::Conflict, $r->error, 'every loser gets a retryable CONFLICT');
                self::assertNotNull($r->familyId, 'the failure is attributable ([N-39])');
            }
        }
        self::assertCount(
            1,
            array_filter($store->inner()->all(), static fn (TokenRecord $r): bool => $r->status === TokenStatus::Active),
            'the 15 orphan successors must have been cleaned up ([N-34] step 5)',
        );
    }

    // ── Store failures fail closed ([N-20]) ─────────────────────────────────

    public function testAFailingInsertNeverHandsBackATokenForStateThatWasNeverWritten(): void
    {
        $engine = $this->makeEngine(new ExplodingStore('insert'));

        $this->expectException(StoreOnFire::class);
        $this->expectExceptionMessage('database is on fire');
        $engine->issue('u1');
    }

    public function testAFailingRevokeFamilyIsNotReportedAsASuccessfulRevocation(): void
    {
        $store = new ExplodingStore('revokeFamily');
        $engine = $this->makeEngine($store);
        $issued = $engine->issue('u1');
        self::assertTrue($engine->refresh($issued->token)->ok);

        // The replay must attempt a family revocation; the exception propagates
        // rather than being swallowed into a confident REUSE_DETECTED.
        $this->expectException(StoreOnFire::class);
        $engine->refresh($issued->token);
    }

    public function testAFailingMarkRotatedDoesNotReturnAToken(): void
    {
        $store = new ExplodingStore('markRotated');
        $engine = $this->makeEngine($store);
        $issued = $engine->issue('u1');

        $this->expectException(StoreOnFire::class);
        $engine->refresh($issued->token);
    }

    public function testAFailingLookupDoesNotDegradeIntoAProtocolOutcome(): void
    {
        $store = new ExplodingStore('findBySelector');
        $engine = $this->makeEngine($store);
        $issued = $engine->issue('u1');

        $this->expectException(StoreOnFire::class);
        $engine->refresh($issued->token);
    }

    // ── Configuration (§5, [N-23], [N-24]) ──────────────────────────────────

    public function testConstructorValidation(): void
    {
        $cases = [
            'pepper below the floor' => fn () => new NebulaEngine(['k1' => 'short'], 'k1', new MemoryRefreshTokenStore()),
            'activeKid absent' => fn () => new NebulaEngine(['k1' => self::PEPPER], 'nope', new MemoryRefreshTokenStore()),
            'kid outside the ABNF' => fn () => new NebulaEngine(['k.1' => self::PEPPER], 'k.1', new MemoryRefreshTokenStore()),
            'kid with a plus' => fn () => new NebulaEngine(['k+1' => self::PEPPER], 'k+1', new MemoryRefreshTokenStore()),
            'empty kid' => fn () => new NebulaEngine(['' => self::PEPPER], '', new MemoryRefreshTokenStore()),
            'kid past MAX_KID_LENGTH' => fn () => new NebulaEngine(
                [str_repeat('k', 65) => self::PEPPER],
                str_repeat('k', 65),
                new MemoryRefreshTokenStore(),
            ),
            'absoluteTtl zero' => fn () => new NebulaEngine(['k1' => self::PEPPER], 'k1', new MemoryRefreshTokenStore(), absoluteTtlSeconds: 0),
            'idleTtl negative' => fn () => new NebulaEngine(['k1' => self::PEPPER], 'k1', new MemoryRefreshTokenStore(), idleTtlSeconds: -5),
            'grace negative' => fn () => new NebulaEngine(['k1' => self::PEPPER], 'k1', new MemoryRefreshTokenStore(), reuseGraceSeconds: -1),
            // [N-11] a pepper that is not valid UTF-8 is not a usable HMAC key.
            // Well over the byte floor, so only the encoding rule can reject it.
            'pepper with no UTF-8 encoding' => fn () => new NebulaEngine(
                ['k1' => "\xED\xA0\x80" . self::PEPPER],
                'k1',
                new MemoryRefreshTokenStore(),
            ),
        ];

        foreach ($cases as $why => $build) {
            try {
                $build();
                self::fail("construction should have been refused: $why");
            } catch (NebulaConfigException $e) {
                self::assertStringStartsWith('[NEBULA]', $e->getMessage(), $why);
            }
        }
    }

    public function testAKidAtTheLengthBoundaryAndAnAllDigitKidAreAccepted(): void
    {
        // An all-digit kid arrives as an int array key; §2 measures the string.
        $engine = new NebulaEngine(
            peppers: ['123' => self::PEPPER, str_repeat('k', 64) => self::PEPPER],
            activeKid: '123',
            store: new MemoryRefreshTokenStore(),
            clock: $this->clock(),
        );
        $issued = $engine->issue('u1');

        self::assertSame('123', Nebula::parseToken($issued->token)->kid);
        self::assertTrue($engine->refresh($issued->token)->ok);
    }

    public function testMinPepperLengthCountsBytesNotCharacters(): void
    {
        $store = new MemoryRefreshTokenStore();
        $wide = str_repeat('日', 16); // 16 characters, 48 UTF-8 bytes

        // Counted with PCRE rather than mbstring, which is not in every build.
        self::assertSame(16, preg_match_all('/./u', $wide));
        self::assertSame(48, strlen($wide));

        $engine = new NebulaEngine(['k1' => $wide], 'k1', $store, clock: $this->clock());
        self::assertTrue($engine->refresh($engine->issue('u1')->token)->ok);

        // ...and 31 ASCII characters look long, are 31 bytes, and are refused.
        // Built inside a closure so the engine is a RETURN VALUE rather than an
        // object constructed only to be dropped (php:S1848), and asserted with
        // the try/fail/catch idiom testConstructorValidation already uses: a
        // trailing expectException() would also have been satisfied if an
        // EARLIER line of this test had raised NebulaConfigException.
        $refused = fn (): NebulaEngine => new NebulaEngine(['k1' => str_repeat('a', 31)], 'k1', $store);
        try {
            $refused();
            self::fail('a 31-byte pepper must be refused ([N-1], [N-23])');
        } catch (NebulaConfigException $e) {
            self::assertStringStartsWith('[NEBULA]', $e->getMessage());
        }
    }

    public function testThePepperMapIsCopiedSoMutatingTheCallersArrayCannotWeakenTheEngine(): void
    {
        $store = new MemoryRefreshTokenStore();
        $peppers = ['k1' => self::PEPPER];
        $engine = new NebulaEngine($peppers, 'k1', $store, clock: $this->clock());

        $peppers['k1'] = 'x'; // would otherwise key the HMAC with a one-byte secret
        unset($peppers['k1']);

        $issued = $engine->issue('u1');
        $parsed = Nebula::parseToken($issued->token);
        self::assertSame(Nebula::hashVerifier(self::PEPPER, $parsed->verifier), $store->all()[0]->verifierHash);
        self::assertTrue($engine->refresh($issued->token)->ok);
    }

    // ── Device identifiers ([N-11], [N-12], [N-14]) ─────────────────────────

    public function testIssueRejectsADeviceIdThatIsNotValidUtf8AtTheCallSite(): void
    {
        $engine = $this->makeEngine(new MemoryRefreshTokenStore());

        $this->expectException(NebulaConfigException::class);
        $engine->issue('u1', "\xED\xA0\x80");
    }

    public function testHashDeviceIdAppliesNoNormalisationTrimmingOrCaseFolding(): void
    {
        // "Café" precomposed (NFC) versus decomposed (NFD).
        self::assertNotSame(
            Nebula::hashDeviceId(self::PEPPER, "Caf\u{00E9}"),
            Nebula::hashDeviceId(self::PEPPER, "Cafe\u{0301}"),
            'NFC and NFD must not be conflated',
        );
        self::assertNotSame(Nebula::hashDeviceId(self::PEPPER, 'x'), Nebula::hashDeviceId(self::PEPPER, ' x'));
        self::assertNotSame(Nebula::hashDeviceId(self::PEPPER, 'x'), Nebula::hashDeviceId(self::PEPPER, 'X'));
    }

    public function testNoRawSecretAppearsInAnythingTheEngineStores(): void
    {
        $store = new MemoryRefreshTokenStore();
        $engine = $this->makeEngine($store);
        $issued = $engine->issue('u1', 'devA');
        $record = $store->all()[0];

        $dump = implode('|', [
            $record->selector, $record->verifierHash, $record->kid, $record->familyId,
            $record->userId, (string) $record->deviceIdHash,
        ]);
        self::assertStringNotContainsString(explode('.', $issued->token)[3], $dump, 'raw verifier');
        self::assertStringNotContainsString('devA', $dump, 'raw device identifier');
        self::assertStringNotContainsString(self::PEPPER, $dump, 'pepper');
        self::assertMatchesRegularExpression('/\A[0-9a-f]{64}\z/', $record->verifierHash);
        self::assertMatchesRegularExpression('/\A[0-9a-f]{64}\z/', (string) $record->deviceIdHash);
    }

    public function testTheRawVerifierIsRedactedFromDebugOutput(): void
    {
        $engine = $this->makeEngine(new MemoryRefreshTokenStore());
        $parsed = Nebula::parseToken($engine->issue('u1')->token);

        ob_start();
        var_dump($parsed);
        $dump = (string) ob_get_clean();

        // [N-14]: the secret must not reach a debug representation.
        self::assertStringNotContainsString($parsed->verifier, $dump);
        self::assertStringContainsString('[redacted]', $dump);
    }

    public function testNoSecretReachesTheDebugRepresentationOfAnyTypeTheSpecDefines(): void
    {
        // PHP prints private properties, so without a __debugInfo() hook a
        // single dd($engine) hands over every pepper, and dd($issued) hands
        // over a token that embeds the raw verifier ([N-14], [N-46]).
        $engine = $this->makeEngine(new MemoryRefreshTokenStore());
        $issued = $engine->issue('u1');
        $refreshed = $engine->refresh($issued->token);
        $failed = $engine->refresh('garbage');

        $dump = static function (object $o): string {
            ob_start();
            var_dump($o);

            return (string) ob_get_clean();
        };

        self::assertStringNotContainsString(self::PEPPER, $dump($engine), 'the pepper must not reach var_dump');
        self::assertStringContainsString('k1', $dump($engine), 'the kid is not secret and stays visible');

        // Each result is checked against ITS OWN token: refresh() returns the
        // successor, so asserting on the issued one would pass vacuously.
        $carriers = [
            'issue' => [$issued, $issued->token],
            'refresh' => [$refreshed, (string) $refreshed->token],
            'failure' => [$failed, $issued->token],
        ];
        foreach ($carriers as $what => [$result, $token]) {
            $text = $dump($result);
            self::assertNotSame('', $token, "$what has no token to check");
            self::assertStringNotContainsString($token, $text, "$what result leaked a token");
            self::assertStringNotContainsString(explode('.', $token)[3], $text, "$what result leaked a raw verifier");
        }
        self::assertStringContainsString('MALFORMED', $dump($failed), 'the error code stays visible');
    }

    public function testTheMemoryStoreRevokeIfActiveIsACompareAndSet(): void
    {
        // [N-18]: revoke if and only if the row is still active, and report
        // whether it did. The engine's own call sites only ever meet an active
        // row, so the negative branch needs asserting here or not at all.
        $store = new MemoryRefreshTokenStore();
        $row = new TokenRecord(
            selector: str_repeat('A', 22),
            verifierHash: self::HASH,
            kid: 'k1',
            familyId: 'f',
            generation: 0,
            userId: 'u1',
            deviceIdHash: null,
            createdAt: 0,
            familyExpiresAt: 10,
            idleExpiresAt: 10,
        );
        $store->insert($row);

        self::assertFalse($store->revokeIfActive('no-such-selector'), 'a missing row cannot be revoked');
        self::assertTrue($store->revokeIfActive($row->selector), 'an active row is revoked and reports true');
        self::assertSame(TokenStatus::Revoked, $store->findBySelector($row->selector)->status);
        self::assertFalse($store->revokeIfActive($row->selector), 'a second call changes nothing and reports false');

        // A rotated row is not active either: reporting true here would tell a
        // grace retry it had won a race it actually lost ([N-30] step 2).
        $rotated = new TokenRecord(
            selector: str_repeat('B', 22),
            verifierHash: self::HASH,
            kid: 'k1',
            familyId: 'f',
            generation: 1,
            userId: 'u1',
            deviceIdHash: null,
            createdAt: 0,
            familyExpiresAt: 10,
            idleExpiresAt: 10,
        );
        $store->insert($rotated);
        self::assertTrue($store->markRotated($rotated->selector, TokenStatus::Active, 1, 'x'));
        self::assertFalse($store->revokeIfActive($rotated->selector), 'a rotated row is not active');
        self::assertSame(TokenStatus::Rotated, $store->findBySelector($rotated->selector)->status);
    }

    // ── Result shape ([N-2], [N-39]) ────────────────────────────────────────

    public function testTimestampsAreIntegerUnixSeconds(): void
    {
        $engine = $this->makeEngine(new MemoryRefreshTokenStore());
        $issued = $engine->issue('u1');

        self::assertIsInt($issued->expiresAt);
        self::assertIsInt($issued->idleExpiresAt);
        self::assertSame($this->now + Nebula::DEFAULT_ABSOLUTE_TTL, $issued->expiresAt);

        $refreshed = $engine->refresh($issued->token);
        self::assertIsInt($refreshed->expiresAt);
        self::assertSame($issued->expiresAt, $refreshed->expiresAt, 'the absolute deadline is never extended');
    }

    public function testFailuresCarryUserIdAndFamilyIdOnceARecordIsResolved(): void
    {
        $engine = $this->makeEngine(new MemoryRefreshTokenStore());
        $issued = $engine->issue('u1');
        $engine->refresh($issued->token);

        $replay = $engine->refresh($issued->token);
        self::assertSame(ErrorCode::ReuseDetected, $replay->error);
        self::assertSame('u1', $replay->userId);
        self::assertSame($issued->familyId, $replay->familyId);

        // Before a record is resolved there is nothing to attribute ([N-39]).
        $malformed = $engine->refresh('garbage');
        self::assertNull($malformed->userId);
        self::assertNull($malformed->familyId);
    }

    // ── Store hygiene ───────────────────────────────────────────────────────

    public function testTheInMemoryStoreRefusesADuplicateSelectorRatherThanOverwriting(): void
    {
        $store = new MemoryRefreshTokenStore();
        $row = new TokenRecord(
            selector: str_repeat('A', 22),
            verifierHash: self::HASH,
            kid: 'k1',
            familyId: 'f',
            generation: 0,
            userId: 'u1',
            deviceIdHash: null,
            createdAt: 0,
            familyExpiresAt: 1,
            idleExpiresAt: 1,
        );
        $store->insert($row);

        $this->expectException(NebulaStoreException::class);
        $this->expectExceptionMessage('duplicate selector');
        $store->insert($row);
    }

    public function testDeleteExpiredOnlyRemovesRecordsPastTheFamilyDeadline(): void
    {
        $store = new MemoryRefreshTokenStore();
        $engine = new NebulaEngine(
            peppers: ['k1' => self::PEPPER],
            activeKid: 'k1',
            store: $store,
            absoluteTtlSeconds: 100,
            idleTtlSeconds: 100,
            clock: $this->clock(),
        );
        $engine->refresh($engine->issue('u1')->token);

        // [N-15]: rotated rows are what reuse detection reads — they must
        // survive until the family's absolute deadline.
        self::assertSame(0, $store->deleteExpired($this->now + 99));
        self::assertCount(2, $store->all());
        self::assertSame(2, $store->deleteExpired($this->now + 100));
    }
}

/** Runs a competing refresh between this refresh's insert and its markRotated. */
final class InterleavingStore implements RefreshTokenStore
{
    private readonly MemoryRefreshTokenStore $inner;

    /** @var (callable(): void)|null */
    private $hook = null;

    public function __construct()
    {
        $this->inner = new MemoryRefreshTokenStore();
    }

    public function inner(): MemoryRefreshTokenStore
    {
        return $this->inner;
    }

    /** @param callable(): void $hook */
    public function beforeNextMarkRotated(callable $hook): void
    {
        $this->hook = $hook;
    }

    public function findBySelector(string $selector): ?TokenRecord
    {
        return $this->inner->findBySelector($selector);
    }

    public function insert(TokenRecord $record): void
    {
        $this->inner->insert($record);
    }

    public function markRotated(
        string $selector,
        TokenStatus $fromStatus,
        int $rotatedAt,
        string $replacedBySelector,
    ): bool {
        $hook = $this->hook;
        if ($hook !== null) {
            $this->hook = null; // the competitor must not re-enter
            $hook();
        }

        return $this->inner->markRotated($selector, $fromStatus, $rotatedAt, $replacedBySelector);
    }

    public function revokeIfActive(string $selector): bool
    {
        return $this->inner->revokeIfActive($selector);
    }

    public function revokeFamily(string $familyId): int
    {
        return $this->inner->revokeFamily($familyId);
    }

    public function revokeUser(string $userId): int
    {
        return $this->inner->revokeUser($userId);
    }
}

/** Pins one selector's reads to a snapshot, so every racer observes the same row. */
final class RacingStore implements RefreshTokenStore
{
    private readonly MemoryRefreshTokenStore $inner;

    /** @var array<string, TokenRecord> */
    private array $pinned = [];

    public function __construct()
    {
        $this->inner = new MemoryRefreshTokenStore();
    }

    public function inner(): MemoryRefreshTokenStore
    {
        return $this->inner;
    }

    public function pinReadsOf(string $selector): void
    {
        $record = $this->inner->findBySelector($selector);
        if ($record !== null) {
            $this->pinned[$selector] = $record;
        }
    }

    public function findBySelector(string $selector): ?TokenRecord
    {
        return $this->pinned[$selector] ?? $this->inner->findBySelector($selector);
    }

    public function insert(TokenRecord $record): void
    {
        $this->inner->insert($record);
    }

    public function markRotated(
        string $selector,
        TokenStatus $fromStatus,
        int $rotatedAt,
        string $replacedBySelector,
    ): bool {
        return $this->inner->markRotated($selector, $fromStatus, $rotatedAt, $replacedBySelector);
    }

    public function revokeIfActive(string $selector): bool
    {
        return $this->inner->revokeIfActive($selector);
    }

    public function revokeFamily(string $familyId): int
    {
        return $this->inner->revokeFamily($familyId);
    }

    public function revokeUser(string $userId): int
    {
        return $this->inner->revokeUser($userId);
    }
}

/**
 * The infrastructure failure ExplodingStore simulates.
 *
 * A dedicated class rather than a bare RuntimeException (php:S112) so the tests
 * above assert that *this* exception propagates out of the engine untouched. A
 * generic one would also be satisfied by an engine that caught the failure and
 * rethrew a RuntimeException of its own, which is precisely the swallowing that
 * [N-20] forbids.
 */
final class StoreOnFire extends RuntimeException
{
}

/** Every call to the named method throws, the way an unreachable database does. */
final class ExplodingStore implements RefreshTokenStore
{
    private readonly MemoryRefreshTokenStore $inner;

    public function __construct(private readonly string $failOn)
    {
        $this->inner = new MemoryRefreshTokenStore();
    }

    public function findBySelector(string $selector): ?TokenRecord
    {
        $this->guard('findBySelector');

        return $this->inner->findBySelector($selector);
    }

    public function insert(TokenRecord $record): void
    {
        $this->guard('insert');
        $this->inner->insert($record);
    }

    public function markRotated(
        string $selector,
        TokenStatus $fromStatus,
        int $rotatedAt,
        string $replacedBySelector,
    ): bool {
        $this->guard('markRotated');

        return $this->inner->markRotated($selector, $fromStatus, $rotatedAt, $replacedBySelector);
    }

    public function revokeIfActive(string $selector): bool
    {
        $this->guard('revokeIfActive');

        return $this->inner->revokeIfActive($selector);
    }

    public function revokeFamily(string $familyId): int
    {
        $this->guard('revokeFamily');

        return $this->inner->revokeFamily($familyId);
    }

    public function revokeUser(string $userId): int
    {
        $this->guard('revokeUser');

        return $this->inner->revokeUser($userId);
    }

    private function guard(string $method): void
    {
        if ($method === $this->failOn) {
            throw new StoreOnFire('database is on fire');
        }
    }
}
