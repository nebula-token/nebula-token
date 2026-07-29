<?php

declare(strict_types=1);

namespace NebulaToken\Tests;

use NebulaToken\IssueResult;
use NebulaToken\MemoryRefreshTokenStore;
use NebulaToken\NebulaEngine;
use NebulaToken\RefreshResult;
use NebulaToken\RefreshTokenStore;
use NebulaToken\RevokeResult;
use NebulaToken\TokenRecord;
use NebulaToken\TokenStatus;
use PHPUnit\Framework\Assert;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use RuntimeException;

/**
 * Normative behavioral suite — spec/behavior-vectors.json (SPECIFICATION.md
 * [N-47], [N-49]).
 *
 * The scenarios are data. Only the runner below is language-specific, which is
 * what stops the ten ports from drifting apart the way ten hand-written suites
 * did.
 */
final class BehaviorVectorsTest extends TestCase
{
    /**
     * Conditions this runtime satisfies.
     *
     * A PHP string is a byte string with no encoding attached, so it holds the
     * WTF-8 encoding of an unpaired surrogate — or any other invalid UTF-8 —
     * exactly as readily as JavaScript holds a lone UTF-16 code unit. The
     * invalid-Unicode scenario therefore applies here and nothing is skipped.
     */
    private const SATISFIED_CONDITIONS = ['runtime-admits-invalid-unicode-strings'];

    /** @return array<string, array{0: array<string, mixed>}> */
    public static function scenarioProvider(): array
    {
        $cases = [];
        foreach (BehaviorRunner::vectors()['scenarios'] as $scenario) {
            $cases[$scenario['id']] = [$scenario];
        }

        return $cases;
    }

    /** @param array<string, mixed> $scenario */
    #[DataProvider('scenarioProvider')]
    public function testScenario(array $scenario): void
    {
        $condition = $scenario['condition'] ?? null;
        if ($condition !== null && !in_array($condition, self::SATISFIED_CONDITIONS, true)) {
            // [N-48]: a skipped conditional scenario must be reported by id.
            self::markTestSkipped(sprintf('%s: runtime does not satisfy "%s"', $scenario['id'], $condition));
        }

        $steps = (new BehaviorRunner(BehaviorRunner::vectors()))->run($scenario);

        self::assertSame(count($scenario['steps']), $steps, $scenario['id'] . ': every step must execute');
    }

    public function testEveryPublishedScenarioIsExecutedOrReported(): void
    {
        $vectors = BehaviorRunner::vectors();
        $runner = new BehaviorRunner($vectors);
        $executed = [];
        $skipped = [];

        foreach ($vectors['scenarios'] as $scenario) {
            $condition = $scenario['condition'] ?? null;
            if ($condition !== null && !in_array($condition, self::SATISFIED_CONDITIONS, true)) {
                $skipped[] = $scenario['id'] . ' (' . $condition . ')';
                continue;
            }
            $runner->run($scenario);
            $executed[] = $scenario['id'];
        }

        // [N-48]: a runner that silently iterated nothing must not report success.
        self::assertSame(
            $vectors['counts']['scenarios'],
            count($executed) + count($skipped),
            'every published scenario must be either executed or explicitly skipped',
        );
        self::assertGreaterThanOrEqual(
            $vectors['counts']['unconditional'],
            count($executed),
            'every unconditional scenario must be executed',
        );
        self::assertSame([], $skipped, 'no scenario is inapplicable to PHP: ' . implode(', ', $skipped));
    }
}

/**
 * Executes one scenario of spec/behavior-vectors.json against an injected clock
 * and a store that can be told to lose a compare-and-set.
 *
 * Divergence is reported through PHPUnit's Assert so a failure names the
 * scenario, the step index and the requirements it covers.
 */
final class BehaviorRunner
{
    /** 32 zero bytes, canonically encoded: well-formed, and never the real secret. */
    private const FORGED_VERIFIER = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';
    private const FORGED_SELECTOR = 'AAAAAAAAAAAAAAAAAAAAAA';

    /**
     * U+D800 in WTF-8. A JSON document cannot carry an unpaired surrogate, so
     * the vectors name the kind instead of embedding it; this byte sequence is
     * what "a string the runtime admits but UTF-8 cannot encode" means for PHP.
     */
    private const LONE_SURROGATE = "\xED\xA0\x80";

    /** @var array<string, mixed>|null */
    private static ?array $cache = null;

    private string $id = '';
    private string $requirements = '';
    private int $now = 0;
    private NebulaEngine $engine;
    private ControllableStore $store;

    /** @var array<string, array{token: string, familyId: string, expiresAt: int}> */
    private array $bindings = [];

    /** @var list<string> */
    private array $issuedTokens = [];

    /** @var list<string> */
    private array $deviceIds = [];

    /** @param array<string, mixed> $vectors */
    public function __construct(private readonly array $vectors)
    {
    }

    /**
     * @return array<string, mixed>
     *
     * php:S112 flags the two RuntimeExceptions below. Kept, unlike the one in
     * MemoryRefreshTokenStore, which became NebulaStoreException: that one is
     * the [N-20] native error channel of a *published contract*, and a caller
     * has to be able to tell a store refusal from any other fault. These two are
     * a test harness reporting that its own fixture is missing. Nothing catches
     * them, nothing can recover from them, and the only consumer is PHPUnit,
     * which prints the message and aborts. A bespoke exception class here would
     * add a type whose only purpose is to satisfy a rule about distinguishing
     * cases that are never distinguished.
     */
    public static function vectors(): array
    {
        if (self::$cache === null) {
            // Walk up to the repository root: the vectors are read where they
            // are published, never copied into the package.
            $dir = __DIR__;
            while (!is_file($dir . '/spec/behavior-vectors.json')) {
                $parent = dirname($dir);
                if ($parent === $dir) {
                    throw new RuntimeException('could not locate spec/behavior-vectors.json above ' . __DIR__); // NOSONAR(php:S112)
                }
                $dir = $parent;
            }
            $raw = file_get_contents($dir . '/spec/behavior-vectors.json');
            if ($raw === false) {
                throw new RuntimeException('could not read spec/behavior-vectors.json'); // NOSONAR(php:S112)
            }
            self::$cache = json_decode($raw, true, 512, JSON_THROW_ON_ERROR);
        }

        return self::$cache;
    }

    /**
     * @param array<string, mixed> $scenario
     *
     * @return int the number of steps executed
     */
    public function run(array $scenario): int
    {
        $this->id = $scenario['id'];
        $this->requirements = implode(', ', $scenario['requirements']);
        $cfg = array_merge($this->vectors['defaults'], $scenario['config'] ?? []);
        $this->now = $cfg['now'];
        $this->store = new ControllableStore();
        $this->bindings = [];
        $this->issuedTokens = [];
        $this->deviceIds = [];
        $this->engine = $this->build($cfg, $cfg['peppers'], $cfg['activeKid']);

        foreach ($scenario['steps'] as $i => $step) {
            $this->step($cfg, $i, $step);
        }

        return count($scenario['steps']);
    }

    /**
     * @param array<string, mixed> $cfg
     * @param array<string, mixed> $step
     */
    private function step(array $cfg, int $i, array $step): void
    {
        $exp = $step['expect'] ?? null;

        switch ($step['op']) {
            case 'issue':
                $this->opIssue($i, $step, $exp);
                break;

            case 'refresh':
                $this->opRefresh($i, $step, $exp);
                break;

            case 'revokeToken':
                $this->opRevokeToken($i, $step, $exp);
                break;

            case 'revokeFamilyOf':
                $this->expectRevoked($i, $exp, $this->engine->revokeFamily($this->binding($i, $step['of'])['familyId']));
                break;

            case 'revokeUser':
                $this->expectRevoked($i, $exp, $this->engine->revokeAllForUser($step['userId']));
                break;

            case 'advance':
                $this->now += $step['seconds'];
                break;

            case 'reconfigure':
                // A new engine over the SAME store: pepper rotation is a
                // configuration change, not a data migration.
                $this->engine = $this->build($cfg, $step['peppers'], $step['activeKid']);
                break;

            case 'failNextCas':
                $this->store->failNextCas($step['method']);
                break;

            case 'expectStatusCounts':
                $this->opExpectStatusCounts($i, $step);
                break;

            case 'expectNoRawSecrets':
                $this->opExpectNoRawSecrets($i);
                break;

            default:
                Assert::fail($this->msg($i, 'unknown op "' . $step['op'] . '"'));
        }
    }

    /**
     * @param array<string, mixed>      $step
     * @param array<string, mixed>|null $exp
     */
    private function opIssue(int $i, array $step, ?array $exp): void
    {
        $deviceId = $this->deviceOf($step);
        $res = $this->engine->issue($step['userId'], $deviceId);

        if (($exp['ok'] ?? true) === false) {
            Assert::fail($this->msg($i, 'expected issue to fail'));
        }
        $this->checkSuccess($i, $exp, $res);
        $this->bind($step, $res->token, $res->familyId, $res->expiresAt);
        $this->issuedTokens[] = $res->token;
        if ($deviceId !== null && $deviceId !== '') {
            $this->deviceIds[] = $deviceId;
        }
    }

    /**
     * @param array<string, mixed>      $step
     * @param array<string, mixed>|null $exp
     */
    private function opRefresh(int $i, array $step, ?array $exp): void
    {
        $res = $this->engine->refresh($this->resolveToken($i, $step['token']), $this->deviceOf($step));

        if ($this->expectsFailure($exp)) {
            Assert::assertFalse($res->ok, $this->msg($i, 'expected ' . $exp['error'] . ', got success'));
            Assert::assertSame($exp['error'], $res->error?->value, $this->msg($i, 'error code'));
            $this->checkAttribution($i, $exp, $res);

            return;
        }

        Assert::assertTrue($res->ok, $this->msg($i, 'expected success, got ' . ($res->error?->value ?? '?')));
        $this->checkSuccess($i, $exp, $res);
        $this->bind($step, (string) $res->token, (string) $res->familyId, (int) $res->expiresAt);
        $this->issuedTokens[] = (string) $res->token;
    }

    /**
     * @param array<string, mixed>      $step
     * @param array<string, mixed>|null $exp
     */
    private function opRevokeToken(int $i, array $step, ?array $exp): void
    {
        $res = $this->engine->revokeToken($this->resolveToken($i, $step['token']));

        if (($exp['ok'] ?? true) === false) {
            Assert::assertFalse($res->ok, $this->msg($i, 'expected ' . $exp['error'] . ', got success'));
            Assert::assertSame($exp['error'], $res->error?->value, $this->msg($i, 'error code'));
            // [N-39] governs every failure result, revokeToken's included.
            $this->checkAttribution($i, $exp, $res);

            return;
        }
        Assert::assertTrue($res->ok, $this->msg($i, 'expected success, got ' . ($res->error?->value ?? '?')));
        $this->expectRevoked($i, $exp, $res->revoked);
    }

    /** @param array<string, mixed> $step */
    private function opExpectStatusCounts(int $i, array $step): void
    {
        $actual = ['active' => 0, 'rotated' => 0, 'revoked' => 0];
        foreach ($this->store->inner()->all() as $record) {
            $actual[$record->status->value]++;
        }
        foreach ($step['counts'] as $status => $want) {
            Assert::assertSame($want, $actual[$status], $this->msg($i, "records with status $status"));
        }
    }

    private function opExpectNoRawSecrets(int $i): void
    {
        // Concatenating the raw field bytes rather than JSON-encoding them
        // keeps the check byte-exact even for values that are not valid UTF-8.
        $dump = '';
        foreach ($this->store->inner()->all() as $r) {
            $dump .= implode('|', [
                $r->selector, $r->verifierHash, $r->kid, $r->familyId, (string) $r->generation,
                $r->userId, (string) $r->deviceIdHash, (string) $r->createdAt,
                (string) $r->familyExpiresAt, (string) $r->idleExpiresAt, $r->status->value,
                (string) $r->rotatedAt, (string) $r->replacedBySelector,
            ]) . "\n";
        }
        foreach ($this->issuedTokens as $token) {
            $verifier = explode('.', $token)[3];
            Assert::assertStringNotContainsString($token, $dump, $this->msg($i, 'a token reached the store ([N-14])'));
            Assert::assertStringNotContainsString(
                $verifier,
                $dump,
                $this->msg($i, 'a raw verifier reached the store ([N-14])'),
            );
        }
        foreach ($this->deviceIds as $deviceId) {
            Assert::assertStringNotContainsString(
                $deviceId,
                $dump,
                $this->msg($i, 'a raw device identifier reached the store ([N-14])'),
            );
        }
    }

    /**
     * @param array<string, mixed> $cfg
     * @param list<string>         $kids
     */
    private function build(array $cfg, array $kids, string $activeKid): NebulaEngine
    {
        $peppers = [];
        foreach ($kids as $kid) {
            $peppers[$kid] = $this->vectors['peppers'][$kid];
        }

        return new NebulaEngine(
            peppers: $peppers,
            activeKid: $activeKid,
            store: $this->store,
            absoluteTtlSeconds: $cfg['absoluteTtlSeconds'],
            idleTtlSeconds: $cfg['idleTtlSeconds'],
            reuseGraceSeconds: $cfg['reuseGraceSeconds'],
            clock: fn (): int => $this->now,
        );
    }

    /** @param array<string, mixed> $ref */
    private function resolveToken(int $i, array $ref): string
    {
        if (array_key_exists('literal', $ref)) {
            return $ref['literal'];
        }
        $token = $this->binding($i, $ref['ref'])['token'];
        if (!isset($ref['forge'])) {
            return $token;
        }
        $parts = explode('.', $token);
        switch ($ref['forge']) {
            case 'verifier':
                $parts[3] = self::FORGED_VERIFIER;
                break;
            case 'unknownKid':
                $parts[1] = 'zz';
                break;
            case 'unknownSelector':
                $parts[2] = self::FORGED_SELECTOR;
                break;
            default:
                Assert::fail($this->msg($i, 'unknown forge "' . $ref['forge'] . '"'));
        }

        return implode('.', $parts);
    }

    /** @param array<string, mixed> $step */
    private function deviceOf(array $step): ?string
    {
        if (($step['deviceIdKind'] ?? null) === 'lone-surrogate') {
            return self::LONE_SURROGATE;
        }

        // An absent key is an unbound call; an empty string is a real binding.
        return $step['deviceId'] ?? null;
    }

    /** @param array<string, mixed>|null $exp */
    private function checkSuccess(int $i, ?array $exp, IssueResult|RefreshResult $res): void
    {
        if ($exp === null) {
            return;
        }
        if (isset($exp['generation'])) {
            Assert::assertSame($exp['generation'], $res->generation, $this->msg($i, 'generation'));
        }
        if (isset($exp['kid'])) {
            Assert::assertSame($exp['kid'], explode('.', (string) $res->token)[1], $this->msg($i, 'kid of the new token'));
        }
        if (isset($exp['sameFamilyAs'])) {
            Assert::assertSame(
                $this->binding($i, $exp['sameFamilyAs'])['familyId'],
                $res->familyId,
                $this->msg($i, 'familyId changed across rotation'),
            );
        }
        if (isset($exp['sameExpiresAtAs'])) {
            Assert::assertSame(
                $this->binding($i, $exp['sameExpiresAtAs'])['expiresAt'],
                $res->expiresAt,
                $this->msg($i, 'the absolute deadline moved'),
            );
        }
        if ($exp['idleEqualsExpires'] ?? false) {
            Assert::assertSame($res->expiresAt, $res->idleExpiresAt, $this->msg($i, 'idleExpiresAt must hit the ceiling'));
        }
    }

    /**
     * [N-39] attribution, tri-state. `true` demands the field, `false` demands
     * its absence — the exclusion list (MALFORMED, UNKNOWN_KID, NOT_FOUND) is a
     * requirement too, and a truthy-only check could never observe it. An absent
     * key asserts nothing. "Absent" here is null: both result types declare the
     * fields, and null is how the engine signals that no record was resolved.
     *
     * @param array<string, mixed>|null $exp
     */
    private function checkAttribution(int $i, ?array $exp, RefreshResult|RevokeResult $res): void
    {
        if (isset($exp['hasUserId'])) {
            Assert::assertSame(
                $exp['hasUserId'],
                $res->userId !== null,
                $this->msg($i, 'expected userId ' . ($exp['hasUserId'] ? 'present' : 'absent') . ' ([N-39])'),
            );
        }
        if (isset($exp['hasFamilyId'])) {
            Assert::assertSame(
                $exp['hasFamilyId'],
                $res->familyId !== null,
                $this->msg($i, 'expected familyId ' . ($exp['hasFamilyId'] ? 'present' : 'absent') . ' ([N-39])'),
            );
        }
    }

    /** @param array<string, mixed>|null $exp */
    private function expectsFailure(?array $exp): bool
    {
        return $exp !== null && (($exp['ok'] ?? true) === false || isset($exp['error']));
    }

    /** @param array<string, mixed>|null $exp */
    private function expectRevoked(int $i, ?array $exp, int $actual): void
    {
        if (isset($exp['revoked'])) {
            Assert::assertSame($exp['revoked'], $actual, $this->msg($i, 'number of records revoked'));
        }
    }

    /** @param array<string, mixed> $step */
    private function bind(array $step, string $token, string $familyId, int $expiresAt): void
    {
        if (isset($step['bind'])) {
            $this->bindings[$step['bind']] = ['token' => $token, 'familyId' => $familyId, 'expiresAt' => $expiresAt];
        }
    }

    /** @return array{token: string, familyId: string, expiresAt: int} */
    private function binding(int $i, string $name): array
    {
        if (!isset($this->bindings[$name])) {
            Assert::fail($this->msg($i, 'unknown binding "' . $name . '"'));
        }

        return $this->bindings[$name];
    }

    private function msg(int $i, string $what): string
    {
        return sprintf('[%s] step %d (%s): %s', $this->id, $i, $this->requirements, $what);
    }
}

/** Wraps the reference store so a scenario can force one compare-and-set to lose. */
final class ControllableStore implements RefreshTokenStore
{
    private readonly MemoryRefreshTokenStore $inner;

    /** @var array<string, bool> */
    private array $failNext = [];

    public function __construct()
    {
        $this->inner = new MemoryRefreshTokenStore();
    }

    public function inner(): MemoryRefreshTokenStore
    {
        return $this->inner;
    }

    public function failNextCas(string $method): void
    {
        $this->failNext[$method] = true;
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
        if ($this->consume('markRotated')) {
            return false;
        }

        return $this->inner->markRotated($selector, $fromStatus, $rotatedAt, $replacedBySelector);
    }

    public function revokeIfActive(string $selector): bool
    {
        if ($this->consume('revokeIfActive')) {
            return false;
        }

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

    private function consume(string $method): bool
    {
        if ($this->failNext[$method] ?? false) {
            $this->failNext[$method] = false;

            return true;
        }

        return false;
    }
}
