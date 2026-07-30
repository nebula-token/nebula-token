# nebula-token (PHP)

PHP reference implementation of [NEBULA](../../SPECIFICATION.md) — opaque rotating refresh tokens (RFC 9700 model). Standard library only, PHP ≥ 8.3. Implements spec version 1.

```
composer require nebula-token/nebula-token
```

```php
use NebulaToken\{NebulaEngine, MemoryRefreshTokenStore, ErrorCode};

$engine = new NebulaEngine(
    peppers: ['k1' => getenv('NEBULA_PEPPER_K1')], // >= 32 bytes, from env/KMS
    activeKid: 'k1',
    store: new MemoryRefreshTokenStore(),          // implement RefreshTokenStore for production
    reuseGraceSeconds: 0,          // strict; see [N-30] before raising this
);

$issued = $engine->issue('usr_1', $deviceId);
// $issued->token, ->userId, ->familyId, ->generation, ->expiresAt, ->idleExpiresAt

$result = $engine->refresh($issued->token, $deviceId);
if ($result->ok) {
    // $result->token is the NEW refresh token; the presented one is now dead
} elseif ($result->error === ErrorCode::Conflict) {
    // a concurrent refresh won the compare-and-set: nothing rotated, retry once
} else {
    // $result->error, plus ->userId / ->familyId when a record was resolved
}

$engine->revokeToken($issued->token);   // authenticated logout -> RevokeResult
$engine->revokeFamily($familyId);       // administrative, returns the count
$engine->revokeAllForUser('usr_1');     // administrative, returns the count
```

Error codes are for your logs, not for the client: collapse every failure to one
generic response at the transport boundary. Treat `ErrorCode` as open — always
give `match` a `default` arm.

Test — **from the repository root, not from this directory**:

```sh
composer install && vendor/bin/phpunit -c packages/php/phpunit.xml
```

There is no `composer.json` in this directory, and that is a constraint rather than
an oversight: Packagist reads a manifest only from a repository root, so the single
[`composer.json`](../../composer.json) lives there and points its PSR-4 autoload at
`packages/php/src/`. The other nine packages keep their manifest beside their
sources; PHP is the one that cannot, and the only way to change it is a separate
read-only mirror repository produced by a subtree split — which this project
deliberately does not have. Nothing else about this directory differs: `src/`,
`tests/`, `examples/` and `skills/` are laid out exactly like the other nine, and
`composer require` installs it like any other package.

The suite is the shared conformance material, read from the repository: the
`spec/test-vectors.json` cases (`tests/ConformanceTest.php`), every scenario of
`spec/behavior-vectors.json` (`tests/BehaviorVectorsTest.php`), and the
PHP-specific properties the vectors cannot express (`tests/EngineTest.php`).

**Agent skill:** [`skills/nebula-token-php/SKILL.md`](skills/nebula-token-php/SKILL.md) teaches an AI coding assistant to integrate this package correctly. Install it with the standard agent-skill installer:

```sh
npx skills add nebula-token/nebula-token --skill nebula-token-php
```

That lands in the project's `.claude/skills/`, checked in and shared with your team; add `-g` for your personal `~/.claude/skills/` instead. In Claude Code it is equally a plugin — `/plugin marketplace add nebula-token/nebula-token`, then `/plugin install nebula-token-php@nebula-token`. Neither route copies anything: both read this directory in place, through [`.claude-plugin/marketplace.json`](https://github.com/nebula-token/nebula-token/blob/main/.claude-plugin/marketplace.json) — absolute for the same reason as the index link below, the manifest being repository metadata that is `export-ignore`d out of the Composer dist archive this README ships inside.

As a fallback the skill also ships inside the published artefact, in the same installable shape — after `composer require nebula-token/nebula-token` the directory is at `vendor/nebula-token/nebula-token/packages/php/skills/nebula-token-php/`, and copying that directory into `~/.claude/skills/` is the whole installation. All ten skills and every install route are in [`skills/README.md`](https://github.com/nebula-token/nebula-token/blob/main/skills/README.md) — an absolute link, because the repository's `skills/` index is `export-ignore`d out of the Composer dist archive while this README ships inside it.
