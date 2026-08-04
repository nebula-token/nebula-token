# nebula-token

TypeScript reference implementation of [NEBULA](../../SPECIFICATION.md) — opaque rotating refresh tokens (RFC 9700 model). Zero dependencies, Node ≥ 22. Implements `spec_version = 1`.

```
npm install nebula-token
```

```ts
import { NebulaEngine, MemoryRefreshTokenStore } from 'nebula-token';

const engine = new NebulaEngine({
  peppers: { k1: process.env.NEBULA_PEPPER_K1! },
  activeKid: 'k1',
  store: new MemoryRefreshTokenStore(), // implement RefreshTokenStore for production
  reuseGraceSeconds: 0,            // strict; see [N-30] before raising this
});

const { token } = await engine.issue('usr_1', deviceId);
const result = await engine.refresh(token, deviceId);
if (result.ok) { /* store result.token client-side; old token is dead */ }
```

See the [repository README](../../README.md) and [SPECIFICATION.md](../../SPECIFICATION.md) for the full model.

Test: `npm test` · Build: `npm run build`

**Agent skill:** [`skills/nebula-token-typescript/SKILL.md`](skills/nebula-token-typescript/SKILL.md) teaches an AI coding assistant to integrate this package correctly. Install it with the standard agent-skill installer:

```sh
npx skills add nebula-token/nebula-token --skill nebula-token-typescript
```

That lands in the project's `.claude/skills/`, checked in and shared with your team; add `-g` for your personal `~/.claude/skills/` instead. In Claude Code it is equally a plugin — `/plugin marketplace add nebula-token/nebula-token`, then `/plugin install nebula-token-typescript@nebula-token`. Neither route copies anything: both read this directory in place, through [`.claude-plugin/marketplace.json`](../../.claude-plugin/marketplace.json).

As a fallback the skill also ships inside the published artefact, in the same installable shape — after `npm i nebula-token` the directory is at `node_modules/nebula-token/skills/nebula-token-typescript/`, and copying that directory into `~/.claude/skills/` is the whole installation. All ten skills and every install route are in [`skills/README.md`](../../skills/README.md).
