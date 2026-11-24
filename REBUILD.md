# Verify this package

Two questions people ask about the ShipGuard CLI. This page answers both with something you can run.

1. Is the package on npm built from this repository?
2. What does the CLI send over the network, and from which file?

## 1. Rebuild the package and compare

The npm package ships source maps (`dist/*.js.map`). From 0.13.0 the maps point to the public source at the tagged commit (they hold line mappings, not a copy of the source text); 0.12.1 embedded the source text. To check that the bundle is what this repo builds:

```bash
# needs node 24, pnpm 9.15.0, git, network
git clone --depth 1 --branch v0.13.2 https://github.com/agenticcli/shipguard.git
cd shipguard
pnpm install --frozen-lockfile --ignore-scripts
pnpm run build                                    # builds the shared packages the CLI bundles
pnpm --filter @agenticcli/shipguard run build:publish
npm pack @agenticcli/shipguard@0.13.2 && mkdir pub && tar -xzf agenticcli-shipguard-0.13.2.tgz -C pub
node packages/cli/scripts/compare-dist.mjs pub/package/dist packages/cli/dist
```

Or in one step: `bash scripts/rebuild-verify.sh 0.13.2` (does the same in a temp folder).

- `MATCH` = the SHA-256 of every `dist/*.js` and `dist/*.js.map` in the npm package equals your rebuild.
- It must be `build:publish`, not `build`. The publish build sets one flag (`SHIPGUARD_PUBLISHED_BUILD=1`) that changes the bytes.
- `cli-facts.json` is not compared: it carries a build timestamp. It holds no code.
- The release runs the same install and build steps (`.github/workflows/release.yml`), then publishes that exact tarball with npm provenance, which links the package to the commit and workflow run.
- What CI proves on every change (`.github/workflows/ci.yml`): two clean builds of the same commit are byte-identical, and every map resolves to a real file under `src/`. What it does not prove: a different machine or Node version gives the same bytes. Use Node 24 (what the release uses) and tell us if a `MISMATCH` shows up: https://github.com/agenticcli/shipguard/issues.
- Maps are not part of the CLI's own integrity check (`dist/checksum-manifest.json` hashes the `.js` files only), so they can never make a scan fail.

## Release candidate (RC) tarball for pre-release testing

`npm pack` does not run any build (only `prepublishOnly` does, and only on publish), so a pack taken after a plain `pnpm run build` carries dev-build telemetry (`provenance: dev`). Build the RC the way the release does:

```bash
pnpm install --frozen-lockfile --ignore-scripts
pnpm run build
pnpm --filter @agenticcli/shipguard run build:publish   # sets SHIPGUARD_PUBLISHED_BUILD=1
(cd packages/cli && npm pack)                           # the RC tarball
```

`.github/workflows/release.yml` already runs `build:publish` before packing, so what it publishes is correct.

## 2. Every network call in the CLI

Nothing is sent about your code. Only product usage telemetry (first row) is on by default; it can be turned off. This list is from the source at this tag (`grep -rn "fetch(" packages/cli/src`); a test fails the build if a new call appears without being listed here.

| File | Call | When |
| --- | --- | --- |
| `src/core/telemetry.ts` | `POST https://agenticcli.dev/api/cli-telemetry` | after a scan, once on first run, after `login`; product usage telemetry, no code or paths; off with `shipguard telemetry disable`, `SHIPGUARD_TELEMETRY=0`, `DO_NOT_TRACK=1` or `telemetry: { enabled: false }` in the policy file; never from a source checkout |
| `src/core/jwks.ts` | `GET https://agenticcli.dev/.well-known/jwks.json` | `scan --pro`: public keys to verify signed rules |
| `src/core/pro-scanner.ts` | `POST <api>/api/rules/fetch` | `scan --pro`: download the signed rules; sends your login token and a scan id, no files |
| `src/core/auth.ts` | `POST <api>/api/agent/exchange`, `POST <api>/api/auth/device/refresh` | `scan --pro` with an API key or an expired login: get or refresh a token |
| `src/commands/login.ts` | `POST <api>/api/auth/device`, `POST <api>/api/auth/device/token` | `shipguard login` |
| `src/commands/status.ts` | `GET <api>/api/user/me` | `shipguard status` |
| `src/core/offer-cache.ts` | `GET <api>/api/cli/v1/offer?stacks=<names>` | a signed-out scan in a terminal, at most once every 7 days: public rule counts for your detected stack names (names only, no login, no code); `shipguard setup` makes the same request once with no names; never in hooks, the gate, CI, `--quiet`, `--dry-run`, safe mode, with `DO_NOT_TRACK` or tracking off, or when signed in |
| `src/core/plan-client.ts` | `GET <api>/api/user/me` | `shipguard status`, `upgrade` and `login` read your account and plan; sends your login token, the CLI version and a random nonce, no files |

`<api>` is `https://agenticcli.dev` unless you set another; calls that carry a token refuse any host that is not https on agenticcli.dev (`src/utils/trust.ts`).
