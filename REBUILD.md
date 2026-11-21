# Verify this package

Two questions people ask about the ShipGuard CLI. This page answers both with something you can run.

1. Is the package on npm built from this repository?
2. What does the CLI send over the network, and from which file?

## 1. Rebuild the package and compare

From 0.12.1 the npm package ships source maps (`dist/*.js.map`) with the real `src/` files embedded, so you can read the code behind the bundle without a checkout. To check that the bundle is what this repo builds:

```bash
# needs node 24, pnpm 9.15.0, git, network
git clone --depth 1 --branch v0.12.1 https://github.com/agenticcli/shipguard.git
cd shipguard
pnpm install --frozen-lockfile --ignore-scripts
pnpm run build                                    # builds the shared packages the CLI bundles
pnpm --filter @agenticcli/shipguard run build:publish
npm pack @agenticcli/shipguard@0.12.1 && mkdir pub && tar -xzf agenticcli-shipguard-0.12.1.tgz -C pub
node packages/cli/scripts/compare-dist.mjs pub/package/dist packages/cli/dist
```

Or in one step: `bash scripts/rebuild-verify.sh 0.12.1` (does the same in a temp folder).

- `MATCH` = the SHA-256 of every `dist/*.js` and `dist/*.js.map` in the npm package equals your rebuild.
- It must be `build:publish`, not `build`. The publish build sets one flag (`SHIPGUARD_PUBLISHED_BUILD=1`) that changes the bytes.
- `cli-facts.json` is not compared: it carries a build timestamp. It holds no code.
- The release runs the same install and build steps (`.github/workflows/release.yml`), then publishes that exact tarball with npm provenance, which links the package to the commit and workflow run.
- What CI proves on every change (`.github/workflows/ci.yml`): two clean builds of the same commit are byte-identical, and every map resolves to a real file under `src/`. What it does not prove: a different machine or Node version gives the same bytes. Use Node 24 (what the release uses) and tell us if a `MISMATCH` shows up: https://github.com/agenticcli/shipguard/issues.
- Maps are not part of the CLI's own integrity check (`dist/checksum-manifest.json` hashes the `.js` files only), so they can never make a scan fail.

## 2. Every network call in the CLI

Nothing is sent about your code. Only the usage ping (first row) is on by default; it can be turned off. This list is from the source at this tag (`grep -rn "fetch(" packages/cli/src`); a test fails the build if a new call appears without being listed here.

| File | Call | When |
| --- | --- | --- |
| `src/core/telemetry.ts` | `POST https://agenticcli.dev/api/cli-telemetry` | after a scan, once on first run, after `login`; usage ping, no code or paths; off with `shipguard telemetry disable`, `SHIPGUARD_TELEMETRY=0`, `DO_NOT_TRACK=1` or `telemetry: { enabled: false }` in the policy file; never from a source checkout |
| `src/core/jwks.ts` | `GET https://agenticcli.dev/.well-known/jwks.json` | `scan --pro`: public keys to verify signed rules |
| `src/core/pro-scanner.ts` | `POST <api>/api/rules/fetch` | `scan --pro`: download the signed rules; sends your login token and a scan id, no files |
| `src/core/auth.ts` | `POST <api>/api/agent/exchange`, `POST <api>/api/auth/device/refresh` | `scan --pro` with an API key or an expired login: get or refresh a token |
| `src/commands/login.ts` | `POST <api>/api/auth/device`, `POST <api>/api/auth/device/token` | `shipguard login` |
| `src/commands/status.ts` | `GET <api>/api/user/me` | `shipguard status` |
| `src/commands/feedback.ts` | `POST <api>/api/feedback` | `shipguard feedback`, text you type |

`<api>` is `https://agenticcli.dev` unless you set another; calls that carry a token refuse any host that is not https on agenticcli.dev (`src/utils/trust.ts`).
