# ShipGuard — repo rules
This file adds rules and context for this repo.

## Stakes & Status
- Paying users: yes, through Pro (the paid rulebook is served by the platform, not from this repo) · Payments: no (none in this repo) · User data: no code or file data (scans run locally; only product usage telemetry with a random install ID, no code, paths or file contents; opt-out)
- High-stakes paths: `packages/cli/src/core/crypto.ts`, `packages/cli/src/core/auth.ts`, `packages/cli/src/core/jwks.ts`, `packages/cli/src/core/release-verify.ts`.

## Rules
- DON'T send scanned file content, file paths or secrets to any server; scans stay 100% local.
- DON'T commit secrets, tokens or private keys, and DON'T print them in CLI output or logs.
- DO keep CLI checks pure functions, (files, policy) → findings, with no side effects.
- DON'T add AST parsing or LLM/AI dependencies; DO use deterministic regex and string matching.
- DO keep the exit codes: 0 = scan completed (read the JSON `recommendation` field, not "safe"); 1 = blocked only with `--strict`; 2 = config error; 3 = runtime error.
- DO keep `--json` machine-readable output working; agents depend on it.
- DO run `pnpm lint` and `pnpm test` before opening a PR, and add a regression test with every bugfix.
- DON'T remove a test to make a change pass.

## Context
- What: ShipGuard by AgenticCLI, the security scanner your coding agent runs before every commit. It checks a project, on your machine, for leaked secrets, unprotected routes, risky database migrations, unverified webhooks and deploy mistakes. Tagline: "Check code against a rulebook before you ship".
- Stack: TypeScript, Commander.js, Vitest, tsup, pnpm workspaces (`packages/cli`, `packages/shared`, `packages/matcher-contract`).
- Licence: Apache-2.0; see `LICENSE`, `NOTICE` and `TRADEMARKS.md`. Contributing: `CONTRIBUTING.md`. Security reports: `SECURITY.md`.
