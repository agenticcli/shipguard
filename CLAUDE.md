# ShipGuard — repo rules
Master rules load from the owner's user-level CLAUDE.md. This file adds rules and context for this repo only.

## Stakes & Status
- Paying users: yes, through Pro on the hosted service (not in this repo) · Payments: no (none in this repo) · User data: no (scans run locally and never send code off the machine) (recorded 2026-10-21, proposed — owner confirms)
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
- What: ShipGuard, a CLI-first release gate for AI-built apps; it catches secrets, auth gaps and deployment issues before they ship.
- Stack: TypeScript, Commander.js, Vitest, tsup, pnpm workspaces (`packages/cli`, `packages/shared`, `packages/matcher-contract`).
- Licence: Elastic License 2.0 (source-available); see `LICENSE`. Security reports: `SECURITY.md`.
