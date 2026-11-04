# ShipGuard

**A release gate for AI-built apps. Run one command before you ship.**

[![npm version](https://img.shields.io/npm/v/@agenticcli/shipguard)](https://www.npmjs.com/package/@agenticcli/shipguard)
[![License: Elastic-2.0](https://img.shields.io/badge/License-Elastic--2.0-blue.svg)](LICENSE)

ShipGuard is a command-line tool from AgenticCLI. It checks your project for leaked secrets, unprotected routes, risky database migrations, unverified payment webhooks and unsafe deploy settings. It runs on your machine, gives the same answer every time, and your code never leaves your computer. Learn more on the [ShipGuard product page](https://agenticcli.dev/shipguard).

It is built for people who ship real apps with AI coding agents (Claude Code, Codex CLI, Cursor) and want a fast, predictable check before code goes live. It gives a verdict and a list of findings; you decide what blocks a release.

## Quickstart (30 seconds)

```bash
npx @agenticcli/shipguard scan
```

No install and no account. You get a list of findings and a verdict: `SAFE_TO_SHIP`, `REVIEW_BEFORE_SHIP` or `DO_NOT_SHIP`.

```bash
npm install -g @agenticcli/shipguard   # optional: install globally
shipguard scan --json                  # machine-readable output for agents and scripts
shipguard scan --strict                # exit 1 if the scan blocks (opt-in hard gate)
shipguard hook --target ci             # write a GitHub Actions workflow for you
```

## Contents

- [Getting started](docs/getting-started.md)
- [What it checks](docs/checks.md)
- [CI and agent setup](docs/ci-setup.md) (GitHub Actions, GitLab, Claude Code, Codex, Cursor)
- [Exit codes and JSON output](docs/exit-codes.md)
- [Privacy](docs/privacy.md)
- [FAQ](docs/faq.md)
- [Changelog](packages/cli/CHANGELOG.md)

## What it checks

Five check groups run locally and are bundled in the CLI:

- **Secrets**: committed `.env` files, and keys such as Stripe, AWS, OpenAI, Anthropic, GitHub and Google, private key blocks, database URLs with passwords, and secrets exposed through `NEXT_PUBLIC_` variables.
- **Auth**: unprotected routes and missing middleware.
- **Database**: destructive SQL in migrations.
- **Payments**: missing Stripe and Razorpay webhook verification.
- **Deployment**: risky config such as open CORS, debug mode and exposed environment values.

ShipGuard is a release gate, not a code reviewer and not a general security scanner. Its checks are plain pattern rules (no AI model in the loop), so results are repeatable.

## Use it in CI

Add this step to a GitHub Actions job. It scans the whole checkout and fails the job when ShipGuard blocks:

```yaml
- uses: actions/checkout@v4
- uses: actions/setup-node@v4
  with:
    node-version: 20
- run: npx --yes @agenticcli/shipguard scan --json --strict
```

`shipguard hook --target ci` writes this workflow for you. `shipguard hook` also installs a git hook, and `shipguard hook --target claude` adds a Claude Code hook. Setup for GitLab, Claude Code, Codex and Cursor is in [CI and agent setup](docs/ci-setup.md).

## Free and Pro

Local scans are free and unlimited, with no account, and `--strict` is free on every plan. Signing in (`shipguard login`, then `shipguard scan --pro`) adds cloud scans with the full current rule set: Free has 5 a month, Plus ($19/mo) 10, Pro ($29/mo, or $19/mo billed yearly) 100. See [plans and pricing](https://agenticcli.dev/pricing).

## Privacy

Scans run 100% on your machine. No file contents, paths or secrets are sent to a server. Published builds send a small anonymous ping after a scan, once on first run, and after `shipguard login`. The first-run and login pings carry 7 keys: `schema`, `event`, `eventId`, `installId` (random), `cliVersion`, `provenance` and `ci`. The scan ping carries 8: `schema`, `eventId`, `installId`, `cliVersion`, `provenance`, `verdict`, `durationBucket` and `ci`. An optional `traffic` label is added only if you set `SHIPGUARD_TRAFFIC`. Turn all pings off with `shipguard telemetry disable`, `SHIPGUARD_TELEMETRY=0`, `DO_NOT_TRACK=1` or `telemetry: { enabled: false }` in your policy file. Details: [docs/privacy.md](docs/privacy.md).

---

## Exit codes

ShipGuard is triggered by an agent, a script, or a human — the exit code is
**verdict-neutral by default**: ShipGuard *informs*, you choose whether to
hard-gate on it. The verdict always lives in the JSON `recommendation` field
(plus `degraded`/`degradedReasons` for a partial scan) — never infer it from
the exit code alone.

| Code | Meaning |
|------|---------|
| `0` | Scan completed. Verdict is in the JSON `recommendation` field — returned even if findings are blocking, and even if the scan is degraded/partial. |
| `1` | Blocked — **only** with `--strict`: a blocking finding, a scan that did not finish (`degraded`), or a `DO_NOT_SHIP` verdict (the opt-in hard gate). |
| `2` | Config error, strictly (bad policy file, bad flags, non-project directory). Never reused for a degraded-but-completed scan. |
| `3` | Runtime error — the scan could not meaningfully run at all. |

Want a hard CI gate? Use `shipguard scan --strict` (exit 1 on blocking findings).
Want to just read the verdict? Use `shipguard scan --json` and check `recommendation` — exit code is always 0 unless you passed `--strict`, or hit a config/runtime error.

---

## License

[Elastic License 2.0](LICENSE) — free to use commercially; you may not offer ShipGuard as a hosted/managed service or resell it. See the [pricing page](https://agenticcli.dev/pricing) for Pro.

---

## Links

- Product page: [ShipGuard release gate](https://agenticcli.dev/shipguard)
- Company site: [AgenticCLI](https://agenticcli.dev/)
- Docs: [agenticcli.dev/shipguard/docs](https://agenticcli.dev/shipguard/docs)
- Pricing / Pro: [agenticcli.dev/pricing](https://agenticcli.dev/pricing)
- Issues: [github.com/agenticcli/shipguard/issues](https://github.com/agenticcli/shipguard/issues)
- Help, billing, bugs and security reports: support@agenticcli.dev
- General and press: contact@agenticcli.dev
