# ShipGuard by AgenticCLI

**The security scanner your coding agent runs before every commit. On your machine. Flat price, no seats.**

Same code, same answer. Review code with a rulebook to build secure code.

[![npm version](https://img.shields.io/npm/v/@agenticcli/shipguard)](https://www.npmjs.com/package/@agenticcli/shipguard)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache--2.0-blue.svg)](LICENSE)
[![Node.js 20+](https://img.shields.io/node/v/@agenticcli/shipguard)](https://www.npmjs.com/package/@agenticcli/shipguard)
[![CI](https://github.com/agenticcli/shipguard/actions/workflows/ci.yml/badge.svg)](https://github.com/agenticcli/shipguard/actions/workflows/ci.yml)

Your agent already shipped it. Did it just re-break it? Long agent sessions quietly regress the app that makes you money. ShipGuard is a security scanner that runs after each change your coding agent makes. It checks your project for leaked secrets, unprotected routes, risky database migrations, unverified payment webhooks and unsafe deploy settings. It runs on your machine and gives the same answer every time. Rules come down; your code never goes up. Learn more on the [ShipGuard product page](https://agenticcli.dev/shipguard).

**Who it is for:** SaaS founders with paying customers, shipping with Claude Code, Codex and Cursor, without a security team.

**Open source CLI. Your code never leaves your machine.** ShipGuard sends only product usage telemetry (no code, no file paths, no file contents) to help us understand how people use it and make the next release better. You can switch it off any time: `shipguard telemetry disable` or `DO_NOT_TRACK=1`. [What is sent](docs/privacy.md)

## Quickstart

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

## Set it up for your agent

```bash
shipguard setup --dry-run              # list every file it would write; writes nothing
shipguard setup --agent claude         # Claude Code: a project hook plus a short block in CLAUDE.md
shipguard setup --agent codex          # Codex or Cursor: a block in AGENTS.md plus git hooks
shipguard setup --agent ci             # a GitHub Actions workflow
shipguard uninstall                    # remove what setup wrote, and name what stays
```

Setup lists every file before it writes and asks you to confirm (an agent running it needs `--yes`). What each layer can and cannot stop is in [CI and agent setup](docs/ci-setup.md#setup-and-uninstall). `shipguard uninstall` removes only what setup wrote and you have not edited, and prints what it left behind.

## Example output

A real run on a small demo project that has a live Stripe key in a committed `.env` file and an unprotected admin route (output shortened):

```text
   CRITICAL  🛑 1 finding
    Stripe Live Secret Key — .env:1 [low false-positive chance]

   HIGH      ⛔ 3 findings
    .env file tracked in git — .env [low false-positive chance]
    No Next.js middleware.ts found — middleware.ts [moderate — review]
    Unprotected API route handler: app/api/admin/route.ts [moderate — review]

⛔ DO NOT SHIP  score=100/100  findings=5  blocking=4  (informational — exit 0; use --strict to enforce)
```

Secret values are masked in the output. Add `--json` for the same result as data: read the verdict from the `recommendation` field.

## Contents

- [Getting started](docs/getting-started.md)
- [What it checks](docs/checks.md)
- [CI and agent setup](docs/ci-setup.md) (GitHub Actions, GitLab, Claude Code, Codex, Cursor)
- [Exit codes and JSON output](docs/exit-codes.md)
- [Privacy](docs/privacy.md)
- [FAQ](docs/faq.md)
- [Support](SUPPORT.md), [Contributing](CONTRIBUTING.md), [Security policy](SECURITY.md)
- [llms.txt](packages/cli/docs/llms.txt) (a plain-text summary for AI tools)
- [Changelog](packages/cli/CHANGELOG.md)

## What it checks

Five check groups run locally and are bundled in the CLI:

- **Secrets**: committed `.env` files, and keys such as Stripe, AWS, OpenAI, Anthropic, GitHub and Google, private key blocks, database URLs with passwords, and secrets exposed through `NEXT_PUBLIC_` variables.
- **Auth**: unprotected routes and missing middleware.
- **Database**: destructive SQL in migrations.
- **Payments**: missing Stripe and Razorpay webhook verification.
- **Deployment**: risky config such as open CORS, debug mode and exposed environment values.

ShipGuard is a focused security scanner, not a full SAST tool and not a code reviewer. Its checks are plain pattern rules (no AI model involved), so results are repeatable. It also runs in CI.

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

## Use with pre-commit

Add ShipGuard to `.pre-commit-config.yaml` (needs Node.js 20 or newer on your PATH):

```yaml
repos:
  - repo: https://github.com/agenticcli/shipguard
    rev: main   # pin to a commit or tag you trust
    hooks:
      - id: shipguard
```

The hook runs `npx -y @agenticcli/shipguard scan --strict` on the whole project and fails the commit when ShipGuard blocks. Test it with `pre-commit run shipguard --all-files`. See [pre-commit hooks](https://pre-commit.com/#new-hooks).

## FAQ

**What is ShipGuard?** A command-line security scanner that your coding agent runs before every commit (it also runs in CI). One command checks for leaked secrets, unprotected routes, destructive database migrations, unverified payment webhooks and risky deploy settings before you ship.

**Is it a security scanner or a code reviewer?** A security scanner, not a code reviewer. It is a fixed set of plain pattern rules that run locally and give the same answer every time. It does not use an AI model and it does not read your code for design problems.

**Does my code leave my machine?** No. Rules come down; your code never goes up. See [Privacy](#privacy).

**Do I need an account?** No. Local scans need no account and are free and unlimited. Pro adds rulebook scans with the full rulebook; what Pro includes is on the [pricing page](https://agenticcli.dev/pricing).

**Which AI coding tools does it work with?** It is a normal command, so it works with Claude Code, Codex and Cursor, and in any CI. See [CI and agent setup](docs/ci-setup.md).

**Why did my CI job pass when ShipGuard found problems?** Without `--strict` the exit code is `0` whenever the scan completes. Use `--strict`, or read `recommendation` in the JSON. See [exit codes](docs/exit-codes.md).

More answers: [docs/faq.md](docs/faq.md). Questions and ideas: [GitHub Discussions](https://github.com/agenticcli/shipguard/discussions).

## Plans

Local scans are free and unlimited, with no account, and `--strict` needs no account. Pro (sign in with `shipguard login`, then `shipguard scan --pro`) adds rulebook scans with the full current rulebook. What Pro includes, and what it costs, is shown by `shipguard status` and on the [plans and pricing](https://agenticcli.dev/pricing) page; this repository does not list prices or counts.

## Privacy

ShipGuard checks your code on your machine. A local scan uses the rules built into the CLI. A rulebook scan (after `shipguard login`) first downloads the full current rulebook, then checks your code the same way, on your machine. Rules come down; your code never goes up: file contents, paths and secrets are never uploaded. The only data sent is small product usage telemetry, plus two small requests that carry no code: a signed-out terminal scan may ask once a week for the public rule counts of your detected stack names (nothing else), and `shipguard status` reads your account and plan. Hooks, CI, `--quiet` and safe mode (`--safe-mode`) make no offer request. The full list of calls, with file names, is in [REBUILD.md](REBUILD.md). Published builds send a small pseudonymous message after a scan, once on first run, and after `shipguard login`. The first-run and login messages carry 7 keys: `schema`, `event`, `eventId`, `installId` (random), `cliVersion`, `provenance` and `ci`. The scan message carries 12: `schema`, `eventId`, `installId`, `cliVersion`, `provenance`, `verdict`, `durationBucket`, `ci`, `agent` (which coding agent ran it, as a label), `interactive`, `output` and `gateKind` (`claude`, `git`, `ci` or `none`: which gate ran the scan). An optional `traffic` label is added only if you set `SHIPGUARD_TRAFFIC`. Turn all telemetry off with `shipguard telemetry disable`, `SHIPGUARD_TELEMETRY=0`, `DO_NOT_TRACK=1` or `telemetry: { enabled: false }` in your policy file. Details: [docs/privacy.md](docs/privacy.md).

---

Rebuild the published package from its tag, and see every network call with file names: [REBUILD.md](REBUILD.md).

## Exit codes

ShipGuard is triggered by an agent, a script, or a human — the exit code is
**verdict-neutral by default**: ShipGuard *informs*, you choose whether to
hard-gate on it. The verdict always lives in the JSON `recommendation` field
(plus `degraded`/`degradedReasons` for a partial scan) — never infer it from
the exit code alone.

| Code | Meaning |
|------|---------|
| `0` | Scan completed. Verdict is in the JSON `recommendation` field — returned even if findings are blocking, and even if the scan is degraded/partial. Not "safe": with blocking findings and no `--strict`, the output ends with `exit 0 = scan finished, not safe. Add --strict to fail on blocking findings.` (`--json`: `exitMeaning`). |
| `1` | Blocked — **only** with `--strict`: a blocking finding, a scan that did not finish (`degraded`), or a `DO_NOT_SHIP` verdict (the opt-in hard gate). |
| `2` | Config error, strictly (bad policy file, bad flags, non-project directory). Never reused for a degraded-but-completed scan. |
| `3` | Runtime error — the scan could not meaningfully run at all. |

Want a hard CI gate? Use `shipguard scan --strict` (exit 1 on blocking findings).
Want to just read the verdict? Use `shipguard scan --json` and check `recommendation` — exit code is always 0 unless you passed `--strict`, or hit a config/runtime error.

---

## License

[Apache License 2.0](LICENSE). Use it, change it and share it, including commercially. See [NOTICE](NOTICE). The ShipGuard and AgenticCLI names and logos are not part of the license: see [TRADEMARKS.md](TRADEMARKS.md). Contributions are welcome under the terms in [CONTRIBUTING.md](CONTRIBUTING.md). Plans are on the [pricing page](https://agenticcli.dev/pricing).

---

## Links

- Product page: [ShipGuard product page](https://agenticcli.dev/shipguard)
- Company site: [AgenticCLI](https://agenticcli.dev/)
- Docs: [agenticcli.dev/shipguard/docs](https://agenticcli.dev/shipguard/docs)
- Pricing: [agenticcli.dev/pricing](https://agenticcli.dev/pricing)
- npm: [@agenticcli/shipguard](https://www.npmjs.com/package/@agenticcli/shipguard)
- Issues: [github.com/agenticcli/shipguard/issues](https://github.com/agenticcli/shipguard/issues)
- Questions and ideas: [GitHub Discussions](https://github.com/agenticcli/shipguard/discussions)
- Help, billing, bugs and security reports: support@agenticcli.dev
- General and press: contact@agenticcli.dev
