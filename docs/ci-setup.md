# CI and agent setup

Use the full scan with `--strict` in CI: `npx --yes @agenticcli/shipguard scan --json --strict`. It scans the whole checkout and exits `1` when the verdict is blocking. Do not use `--changed` in CI: on a clean checkout nothing differs from `HEAD`, so it reads no files (and a scan that reads nothing is reported as `DO_NOT_SHIP`).

`--strict` is free on every plan.

## GitHub Actions

```yaml
name: ShipGuard release gate
on:
  pull_request:
  push:
    branches: [main]
jobs:
  shipguard:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: '20'
      - run: npx --yes @agenticcli/shipguard scan --json --strict
```

`shipguard hook --target ci` writes this file to `.github/workflows/shipguard.yml`. Turn on branch protection for the check so it blocks merges. For GitHub Code Scanning, `shipguard scan --sarif` produces SARIF 2.1.0.

## GitLab CI

```yaml
shipguard:
  image: node:20
  script:
    - npx --yes @agenticcli/shipguard scan --json --strict
```

## Any other CI

Any runner with Node.js 20 or newer works. Run the same command as a step and let a non-zero exit code fail the job.

## Git hook

```bash
shipguard hook
```

Installs `pre-push` and `pre-merge-commit` hooks that run `shipguard scan --json --strict`. A hook binds people and well-behaved agents only: `git push --no-verify` skips it. Use CI as the check nobody can skip.

## Claude Code

```bash
shipguard hook --target claude
```

Adds a Claude Code hook in `.claude/settings.json` that runs the check before the agent runs `git push` or `git merge`. The hook runs outside the model, so the agent cannot talk its way past it. Guide: [ShipGuard with Claude Code](https://agenticcli.dev/guides/claude-code).

## Codex CLI and Cursor

These tools read an `AGENTS.md` file. Add this block so the agent runs the gate itself:

```markdown
## ShipGuard
- ShipGuard is the release gate for this repo. It runs locally; code never leaves this machine.
- Before every push or merge, run: shipguard scan --json --strict
- Exit 0 means the scan completed: read "recommendation" in the JSON. Exit 1 means blocked: fix each finding with blocking:true, then scan again.
- Do not skip the hooks with --no-verify.
```

Guides: [Codex](https://agenticcli.dev/guides/codex) and [Cursor](https://agenticcli.dev/guides/cursor). Use CI as well: an instruction file asks an agent, CI enforces.
