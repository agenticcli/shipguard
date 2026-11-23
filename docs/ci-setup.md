# CI and agent setup

Use the full scan with `--strict` in CI: `npx --yes @agenticcli/shipguard scan --json --strict`. It scans the whole checkout and exits `1` when the verdict is blocking. Do not use `--changed` in CI: on a clean checkout nothing differs from `HEAD`, so it reads no files: the result is degraded `NO_FILES_SCANNED` with `DO_NOT_SHIP` and `--strict` exits `1` (`coverage.changed.nothingToCheck` is `true`, `filesScanned` is `0`). That is never a pass for the project.

`--strict` needs no account.

## GitHub Actions

```yaml
name: ShipGuard security scan
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

## Codex and Cursor

These tools read an `AGENTS.md` file. Add this block so the agent runs ShipGuard itself:

```markdown
## ShipGuard
- ShipGuard is the security scanner for this repo. It runs on this machine; code never leaves it.
- Before every push or merge, run: npx --no-install @agenticcli/shipguard scan --json --strict
- Exit 0 means the scan completed: read "recommendation" in the JSON. Exit 1 means blocked: fix each finding with blocking:true, then scan again.
- Do not skip the hooks with --no-verify.
```

That command is for a project with ShipGuard as a devDependency (not on PATH). With a global install use `shipguard scan --json --strict`; `shipguard setup` writes the right one for you.

Guides: [Codex](https://agenticcli.dev/guides/codex) and [Cursor](https://agenticcli.dev/guides/cursor). Use CI as well: an instruction file asks an agent, CI enforces.

## Setup and uninstall

`shipguard setup` writes the right gate for your agent in one command. It lists every file first, asks you to confirm (an agent running it needs `--yes`), checks the result and tells you what the gate can and cannot stop.

```bash
shipguard setup --dry-run          # plan only; writes nothing
shipguard setup --agent claude     # project hook in .claude/settings.json + a managed block in CLAUDE.md
shipguard setup --agent codex      # a managed block in AGENTS.md + git pre-push and pre-merge-commit hooks
shipguard setup --agent cursor     # same as Codex (Cursor reads AGENTS.md)
shipguard setup --agent ci         # .github/workflows/shipguard.yml (Node 22)
shipguard uninstall --dry-run      # what would be removed and what stays; writes nothing
shipguard uninstall                # remove it
```

What each layer can stop:

| Layer | Strength |
|---|---|
| Instructions (CLAUDE.md or AGENTS.md block) | Advisory: the agent can ignore them. |
| Claude Code hook | Blocks `git push`, `git merge` and the GitHub CLI PR merge when run through Claude Code's Bash tool. Checks one commit, not the merged result. Skipped if the hook entry is removed or the host stops the hook. |
| Git hooks | Block `git push` and local `git merge` for people and agents. Skipped by `--no-verify`. They do not cover the GitHub CLI PR merge, which merges on GitHub. |
| CI check + branch protection | The only layer nothing local can skip, once branch protection requires the check. |

Setup records what it wrote in `.shipguard/installed.json`. `shipguard uninstall` removes only those files and blocks, leaves anything you edited by hand and names it, and keeps `shipguard.policy.yml` and `.shipguard/` (reports and history; `--purge` deletes them). It does not remove the npm package (`npm uninstall @agenticcli/shipguard`) or your sign-in (`shipguard logout`). `shipguard setup` may fetch one public offer document once (no project data, no login); it skips that when you are signed in, with `DO_NOT_TRACK`, or in safe mode.
