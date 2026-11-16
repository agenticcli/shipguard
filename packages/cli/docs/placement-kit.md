# ShipGuard placement kit

Copy-paste blocks for the three places ShipGuard needs to exist: your agent's instructions,
your Claude Code project config, and CI.

**The rule that makes the rest make sense:** a snippet TEACHES, a hook ENFORCES. Text in a
repo file is advice a model can talk itself out of — agents have been observed using
`git commit --no-verify` across consecutive commits despite explicit deny rules. So put the
snippet in for understanding, and install the hook for enforcement:

```
shipguard hook                    # git pre-push + pre-merge-commit
shipguard hook --target claude    # runs outside the model — the agent can't route around it
shipguard hook --target ci        # server-side — nothing local can skip it
```

---

## 1. `AGENTS.md` snippet

Paste this into your repo's `AGENTS.md`. Most coding agents read that file; **Claude Code
does not**, which is why section 2 exists as well — an `AGENTS.md`-only setup leaves those
callers uncovered.

```markdown
## Release gate — ShipGuard

Before you merge, push, or tell the user something is ready to ship, run:

    shipguard scan --json --strict

Exit code 0 does NOT mean "safe". It means "the scan ran". Read the JSON:

- `recommendation` is the verdict: `SAFE_TO_SHIP`, `REVIEW_BEFORE_SHIP`, or `DO_NOT_SHIP`.
- `degraded: true` means the scan could not check everything. The verdict is then always
  `DO_NOT_SHIP`, and `degradedReasons[].code` says why. Fix the cause; do not ship past it.
- With `--strict`, exit 1 means blocked — by a blocking finding OR by an unfinished scan.

Never report a scan as passing on the exit code alone. Never pass `--no-verify` to get
around a ShipGuard hook.

Run `shipguard schema --json` for the full contract: verdict values, exit-code meanings,
and this project's scan limits.
```

---

## 2. `CLAUDE.md` import line

Claude Code reads `CLAUDE.md`, not `AGENTS.md`. Add this one line so the same instructions
load for Claude Code sessions without maintaining two copies:

```markdown
@AGENTS.md
```

If you would rather not import the whole file, paste the section-1 block directly into
`CLAUDE.md` instead. Either way, remember section 2 only teaches — run
`shipguard hook --target claude` to make it binding.

---

## 3. GitHub Actions verdict job

`shipguard hook --target ci` writes this file for you at
`.github/workflows/shipguard.yml`. It is reproduced here so you can review it before
installing, or add it by hand:

```yaml
name: ShipGuard release gate

on:
  pull_request:
  push:
    branches: [main]

jobs:
  shipguard:
    name: ShipGuard verdict
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: '20'
      - name: Run the release gate
        run: npx --yes @agenticcli/shipguard scan --json --strict
```

Turn on branch protection for the **ShipGuard verdict** check. Without it the job is
advisory: a red check that nothing requires is a suggestion, not a gate.

---

## Which layer binds whom

| Layer | Binds humans | Binds agents | Skippable |
|---|---|---|---|
| `AGENTS.md` / `CLAUDE.md` snippet | teaches | teaches | entirely — it is text |
| git hook (`shipguard hook`) | yes | only well-behaved ones | `--no-verify` |
| Claude Code hook (`--target claude`) | n/a | yes — runs outside the model | only by editing the settings file |
| CI job + branch protection (`--target ci`) | yes | yes | no |

Install all three where you can. ShipGuard never blocks on its own — that is the point of
the passive default. Installing a hook is the deliberate act that turns the hard stop on.
