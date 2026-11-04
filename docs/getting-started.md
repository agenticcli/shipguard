# Getting started with ShipGuard

ShipGuard is a release gate for AI-built apps. This page gets you from zero to a first scan. For the full guide, see the [ShipGuard docs](https://agenticcli.dev/shipguard/docs).

## 1. Run a scan (no install, no account)

```bash
npx @agenticcli/shipguard scan
```

Run it from the root of your project. You need Node.js 20 or newer. The scan runs on your machine and prints a list of findings and a verdict.

## 2. Read the verdict

| Verdict | What it means |
|---------|---------------|
| `SAFE_TO_SHIP` | The scan finished and found nothing that blocks. |
| `REVIEW_BEFORE_SHIP` | The scan found things worth a look before you ship. |
| `DO_NOT_SHIP` | The scan found blocking issues, or it could not finish. |

Read the verdict from the `recommendation` field of `shipguard scan --json`. By default the exit code is `0` whenever the scan completes, so a script that only checks the exit code will not see a bad verdict. See [exit codes](exit-codes.md).

## 3. Install it (optional)

```bash
npm install -g @agenticcli/shipguard
shipguard scan
```

`npm install` without `-g` does not put `shipguard` on your PATH. Use `npx @agenticcli/shipguard` or the global install.

## 4. Make it stop a release

ShipGuard informs; you choose whether it blocks. Add `--strict` to make it exit `1` when the verdict is blocking:

```bash
shipguard scan --strict
```

Or let ShipGuard install the gate for you:

```bash
shipguard hook                    # git pre-push and pre-merge-commit hooks
shipguard hook --target claude    # Claude Code hook
shipguard hook --target ci        # GitHub Actions workflow
```

More on each option in [CI and agent setup](ci-setup.md).

## 5. Fix findings

Each finding has a title, the file and line, an explanation and a suggested fix. To skip a finding on purpose, add an inline comment: `// shipguard-ignore: <ruleId> -- <reason>`. To set project rules, run `shipguard init` to create a policy file.

## Next

- [What ShipGuard checks](checks.md)
- [FAQ](faq.md)
- [Privacy](privacy.md)
