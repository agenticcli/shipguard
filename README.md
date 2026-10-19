# ShipGuard

**CLI-first release gate for AI-built apps.**

ShipGuard catches secrets, auth gaps, and deployment issues before they ship — deterministic, fast, and **your code never leaves your machine**.

[![npm](https://img.shields.io/npm/v/@agenticcli/shipguard)](https://www.npmjs.com/package/@agenticcli/shipguard)
[![License: Elastic-2.0](https://img.shields.io/badge/License-Elastic--2.0-blue.svg)](https://www.elastic.co/licensing/elastic-license)

---

## Why ShipGuard?

AI coding tools (Cursor, Copilot, Claude Code) write production code fast — sometimes too fast. ShipGuard is the last safety check before you push: a deterministic, regex-based scanner that catches the failure classes AI agents introduce most often.

- **Your code never leaves your machine.** 100% local scan — no file content, no paths, no secrets are ever sent to a server.
- **Zero install required.** `npx @agenticcli/shipguard scan` — works in CI with no setup.
- **Source-available under the Elastic License 2.0.** The source is public so you can audit exactly what runs in your repo. It is not an OSI-approved open-source license.
- **Pro rules** add deeper AI-targeted checks, served encrypted and verified via Ed25519 signature.

---

## Quick start

```bash
# Zero-install scan (no login required)
npx @agenticcli/shipguard scan

# Install globally
npm install -g @agenticcli/shipguard

# Scan current project — verdict is in the JSON `recommendation` field
shipguard scan

# CI hard gate — exit 1 if blocking findings exist (opt-in)
shipguard scan --strict

# Machine-readable output for agents
shipguard scan --json

# Sign in to scan against the full current rule corpus
# (offline scans use the bundled subset and need no account)
shipguard login
shipguard scan --pro
```

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
| `1` | Blocked — **only** with `--strict` and at least one blocking finding (the opt-in hard gate). |
| `2` | Config error, strictly (bad policy file, bad flags, non-project directory). Never reused for a degraded-but-completed scan. |
| `3` | Runtime error — the scan could not meaningfully run at all. |

Want a hard CI gate? Use `shipguard scan --strict` (exit 1 on blocking findings).
Want to just read the verdict? Use `shipguard scan --json` and check `recommendation` — exit code is always 0 unless you passed `--strict`, or hit a config/runtime error.

---

## License

[Elastic License 2.0](LICENSE) — free to use commercially; you may not offer ShipGuard as a hosted/managed service or resell it. See [agenticcli.dev/pricing](https://agenticcli.dev/pricing) for Pro.

---

## Links

- Site: [agenticcli.dev](https://agenticcli.dev)
- Docs: [agenticcli.dev/docs](https://agenticcli.dev/docs)
- Pricing / Pro: [agenticcli.dev/pricing](https://agenticcli.dev/pricing)
- Issues: [github.com/agenticcli/shipguard/issues](https://github.com/agenticcli/shipguard/issues)
