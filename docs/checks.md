# What ShipGuard checks

ShipGuard is a release gate, not a code reviewer and not a general security scanner. It looks for a small set of failures that AI coding tools introduce often. Checks are plain pattern rules (no AI model), so the same project gives the same result every time.

Five check groups are bundled in the CLI and run locally, with no account:

| Group | Looks for |
|-------|-----------|
| secrets | A `.env` file tracked in git; Stripe, AWS, OpenAI, Anthropic, GitHub, Google and Razorpay keys; JWT secrets; database URLs with a password; PEM private keys; high-entropy secrets; `NEXT_PUBLIC_` variables that hold secrets |
| auth | Unprotected routes and missing middleware |
| database | Destructive SQL in migrations (`DROP TABLE`, `DROP COLUMN`, `TRUNCATE`, `DELETE` without `WHERE`), and schema changes pushed without a migration |
| payments | Stripe and Razorpay webhooks that do not verify the signature |
| deployment | Wildcard CORS, debug mode, exposed environment values, missing security headers |

Findings are printed with a severity (info, low, medium, high, critical), the file and line, and a suggested fix. Secret values are shortened in all output.

## Rule matching

Rules are matched with RE2JS, a linear-time engine, so a bad pattern cannot hang a scan.

## Cloud scans

After `shipguard login`, `shipguard scan --pro` fetches the full current rule set from ShipGuard's servers. Rules come down; your code never goes up. See the [FAQ](faq.md) for plan limits.

## Full list

The complete rule list, with IDs, is on the [ShipGuard docs](https://agenticcli.dev/shipguard/docs).
