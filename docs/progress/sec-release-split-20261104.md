# sec-release-split-20261104

- Goal: no dependency code in the job that can publish (supply-chain judge M1 / A3b).
- Done: release.yml split into `build` (contents: read, `--ignore-scripts`, pack, artifact + sha256) and `publish` (id-token only, no checkout/install/cache, sha256 + version verify, then publish the tarball). Added .github/dependabot.yml (github-actions + npm, monthly, grouped, cooldown).
- Checked locally: yaml, shellcheck, build/lint/release-gate dry run, tarball identical with and without install scripts (only cli-facts generatedAt differs), publish-verify step pass/fail cases. Full suite: only load-induced timeouts, 70/70 pass on re-run.
- Not tested: the workflow on GitHub. First real tag should be a prerelease, watched.
- Owner settings: required reviewer on `npm-publish` environment; npm "Require two-factor authentication and disallow tokens"; Dependabot security updates on.
- PR: https://github.com/agenticcli/shipguard/pull/12 (draft)
