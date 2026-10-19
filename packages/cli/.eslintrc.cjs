// packages/cli/.eslintrc.cjs
// ESLint v8 classic config (CJS extension required because package.json sets "type": "module").
//
// SCOPE: The `no-restricted-syntax` rule below is scoped ONLY to src/checks/**
// (content-scanning detectors). All other src/** directories (core, utils, etc.)
// are NOT covered by this prohibition and will not produce false positives.
//
// PURPOSE (Phase D.3): Ban native JavaScript RegExp from content-scanning detectors
// to prevent future ReDoS-able / engine-divergent patterns from creeping back in.
// Phase D.4 migration is COMPLETE — all 5 detector files now use re2js exclusively.
// The allowlist is empty; the ban is fully enforced across all of src/checks/**.

"use strict";

module.exports = {
  root: true,
  parser: "@typescript-eslint/parser",
  parserOptions: {
    ecmaVersion: 2022,
    sourceType: "module",
  },
  plugins: ["@typescript-eslint"],

  // Default: no rules active for the rest of src/** (core, utils, etc.)
  rules: {},

  overrides: [
    // ── Phase D.3: native RegExp ban in content-scanning detectors ────────────
    //
    // Rule targets src/checks/** (the five free-tier detectors).
    // Bans:
    //   • regex literals  — selector: Literal[regex]
    //   • new RegExp(...) — selector: NewExpression[callee.name='RegExp']
    //
    // Documented gap: string-method inline regexes (e.g. content.match(/foo/))
    // cannot be distinguished from non-content uses statically without type info.
    // The inventory shows these exist in all 5 detector files (see regex-inventory.yaml
    // string-method-regex entries); they are covered by the D.4 migration scope but
    // cannot be caught by this static rule. No false positives will fire for them.
    {
      files: ["src/checks/**/*.ts"],
      rules: {
        "no-restricted-syntax": [
          "error",
          {
            selector: "Literal[regex]",
            message:
              "native RegExp banned in content scanners — use the re2js MatcherContract engine (ReDoS-immune, engine-consistent). See D.4 migration.",
          },
          {
            selector: "NewExpression[callee.name='RegExp']",
            message:
              "native RegExp banned in content scanners — use the re2js MatcherContract engine (ReDoS-immune, engine-consistent). See D.4 migration.",
          },
        ],
      },
    },

    // ── TEMPORARY allowlist — D.4 migration COMPLETE ──────────────────────────
    //
    // All 5 detector files (secrets, deployment, payments, database, auth) have
    // been migrated to re2js. The allowlist is now EMPTY — the native RegExp ban
    // is fully enforced across all of src/checks/**. No overrides remain.
    //
    // secrets.ts:    D.4 complete (re2js engine, PR landed)
    // deployment.ts: D.4 complete (re2js + replaceFirst helper)
    // payments.ts:   D.4 complete (re2js engine)
    // database.ts:   D.4 complete (re2js + replace helper)
    // auth.ts:       D.4 complete (re2js engine)
  ],
};
