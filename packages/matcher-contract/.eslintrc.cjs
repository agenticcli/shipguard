// packages/matcher-contract/.eslintrc.cjs
// ESLint v8 classic config (CJS extension required because package.json sets "type": "module").
//
// SCOPE: The `no-restricted-syntax` rule below is scoped to the re2js-v1 adapter
// (src/adapters/re2js-v1.ts) — the content-matching engine core.
//
// PURPOSE (Phase D.3 extension): Ban native JavaScript RegExp from the adapter's
// content-scanning code. The original D.3 ban covered the CLI `src/checks/**`; this
// extends the ban to the engine core so a regression like the requiresPattern/round-6
// gap (native RegExp on scanned file content) is caught at lint time.
//
// ALLOWLIST: Two narrow, documented exceptions exist inside re2js-v1.ts. Both are
// verified to NOT run against scanned user file content:
//
//   1. globToRegExp() — src/adapters/re2js-v1.ts:285–311
//      Uses new RegExp(regexStr) to match a TRUSTED CORPUS GLOB against
//      ctx.allRelativePaths (file path strings), not file content.
//      The regex literal /[+?^${}()|[\]\\]/ at line 301 tests a single
//      character from the GLOB PATTERN STRING — also not file content.
//
// Any new RegExp usage on the adapter content path must be converted to
// RE2JS.compile(pattern).matcher(input).find() before landing.

"use strict";

module.exports = {
  root: true,
  parser: "@typescript-eslint/parser",
  parserOptions: {
    ecmaVersion: 2022,
    sourceType: "module",
  },
  plugins: ["@typescript-eslint"],

  // Default: no rules for files outside the adapter
  rules: {},

  overrides: [
    // ── Phase D.3 (extended): native RegExp ban in the re2js-v1 adapter ──────
    //
    // Bans:
    //   • regex literals  — selector: Literal[regex]
    //   • new RegExp(...) — selector: NewExpression[callee.name='RegExp']
    //
    // NARROW ALLOWLIST — two sites in globToRegExp() are exempted because they
    // operate on file PATHS and GLOB STRINGS, NOT on scanned user file content.
    // The allowlist lines must be verified to remain non-content any time this
    // file is updated.
    {
      files: ["src/adapters/re2js-v1.ts"],
      rules: {
        "no-restricted-syntax": [
          "error",
          {
            selector: "Literal[regex]",
            message:
              "native RegExp literal banned in re2js-v1 adapter — use RE2JS.compile(pattern).matcher(input).find() for all content-scanning paths. See Phase D.3 extension.",
          },
          {
            selector: "NewExpression[callee.name='RegExp']",
            message:
              "native new RegExp() banned in re2js-v1 adapter — use RE2JS.compile(pattern).matcher(input).find() for all content-scanning paths. See Phase D.3 extension.",
          },
        ],
      },
    },

    // ── ALLOWLIST — globToRegExp() in re2js-v1.ts ────────────────────────────
    //
    // globToRegExp() uses native RegExp in two ways that are NOT content-scanning:
    //   1. A regex literal /[+?^${}()|[\]\\]/ to test a SINGLE CHAR from the
    //      glob PATTERN STRING (not file content). Line ~301.
    //   2. new RegExp(regexStr) to produce a RegExp for matching RELATIVE FILE
    //      PATHS (ctx.allRelativePaths), not file content. Line ~310.
    //
    // We cannot use ESLint disable-comments (they clutter the source and can
    // silence entire regions). Instead we re-scope the allowlist to a function
    // name via a selector trick: allow Literal[regex] and NewExpression inside
    // identifiers named globToRegExp. This is fragile by function-name but is
    // intentionally narrow — any rename of globToRegExp MUST update this rule.
    //
    // NOTE: ESLint v8 `no-restricted-syntax` does not support per-callsite
    // exceptions natively. The approved pattern here is to WIDEN the file scope
    // with a disable-comment at the function boundary — i.e. add a pair of
    //   /* eslint-disable no-restricted-syntax */
    //   /* eslint-enable  no-restricted-syntax */
    // AROUND the globToRegExp function body ONLY. The disable comment documents
    // the intent at the allowlist site and avoids silencing the whole file.
    //
    // The matching override below is a placeholder comment recording the decision;
    // the actual allowlist is implemented via eslint-disable comments in the source.
    // (This comment block intentionally has no functional override to avoid a broad
    //  file-level re-enable that defeats the purpose of the ban.)
    //
    // VERIFIED non-content sites (2026-06-25):
    //   re2js-v1.ts:285–311 — globToRegExp() body — glob → path match, not file content.
  ],
};
