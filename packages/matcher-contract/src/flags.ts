// Strict flag enum for RE2-compatible regex flags.
// Only "i" (case-insensitive), "m" (multiline), and "s" (dotAll) are permitted.
// "g", "y", "u", "x" and any unknown or duplicate characters are rejected.
// Engine-level options (e.g. RE2JS.LOOKBEHINDS) are NOT represented here —
// they are kept separate in the adapter layer (Phase B / Task A.9).

/** The three flag characters permitted in the v1 contract. */
export type Flag = 'i' | 'm' | 's'

/** The superset of characters that LOOK like flags but are explicitly rejected. */
const REJECTED_CHARS: ReadonlySet<string> = new Set(['g', 'y', 'u', 'x'])

/**
 * Parse and validate a flag string produced by Gate B / Gate C / the rule schema.
 *
 * Accepts:
 *   - Empty string ("") — no flags.
 *   - Any combination of "i", "m", "s" with no duplicates.
 *
 * Rejects (returns ok=false with a human-readable reason):
 *   - "g", "y", "u", "x" — JS-only / unsupported flags.
 *   - Any other unknown character.
 *   - Duplicate characters (e.g. "ii", "ig").
 *
 * @param input - The raw flags string from a rule definition.
 * @returns A discriminated result: ok=true with a Set<Flag>, or ok=false with a reason string.
 */
export function parseFlags(
  input: string,
): { ok: true; flags: Set<Flag> } | { ok: false; reason: string } {
  const seen = new Set<string>()

  for (const ch of input) {
    if (seen.has(ch)) {
      return { ok: false, reason: `Duplicate flag character: "${ch}" (input: "${input}")` }
    }
    seen.add(ch)

    if (REJECTED_CHARS.has(ch)) {
      return {
        ok: false,
        reason: `Unsupported flag: "${ch}" — only "i", "m", "s" are permitted (got: "${input}")`,
      }
    }

    if (ch !== 'i' && ch !== 'm' && ch !== 's') {
      return {
        ok: false,
        reason: `Unknown flag character: "${ch}" — only "i", "m", "s" are permitted (got: "${input}")`,
      }
    }
  }

  return { ok: true, flags: new Set(seen as Set<Flag>) }
}
