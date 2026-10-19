/**
 * Links the CLI PRINTS for people to follow (terminal output, help, error hints).
 *
 * They are short links, https://agenticcli.dev/go/<slot>, because the CLI draws boxes 78 columns wide and a full UTM query
 * (about 85 characters) would not fit. The website redirects each slot to the real page WITH the tags
 * utm_source=shipguard_cli, utm_medium=cli, utm_campaign=shipguard_evergreen, utm_content=<slot>
 * (agenticcli repo: apps/web/lib/go-links.mjs and analytics-registry/utm-surfaces.json), so a visit from a terminal is credited
 * to the CLI in PostHog instead of landing in Direct.
 *
 * KEEP THE SLOT LIST IN SYNC with apps/web/lib/go-links.mjs: a slot printed here that the site does not redirect is a dead link
 * in every user's terminal. The site must carry a slot BEFORE a CLI release prints it.
 *
 * NOT for API calls: login, scan, rule fetch and JWKS use the API base URL (core/auth.ts, core/jwks.ts) and are never tagged.
 */
export const GO_SLOTS = ['docs', 'site', 'pricing', 'billing', 'dashboard', 'telemetry'] as const
export type GoSlot = (typeof GO_SLOTS)[number]

const GO_BASE = 'https://agenticcli.dev/go/'

/** The short link for a slot, e.g. goLink('docs') -> https://agenticcli.dev/go/docs */
export function goLink(slot: GoSlot): string {
  return `${GO_BASE}${slot}`
}
