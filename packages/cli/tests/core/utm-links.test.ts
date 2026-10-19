/**
 * Every link to https://agenticcli.dev that this repo hands to a person must be tagged (founder decision 2026-10-18).
 *
 *  - Text the CLI prints uses SHORT links, https://agenticcli.dev/go/<slot> (core/links.ts): a full UTM query does not fit in the
 *    78-column boxes. The site redirects each slot to the real page with utm_source=shipguard_cli, utm_medium=cli,
 *    utm_campaign=shipguard_evergreen (agenticcli repo: apps/web/lib/go-links.mjs).
 *  - Links in READMEs and package.json carry the full tags, one source per surface:
 *      README.md                github_readme  / repo    / shipguard_evergreen
 *      packages/cli/README.md   npm_readme     / package / shipguard_evergreen
 *      package.json homepage    npm_homepage   / package / shipguard_evergreen
 *  - API calls (login, scan, rule fetch, JWKS, the --api-url default) are NEVER tagged: they are not links a person follows.
 *
 * Scheme: analytics-registry/utm-surfaces.json in the agenticcli repo.
 */
import { describe, it, expect } from 'vitest'
import { readFileSync, readdirSync, statSync } from 'node:fs'
import { join, relative, resolve } from 'node:path'
import { GO_SLOTS, goLink } from '../../src/core/links.js'

const ROOT = resolve(__dirname, '../../../..')
const read = (rel: string) => readFileSync(join(ROOT, rel), 'utf8')
const URL_RE = /https?:\/\/(?:www\.)?agenticcli\.dev[^\s'"`)\]<>,]*/g

/** Lines in src/ that are API endpoints, trust anchors or comments, not links a person follows. */
const API_LINE = [
  /DEFAULT_API_URL\s*=/,
  /JWKS_URL\s*=/,
  /\.option\('--api-url/,
  /^\s*(\*|\/\/)/, // comments
]

function walk(dir: string): string[] {
  return readdirSync(dir).flatMap((n) => {
    const p = join(dir, n)
    return statSync(p).isDirectory() ? walk(p) : p.endsWith('.ts') ? [p] : []
  })
}

function missingTags(url: string, required: Record<string, string>): string[] {
  const q = new URL(url).searchParams
  return Object.entries(required).filter(([k, v]) => q.get(k) !== v).map(([k, v]) => `${k}=${v}`)
}

describe('goLink', () => {
  it('has the six slots the site redirects', () => {
    expect([...GO_SLOTS].sort()).toEqual(['billing', 'dashboard', 'docs', 'pricing', 'site', 'telemetry'])
  })
  it('builds https://agenticcli.dev/go/<slot>, short enough for the 78-column boxes', () => {
    for (const s of GO_SLOTS) {
      expect(goLink(s)).toBe(`https://agenticcli.dev/go/${s}`)
      expect(goLink(s).length).toBeLessThan(40)
    }
  })
})

describe('text the CLI prints (packages/cli/src)', () => {
  // links.ts is the one place that spells the /go/ base; everything else must go through goLink()
  const files = walk(join(ROOT, 'packages/cli/src')).filter((f) => !f.endsWith('src/core/links.ts'))

  it('every agenticcli.dev link is a /go/<known slot> short link, except API endpoints and comments', () => {
    const bad: string[] = []
    for (const f of files) {
      read(relative(ROOT, f))
        .split('\n')
        .forEach((line, i) => {
          if (API_LINE.some((re) => re.test(line))) return
          for (const m of line.matchAll(URL_RE)) {
            const m2 = /^https:\/\/agenticcli\.dev\/go\/([a-z]+)$/.exec(m[0])
            if (!m2 || !(GO_SLOTS as readonly string[]).includes(m2[1])) {
              bad.push(`${relative(ROOT, f)}:${i + 1} ${m[0]}`)
            }
          }
        })
    }
    expect(bad, `untagged links printed by the CLI (use goLink('<slot>')):\n${bad.join('\n')}`).toEqual([])
  })

  it('the detector bites: an untagged printed link is found', () => {
    const line = "console.log('Docs https://agenticcli.dev/docs')"
    const hits = [...line.matchAll(URL_RE)].filter((m) => !/\/go\/[a-z]+$/.test(m[0]))
    expect(hits).toHaveLength(1)
  })
})

describe('README and package.json links', () => {
  const surfaces: Array<[string, Record<string, string>]> = [
    ['README.md', { utm_source: 'github_readme', utm_medium: 'repo', utm_campaign: 'shipguard_evergreen' }],
    ['packages/cli/README.md', { utm_source: 'npm_readme', utm_medium: 'package', utm_campaign: 'shipguard_evergreen' }],
  ]
  it.each(surfaces)('%s: every agenticcli.dev link carries the full tags', (rel, required) => {
    const bad: string[] = []
    read(rel).split('\n').forEach((line, i) => {
      for (const m of line.matchAll(URL_RE)) {
        const miss = missingTags(m[0], required)
        if (miss.length) bad.push(`${rel}:${i + 1} ${m[0]} needs ${miss.join(', ')}`)
      }
    })
    expect(bad).toEqual([])
  })

  it('packages/cli/package.json homepage carries the npm_homepage tags', () => {
    const pkg = JSON.parse(read('packages/cli/package.json')) as { homepage: string }
    expect(missingTags(pkg.homepage, { utm_source: 'npm_homepage', utm_medium: 'package', utm_campaign: 'shipguard_evergreen' })).toEqual([])
    expect(new URL(pkg.homepage).pathname).toBe('/shipguard')
  })

  it('mailto and GitHub links are not touched', () => {
    expect(read('SECURITY.md')).toContain('founders@agenticcli.dev')
  })
})
