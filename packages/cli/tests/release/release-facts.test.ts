/**
 * Plan W12 (public side): scripts/release-facts.sh pre-publish check, sync and post-publish emit,
 * plus the shape of the release-facts job in .github/workflows/release.yml.
 * The script runs against a throwaway repo root (--root) and a fake `npm` on PATH: nothing touches the network.
 */
import { spawnSync } from 'node:child_process'
import { chmodSync, mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'
import { createHash } from 'node:crypto'
import { afterAll, describe, expect, it } from 'vitest'

const CLI = resolve(__dirname, '..', '..')
const ROOT = resolve(CLI, '..', '..')
const SCRIPT = join(ROOT, 'scripts', 'release-facts.sh')
const TODAY = new Date().toISOString().slice(0, 10)
const made: string[] = []

function fixture(over: { version?: string; heading?: string } = {}): string {
  const version = over.version ?? '0.13.0'
  const d = mkdtempSync(join(tmpdir(), 'rf-'))
  made.push(d)
  mkdirSync(join(d, 'packages', 'cli'), { recursive: true })
  mkdirSync(join(d, 'docs', 'security'), { recursive: true })
  writeFileSync(join(d, 'packages', 'cli', 'package.json'), JSON.stringify({ name: '@agenticcli/shipguard', version }))
  writeFileSync(
    join(d, 'packages', 'cli', 'CHANGELOG.md'),
    `# @agenticcli/shipguard\n\n${over.heading ?? `## ${version.split('-')[0]} - ${TODAY}`}\n\n- Added: a thing.\n- Fixed: another thing.\n\n## 0.12.0 - 2026-11-17\n\n- old\n`,
  )
  writeFileSync(join(d, 'CITATION.cff'), `cff-version: 1.2.0\ntitle: "ShipGuard"\nversion: ${version}\ndate-released: ${TODAY}\nlicense: Apache-2.0\n`)
  writeFileSync(
    join(d, 'REBUILD.md'),
    `# Verify\n\nFrom 0.12.1 the package ships maps.\n\n\`\`\`bash\ngit clone --depth 1 --branch v${version} https://x/shipguard.git\nnpm pack @agenticcli/shipguard@${version} && tar -xzf agenticcli-shipguard-${version}.tgz\n\`\`\`\n\nOr: \`bash scripts/rebuild-verify.sh ${version}\`.\n`,
  )
  writeFileSync(join(d, 'README.md'), `# ShipGuard\n\nRun \`npx @agenticcli/shipguard@0 scan\` (any 0.x).\n`)
  writeFileSync(join(d, 'docs', 'faq.md'), `# FAQ\n\nPin it: \`npm i -D @agenticcli/shipguard@${version}\`.\n`)
  writeFileSync(
    join(d, 'docs', 'security', 'shipguard.openvex.json'),
    JSON.stringify({ statements: [{ products: [{ '@id': `pkg:npm/%40agenticcli/shipguard@${version}`, identifiers: { purl: `pkg:npm/%40agenticcli/shipguard@${version}` } }] }] }),
  )
  return d
}

function run(args: string[], env: Record<string, string> = {}) {
  const r = spawnSync('bash', [SCRIPT, ...args], { encoding: 'utf-8', env: { ...process.env, ...env } })
  return { code: r.status, out: (r.stdout ?? '') + (r.stderr ?? '') }
}
const check = (root: string, tag = 'v0.13.0') => run(['check', '--tag', tag, '--root', root])
const edit = (root: string, rel: string, from: string | RegExp, to: string) => {
  const p = join(root, rel)
  const before = readFileSync(p, 'utf-8')
  const after = before.replace(from, to)
  expect(after, `edit ${rel} changed nothing`).not.toBe(before)
  writeFileSync(p, after)
}

afterAll(() => made.forEach((d) => rmSync(d, { recursive: true, force: true })))

describe('release-facts.sh check (pre-publish, fail closed)', () => {
  it('passes when tag, package.json, CHANGELOG, CITATION, OpenVEX and pinned docs all agree', () => {
    const r = check(fixture())
    expect(r.code, r.out).toBe(0)
    expect(r.out).toContain('release-facts: OK 0.13.0')
  })

  it('fails when the tag differs from package.json', () => {
    const r = check(fixture(), 'v0.13.1')
    expect(r.code).toBe(1)
    expect(r.out).toMatch(/tag v0\.13\.1 != package\.json version v0\.13\.0/)
  })

  it('fails on a CHANGELOG top entry that is "unreleased"', () => {
    const r = check(fixture({ heading: '## 0.13.0 - unreleased' }))
    expect(r.code).toBe(1)
    expect(r.out).toMatch(/must read '## 0\.13\.0 - YYYY-MM-DD'/)
  })

  it('fails on a CHANGELOG top entry for another version', () => {
    const r = check(fixture({ heading: `## 0.12.9 - ${TODAY}` }))
    expect(r.code).toBe(1)
    expect(r.out).toMatch(/top entry is 0\.12\.9, expected 0\.13\.0/)
  })

  it('fails on a date that is not a real day, and on a date in the future', () => {
    const bad = check(fixture({ heading: '## 0.13.0 - 2026-02-30' }))
    expect(bad.code).toBe(1)
    expect(bad.out).toMatch(/not a real, non-future date/)
    const future = new Date(Date.now() + 5 * 86400_000).toISOString().slice(0, 10)
    const fut = check(fixture({ heading: `## 0.13.0 - ${future}` }))
    expect(fut.code).toBe(1)
    expect(fut.out).toMatch(/not a real, non-future date/)
  })

  it('names every stale place: CITATION version + date, OpenVEX purl, README/docs pin, REBUILD.md pins', () => {
    const d = fixture()
    edit(d, 'CITATION.cff', 'version: 0.13.0', 'version: 0.12.0')
    edit(d, 'CITATION.cff', `date-released: ${TODAY}`, 'date-released: 2026-11-10')
    edit(d, 'docs/security/shipguard.openvex.json', /shipguard@0\.13\.0/g, 'shipguard@0.12.0')
    edit(d, 'docs/faq.md', '@0.13.0', '@0.12.0')
    edit(d, 'REBUILD.md', '--branch v0.13.0', '--branch v0.12.1')
    edit(d, 'REBUILD.md', 'rebuild-verify.sh 0.13.0', 'rebuild-verify.sh 0.12.1')
    const r = check(d)
    expect(r.code).toBe(1)
    expect(r.out).toMatch(/CITATION\.cff version is '0\.12\.0', expected 0\.13\.0/)
    expect(r.out).toMatch(/CITATION\.cff date-released is '2026-11-10'/)
    expect(r.out).toMatch(/shipguard\.openvex\.json names .*@0\.12\.0, expected 0\.13\.0/)
    expect(r.out).toMatch(/docs\/faq\.md:\d+ pins 0\.12\.0, expected 0\.13\.0/)
    expect(r.out).toMatch(/REBUILD\.md:\d+ pins 0\.12\.1, expected 0\.13\.0/)
    expect(r.out).toMatch(/6 mismatch/)
  })

  it('major-only pins (@0) and historical sentences ("From 0.12.1 ...") are not flagged', () => {
    const r = check(fixture())
    expect(r.code, r.out).toBe(0)
  })

  it('fails when REBUILD.md has no pinned version at all (a blind check is a failed check)', () => {
    const d = fixture()
    writeFileSync(join(d, 'REBUILD.md'), '# Verify\n\nNothing pinned here.\n')
    const r = check(d)
    expect(r.code).toBe(1)
    expect(r.out).toMatch(/REBUILD\.md has no pinned version to check/)
  })

  it('fails when CITATION.cff or the OpenVEX file is missing', () => {
    const d = fixture()
    rmSync(join(d, 'CITATION.cff'))
    rmSync(join(d, 'docs', 'security', 'shipguard.openvex.json'))
    const r = check(d)
    expect(r.code).toBe(1)
    expect(r.out).toMatch(/CITATION\.cff is missing/)
    expect(r.out).toMatch(/shipguard\.openvex\.json is missing/)
  })

  it('a prerelease checks tag, package.json and CHANGELOG only', () => {
    const d = fixture({ version: '0.14.0-rc.0' })
    edit(d, 'CITATION.cff', 'version: 0.14.0-rc.0', 'version: 0.12.0')
    const r = check(d, 'v0.14.0-rc.0')
    expect(r.code, r.out).toBe(0)
    expect(r.out).toContain('prerelease 0.14.0-rc.0')
  })

  it('requires --tag (fail closed) and rejects an unknown argument', () => {
    expect(run(['check', '--root', fixture()]).code).toBe(1)
    expect(run(['check', '--tag', 'v0.13.0', '--wat']).code).toBe(1)
  })
})

describe('release-facts.sh sync', () => {
  it('rewrites every version place from package.json + the CHANGELOG date, then check passes; idempotent', () => {
    const d = fixture({ version: '0.14.0' })
    // all places still say 0.13.0
    for (const [rel, from] of [
      ['CITATION.cff', 'version: 0.14.0'],
      ['docs/faq.md', '@0.14.0'],
    ] as const) edit(d, rel, from, from.replace('0.14.0', '0.13.0'))
    edit(d, 'REBUILD.md', /0\.14\.0/g, '0.13.0')
    edit(d, 'docs/security/shipguard.openvex.json', /0\.14\.0/g, '0.13.0')
    edit(d, 'CITATION.cff', `date-released: ${TODAY}`, 'date-released: 2026-11-01')
    expect(check(d, 'v0.14.0').code).toBe(1)
    const r = run(['sync', '--tag', 'v0.14.0', '--root', d])
    expect(r.code, r.out).toBe(0)
    expect(readFileSync(join(d, 'CITATION.cff'), 'utf-8')).toContain(`date-released: ${TODAY}`)
    expect(readFileSync(join(d, 'REBUILD.md'), 'utf-8')).toContain('--branch v0.14.0')
    expect(readFileSync(join(d, 'REBUILD.md'), 'utf-8')).toContain('From 0.12.1 the package') // history untouched
    expect(readFileSync(join(d, 'README.md'), 'utf-8')).toContain('shipguard@0 scan')
    const again = run(['sync', '--tag', 'v0.14.0', '--root', d])
    expect(again.code, again.out).toBe(0)
  })

  it('refuses while the CHANGELOG entry is not release-ready', () => {
    const d = fixture({ heading: '## 0.13.0 - unreleased' })
    const r = run(['sync', '--tag', 'v0.13.0', '--root', d])
    expect(r.code).toBe(1)
    expect(r.out).toMatch(/fix the CHANGELOG entry first/)
  })
})

describe('release-facts.sh emit (post-publish)', () => {
  function fakeNpm(root: string, opts: { latest?: string; integrity?: string; provenance?: boolean }) {
    const bin = join(root, 'bin')
    mkdirSync(bin)
    const tgz = join(root, 'agenticcli-shipguard-0.13.0.tgz')
    writeFileSync(tgz, 'fake tarball bytes')
    const integrity = opts.integrity ?? 'sha512-' + createHash('sha512').update('fake tarball bytes').digest('base64')
    writeFileSync(join(root, 'tags.json'), JSON.stringify({ latest: opts.latest ?? '0.13.0', next: '0.10.0-rc.0' }))
    writeFileSync(
      join(root, 'dist.json'),
      JSON.stringify({ integrity, attestations: opts.provenance === false ? undefined : { provenance: { predicateType: 'https://slsa.dev/provenance/v1' } } }),
    )
    writeFileSync(join(root, 'time.json'), JSON.stringify({ '0.13.0': '2026-11-24T09:00:00.000Z' }))
    writeFileSync(
      join(bin, 'npm'),
      `#!/usr/bin/env bash\nd="${root}"\ncase "$*" in\n  *dist-tags*) cat "$d/tags.json" ;;\n  *"@0.13.0 dist"*) cat "$d/dist.json" ;;\n  *" time "*) cat "$d/time.json" ;;\n  *) echo "fake npm: unexpected: $*" >&2; exit 9 ;;\nesac\n`,
    )
    chmodSync(join(bin, 'npm'), 0o755)
    return { bin, tgz }
  }
  const emit = (root: string, bin: string, tgz: string, out: string) =>
    run(['emit', '--tag', 'v0.13.0', '--root', root, '--tarball', tgz, '--out', out], {
      PATH: `${bin}:${process.env.PATH}`,
      RELEASE_FACTS_TRIES: '1',
      RELEASE_FACTS_SLEEP: '0',
    })

  it('writes release-facts.json when the registry shows the version, the same integrity and a provenance attestation', () => {
    const d = fixture()
    const { bin, tgz } = fakeNpm(d, {})
    const out = join(d, 'release-facts.json')
    const r = emit(d, bin, tgz, out)
    expect(r.code, r.out).toBe(0)
    const f = JSON.parse(readFileSync(out, 'utf-8'))
    expect(f).toMatchObject({
      schema: 1,
      package: '@agenticcli/shipguard',
      version: '0.13.0',
      tag: 'v0.13.0',
      distTag: 'latest',
      changelogDate: TODAY,
      publishedAt: '2026-11-24T09:00:00.000Z',
      provenance: 'https://slsa.dev/provenance/v1',
    })
    expect(f.changelogEntry).toContain('- Added: a thing.')
    expect(f.changelogEntry).not.toContain('0.12.0')
    expect(f.tarball).toMatchObject({ name: 'agenticcli-shipguard-0.13.0.tgz', bytes: 18 })
  })

  it('fails when latest does not show the version yet', () => {
    const d = fixture()
    const { bin, tgz } = fakeNpm(d, { latest: '0.12.0' })
    const r = emit(d, bin, tgz, join(d, 'o.json'))
    expect(r.code).toBe(1)
    expect(r.out).toMatch(/dist-tag 'latest' shows '0\.12\.0', expected 0\.13\.0/)
  })

  it('fails when the registry integrity differs from the tarball the build made', () => {
    const d = fixture()
    const { bin, tgz } = fakeNpm(d, { integrity: 'sha512-AAAA' })
    const r = emit(d, bin, tgz, join(d, 'o.json'))
    expect(r.code).toBe(1)
    expect(r.out).toMatch(/registry integrity sha512-AAAA != built tarball/)
  })

  it('fails when the registry shows no provenance attestation', () => {
    const d = fixture()
    const { bin, tgz } = fakeNpm(d, { provenance: false })
    const r = emit(d, bin, tgz, join(d, 'o.json'))
    expect(r.code).toBe(1)
    expect(r.out).toMatch(/no provenance attestation/)
  })

  it('rejects a tarball with an unexpected name', () => {
    const d = fixture()
    const { bin } = fakeNpm(d, {})
    writeFileSync(join(d, 'evil.tgz'), 'x')
    const r = emit(d, bin, join(d, 'evil.tgz'), join(d, 'o.json'))
    expect(r.code).toBe(1)
    expect(r.out).toMatch(/unexpected tarball name/)
  })
})

describe('.github/workflows/release.yml: W12 additions', () => {
  const wf = readFileSync(join(ROOT, '.github', 'workflows', 'release.yml'), 'utf-8')
  const code = wf.split('\n').filter((l) => !l.trim().startsWith('#')).join('\n')
  const job = code.slice(code.indexOf('\n  release-facts:'))

  it('runs the check (in the shared release-build action the build job uses) before install, build and pack', () => {
    expect(code).toContain('uses: ./.github/actions/release-build')
    const act = readFileSync(join(ROOT, '.github', 'actions', 'release-build', 'action.yml'), 'utf-8')
      .split('\n').filter((l) => !l.trim().startsWith('#')).join('\n')
    const at = act.indexOf('bash scripts/release-facts.sh check --tag "$TAG"')
    expect(at).toBeGreaterThan(0)
    expect(at).toBeLessThan(act.indexOf('pnpm install'))
    expect(at).toBeLessThan(act.indexOf('Pack with pnpm'))
  })

  it('release-facts job: after publish, contents: read only, no secret, no write, no install, no dist-tag', () => {
    expect(job).toMatch(/needs:\s*\[build, publish\]/)
    expect(job).toMatch(/permissions:\n\s+contents: read\n\s+steps:/)
    expect(job).not.toMatch(/id-token|contents: write|actions: write|pull-requests|secrets\.|github\.token|GH_TOKEN|GITHUB_TOKEN|NODE_AUTH_TOKEN/)
    expect(job).not.toMatch(/pnpm|npm (ci|install|publish|dist-tag)|gh (pr|api|release)/)
    expect(job).toContain('bash scripts/release-facts.sh emit --tag "$GITHUB_REF_NAME"')
  })

  it('the workflow as a whole has no secrets reference and only the publish job holds id-token', () => {
    expect(code).not.toMatch(/secrets\./)
    expect(code.match(/id-token: write/g)).toHaveLength(1)
  })
})
