/**
 * Release preflight: scripts/check-preflight.sh (a fake `gh` on PATH, no network) and the shape of the three
 * workflows + the shared composite action. Goal: a release tag can only be made on a commit whose real
 * release gate already passed, and the preflight and the release run the same steps.
 */
import { spawnSync } from 'node:child_process'
import { chmodSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'
import { afterAll, describe, expect, it } from 'vitest'
import { parse } from 'yaml'

const ROOT = resolve(__dirname, '..', '..', '..', '..')
const SCRIPT = join(ROOT, 'scripts', 'check-preflight.sh')
const SHA = 'a'.repeat(40)
const made: string[] = []
afterAll(() => made.forEach((d) => rmSync(d, { recursive: true, force: true })))

const read = (rel: string) => readFileSync(join(ROOT, rel), 'utf-8')
const stripComments = (s: string) => s.split('\n').filter((l) => !l.trim().startsWith('#')).join('\n')

function fakeGh(answer: string, exit = 0): string {
  const d = mkdtempSync(join(tmpdir(), 'pf-'))
  made.push(d)
  writeFileSync(join(d, 'answer.json'), answer)
  writeFileSync(join(d, 'gh'), `#!/bin/sh\necho "$@" > "${d}/args"\n[ ${exit} -eq 0 ] || { echo boom >&2; exit ${exit}; }\ncat "${d}/answer.json"\n`)
  chmodSync(join(d, 'gh'), 0o755)
  return d
}
function run(args: string[], bin?: string) {
  const r = spawnSync('bash', [SCRIPT, ...args], {
    encoding: 'utf-8',
    env: { ...process.env, PATH: `${bin ?? '/nonexistent'}:${process.env.PATH}`, GITHUB_REPOSITORY: 'o/r', GITHUB_ACTIONS: '' },
  })
  return { code: r.status, out: (r.stdout ?? '') + (r.stderr ?? '') }
}
const runRec = (over: Record<string, unknown> = {}) => ({
  id: 1, html_url: 'https://github.com/o/r/actions/runs/1', head_sha: SHA, head_branch: 'main', event: 'push',
  status: 'completed', conclusion: 'success', ...over,
})
const runs = (...r: unknown[]) => JSON.stringify({ total_count: r.length, workflow_runs: r })

describe('scripts/check-preflight.sh', () => {
  it('passes on a green main run for exactly this sha, and asks the API for that sha and workflow', () => {
    const bin = fakeGh(runs(runRec()))
    const r = run([SHA], bin)
    expect(r.code).toBe(0)
    expect(r.out).toMatch(/OK: release-preflight.yml passed/)
    const args = readFileSync(join(bin, 'args'), 'utf-8')
    expect(args).toContain('repos/o/r/actions/workflows/release-preflight.yml/runs')
    expect(args).toContain(`head_sha=${SHA}`)
  })
  it('accepts a workflow_dispatch run too', () => {
    expect(run([SHA], fakeGh(runs(runRec({ event: 'workflow_dispatch' })))).code).toBe(0)
  })
  it.each([
    ['no runs at all', runs()],
    ['a failed run', runs(runRec({ conclusion: 'failure' }))],
    ['a cancelled run', runs(runRec({ conclusion: 'cancelled' }))],
    ['a run still in progress', runs(runRec({ status: 'in_progress', conclusion: null }))],
    ['a green run for another sha', runs(runRec({ head_sha: 'b'.repeat(40) }))],
    ['a green run on a branch other than main', runs(runRec({ head_branch: 'evil' }))],
    ['a green run from a pull request event', runs(runRec({ event: 'pull_request' }))],
    ['an answer without workflow_runs', JSON.stringify({ message: 'Not Found' })],
  ])('fails closed on %s', (_n, answer) => {
    const r = run([SHA], fakeGh(answer))
    expect(r.code).toBe(1)
    expect(r.out).toMatch(/no green release-preflight\.yml run/)
  })
  it('fails closed when gh fails or answers garbage', () => {
    expect(run([SHA], fakeGh('{}', 1)).code).toBe(1)
    const r = run([SHA], fakeGh('<html>'))
    expect(r.code).toBe(1)
    expect(r.out).toMatch(/could not read/)
  })
  it('fails closed when gh is missing', () => {
    const r = spawnSync('/bin/bash', [SCRIPT, SHA], { encoding: 'utf-8', env: { PATH: '/nonexistent', GITHUB_REPOSITORY: 'o/r' } })
    expect(r.status).not.toBe(0)
  })
  it('rejects a bad sha or repo with exit 2 (no API call)', () => {
    const bin = fakeGh(runs(runRec()))
    expect(run(['main'], bin).code).toBe(2)
    expect(run(['A'.repeat(40)], bin).code).toBe(2)
    expect(run([SHA, '--repo', 'no-slash'], bin).code).toBe(2)
    expect(run([], bin).code).toBe(2)
  })
})

type Step = { name?: string; uses?: string; run?: string; shell?: string; env?: Record<string, string>; with?: Record<string, string> }
type Job = { needs?: string | string[]; if?: string; permissions?: Record<string, string>; steps: Step[] }
type Wf = { on: Record<string, unknown>; permissions: Record<string, string>; jobs: Record<string, Job> }
const wf = (name: string) => parse(read(`.github/workflows/${name}`)) as Wf
const action = parse(read('.github/actions/release-build/action.yml')) as { runs: { using: string; steps: Step[] } }
const SHARED = './.github/actions/release-build'

describe('shared composite action', () => {
  const text = stripComments(read('.github/actions/release-build/action.yml'))
  it('holds the whole gate, in order: facts check, install, build/lint/test, release-gate, pack', () => {
    const order = ['release-facts.sh check --tag "$TAG"', 'pnpm install --frozen-lockfile --ignore-scripts', 'pnpm test', 'bash scripts/release-gate.sh', 'pnpm pack']
    const at = order.map((s) => text.indexOf(s))
    at.forEach((i) => expect(i).toBeGreaterThan(0))
    expect([...at].sort((a, b) => a - b)).toEqual(at)
  })
  it('never runs the gate in dry-run mode and never publishes or writes', () => {
    expect(text).not.toMatch(/RELEASE_GATE_DRY_RUN/)
    expect(text).not.toMatch(/npm (publish|dist-tag)|gh (release|api)|id-token|secrets\./)
  })
  it('every run step sets a shell (composite rule)', () => {
    action.runs.steps.filter((s) => s.run).forEach((s) => expect(s.shell).toBe('bash'))
  })
})

describe('release-preflight.yml', () => {
  const w = wf('release-preflight.yml')
  const code = stripComments(read('.github/workflows/release-preflight.yml'))
  it('runs on dispatch and on pushes to main that touch the package version file', () => {
    expect(Object.keys(w.on).sort()).toEqual(['push', 'workflow_dispatch'])
    expect(w.on.push).toEqual({ branches: ['main'], paths: ['packages/cli/package.json'] })
  })
  it('uses the shared action, only on main, read-only, no secrets, no id-token', () => {
    const j = w.jobs.preflight
    expect(j.if).toContain('refs/heads/main')
    expect(j.steps.some((s) => s.uses === SHARED)).toBe(true)
    expect(w.permissions).toEqual({ contents: 'read' })
    expect(j.permissions).toEqual({ contents: 'read' })
    expect(code).not.toMatch(/id-token|secrets\.|npm publish|gh release|contents: write/)
    expect(code).not.toMatch(/RELEASE_GATE_DRY_RUN/)
  })
})

describe('release-tag.yml', () => {
  const w = wf('release-tag.yml')
  const code = stripComments(read('.github/workflows/release-tag.yml'))
  const job = w.jobs.tag
  it('is dispatch-only with a version input and runs only on main', () => {
    expect(Object.keys(w.on)).toEqual(['workflow_dispatch'])
    expect(job.if).toContain('refs/heads/main')
  })
  it('checks version, main HEAD and preflight BEFORE it creates the tag', () => {
    const at = (s: string) => code.indexOf(s)
    const create = at('git/tags')
    expect(create).toBeGreaterThan(0)
    for (const before of ['package.json version must equal the request', 'git/ref/heads/main', 'scripts/check-preflight.sh', 'Tag must not exist yet']) {
      expect(at(before)).toBeGreaterThan(0)
      expect(at(before)).toBeLessThan(create)
    }
    expect(at('gh workflow run release.yml')).toBeGreaterThan(create)
  })
  it('has the least permissions it needs, no id-token, and never puts the input into a shell line', () => {
    expect(w.permissions).toEqual({ contents: 'read' })
    expect(job.permissions).toEqual({ contents: 'write', actions: 'write' })
    expect(code).not.toMatch(/id-token|secrets\./)
    for (const s of job.steps) expect(s.run ?? '').not.toMatch(/\$\{\{/)
  })
})

describe('release.yml', () => {
  const w = wf('release.yml')
  const code = stripComments(read('.github/workflows/release.yml'))
  it('starts on a tag push or a dispatch on a tag (release-tag.yml dispatches it)', () => {
    expect(Object.keys(w.on).sort()).toEqual(['push', 'workflow_dispatch'])
  })
  it('verifies preflight first: build needs it, and it checks the ref type before the check script', () => {
    expect(w.jobs.build.needs).toBe('verify-preflight')
    const steps = w.jobs['verify-preflight'].steps
    expect(steps[0].run).toMatch(/REF_TYPE/)
    expect(steps[steps.length - 1].run).toContain('scripts/check-preflight.sh "$GITHUB_SHA"')
    expect(w.jobs['verify-preflight'].permissions).toEqual({ contents: 'read', actions: 'read' })
  })
  it('builds through the same shared action as the preflight', () => {
    const build = w.jobs.build.steps.find((s) => s.uses === SHARED)
    expect(build?.with?.tag).toBe('${{ github.ref_name }}')
    expect(wf('release-preflight.yml').jobs.preflight.steps.some((s) => s.uses === SHARED)).toBe(true)
  })
  it('publish is unchanged: OIDC only, provenance, no checkout, no dist-tag', () => {
    expect(code.match(/id-token: write/g)).toHaveLength(1)
    expect(w.jobs.publish.steps.some((s) => (s.uses ?? '').startsWith('actions/checkout'))).toBe(false)
    expect(code).toContain('npm publish "./$TARBALL" --provenance --access public --tag "$tag" --ignore-scripts')
    expect(code).not.toMatch(/npm\s+dist-tag/)
  })
})

describe('every run block in the new and changed workflows parses as bash', () => {
  const files = ['.github/workflows/release.yml', '.github/workflows/release-preflight.yml', '.github/workflows/release-tag.yml', '.github/actions/release-build/action.yml']
  for (const f of files) {
    it(f, () => {
      const doc = parse(read(f)) as { jobs?: Record<string, Job>; runs?: { steps: Step[] } }
      const steps = doc.jobs ? Object.values(doc.jobs).flatMap((j) => j.steps) : doc.runs!.steps
      for (const s of steps.filter((x) => x.run)) {
        const r = spawnSync('bash', ['-n'], { input: s.run!.replace(/\$\{\{[^}]*\}\}/g, 'EXPR'), encoding: 'utf-8' })
        expect(r.status, `${s.name}: ${r.stderr}`).toBe(0)
      }
    })
  }
})
