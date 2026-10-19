/**
 * Run a real built CLI with a telemetry env of the test's own choosing, with NOTHING able to leave
 * the machine.
 *
 * Why this exists: tests/setup/no-telemetry.ts forces SHIPGUARD_TELEMETRY=0 into every child the
 * test process spawns, so a test cannot observe the "telemetry ON, default endpoint" path through an
 * ordinary spawn. Here the test process spawns a tiny runner, and the RUNNER (whose own
 * child_process is not patched) spawns the CLI with exactly the env the test asked for. Safety does
 * not depend on that env: every CLI run gets a NODE_OPTIONS preload that REPLACES global fetch with
 * a recorder, so an attempted send is written to a log and answered locally, never put on the wire.
 *
 * Builds: `buildVariant('dev' | 'published', tag)` compiles the CLI with tsup into
 * node_modules/.cache/sg-test-builds/<tag>-<kind> (inside the package so `re2js` etc. resolve).
 * `published` sets SHIPGUARD_PUBLISHED_BUILD=1, exactly like `pnpm build:publish`.
 */
import { execFileSync } from 'node:child_process'
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join, resolve, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'
import { spawnNode } from './spawn-cli.js'

const pkgRoot = resolve(dirname(fileURLToPath(import.meta.url)), '../..')

export type BuildKind = 'dev' | 'published'

export function buildVariant(kind: BuildKind, tag: string): string {
  const out = join(pkgRoot, 'node_modules', '.cache', 'sg-test-builds', `${tag}-${kind}`)
  execFileSync('npx', ['tsup', '--out-dir', out, '--onSuccess', ''], {
    cwd: pkgRoot,
    stdio: 'pipe',
    env: { ...process.env, SHIPGUARD_PUBLISHED_BUILD: kind === 'published' ? '1' : '' },
  })
  return join(out, 'cli.js')
}

export interface Attempt {
  url: string
  body: string
}

export interface RecordedRun {
  code: number
  stdout: string
  stderr: string
  attempts: Attempt[]
}

export interface RecordedCli {
  /** `env` is the COMPLETE env of the CLI (plus HOME, which defaults to an empty temp dir). */
  run(args: string[], opts?: { cwd?: string; env?: NodeJS.ProcessEnv; fetchDelayMs?: number }): Promise<RecordedRun>
  home: string
  project: string
  cleanup(): void
}

export function makeRecordedCli(cliPath: string): RecordedCli {
  const work = mkdtempSync(join(tmpdir(), 'sg-recorded-'))
  const home = join(work, 'home')
  const project = join(work, 'proj')
  const log = join(work, 'attempts.jsonl')
  const recorder = join(work, 'record-fetch.cjs')
  const runner = join(work, 'runner.cjs')
  for (const d of [home, project]) execFileSync('mkdir', ['-p', d])
  writeFileSync(join(project, 'package.json'), JSON.stringify({ name: 'x', version: '1.0.0' }))
  writeFileSync(join(project, 'index.js'), 'console.log("hi")\n')
  writeFileSync(
    recorder,
    `const fs=require('fs');
globalThis.fetch=function(u,init){
  const url=String((u&&u.url)||u);
  const body=init&&init.body?String(init.body):'';
  const delay=Number(process.env.SG_RECORD_DELAY_MS||0);
  return new Promise((res)=>setTimeout(()=>{
    fs.appendFileSync(${JSON.stringify(log)},JSON.stringify({url,body})+'\\n');
    res(new Response('ok'));
  },delay));
}\n`,
  )
  writeFileSync(
    runner,
    `const {spawnSync}=require('child_process');
const r=spawnSync(process.execPath,[process.env.SG_CLI,...JSON.parse(process.env.SG_ARGS)],
  {cwd:process.env.SG_CWD,env:JSON.parse(process.env.SG_CHILD_ENV),encoding:'utf8',timeout:25000});
process.stdout.write(JSON.stringify({code:r.status===null?-1:r.status,stdout:r.stdout||'',stderr:r.stderr||''}));\n`,
  )
  return {
    home,
    project,
    cleanup: () => rmSync(work, { recursive: true, force: true }),
    async run(args, opts = {}) {
      rmSync(log, { force: true })
      const childEnv: NodeJS.ProcessEnv = {
        PATH: process.env.PATH,
        HOME: home,
        ...(opts.env ?? {}),
        NODE_OPTIONS: `--require ${recorder}`,
        SG_RECORD_DELAY_MS: String(opts.fetchDelayMs ?? 0),
      }
      const res = await spawnNode(runner, [], {
        cwd: opts.cwd ?? project,
        env: {
          PATH: process.env.PATH,
          SG_CLI: cliPath,
          SG_ARGS: JSON.stringify(args),
          SG_CWD: opts.cwd ?? project,
          SG_CHILD_ENV: JSON.stringify(childEnv),
        },
      })
      const parsed = JSON.parse(res.stdout) as { code: number; stdout: string; stderr: string }
      const attempts = existsSync(log)
        ? readFileSync(log, 'utf-8').split('\n').filter(Boolean).map((l) => JSON.parse(l) as Attempt)
        : []
      return { ...parsed, attempts }
    },
  }
}
