// Regression: on a fresh machine (no ~/.shipguard, no ~/.config/shipguard)
// every writer under the user's home must create its own parent dir (0700) and write
// secrets 0600. One test per writer + the shared helper.
import { describe, it, expect, beforeEach, afterEach } from 'vitest'
import * as fs from 'node:fs'
import * as os from 'node:os'
import * as path from 'node:path'
import { ensureSecureDir, writeSecureFileSync } from '../../src/utils/secure-fs.js'
import { saveCredentials } from '../../src/core/auth.js'
import {
  getOrCreateInstallId,
  writeUserEnabled,
  markNoticeShown,
  readInstallId,
  configFilePath,
} from '../../src/core/telemetry-config.js'
import { welcomeBanner } from '../../src/core/render.js'

const posix = process.platform !== 'win32'
const mode = (p: string) => fs.statSync(p).mode & 0o777

let home: string
let prevHome: string | undefined

beforeEach(() => {
  home = fs.mkdtempSync(path.join(os.tmpdir(), 'sg-fresh-home-'))
  prevHome = process.env['HOME']
  process.env['HOME'] = home // os.homedir() honours $HOME on POSIX
})
afterEach(() => {
  if (prevHome === undefined) delete process.env['HOME']
  else process.env['HOME'] = prevHome
  fs.rmSync(home, { recursive: true, force: true })
})

describe('fresh HOME: every writer creates its parent dir', () => {
  it('ensureSecureDir: creates nested dirs, leaf 0700, tightens a loose existing dir', () => {
    const leaf = path.join(home, 'a', 'b')
    ensureSecureDir(leaf)
    expect(fs.statSync(leaf).isDirectory()).toBe(true)
    if (posix) {
      expect(mode(leaf)).toBe(0o700)
      fs.chmodSync(leaf, 0o755)
      ensureSecureDir(leaf)
      expect(mode(leaf)).toBe(0o700)
    }
  })

  it('writeSecureFileSync: 0600, and tightens a pre-existing loose file', () => {
    const f = path.join(home, 'secret')
    fs.writeFileSync(f, 'x', { mode: 0o644 })
    writeSecureFileSync(f, 'y')
    expect(fs.readFileSync(f, 'utf-8')).toBe('y')
    if (posix) expect(mode(f)).toBe(0o600)
  })

  it('saveCredentials (~/.config/shipguard/credentials.json)', async () => {
    await saveCredentials({ accessToken: 't', refreshToken: 'r' } as never)
    const dir = path.join(home, '.config', 'shipguard')
    const file = path.join(dir, 'credentials.json')
    expect(fs.existsSync(file)).toBe(true)
    if (posix) {
      expect(mode(dir)).toBe(0o700)
      expect(mode(file)).toBe(0o600)
    }
  })

  it('telemetry install id (getOrCreateInstallId)', () => {
    const dir = path.join(home, '.config', 'shipguard')
    const id = getOrCreateInstallId(dir)
    expect(id).toMatch(/^[0-9a-f-]{36}$/)
    expect(readInstallId(dir)).toBe(id)
    if (posix) {
      expect(mode(dir)).toBe(0o700)
      expect(mode(configFilePath(dir))).toBe(0o600)
    }
  })

  it('telemetry opt-in/out config (writeUserEnabled)', () => {
    const dir = path.join(home, '.config', 'shipguard')
    const file = writeUserEnabled(dir, false)
    expect(fs.existsSync(file)).toBe(true)
    if (posix) expect(mode(file)).toBe(0o600)
  })

  it('telemetry notice marker (markNoticeShown)', () => {
    const dir = path.join(home, '.config', 'shipguard')
    markNoticeShown(dir)
    const marker = fs.readdirSync(dir).find((n) => n === 'telemetry-notice-shown')
    expect(marker).toBeDefined()
    if (posix) expect(mode(dir)).toBe(0o700)
  })

  it('first-run welcome marker (welcomeBanner)', () => {
    const dir = path.join(home, '.config', 'shipguard')
    expect(welcomeBanner(dir)).not.toBe('')
    expect(fs.existsSync(path.join(dir, '.welcomed'))).toBe(true)
    expect(welcomeBanner(dir)).toBe('') // marker persisted: banner is once-only
    if (posix) expect(mode(dir)).toBe(0o700)
  })
})
