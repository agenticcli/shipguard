/**
 * QA fix 1 (QA-CLI-0130 FAIL 1): safe mode writes nothing under ~/.config. The welcome banner marker was
 * written on a terminal scan; the shared config-store writer (nag, hint, plan, offer cache) is now guarded too.
 */
import { existsSync, mkdtempSync, readdirSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterEach, describe, expect, it } from 'vitest'
import { welcomeBanner } from '../../src/core/render.js'
import { writeConfigText } from '../../src/core/config-store.js'

const prev = process.env.SHIPGUARD_SAFE_MODE
let dir: string
afterEach(() => {
  if (prev === undefined) delete process.env.SHIPGUARD_SAFE_MODE
  else process.env.SHIPGUARD_SAFE_MODE = prev
  if (dir) rmSync(dir, { recursive: true, force: true })
})

describe('safe mode: welcome marker and config-store writes', () => {
  it('welcomeBanner in safe mode returns nothing and creates neither folder nor marker', () => {
    process.env.SHIPGUARD_SAFE_MODE = '1'
    dir = mkdtempSync(join(tmpdir(), 'sg-safe-welcome-'))
    const cfg = join(dir, 'shipguard')
    expect(welcomeBanner(cfg)).toBe('')
    expect(existsSync(cfg)).toBe(false)
  })

  it('control: without safe mode the banner shows once and writes the marker', () => {
    delete process.env.SHIPGUARD_SAFE_MODE
    dir = mkdtempSync(join(tmpdir(), 'sg-safe-welcome-'))
    const cfg = join(dir, 'shipguard')
    expect(welcomeBanner(cfg)).not.toBe('')
    expect(existsSync(join(cfg, '.welcomed'))).toBe(true)
  })

  it('writeConfigText writes nothing in safe mode and returns false', () => {
    process.env.SHIPGUARD_SAFE_MODE = '1'
    dir = mkdtempSync(join(tmpdir(), 'sg-safe-cfg-'))
    const cfg = join(dir, 'shipguard')
    expect(writeConfigText(cfg, 'nag.json', '{}')).toBe(false)
    expect(existsSync(cfg)).toBe(false)
    expect(readdirSync(dir)).toEqual([])
  })

  it('control: writeConfigText writes without safe mode', () => {
    delete process.env.SHIPGUARD_SAFE_MODE
    dir = mkdtempSync(join(tmpdir(), 'sg-safe-cfg-'))
    expect(writeConfigText(join(dir, 'shipguard'), 'nag.json', '{}')).toBe(true)
  })
})
