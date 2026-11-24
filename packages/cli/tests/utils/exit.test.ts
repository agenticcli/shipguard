/**
 * B14 (unit): utils/exit.ts. setExitCode only sets process.exitCode and returns: it never calls
 * process.exit, schedules no timer. The stream error handlers are installed once and keep the code.
 */
import { afterEach, describe, expect, it, vi } from 'vitest'
import {
  exitWhenDrained,
  installStreamErrorHandlers,
  resetStreamErrorHandlersForTest,
  setExitCode,
} from '../../src/utils/exit.js'

afterEach(() => {
  process.exitCode = undefined
  vi.useRealTimers()
  vi.restoreAllMocks()
  resetStreamErrorHandlersForTest()
  process.stdout.removeAllListeners('error')
  process.stderr.removeAllListeners('error')
})

describe('setExitCode (B14)', () => {
  it('sets process.exitCode and never calls process.exit', () => {
    const exitSpy = vi.spyOn(process, 'exit').mockImplementation(() => {
      throw new Error('process.exit must not be called')
    })
    setExitCode(1)
    expect(process.exitCode).toBe(1)
    setExitCode(3)
    expect(process.exitCode).toBe(3)
    expect(exitSpy).not.toHaveBeenCalled()
  })

  it('schedules no timer (no forced-exit timeout)', () => {
    vi.useFakeTimers()
    setExitCode(1)
    expect(vi.getTimerCount()).toBe(0)
  })
})

describe('installStreamErrorHandlers (B14)', () => {
  it('installs one error handler on stdout and stderr, once', () => {
    const before = [process.stdout.listenerCount('error'), process.stderr.listenerCount('error')]
    installStreamErrorHandlers()
    installStreamErrorHandlers()
    expect(process.stdout.listenerCount('error')).toBe(before[0] + 1)
    expect(process.stderr.listenerCount('error')).toBe(before[1] + 1)
  })

  it('EPIPE on stdout keeps the computed exit code and does not exit', () => {
    const exitSpy = vi.spyOn(process, 'exit').mockImplementation(() => {
      throw new Error('process.exit must not be called')
    })
    installStreamErrorHandlers()
    setExitCode(1)
    const err = Object.assign(new Error('write EPIPE'), { code: 'EPIPE' })
    expect(() => process.stdout.emit('error', err)).not.toThrow()
    expect(process.exitCode).toBe(1)
    expect(exitSpy).not.toHaveBeenCalled()
  })

  it('an unexpected stdout error is logged and also keeps the code', () => {
    installStreamErrorHandlers()
    const warn = vi.spyOn(console, 'error').mockImplementation(() => {})
    setExitCode(1)
    expect(() => process.stdout.emit('error', Object.assign(new Error('boom'), { code: 'EIO' }))).not.toThrow()
    expect(process.exitCode).toBe(1)
    expect(warn).toHaveBeenCalled()
  })
})

describe('exitWhenDrained', () => {
  it('does nothing when no non-zero code was set', () => {
    const exitSpy = vi.spyOn(process, 'exit').mockImplementation(() => undefined as never)
    exitWhenDrained()
    process.exitCode = 0
    exitWhenDrained()
    expect(exitSpy).not.toHaveBeenCalled()
  })
})
