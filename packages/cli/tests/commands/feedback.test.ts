import { describe, it, expect, vi, beforeEach } from 'vitest';

describe('feedbackCommand', () => {
  it('module exports feedbackCommand and rateCommand functions', async () => {
    const mod = await import('../../src/commands/feedback.js');
    expect(typeof mod.feedbackCommand).toBe('function');
    expect(typeof mod.rateCommand).toBe('function');
  });

  it('feedbackCommand creates a Commander command named "feedback"', async () => {
    const { feedbackCommand } = await import('../../src/commands/feedback.js');
    const cmd = feedbackCommand();
    expect(cmd.name()).toBe('feedback');
  });

  it('rateCommand creates a Commander command named "rate"', async () => {
    const { rateCommand } = await import('../../src/commands/feedback.js');
    const cmd = rateCommand();
    expect(cmd.name()).toBe('rate');
  });

  // 0.13.2: both commands only print where to send feedback. No network call, no login, no credentials read.
  it.each([
    ['feedback', ['some free text']],
    ['feedback', []],
    ['rate', ['1', 'helpful']],
    ['rate', []],
  ])('%s %j makes no network call and points to GitHub issues', async (name, args) => {
    const fetchSpy = vi.fn(() => { throw new Error('network call attempted') });
    vi.stubGlobal('fetch', fetchSpy);
    const err = vi.spyOn(console, 'error').mockImplementation(() => {});
    try {
      const { feedbackCommand, rateCommand } = await import('../../src/commands/feedback.js');
      const cmd = name === 'rate' ? rateCommand() : feedbackCommand();
      await cmd.parseAsync(args, { from: 'user' });
      const out = err.mock.calls.map((c) => c.join(' ')).join('\n');
      expect(fetchSpy).not.toHaveBeenCalled();
      expect(out).toContain('https://github.com/agenticcli/shipguard/issues');
      expect(out).not.toMatch(/helpful|some free text|Not authenticated|login/i);
    } finally {
      err.mockRestore();
      vi.unstubAllGlobals();
    }
  });
});
