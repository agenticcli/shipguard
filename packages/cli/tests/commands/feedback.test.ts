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
});
