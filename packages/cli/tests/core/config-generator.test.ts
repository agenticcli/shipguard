import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { mkdtempSync, rmSync, readFileSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { hasConfig, generateConfig } from '../../src/core/config-generator.js';

describe('config-generator', () => {
  let tempDir: string;

  beforeEach(() => {
    tempDir = mkdtempSync(join(tmpdir(), 'shipguard-test-'));
  });

  afterEach(() => {
    rmSync(tempDir, { recursive: true, force: true });
  });

  it('hasConfig returns false when no .shipguard.yml', () => {
    expect(hasConfig(tempDir)).toBe(false);
  });

  it('hasConfig returns true after generation', () => {
    generateConfig(tempDir, [{ name: 'nextjs', version: '15.0.0' }]);
    expect(hasConfig(tempDir)).toBe(true);
  });

  it('generates valid YAML with framework', () => {
    generateConfig(tempDir, [{ name: 'nextjs', version: '15.0.0' }]);
    const content = readFileSync(join(tempDir, '.shipguard.yml'), 'utf-8');
    expect(content).toContain('configVersion: 2');
    expect(content).toContain('name: nextjs');
    expect(content).toContain('version: "15.0.0"');
    expect(content).toContain('telemetry:');
  });

  it('generates config with multiple frameworks', () => {
    generateConfig(tempDir, [
      { name: 'nextjs', version: '15.0.0' },
      { name: 'prisma', version: '5.x' },
    ]);
    const content = readFileSync(join(tempDir, '.shipguard.yml'), 'utf-8');
    expect(content).toContain('name: nextjs');
    expect(content).toContain('name: prisma');
  });

  it('generates config with generic fallback', () => {
    generateConfig(tempDir, [{ name: 'generic' }]);
    const content = readFileSync(join(tempDir, '.shipguard.yml'), 'utf-8');
    expect(content).toContain('name: generic');
  });

  it('generates config with limits block containing default values', () => {
    generateConfig(tempDir, [{ name: 'nextjs' }]);
    const content = readFileSync(join(tempDir, '.shipguard.yml'), 'utf-8');
    expect(content).toContain('limits:');
    expect(content).toContain('maxFileSizeBytes: 524288');   // 512 * 1024
    expect(content).toContain('maxTotalBytes: 268435456');   // 256 * 1024 * 1024
    expect(content).toContain('maxFiles: 5000');
  });
});
