import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { detectFramework, detectFrameworks } from '../../src/core/framework.js';

const BASE = join(tmpdir(), 'fw-test-' + process.pid);

function writePackageJson(dir: string, deps: Record<string, string>) {
  mkdirSync(dir, { recursive: true });
  writeFileSync(join(dir, 'package.json'), JSON.stringify({ dependencies: deps }));
}

function createTempProject(deps: Record<string, string> = {}, devDeps: Record<string, string> = {}): string {
  const dir = mkdtempSync(join(tmpdir(), 'sg-fw-'));
  writeFileSync(join(dir, 'package.json'), JSON.stringify({
    name: 'test',
    dependencies: deps,
    devDependencies: devDeps,
  }));
  return dir;
}

beforeEach(() => mkdirSync(BASE, { recursive: true }));
afterEach(() => rmSync(BASE, { recursive: true, force: true }));

describe('detectFramework', () => {
  it('detects nextjs and extracts version', () => {
    const dir = join(BASE, 'next');
    writePackageJson(dir, { next: '^14.2.0' });
    expect(detectFramework(dir)).toEqual({ framework: 'nextjs', version: '14.2.0' });
  });

  it('detects express', () => {
    const dir = join(BASE, 'express');
    writePackageJson(dir, { express: '^4.18.0' });
    expect(detectFramework(dir)).toEqual({ framework: 'express', version: '4.18.0' });
  });

  it('does not detect stacks that have no rule of their own (fastify, drizzle)', () => {
    const dir = join(BASE, 'fastify');
    writePackageJson(dir, { fastify: '^4.0.0', 'drizzle-orm': '^0.30.0' });
    expect(detectFramework(dir)).toEqual({ framework: 'generic' });
  });

  it('returns generic when no known framework found', () => {
    const dir = join(BASE, 'generic');
    writePackageJson(dir, { lodash: '^4.0.0' });
    expect(detectFramework(dir)).toEqual({ framework: 'generic' });
  });

  it('returns generic when no package.json exists', () => {
    const dir = join(BASE, 'empty');
    mkdirSync(dir, { recursive: true });
    expect(detectFramework(dir)).toEqual({ framework: 'generic' });
  });
});

describe('detectFrameworks', () => {
  it('detects Next.js', () => {
    const dir = createTempProject({ next: '^15.2.3' });
    const result = detectFrameworks(dir);
    expect(result.frameworks).toContainEqual({ name: 'nextjs', version: '15.2.3' });
    rmSync(dir, { recursive: true });
  });

  it('detects multiple frameworks (Next.js + Prisma)', () => {
    const dir = createTempProject({ next: '^15.0.0', '@prisma/client': '^5.1.0' });
    const result = detectFrameworks(dir);
    expect(result.frameworks.length).toBeGreaterThanOrEqual(2);
    expect(result.frameworks.map(f => f.name)).toContain('nextjs');
    expect(result.frameworks.map(f => f.name)).toContain('prisma');
    rmSync(dir, { recursive: true });
  });

  it('returns generic for no-framework project', () => {
    const dir = createTempProject({ lodash: '^4.0.0' });
    const result = detectFrameworks(dir);
    expect(result.frameworks).toEqual([{ name: 'generic' }]);
    rmSync(dir, { recursive: true });
  });

  it('returns generic for directory without package.json', () => {
    const dir = mkdtempSync(join(tmpdir(), 'sg-fw-'));
    const result = detectFrameworks(dir);
    expect(result.frameworks).toEqual([{ name: 'generic' }]);
    rmSync(dir, { recursive: true });
  });
});

describe('detectFrameworks: React and Firebase', () => {
  it('detects React from react or react-dom, with the version', () => {
    const a = createTempProject({ react: '^19.0.0' });
    const b = createTempProject({ 'react-dom': '~18.3.1' });
    expect(detectFrameworks(a).frameworks).toEqual([{ name: 'react', version: '19.0.0' }]);
    expect(detectFrameworks(b).frameworks).toEqual([{ name: 'react', version: '18.3.1' }]);
    rmSync(a, { recursive: true });
    rmSync(b, { recursive: true });
  });

  it('a Next.js app reports both nextjs and react', () => {
    const dir = createTempProject({ next: '^15.0.0', react: '^19.0.0', 'react-dom': '^19.0.0' });
    expect(detectFrameworks(dir).frameworks.map((f) => f.name)).toEqual(['nextjs', 'react']);
    rmSync(dir, { recursive: true });
  });

  it('detects Firebase from firebase, firebase-admin or firebase-functions', () => {
    for (const dep of ['firebase', 'firebase-admin', 'firebase-functions']) {
      const dir = createTempProject({ [dep]: '^11.0.0' });
      expect(detectFrameworks(dir).frameworks).toEqual([{ name: 'firebase', version: '11.0.0' }]);
      rmSync(dir, { recursive: true });
    }
  });

  it('detects a rules-only Firebase repo (no package.json) from firebase.json or firestore.rules', () => {
    for (const file of ['firebase.json', 'firestore.rules']) {
      const dir = mkdtempSync(join(tmpdir(), 'sg-fw-'));
      writeFileSync(join(dir, file), '{}');
      expect(detectFrameworks(dir).frameworks).toEqual([{ name: 'firebase' }]);
      rmSync(dir, { recursive: true });
    }
  });

  it('every detectable stack name is lower-case and matches a rule-id prefix', () => {
    const dir = createTempProject({
      next: '1', express: '1', '@prisma/client': '1', '@supabase/supabase-js': '1', react: '1', firebase: '1',
    });
    expect(detectFrameworks(dir).frameworks.map((f) => f.name).sort()).toEqual(
      ['express', 'firebase', 'nextjs', 'prisma', 'react', 'supabase'],
    );
    rmSync(dir, { recursive: true });
  });
});

describe('detectFramework (backward compat)', () => {
  it('returns primary framework', () => {
    const dir = createTempProject({ next: '^15.0.0' });
    const result = detectFramework(dir);
    expect(result.framework).toBe('nextjs');
    rmSync(dir, { recursive: true });
  });

  it('returns generic when no framework found', () => {
    const dir = createTempProject({});
    const result = detectFramework(dir);
    expect(result.framework).toBe('generic');
    rmSync(dir, { recursive: true });
  });
});
