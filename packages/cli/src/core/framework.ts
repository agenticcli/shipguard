import { readFileSync, existsSync } from 'node:fs';
import { join } from 'node:path';

export interface FrameworkEntry { name: string; version?: string }
export interface FrameworkDetectionResult { frameworks: FrameworkEntry[] }

// Keep backward-compatible single-framework type for callers that haven't migrated
export interface FrameworkInfo { framework: string; version?: string }

export function detectFrameworks(projectDir: string): FrameworkDetectionResult {
  const pkgPath = join(projectDir, 'package.json');
  if (!existsSync(pkgPath)) return { frameworks: [{ name: 'generic' }] };

  const pkg = JSON.parse(readFileSync(pkgPath, 'utf-8'));
  const deps = { ...pkg.dependencies, ...pkg.devDependencies };
  const frameworks: FrameworkEntry[] = [];

  if (deps['next']) frameworks.push({ name: 'nextjs', version: deps['next'].replace(/[\^~]/, '') });
  if (deps['express']) frameworks.push({ name: 'express', version: deps['express'].replace(/[\^~]/, '') });
  if (deps['fastify']) frameworks.push({ name: 'fastify', version: deps['fastify'].replace(/[\^~]/, '') });
  if (deps['prisma'] || deps['@prisma/client']) frameworks.push({ name: 'prisma', version: (deps['prisma'] ?? deps['@prisma/client'])?.replace(/[\^~]/, '') });
  if (deps['drizzle-orm']) frameworks.push({ name: 'drizzle', version: deps['drizzle-orm']?.replace(/[\^~]/, '') });
  if (deps['@supabase/supabase-js']) frameworks.push({ name: 'supabase', version: deps['@supabase/supabase-js']?.replace(/[\^~]/, '') });

  if (frameworks.length === 0) frameworks.push({ name: 'generic' });

  return { frameworks };
}

// Backward-compatible wrapper — returns the primary framework only
export function detectFramework(projectDir: string): FrameworkInfo {
  const { frameworks } = detectFrameworks(projectDir);
  const primary = frameworks.find(f => f.name !== 'generic') ?? frameworks[0];
  return { framework: primary.name, version: primary.version };
}
