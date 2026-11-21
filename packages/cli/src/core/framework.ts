import { readFileSync, existsSync } from 'node:fs';
import { join } from 'node:path';

export interface FrameworkEntry { name: string; version?: string }
export interface FrameworkDetectionResult { frameworks: FrameworkEntry[] }

// Keep backward-compatible single-framework type for callers that haven't migrated
export interface FrameworkInfo { framework: string; version?: string }

// Only stacks with at least one stack-specific rule in the rulebook are detected (a stack with no rule of its own
// adds nothing: the general rules run for every project). Names match the first part of the rule ids; the server's
// per-stack offer counts cover exactly this set.
const ver = (v: unknown): string | undefined => (typeof v === 'string' ? v.replace(/[\^~]/, '') : undefined);

export function detectFrameworks(projectDir: string): FrameworkDetectionResult {
  const pkgPath = join(projectDir, 'package.json');
  const pkg = existsSync(pkgPath) ? JSON.parse(readFileSync(pkgPath, 'utf-8')) : {};
  const deps = { ...pkg.dependencies, ...pkg.devDependencies };
  const frameworks: FrameworkEntry[] = [];

  if (deps['next']) frameworks.push({ name: 'nextjs', version: ver(deps['next']) });
  if (deps['express']) frameworks.push({ name: 'express', version: ver(deps['express']) });
  if (deps['prisma'] || deps['@prisma/client']) frameworks.push({ name: 'prisma', version: ver(deps['prisma'] ?? deps['@prisma/client']) });
  if (deps['@supabase/supabase-js']) frameworks.push({ name: 'supabase', version: ver(deps['@supabase/supabase-js']) });
  if (deps['react'] || deps['react-dom']) frameworks.push({ name: 'react', version: ver(deps['react'] ?? deps['react-dom']) });
  const fbDep = deps['firebase'] ?? deps['firebase-admin'] ?? deps['firebase-functions'];
  // A Firebase project without a package.json dependency (rules-only repo) still has firebase.json or firestore.rules.
  if (fbDep || existsSync(join(projectDir, 'firebase.json')) || existsSync(join(projectDir, 'firestore.rules'))) {
    frameworks.push({ name: 'firebase', version: ver(fbDep) });
  }

  if (frameworks.length === 0) frameworks.push({ name: 'generic' });

  return { frameworks };
}

// Backward-compatible wrapper — returns the primary framework only
export function detectFramework(projectDir: string): FrameworkInfo {
  const { frameworks } = detectFrameworks(projectDir);
  const primary = frameworks.find(f => f.name !== 'generic') ?? frameworks[0];
  return { framework: primary.name, version: primary.version };
}
