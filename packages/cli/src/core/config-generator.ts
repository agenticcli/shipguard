import { writeFileSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import type { FrameworkEntry } from './framework.js';
import { DEFAULT_MAX_FILE_SIZE_BYTES, DEFAULT_MAX_TOTAL_BYTES, DEFAULT_MAX_FILES } from '../utils/fs.js';

const CONFIG_FILENAME = '.shipguard.yml';

export function hasConfig(cwd: string): boolean {
  return existsSync(join(cwd, CONFIG_FILENAME));
}

export function generateConfig(cwd: string, frameworks: FrameworkEntry[]): string {
  const frameworkLines = frameworks
    .filter(f => f.name !== 'generic')
    .map(f => {
      const version = f.version ? `\n      version: "${f.version}"` : '';
      return `    - name: ${f.name}${version}`;
    })
    .join('\n');

  const config = `# ShipGuard configuration — auto-generated ${new Date().toISOString().split('T')[0]}
# Edit to customize scanning behavior
configVersion: 2

project:
  name: ${cwd.split('/').pop() || 'my-app'}

stack:
  frameworks:
${frameworkLines || '    - name: generic'}
  language: typescript

scan:
  categories:
    - auth
    - injection
    - supply-chain
    - secrets
    - deployment
  severityThreshold: medium
  changedOnly: false
  rulesVersion: null

ignore:
  paths:
    - "**/__tests__/**"
    - "**/test/**"
    - "**/*.test.ts"
    - "**/node_modules/**"

limits:
  # Per-file size cap — files larger than this are skipped (not read into memory)
  maxFileSizeBytes: ${DEFAULT_MAX_FILE_SIZE_BYTES}
  # Total bytes cap across all files — scan stops if exceeded (degraded mode)
  maxTotalBytes: ${DEFAULT_MAX_TOTAL_BYTES}
  # Maximum number of files to scan — scan stops if exceeded (degraded mode)
  maxFiles: ${DEFAULT_MAX_FILES}

# Pseudonymous usage ping (see \`shipguard telemetry status\`). Set enabled: false to opt out in this project.
telemetry:
  enabled: true

output:
  report: null
`;

  const configPath = join(cwd, CONFIG_FILENAME);
  writeFileSync(configPath, config, 'utf-8');
  return configPath;
}
