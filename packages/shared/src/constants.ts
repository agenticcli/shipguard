export const SEVERITY_WEIGHTS: Record<string, number> = {
  info: 1,
  low: 5,
  medium: 15,
  high: 30,
  critical: 50,
}

export const EXIT_CODES = {
  SAFE: 0,
  BLOCKED: 1,
  CONFIG_ERROR: 2,
  RUNTIME_ERROR: 3,
} as const

export const CATEGORIES = ['secrets', 'auth', 'payments', 'database', 'deployment', 'injection', 'supply-chain', 'crypto', 'config'] as const

export const DEFAULT_POLICY_PATH = 'shipguard.policy.yml'
export const DEFAULT_REPORT_DIR = '.shipguard/reports'
export const DEFAULT_REPORT_FILE = '.shipguard/reports/latest.md'

// observability/audit-trail store
export const DEFAULT_HISTORY_PATH = '.shipguard/history.db'
export const HISTORY_PATH_ENV_VAR = 'SHIPGUARD_HISTORY_PATH'
export const DEFAULT_REPO_ID_FALLBACK_PATH = '.shipguard/repo-id'

// ScanId reuse: scanId retry-idempotency reuse window. A retried CLI process
// (agent re-runs `shipguard scan` after a dropped response) reuses the prior scanId only if
// the prior reservation for the identical (repo, scope, content) key is still within this
// window — see history/scan-id.ts. 30 minutes covers realistic agent-retry latency (network
// blip, rate-limit backoff, a human re-running the command) without keeping a scanId "live"
// so long that a genuinely new scan of unchanged code gets silently merged into an old one.
export const DEFAULT_SCAN_ID_REUSE_WINDOW_MINUTES = 30
export const SCAN_ID_REUSE_WINDOW_ENV_VAR = 'SHIPGUARD_SCAN_ID_REUSE_WINDOW_MINUTES'
