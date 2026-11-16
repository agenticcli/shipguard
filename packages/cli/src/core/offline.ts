/**
 * Agent-safe offline mode: `shipguard scan --offline` or `SHIPGUARD_OFFLINE=1`.
 *
 * With the mode on, ShipGuard sends nothing (no usage ping, no first-run ping, no rulebook download,
 * no login or token calls) and writes nothing outside the project: no `~/.config/shipguard`, no
 * `~/.shipguard`, no `.gitignore` edit, no local history store. The free rules and the bundled rules
 * run on the machine as usual.
 *
 * One process-wide switch, set once at startup (cli.ts preAction and the scan command). The places
 * that would talk to the network or write to the home directory check it before they act.
 */

/** The line printed first (human: first stdout line; --json/--sarif/--quiet: stderr). */
export const OFFLINE_ANNOUNCE =
  'shipguard: offline mode - nothing is sent and no files are written (bundled rules only, run on this machine).'

let offline = false

/**
 * True when the environment asks for offline mode. Fails closed: any non-empty value other than
 * `0`, `false`, `no` or `off` (any case) switches it on, so a typo such as `yes` or `on` never
 * silently leaves pings and downloads running.
 */
export function offlineRequestedByEnv(env: NodeJS.ProcessEnv = process.env): boolean {
  const v = env.SHIPGUARD_OFFLINE?.trim().toLowerCase()
  if (!v) return false
  return !['0', 'false', 'no', 'off'].includes(v)
}

/** Commands that cannot work without the network. Under offline mode they refuse with exit 2. */
export const NETWORK_COMMANDS: ReadonlySet<string> = new Set(['login', 'status', 'rate'])

/** The one line printed when a network command is run under offline mode. */
export const OFFLINE_REFUSAL = 'offline mode: this command needs the network'

export function setOffline(value: boolean): void {
  offline = value
}

export function isOffline(): boolean {
  return offline
}
