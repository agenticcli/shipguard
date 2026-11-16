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

/** True when the environment asks for offline mode (`SHIPGUARD_OFFLINE=1` or `true`). */
export function offlineRequestedByEnv(env: NodeJS.ProcessEnv = process.env): boolean {
  const v = env.SHIPGUARD_OFFLINE?.trim().toLowerCase()
  return v === '1' || v === 'true'
}

export function setOffline(value: boolean): void {
  offline = value
}

export function isOffline(): boolean {
  return offline
}
