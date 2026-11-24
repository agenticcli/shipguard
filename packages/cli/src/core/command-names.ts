// The command-name table for 0.13 (registered in cli.ts).
// One list so every command uses the same names: status, upgrade, setup, uninstall, gate, ignore.
export const NEW_COMMAND_NAMES = ['status', 'upgrade', 'setup', 'uninstall', 'gate', 'ignore'] as const;
export type NewCommandName = (typeof NEW_COMMAND_NAMES)[number];
