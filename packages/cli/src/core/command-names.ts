// The command-name table for 0.13 (P0 STUB; W2b registers these in cli.ts, W3/W4a/W4b/W1b implement them).
// One list so every stream uses the same names. Plan section 7 (P0): status, upgrade, setup, uninstall, gate, ignore.
export const NEW_COMMAND_NAMES = ['status', 'upgrade', 'setup', 'uninstall', 'gate', 'ignore'] as const;
export type NewCommandName = (typeof NEW_COMMAND_NAMES)[number];
