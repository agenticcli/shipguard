// Types for the signed plan block and the public offer (contract: docs/contracts/plan-v2.json).
// P0 STUB: types only, no logic. W1a owns this file from here (verify, safe-text, hint, nag, offer cache).
// HARD RULE: the CLI holds no plan facts: nothing in this file may be a price, count, pack size, trial
// length, plan name or limit. Every value below arrives from the server, signed, and is shown verbatim.

/** Account states the server may send. An unknown value is kept as 'unsupported', never as 'none'. */
export type AccountStatus = 'active' | 'trialing' | 'pending' | 'past_due' | 'ending' | 'lapsed' | 'none' | 'unsupported';
/** Usage states: ok = no notice, warn and used = the capped allowance notice. Unknown = ok. */
export type UsageState = 'ok' | 'warn' | 'used';
/** Why plan data is unavailable (spec 02, "The plan block"). */
export type PlanUnavailableReason = 'OFFLINE' | 'NOT_FETCHED' | 'SERVER_NO_PLAN' | 'FETCH_FAILED' | 'PLAN_UNVERIFIED';

export interface PlanServerBlock {
  fetchedAt: string;
  validUntil: string;
  label: string | null;
  account: { status: AccountStatus; text: string | null } | null;
  usage: { percent: number; state: UsageState; resetsAt: string | null; text: string | null; counted: boolean | null } | null;
  limit: { text: string } | null;
  capabilities: { rulebookDefault: boolean; rulebookTiers: string[] } | null;
  refreshAfter: number | null;
  updateNotice: string | null;
  proAdds: { planName: string | null; rules: number | null; stacks: string[]; areas: string[] } | null;
  offer: { text: string; slot: string } | null;
}

export interface PlanBlock {
  status: 'live' | 'cached' | 'unavailable';
  reason: PlanUnavailableReason | null;
  /** The plan command to run next (a CLI command name, never server text). */
  command: string;
  /** Go-link built by the CLI from a server-given slot name, else null. Never a URL from the server. */
  link: string | null;
  server: PlanServerBlock | null;
}

/** Signed plan document payload (jws typ shipguard-account+jws). Required: dv, iss, aud, acct, iat, exp. */
export interface PlanDocumentPayload {
  dv: number; iss: string; aud: string; acct: string; iat: number; exp: number;
  refreshAfter?: number; nonce?: string; binding?: { scanId: string };
  label?: string; account?: { status: string; text?: string };
  usage?: { percent: number; state: string; resetsAt?: string; text?: string; counted?: boolean | null };
  limit?: { text: string }; capabilities?: { rulebookDefault: boolean; rulebookTiers: string[] };
  proAdds?: { planName?: string; rules?: number | null; stacks?: string[]; areas?: string[] };
  offer?: { text: string; slot: string }; updateNotice?: string | null;
}

/** Signed public offer payload (jws typ shipguard-offer+jws). Required: dv, iss, aud, iat, exp. */
export interface OfferDocumentPayload {
  dv: number; iss: string; aud: string; iat: number; exp: number;
  offer?: { text: string; slot: string };
  counts?: Record<string, { rules: number; areas: string[] }>;
}
