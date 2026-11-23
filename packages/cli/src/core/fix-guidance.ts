/**
 * fix-guidance.ts: the per-finding guidance record (spec 04). Bundled data, no network, no link.
 *
 * One canonical one-liner per finding (`summary`). The scan screen, the report and `--json` print
 * the same sentence word for word; `steps` adds detail, never a different instruction.
 *
 * Stack handling (spec 04):
 *  - the rule has a variant for a detected stack  -> that variant, certainty "stack-specific"
 *  - stack detected, no variant for it            -> generic text, ends "(generic: no <stack> variant yet)"
 *  - stack not detected                           -> generic text, ends "(generic: stack not detected; adapt to your framework)"
 *  - the rule is stack-neutral (variant '*')      -> that text, no suffix
 * A finding with no data here falls back to its own `fix` / `recommendation` text (first sentence).
 */

import type { Finding } from '@agenticcli/shared'

export type Effort = 'quick' | 'small' | 'medium'

interface Variant {
  summary: string
  steps?: string[]
  /** Short stack label for the "Fix (<label>)" report line, e.g. "Next.js + Supabase". */
  label?: string
}

interface GuidanceData {
  /** Short "what is wrong" for the screen line (spec 01). */
  what: string
  /** One plain sentence: why it matters (report). */
  why: string
  effort: Effort
  /** One honest condition under which this is a false positive. Absent for certain matches. */
  notIf?: string
  /** Manual check line for the report, when one applies. */
  manual?: string
  /** Extra line for the report (secret history note). */
  note?: string
  /** Key '*' = stack-neutral; other keys = detected framework names (lowercase, as framework.ts). */
  variants: Record<string, Variant>
}

const GUIDANCE: Record<string, GuidanceData> = {
  'generic.secrets.stripe-live-key': {
    what: 'live Stripe secret key in source',
    why: 'a live Stripe key gives full access to charges, refunds, customer data and payouts. It is in your source, so treat it as exposed.',
    effort: 'quick',
    note: 'Git history still holds the old key; rotating makes it useless.',
    variants: {
      '*': {
        summary:
          'rotate the key in Stripe first (the old one is exposed), then read the new one from process.env.STRIPE_SECRET_KEY',
        steps: [
          'Rotate it first: Stripe dashboard > Developers > API keys > Roll key.',
          'Read it from the environment:  const stripe = new Stripe(process.env.STRIPE_SECRET_KEY!);',
          "Put the new key in your git-ignored local env file and in your host's environment settings. Delete the old one from the source file.",
        ],
      },
    },
  },
  payment_webhook_without_signature_check: {
    what: 'webhook does not verify the Stripe signature',
    why: 'anyone can post a fake "payment succeeded" event to this URL and trigger your payment logic without paying.',
    effort: 'small',
    notIf: 'a shared wrapper or middleware already verifies the Stripe signature before this handler runs.',
    manual: 'POST {} to the route; expect 400.',
    variants: {
      nextjs: {
        label: 'Next.js App Router + Stripe',
        summary: 'build the event with stripe.webhooks.constructEvent(await req.text(), sig, secret); return 400 if it throws',
        steps: [
          'const body = await req.text();   // raw body, not req.json()',
          'const sig = req.headers.get("stripe-signature");',
          'let event;',
          'try { event = stripe.webhooks.constructEvent(body, sig!, process.env.STRIPE_WEBHOOK_SECRET!); }',
          'catch { return new Response("Bad signature", { status: 400 }); }',
          '(Edge runtime: use stripe.webhooks.constructEventAsync.)',
        ],
      },
      generic: {
        summary: 'verify the Stripe signature on the raw request body with stripe.webhooks.constructEvent before acting; return 400 if it fails',
      },
    },
  },
  auth_route_without_guard: {
    what: 'no sign-in check on an admin route',
    why: 'any caller, signed in or not, can call this admin endpoint.',
    effort: 'small',
    notIf:
      'middleware.ts (or a gateway) already enforces BOTH on this route before the handler runs: signed-out requests get 401 and signed-in non-admin users get 403. Rejecting signed-out requests alone is not enough; test it with a non-admin session before you rely on this.',
    manual: 'call the route signed out (expect 401), then signed in as a normal non-admin user (expect 403).',
    variants: {
      supabase: {
        label: 'Supabase',
        summary:
          'call supabase.auth.getUser() and return 401 if there is no user; then return 403 unless the user is an admin (role claim or profiles table)',
        steps: [
          'const { data: { user } } = await supabase.auth.getUser();   // server Supabase client your app already has',
          'if (!user) return new Response("Unauthorized", { status: 401 });',
          'Then check the user is an admin (role claim or profiles table). Signing in alone is not enough for /admin.',
        ],
      },
      generic: {
        summary:
          'check the signed-in user at the top of the handler and return 401 if there is none; then check the user may use admin routes (403 if not)',
        steps: [
          'Check the signed-in user at the top of the handler and return 401 if there is none. Then check the user may use admin routes.',
        ],
      },
    },
  },
  missing_error_handling: {
    what: 'payment route has no try/catch',
    why: 'an uncaught error in a payment route can leak a stack trace or fail silently.',
    effort: 'quick',
    notIf: 'a shared wrapper (for example withErrorHandler) already catches errors for this route.',
    variants: {
      '*': {
        summary: 'wrap the payment logic in try/catch, log the error and return a 500 response',
        steps: ['try { /* payment logic */ } catch (err) { console.error(err); return new Response("Payment failed", { status: 500 }); }'],
      },
    },
  },
  missing_idempotency: {
    what: 'no duplicate-delivery check on the webhook',
    why: 'Stripe can send the same event twice (for example after a timeout); a repeat could run the action twice, such as a second fulfilment.',
    effort: 'small',
    notIf: 'a shared helper or a database constraint already handles repeats.',
    variants: {
      '*': {
        summary: 'store each event.id before acting; if it is already stored, return 200 without running the action again',
        steps: [
          'Store each event.id before acting; if it is already stored, return 200 without running the action again (a unique index on event.id makes this safe under parallel deliveries).',
        ],
      },
    },
  },
}

/** Display names for framework identifiers (names only; no plan data). */
const STACK_DISPLAY: Record<string, string> = {
  nextjs: 'Next.js',
  supabase: 'Supabase',
  react: 'React',
  firebase: 'Firebase',
  express: 'Express',
  fastify: 'Fastify',
  nestjs: 'NestJS',
  remix: 'Remix',
  nuxt: 'Nuxt',
  vue: 'Vue',
  svelte: 'Svelte',
  sveltekit: 'SvelteKit',
  astro: 'Astro',
  prisma: 'Prisma',
  drizzle: 'Drizzle',
  stripe: 'Stripe',
}

export function stackDisplayName(name: string): string {
  return STACK_DISPLAY[name.toLowerCase()] ?? name
}

/** Real stack names only: 'generic' means "nothing recognised". */
export function realStacks(names: readonly string[] | undefined): string[] {
  return (names ?? []).map((n) => n.toLowerCase()).filter((n) => n !== 'generic' && n !== '')
}

/** First sentence of a text: up to the first ". " (or the end), without the final period. */
export function firstSentence(text: string): string {
  const t = text.replace(/\s+/g, ' ').trim()
  const m = /[.!?](?=\s|$)/.exec(t)
  const s = m ? t.slice(0, m.index) : t
  return s.trim()
}

export interface FixGuidance {
  /** Short "what is wrong" (screen line). */
  what: string
  why: string | null
  /** The one canonical fix sentence (spec 04 `fix.summary`), suffix included. */
  summary: string
  steps: string[]
  certainty: 'stack-specific' | 'generic'
  /** "Fix (<label>)" text for the report header; null when the rule has no stack label. */
  fixLabel: string | null
  effort: Effort | null
  notAVulnerabilityIf: string | null
  manual: string | null
  note: string | null
}

/**
 * Build the guidance record for one finding in the detected stack.
 * @param stacks detected framework names (lowercase); 'generic' / empty = not detected.
 */
export function fixGuidance(f: Finding, stacks: readonly string[] | undefined): FixGuidance {
  const detected = realStacks(stacks)
  const data = GUIDANCE[f.id]

  if (!data) {
    const raw = f.fix ?? f.recommendation ?? ''
    return {
      what: f.title,
      why: null,
      summary: firstSentence(raw) || 'see the report for the fix',
      steps: [],
      certainty: 'generic',
      fixLabel: null,
      effort: null,
      notAVulnerabilityIf: null,
      manual: null,
      note: null,
    }
  }

  const neutral = data.variants['*']
  if (neutral) {
    return {
      what: data.what,
      why: data.why,
      summary: neutral.summary,
      steps: neutral.steps ?? [],
      certainty: 'stack-specific',
      fixLabel: neutral.label ?? null,
      effort: data.effort,
      notAVulnerabilityIf: data.notIf ?? null,
      manual: data.manual ?? null,
      note: data.note ?? null,
    }
  }

  const hit = detected.find((s) => data.variants[s] !== undefined)
  if (hit) {
    const v = data.variants[hit]
    // Label names the matching framework and, when detected, supabase next to nextjs (spec sample).
    return {
      what: data.what,
      why: data.why,
      summary: v.summary,
      steps: v.steps ?? [],
      certainty: 'stack-specific',
      fixLabel: v.label ?? stackDisplayName(hit),
      effort: data.effort,
      notAVulnerabilityIf: data.notIf ?? null,
      manual: data.manual ?? null,
      note: data.note ?? null,
    }
  }

  const g = data.variants.generic
  const suffix =
    detected.length > 0
      ? `(generic: no ${detected.map(stackDisplayName).join(' + ')} variant yet)`
      : '(generic: stack not detected; adapt to your framework)'
  return {
    what: data.what,
    why: data.why,
    summary: `${g.summary} ${suffix}`,
    steps: g.steps ?? [],
    certainty: 'generic',
    fixLabel: detected.length > 0 ? `generic: no ${detected.map(stackDisplayName).join(' + ')} variant yet` : 'generic: stack not detected; adapt to your framework',
    effort: data.effort,
    notAVulnerabilityIf: data.notIf ?? null,
    manual: data.manual ?? null,
    note: data.note ?? null,
  }
}

const SEV_RANK: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 }
const CAT_RANK: Record<string, number> = { secrets: 0, payments: 1, auth: 2 }

/**
 * Order for screen, report and nextSteps (spec 04 "Order and grouping"):
 * 1 exposed secrets, 2 other blocking (critical then high; payments and auth first),
 * 3 non-blocking, 4 LOW-confidence last ("check by hand").
 */
export function fixOrderGroup(f: Finding): 0 | 1 | 2 | 3 {
  if (f.blocking) return f.category === 'secrets' ? 0 : 1
  return f.confidence === 'LOW' ? 3 : 2
}

export function orderFindings(findings: readonly Finding[]): Finding[] {
  return [...findings].sort((a, b) => {
    const g = fixOrderGroup(a) - fixOrderGroup(b)
    if (g !== 0) return g
    const s = (SEV_RANK[a.severity] ?? 9) - (SEV_RANK[b.severity] ?? 9)
    if (s !== 0) return s
    const c = (CAT_RANK[a.category] ?? 9) - (CAT_RANK[b.category] ?? 9)
    if (c !== 0) return c
    if (a.file !== b.file) return a.file < b.file ? -1 : 1
    return (a.line ?? 0) - (b.line ?? 0)
  })
}
