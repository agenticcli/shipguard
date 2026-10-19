// Free-tier checks — governance + tiering basis: /rules.md. Source of truth is migrating to the Convex rule registry.
import type { CheckModule, FileInfo, Finding, Policy } from '@agenticcli/shared'
import { compileDetectorRegex } from '../core/re2-detector-engine.js'

// ---------------------------------------------------------------------------
// Path classifiers
// ---------------------------------------------------------------------------

/** True for routes that are likely Stripe webhook handlers. */
function isStripeWebhookRoute(relativePath: string): boolean {
  const p = relativePath.toLowerCase()
  // Must be in an API route directory
  if (!p.includes('api/') && !p.includes('api\\')) return false
  return (
    p.includes('webhook') ||
    p.includes('stripe')
  )
}

/** True for routes that are likely Razorpay webhook handlers. */
function isRazorpayWebhookRoute(relativePath: string): boolean {
  const p = relativePath.toLowerCase()
  if (!p.includes('api/') && !p.includes('api\\')) return false
  return p.includes('razorpay') || (p.includes('webhook') && p.includes('razorpay'))
}

/** True for payment-related API routes (checkout, billing, subscription, payment). */
function isPaymentRoute(relativePath: string): boolean {
  const p = relativePath.toLowerCase()
  if (!p.includes('api/') && !p.includes('api\\')) return false
  return (
    p.includes('checkout') ||
    p.includes('billing') ||
    p.includes('subscription') ||
    p.includes('payment')
  )
}

/**
 * True for client-side files: in app/, pages/, or components/ but NOT inside
 * an API sub-path (app/api/, pages/api/).
 */
function isClientSideFile(relativePath: string): boolean {
  // eslint-disable-next-line no-restricted-syntax
  const p = relativePath.toLowerCase().replace(/\\/g, '/') // path normalizer — not content-scanning
  // Exclude API routes — they are server-side
  if (p.startsWith('app/api/') || p.startsWith('pages/api/')) return false
  return (
    p.startsWith('app/') ||
    p.startsWith('pages/') ||
    p.startsWith('components/')
  )
}

// ---------------------------------------------------------------------------
// Compiled re2js patterns (content-scanning only; path classifiers stay native)
// ---------------------------------------------------------------------------

// Lines 59–60 in inventory: /stripe\.webhooks\.constructEvent/i (both lowercase and
// uppercase-S form are collapsed into one case-insensitive pattern — semantically
// identical under the 'i' flag, confirmed by differential).
const RE_STRIPE_CONSTRUCT_EVENT = compileDetectorRegex('stripe\\.webhooks\\.constructEvent', 'i')

// Line 65: /stripe-signature/i
const RE_STRIPE_SIGNATURE = compileDetectorRegex('stripe-signature', 'i')

// Line 70: /validateWebhookSignature/i
const RE_RAZORPAY_VALIDATE = compileDetectorRegex('validateWebhookSignature', 'i')

// Lines 80–83: four idempotency signals
const RE_IDEMPOTENCY_WORD    = compileDetectorRegex('idempoten(?:cy|t)', 'i') // (cy|t) is RE2-safe
const RE_EVENT_ID            = compileDetectorRegex('event\\.id', 'i')
const RE_PROCESSED_EVENTS    = compileDetectorRegex('processedEvents', 'i')
const RE_ALREADY_PROCESSED   = compileDetectorRegex('alreadyProcessed', 'i')

// Lines 91×2: /\btry\b/ and /\bcatch\b/ — word boundaries are RE2-safe
const RE_TRY   = compileDetectorRegex('\\btry\\b')
const RE_CATCH = compileDetectorRegex('\\bcatch\\b')

// Lines 199–200: client-side secret-key exposure
const RE_STRIPE_SECRET_KEY   = compileDetectorRegex('STRIPE_SECRET_KEY', 'i')
const RE_RAZORPAY_KEY_SECRET = compileDetectorRegex('RAZORPAY_KEY_SECRET', 'i')

// ---------------------------------------------------------------------------
// Content analyzers
// ---------------------------------------------------------------------------

/** Returns true when the file contains stripe.webhooks.constructEvent (any casing). */
function hasStripeConstructEvent(content: string): boolean {
  return RE_STRIPE_CONSTRUCT_EVENT.test(content)
}

/** Returns true when the file reads the stripe-signature header. */
function hasStripeSignatureHeader(content: string): boolean {
  return RE_STRIPE_SIGNATURE.test(content)
}

/** Returns true when the file contains Razorpay's validateWebhookSignature. */
function hasRazorpayValidateWebhook(content: string): boolean {
  return RE_RAZORPAY_VALIDATE.test(content)
}

/**
 * Returns true when the file appears to have idempotency handling.
 * We look for common patterns: idempotency key tracking, event id recording,
 * or explicit duplicate/already-processed guards.
 */
function hasIdempotencyHandling(content: string): boolean {
  return (
    RE_IDEMPOTENCY_WORD.test(content) ||
    RE_EVENT_ID.test(content) ||
    RE_PROCESSED_EVENTS.test(content) ||
    RE_ALREADY_PROCESSED.test(content)
  )
}

/**
 * Returns true when the file has both try and catch blocks (basic error handling).
 */
function hasErrorHandling(content: string): boolean {
  return RE_TRY.test(content) && RE_CATCH.test(content)
}

// ---------------------------------------------------------------------------
// Finding builders
// ---------------------------------------------------------------------------

function isBlocking(id: string, policy: Policy): boolean {
  return policy.block.includes(id)
}

// ---------------------------------------------------------------------------
// CheckModule implementation
// ---------------------------------------------------------------------------

export const payments: CheckModule = {
  id: 'payments',
  name: 'Payment & Webhook Security',

  run(files: FileInfo[], policy: Policy): Finding[] {
    const findings: Finding[] = []

    for (const file of files) {
      const { relativePath, content } = file

      // ------------------------------------------------------------------
      // 1. Stripe webhook route missing constructEvent signature verification
      // ------------------------------------------------------------------
      if (isStripeWebhookRoute(relativePath)) {
        if (!hasStripeConstructEvent(content)) {
          const id = 'payment_webhook_without_signature_check'
          findings.push({
            id,
            title: 'Stripe webhook missing signature verification',
            severity: 'critical',
            category: 'payments',
            file: relativePath,
            evidence: 'No call to stripe.webhooks.constructEvent() found',
            confidence: 'MEDIUM',
            explanation:
              'Without calling stripe.webhooks.constructEvent(), the webhook endpoint cannot verify that ' +
              'requests originate from Stripe. Attackers can send forged events to trigger payment logic ' +
              '(e.g., fake payment_intent.succeeded) without making a real payment.',
            recommendation:
              'Verify every incoming webhook with stripe.webhooks.constructEvent(rawBody, sig, webhookSecret). ' +
              'Pass the raw request body — not a parsed JSON object — to prevent HMAC mismatch.',
            blocking: isBlocking(id, policy),
          })
        }

        // ----------------------------------------------------------------
        // 2. Stripe webhook route missing stripe-signature header read
        //    (separate check — constructEvent may be present but header may
        //    be fetched incorrectly in a wrapper; also catches middleware
        //    that skips the header entirely)
        // ----------------------------------------------------------------
        if (!hasStripeSignatureHeader(content)) {
          const id = 'payment_webhook_without_signature_check'
          findings.push({
            id,
            title: 'Stripe webhook does not read stripe-signature header',
            severity: 'critical',
            category: 'payments',
            file: relativePath,
            evidence: 'No reference to stripe-signature header found',
            confidence: 'MEDIUM',
            explanation:
              'The Stripe-Signature header carries the HMAC timestamp+hash that proves the request ' +
              'originated from Stripe. Without reading it, signature verification is impossible.',
            recommendation:
              'Read the header with request.headers.get("stripe-signature") (Next.js) or ' +
              'req.headers["stripe-signature"] (Express) before calling constructEvent().',
            blocking: isBlocking(id, policy),
          })
        }
      }

      // ------------------------------------------------------------------
      // 3. Razorpay webhook route missing validateWebhookSignature
      // ------------------------------------------------------------------
      if (isRazorpayWebhookRoute(relativePath)) {
        if (!hasRazorpayValidateWebhook(content)) {
          const id = 'payment_webhook_without_signature_check'
          findings.push({
            id,
            title: 'Razorpay webhook missing signature verification',
            severity: 'critical',
            category: 'payments',
            file: relativePath,
            evidence: 'No call to validateWebhookSignature() found',
            confidence: 'MEDIUM',
            explanation:
              'Without validateWebhookSignature(), the webhook endpoint cannot verify that ' +
              'requests originate from Razorpay. An attacker can send forged payment confirmation ' +
              'events without completing an actual payment.',
            recommendation:
              'Use Razorpay.validateWebhookSignature(rawBody, signature, webhookSecret) ' +
              'where signature is taken from the x-razorpay-signature header. ' +
              'Always pass the raw (unparsed) body.',
            blocking: isBlocking(id, policy),
          })
        }
      }

      // ------------------------------------------------------------------
      // 4. STRIPE_SECRET_KEY or RAZORPAY_KEY_SECRET in client-side files
      // ------------------------------------------------------------------
      if (isClientSideFile(relativePath)) {
        const stripeSecretInFile = RE_STRIPE_SECRET_KEY.test(content)
        const razorpaySecretInFile = RE_RAZORPAY_KEY_SECRET.test(content)

        if (stripeSecretInFile) {
          const id = 'exposed_env'
          findings.push({
            id,
            title: 'STRIPE_SECRET_KEY referenced in client-side file',
            severity: 'critical',
            category: 'payments',
            file: relativePath,
            evidence: 'Reference to STRIPE_SECRET_KEY found in a client-bundle file',
            confidence: 'MEDIUM',
            explanation:
              'STRIPE_SECRET_KEY is a server-only secret. If it is bundled into client-side code ' +
              'it will be exposed in the browser, allowing anyone to make API calls on your behalf — ' +
              'creating charges, accessing customer data, or issuing refunds.',
            recommendation:
              'Move Stripe secret key usage exclusively to API routes (app/api/ or pages/api/). ' +
              'Use NEXT_PUBLIC_ prefix only for the Stripe publishable key.',
            blocking: isBlocking(id, policy),
          })
        }

        if (razorpaySecretInFile) {
          const id = 'exposed_env'
          findings.push({
            id,
            title: 'RAZORPAY_KEY_SECRET referenced in client-side file',
            severity: 'critical',
            category: 'payments',
            file: relativePath,
            evidence: 'Reference to RAZORPAY_KEY_SECRET found in a client-bundle file',
            confidence: 'MEDIUM',
            explanation:
              'RAZORPAY_KEY_SECRET is a server-only secret. Exposure in client-side code allows ' +
              'attackers to forge payment signatures and verify payments without completing them.',
            recommendation:
              'Use RAZORPAY_KEY_SECRET only in server-side API routes. ' +
              'For the client, only use the Razorpay key_id (public).',
            blocking: isBlocking(id, policy),
          })
        }
      }

      // ------------------------------------------------------------------
      // 5. Webhook routes without idempotency handling
      //    Applies to both Stripe and Razorpay webhook files.
      // ------------------------------------------------------------------
      if (isStripeWebhookRoute(relativePath) || isRazorpayWebhookRoute(relativePath)) {
        if (!hasIdempotencyHandling(content)) {
          const id = 'missing_idempotency'
          findings.push({
            id,
            title: 'Webhook handler lacks idempotency protection',
            severity: 'medium',
            category: 'payments',
            file: relativePath,
            evidence: 'No idempotency key, event.id check, or duplicate-detection logic found',
            confidence: 'LOW',
            explanation:
              'Payment providers may deliver the same webhook event more than once (retries after ' +
              'network failure, provider-side bugs). Without idempotency guards, duplicate deliveries ' +
              'can cause double-charges, double-fulfillments, or double-refunds.',
            recommendation:
              'Record processed event IDs (e.g., store event.id in a database) before acting on the ' +
              'event. If the ID already exists, return 200 immediately without reprocessing.',
            blocking: isBlocking(id, policy),
          })
        }
      }

      // ------------------------------------------------------------------
      // 6. Payment-related routes without basic error handling
      // ------------------------------------------------------------------
      if (isPaymentRoute(relativePath)) {
        if (!hasErrorHandling(content)) {
          const id = 'missing_error_handling'
          findings.push({
            id,
            title: 'Payment route lacks error handling',
            severity: 'low',
            category: 'payments',
            file: relativePath,
            evidence: 'No try/catch block found in payment-related route',
            confidence: 'LOW',
            explanation:
              'Unhandled exceptions in payment routes can leak stack traces to the client, cause ' +
              'silent failures in payment processing, and make debugging production incidents harder.',
            recommendation:
              'Wrap payment logic in try/catch. Return a structured error response (e.g., 500 with ' +
              'a generic message) and log the full error server-side.',
            blocking: isBlocking(id, policy),
          })
        }
      }
    }

    return findings
  },
}

export default payments
