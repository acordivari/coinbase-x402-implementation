/**
 * Mandate enforcement gate. Sits in front of the x402 paywall on /buy routes
 * and refuses any purchase that isn't covered by a signed Human Authorization
 * Mandate (HAM). It proves, before settlement, that:
 *   - a real human authorized this agent (Intent signature + verified OIDC sub)
 *   - the purchase is in scope (Cart ⊆ Intent: merchant, category, per-purchase
 *     cap, validity window) — checked via the shared validators
 *   - the agent is paying the merchant's OWN catalog price (not an amount of its
 *     own choosing) and the payer is the wallet the human authorized
 *   - cumulative spend across purchases stays within the Intent cap
 *
 * The cart is derived server-side from the catalog, so the merchant authorizes
 * against its own source of truth rather than trusting agent-supplied figures.
 */
import type { NextFunction, Request, Response } from "express";
import {
  IntentMandate,
  X402_NETWORK,
  collect,
  nowSeconds,
  validateCartAgainstIntent,
  validatePaymentAgainstCart,
} from "@agentic-payments/shared";
import {
  buildCartMandate,
  buildPaymentMandate,
  type MandateVerifier,
  type RevocationChecker,
} from "@agentic-payments/identity";
import { findProduct, productPriceAtomic } from "./catalog.ts";
import { decodePaymentAuthorization } from "./x402-headers.ts";
import type { SpendLedger } from "./spend-ledger.ts";

// The spend-cap ledger seam (in-memory / file / http) lives in `spend-ledger.ts`;
// re-exported here for back-compat with the historical `IntentSpendLedger` name.
export { InMemorySpendLedger, IntentSpendLedger, type SpendLedger } from "./spend-ledger.ts";

const MANDATE_HEADER = "x-authorization-mandate";

export interface MandateGateOptions {
  verifier: MandateVerifier;
  merchant: `0x${string}`;
  asset: `0x${string}`;
  network: typeof X402_NETWORK;
  /** Spend-cap ledger — in-memory (default), durable (file), or global (http). */
  ledger: SpendLedger;
  /** Optional issuer revocation list — a revoked Intent is refused before settlement. */
  revocation?: RevocationChecker;
  now?: () => number;
}

function deny(res: Response, status: number, error: string, violations?: string[]): void {
  res.status(status).json(violations ? { error, violations } : { error });
}

function decodeMandateHeader(req: Request): IntentMandate | undefined {
  const raw = req.header(MANDATE_HEADER);
  if (!raw) return undefined;
  try {
    return IntentMandate.parse(JSON.parse(Buffer.from(raw, "base64").toString("utf8")));
  } catch {
    return undefined;
  }
}

export function createMandateGate(opts: MandateGateOptions) {
  const now = opts.now ?? nowSeconds;

  return async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    const sku = req.path.replace(/^\//, "");
    const product = findProduct(sku);
    if (!product) return next(); // unknown sku — let the route 404 normally

    const intent = decodeMandateHeader(req);
    if (!intent) return deny(res, 401, "authorization mandate required");

    // The merchant's OWN price is the source of truth — never the agent's input.
    const price = productPriceAtomic(product.sku);
    const cart = buildCartMandate({
      intentId: intent.id,
      merchant: opts.merchant,
      items: [
        {
          sku: product.sku,
          name: product.name,
          category: product.category,
          unitPrice: price.toString(),
          quantity: 1,
        },
      ],
      nowSeconds: now(),
    });

    // Signature + revocation + Cart ⊆ Intent (merchant, category, per-purchase
    // cap, validity window — including not-yet-active) via the shared validators.
    // Revocation is checked here so a killed mandate is refused even at the unpaid
    // 402 stage and BEFORE any cap reservation — independent of scope/expiry.
    const sigOk = await opts.verifier.verifyProof(intent);
    const revoked = opts.revocation ? await opts.revocation.isRevoked(intent.id) : false;
    const cartScope = validateCartAgainstIntent(cart, intent, now());
    const base = collect([
      sigOk ? null : "intent mandate signature is invalid or untrusted",
      revoked ? "intent mandate has been revoked" : null,
      ...(cartScope.ok ? [] : cartScope.violations),
    ]);
    if (!base.ok) return deny(res, 403, "authorization denied", base.violations);

    // Cumulative-cap feasibility (committed + reserved + this purchase). The
    // ledger may be remote (global/durable); if its status can't be read, fail
    // CLOSED — deny rather than risk over-spend.
    let priorTotal: bigint;
    try {
      priorTotal = BigInt(await opts.ledger.total(intent.id));
    } catch {
      return deny(res, 403, "authorization denied", ["spend ledger unavailable"]);
    }
    if (priorTotal + price > BigInt(intent.scope.maxAmount)) {
      return deny(res, 403, "authorization denied", [
        `purchase would exceed intent cap ${intent.scope.maxAmount}`,
      ]);
    }

    const payment = decodePaymentAuthorization(req);
    // Unpaid challenge: scope is good — let the x402 paywall emit its 402.
    if (!payment.nonce || !payment.value || !payment.from) return next();

    // Paid request: the payer must be the authorized wallet, and the signed
    // amount must equal the merchant's price (Payment ⊆ Cart catches the latter
    // because the cart total is the catalog price, not the agent's figure).
    if (payment.from.toLowerCase() !== intent.agentWallet.toLowerCase()) {
      return deny(res, 403, "payer is not the authorized agent wallet");
    }
    const paymentMandate = buildPaymentMandate({
      cartId: cart.id,
      payTo: opts.merchant,
      asset: opts.asset,
      amount: payment.value,
      network: opts.network,
      nonce: payment.nonce,
    });
    const paymentScope = validatePaymentAgainstCart(paymentMandate, cart);
    if (!paymentScope.ok) {
      return deny(res, 403, "authorization denied", paymentScope.violations);
    }

    // Reserve the merchant's price against the cap. Release it if this request
    // does not end in an authorized (200) purchase — otherwise the settle hooks
    // own the eventual commit/release. This pairs every reserve with exactly
    // one commit or release (no leaked reservations on a paywall rejection).
    const reservation = await opts.ledger.reserve(
      intent.id,
      payment.nonce,
      price,
      BigInt(intent.scope.maxAmount),
    );
    if (!reservation.ok) return deny(res, 403, "authorization denied", reservation.violations);

    const nonce = payment.nonce;
    res.on("finish", () => {
      // Best-effort (the response is already sent); release may be async/remote.
      if (res.statusCode !== 200) void opts.ledger.release(nonce);
    });

    next();
  };
}
