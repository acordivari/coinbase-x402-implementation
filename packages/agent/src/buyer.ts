/**
 * Headless buyer agent. Discovers the merchant catalog, then buys a SKU over
 * x402 — the paying fetch transparently handles the 402 challenge, signs the
 * payment with the agent's wallet, and retries. An Idempotency-Key makes a
 * retried purchase safe (the merchant returns the same receipt, never charging
 * twice).
 *
 * Run: `npm run agent`  (WALLET_MODE=local needs no keys; WALLET_MODE=cdp uses
 * the CDP Server Wallet and real Base Sepolia settlement).
 */
import { randomUUID } from "node:crypto";
import {
  validateRequirementsBeforePaying,
  PaymentRequiredResponse,
} from "@agentic-payments/shared";
import { createSigner } from "./wallet.ts";
import { createPayingFetch } from "./x402-client.ts";

export interface PurchaseOptions {
  merchantUrl: string;
  sku: string;
  rpcUrl?: string;
  idempotencyKey?: string;
  /** A signed Intent mandate (HAM). Required when the merchant enforces it. */
  intentMandate?: unknown;
}

export interface PurchaseResult {
  ok: boolean;
  status: number;
  body: unknown;
  settledOrder?: unknown;
  agentAddress: string;
  idempotencyKey: string;
}

export async function runPurchase(opts: PurchaseOptions): Promise<PurchaseResult> {
  const signer = await createSigner();
  const payingFetch = await createPayingFetch(signer, { rpcUrl: opts.rpcUrl });
  const idempotencyKey = opts.idempotencyKey ?? randomUUID();

  const mandateHeader: Record<string, string> = opts.intentMandate
    ? {
        "X-Authorization-Mandate": Buffer.from(
          JSON.stringify(opts.intentMandate),
        ).toString("base64"),
      }
    : {};

  console.log(`[agent] wallet ${signer.label} ${signer.address}`);

  // Optional pre-flight: peek at the quote and refuse obviously-bad ones before
  // we ever sign. (The paying fetch would otherwise pay automatically.)
  const challenge = await fetch(`${opts.merchantUrl}/buy/${opts.sku}`, {
    headers: mandateHeader,
  });
  // The merchant gates on a Human Authorization Mandate: a 401/403 here means
  // the mandate is missing or out of scope — fail fast with a clear message.
  if (challenge.status === 401 || challenge.status === 403) {
    const detail = await challenge.json().catch(() => ({}));
    throw new Error(
      `merchant rejected authorization (HTTP ${challenge.status}): ${JSON.stringify(detail)}`,
    );
  }
  if (challenge.status === 402) {
    const header = challenge.headers.get("PAYMENT-REQUIRED");
    if (header) {
      try {
        const decoded = PaymentRequiredResponse.parse(
          JSON.parse(Buffer.from(header, "base64").toString("utf8")),
        );
        const quote = decoded.accepts[0];
        if (quote) {
          const check = validateRequirementsBeforePaying(quote);
          if (!check.ok) {
            throw new Error(`refusing to pay bad quote: ${check.violations.join("; ")}`);
          }
        }
      } catch (err) {
        // A decode failure here is non-fatal — the paying fetch still enforces
        // payment correctness; we just couldn't pre-validate.
        console.warn(`[agent] could not pre-validate quote: ${(err as Error).message}`);
      }
    }
  }

  const res = await payingFetch(`${opts.merchantUrl}/buy/${opts.sku}`, {
    method: "GET",
    headers: { "Idempotency-Key": idempotencyKey, ...mandateHeader },
  });

  const body = (await res.json().catch(() => ({}))) as {
    receipt?: { paymentNonce?: string };
  };

  // Settlement is asynchronous: poll until the order reaches a terminal state.
  let settledOrder: unknown;
  const nonce = body?.receipt?.paymentNonce;
  if (res.ok && nonce) {
    settledOrder = await pollOrder(opts.merchantUrl, nonce);
  }

  return {
    ok: res.ok,
    status: res.status,
    body,
    settledOrder,
    agentAddress: signer.address,
    idempotencyKey,
  };
}

/** Poll the merchant until the order settles (or a few attempts elapse). */
async function pollOrder(
  merchantUrl: string,
  nonce: string,
  attempts = 10,
  delayMs = 200,
): Promise<unknown> {
  for (let i = 0; i < attempts; i++) {
    const r = await fetch(`${merchantUrl}/orders/by-nonce/${nonce}`);
    if (r.ok) {
      const order = (await r.json()) as { state?: string };
      if (order.state === "SETTLED" || order.state === "FAILED") return order;
    }
    await new Promise((res) => setTimeout(res, delayMs));
  }
  return undefined;
}

const isMain = process.argv[1]?.endsWith("buyer.ts");
if (isMain) {
  const merchantUrl = process.env.MERCHANT_URL ?? "http://localhost:4021";
  const sku = process.argv[2] ?? process.env.SKU ?? "allergy-relief-24";
  runPurchase({ merchantUrl, sku, rpcUrl: process.env.BASE_SEPOLIA_RPC_URL })
    .then((result) => {
      console.log(`[agent] HTTP ${result.status}`);
      console.log(JSON.stringify(result.body, null, 2));
      if (result.settledOrder) {
        console.log("[agent] settled order:");
        console.log(JSON.stringify(result.settledOrder, null, 2));
      }
      process.exit(result.ok ? 0 : 1);
    })
    .catch((err) => {
      console.error(`[agent] purchase failed: ${err.message}`);
      process.exit(1);
    });
}
