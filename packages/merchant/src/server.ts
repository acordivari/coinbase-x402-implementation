/**
 * Mock-CVS merchant server. Uses the official @x402/express middleware for
 * protocol-correct 402 challenge + verify + settle (via our resilient
 * facilitator), and layers an order ledger + HTTP-level idempotency around it.
 *
 * The x402 middleware grants access on `verify` and settles AFTER the response,
 * so the lifecycle maps as: verify -> order AUTHORIZED (synchronous, in the
 * route handler); settle success -> order SETTLED (asynchronous, via the
 * facilitator settle hook). Clients poll /orders/by-nonce/:nonce for the final
 * settled receipt + tx hash.
 *
 * Run: `npm run merchant`  (FACILITATOR_MODE=mock needs no key or funds).
 */
import { randomUUID } from "node:crypto";
import express, { type Request, type Response } from "express";
import { x402ResourceServer, type RoutesConfig } from "@x402/core/server";
import { registerExactEvmScheme } from "@x402/evm/exact/server";
import { paymentMiddleware } from "@x402/express";
import { CATALOG, findProduct, productPriceAtomic } from "./catalog.ts";
import {
  assertConfigValid,
  loadMerchantConfig,
  type MerchantConfig,
} from "./config.ts";
import { buildFacilitator } from "./facilitator/index.ts";
import type { SettleHooks } from "./facilitator/resilient.ts";
import { MemoryOrderStore, type OrderStore } from "./order-store.ts";
import { createMandateGate, IntentSpendLedger } from "./mandate-gate.ts";
import { decodePaymentAuthorization } from "./x402-headers.ts";
import type { MandateVerifier } from "@agentic-payments/identity";

export interface MerchantAppOptions {
  /** When set, /buy requires a signed Human Authorization Mandate (Phase 2). */
  mandateVerifier?: MandateVerifier;
}

const ORDER_HEADER = "idempotency-key";

/** Build the priced x402 routes from the catalog (one static route per sku). */
function buildRoutes(config: MerchantConfig): RoutesConfig {
  const routes: Record<string, unknown> = {};
  for (const p of CATALOG) {
    routes[`GET /buy/${p.sku}`] = {
      accepts: {
        scheme: "exact",
        payTo: config.payTo,
        price: `$${p.priceUsd}`,
        network: config.network,
        maxTimeoutSeconds: 120,
      },
      description: p.name,
      mimeType: "application/json",
    };
  }
  return routes as RoutesConfig;
}

export interface MerchantApp {
  app: express.Express;
  orders: OrderStore;
  config: MerchantConfig;
}

export function createMerchantApp(
  configOverride?: Partial<MerchantConfig>,
  options: MerchantAppOptions = {},
): MerchantApp {
  const config = { ...loadMerchantConfig(), ...configOverride };
  assertConfigValid(config);
  const orders = new MemoryOrderStore();
  const nonceToOrder = new Map<string, string>();
  const ledger = new IntentSpendLedger();

  // When settlement resolves (after the response), advance the order. This is
  // where AUTHORIZED -> SETTLED (or -> FAILED) actually happens.
  const hooks: SettleHooks = {
    onSettleSuccess: (nonce, res) => {
      ledger.commit(nonce); // move reserved spend to committed
      const id = nonceToOrder.get(nonce.toLowerCase());
      const order = id ? orders.get(id) : undefined;
      if (!id || order?.state !== "AUTHORIZED") return;
      orders.transition(id, "SETTLING");
      orders.transition(id, "SETTLED");
      orders.attachPayment(id, { nonce, txHash: res.transaction });
    },
    onSettleFailure: (nonce) => {
      ledger.release(nonce); // free the cap reservation
      const id = nonceToOrder.get(nonce.toLowerCase());
      const order = id ? orders.get(id) : undefined;
      if (id && order?.state === "AUTHORIZED") orders.transition(id, "FAILED");
    },
  };

  const { resilient } = buildFacilitator(config, { hooks });
  const resourceServer = new x402ResourceServer(resilient);
  registerExactEvmScheme(resourceServer, { networks: [config.network] });

  const app = express();
  app.use(express.json());

  // --- Open routes (no payment required) ---
  app.get("/healthz", (_req, res) => {
    res.json({ ok: true, mode: config.facilitatorMode, network: config.network });
  });

  app.get("/catalog", (_req, res) => {
    res.json({ products: CATALOG, payTo: config.payTo, network: config.network });
  });

  app.get("/orders/:id", (req, res) => {
    const order = orders.get(req.params.id ?? "");
    if (!order) return res.status(404).json({ error: "order not found" });
    res.json(order);
  });

  app.get("/orders/by-nonce/:nonce", (req, res) => {
    const id = nonceToOrder.get((req.params.nonce ?? "").toLowerCase());
    const order = id ? orders.get(id) : undefined;
    if (!order) return res.status(404).json({ error: "order not found" });
    res.json(order);
  });

  // --- Idempotency guard: a replayed checkout under the same key returns the
  // existing (already-authorized/settled) order and never re-enters payment,
  // so a retried purchase can't double-charge. ---
  app.use("/buy", (req, res, next) => {
    const key = req.header(ORDER_HEADER);
    if (!key) return next();
    const existing = orders.findByIdempotencyKey(key);
    if (existing && existing.state !== "CREATED" && existing.state !== "QUOTED") {
      return res.json({ replayed: true, order: existing });
    }
    next();
  });

  // --- Human Authorization Mandate gate (Phase 2): when a verifier is
  // configured, every /buy must carry a signed, in-scope Intent mandate. ---
  if (options.mandateVerifier) {
    app.use(
      "/buy",
      createMandateGate({
        verifier: options.mandateVerifier,
        merchant: config.payTo,
        asset: config.asset,
        network: config.network,
        ledger,
      }),
    );
  }

  // --- The x402 paywall: challenges with 402, verifies on retry ---
  app.use(paymentMiddleware(buildRoutes(config), resourceServer));

  // --- Fulfilment: runs after the payment verifies (settlement is async) ---
  app.get("/buy/:sku", (req: Request, res: Response) => {
    const product = findProduct(req.params.sku ?? "");
    if (!product) return res.status(404).json({ error: "unknown sku" });

    const nonce = decodePaymentAuthorization(req).nonce ?? "";
    const id = `ord_${nonce || randomUUID()}`;
    if (!orders.get(id)) {
      orders.create({
        id,
        sku: product.sku,
        amount: productPriceAtomic(product.sku).toString(),
        payTo: config.payTo,
        idempotencyKey: req.header(ORDER_HEADER),
      });
      orders.transition(id, "QUOTED");
      orders.transition(id, "AUTHORIZED");
      if (nonce) {
        orders.attachPayment(id, { nonce });
        nonceToOrder.set(nonce.toLowerCase(), id);
      }
    }
    const order = orders.get(id)!;

    res.json({
      receipt: {
        orderId: order.id,
        product: { sku: product.sku, name: product.name },
        amountUsd: product.priceUsd,
        network: config.network,
        state: order.state, // AUTHORIZED now; SETTLED after async settlement
        paymentNonce: nonce || undefined,
        settlement: "pending",
        pollUrl: nonce ? `/orders/by-nonce/${nonce}` : undefined,
      },
    });
  });

  return { app, orders, config };
}

// Boot when run directly.
const isMain = process.argv[1]?.endsWith("server.ts");
if (isMain) {
  const { app, config } = createMerchantApp();
  app.listen(config.port, () => {
    console.log(
      `[mock-CVS] listening on :${config.port} ` +
        `(facilitator=${config.facilitatorMode}, network=${config.network})`,
    );
  });
}
