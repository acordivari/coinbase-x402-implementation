/**
 * Offline end-to-end: a headless agent (throwaway viem wallet) buys from the
 * mock-CVS merchant over real x402 (402 challenge -> EIP-3009 signing -> verify
 * -> async settle via the mock facilitator). No keys, no funds, no chain.
 *
 * This proves the protocol wiring AND the application guarantees (order
 * lifecycle + idempotency) hold together, not just in isolation.
 */
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import type { AddressInfo } from "node:net";
import type { Server } from "node:http";
import { createMerchantApp, type MerchantApp } from "@agentic-payments/merchant";
import { createLocalSigner, createPayingFetch } from "@agentic-payments/agent";

let merchant: MerchantApp;
let server: Server;
let base: string;

beforeAll(async () => {
  merchant = createMerchantApp({
    facilitatorMode: "mock",
    payTo: "0x000000000000000000000000000000000000dead",
  });
  await new Promise<void>((resolve) => {
    server = merchant.app.listen(0, resolve);
  });
  const { port } = server.address() as AddressInfo;
  base = `http://127.0.0.1:${port}`;
});

afterAll(async () => {
  await new Promise<void>((resolve) => server.close(() => resolve()));
});

async function pollOrder(nonce: string): Promise<{ state: string; txHash?: string }> {
  for (let i = 0; i < 20; i++) {
    const r = await fetch(`${base}/orders/by-nonce/${nonce}`);
    if (r.ok) {
      const order = (await r.json()) as { state: string; txHash?: string };
      if (order.state === "SETTLED" || order.state === "FAILED") return order;
    }
    await new Promise((res) => setTimeout(res, 50));
  }
  throw new Error("order did not settle in time");
}

describe("x402 agent -> mock-CVS merchant (offline E2E)", () => {
  it("challenges with 402, then settles a signed payment to SETTLED", async () => {
    const signer = createLocalSigner();
    const payingFetch = await createPayingFetch(signer);

    // Without payment we get a 402 challenge.
    const challenge = await fetch(`${base}/buy/allergy-relief-24`);
    expect(challenge.status).toBe(402);

    // The paying fetch signs + retries automatically.
    const res = await payingFetch(`${base}/buy/allergy-relief-24`, {
      headers: { "Idempotency-Key": "e2e-key-1" },
    });
    expect(res.status).toBe(200);
    const body = (await res.json()) as {
      receipt: { state: string; paymentNonce: string; amountUsd: string };
    };
    expect(body.receipt.state).toBe("AUTHORIZED");
    expect(body.receipt.amountUsd).toBe("1.50");

    // Settlement is async; the order reaches SETTLED with a tx hash.
    const order = await pollOrder(body.receipt.paymentNonce);
    expect(order.state).toBe("SETTLED");
    expect(order.txHash).toMatch(/^0xmocktx/);
  });

  it("is idempotent: replaying the same key does not settle twice", async () => {
    const key = "e2e-idem-key";
    const buy = async () => {
      const signer = createLocalSigner();
      const payingFetch = await createPayingFetch(signer);
      const res = await payingFetch(`${base}/buy/ibuprofen-200`, {
        headers: { "Idempotency-Key": key },
      });
      return res.json();
    };

    const first = (await buy()) as { receipt?: { paymentNonce?: string } };
    expect(first.receipt?.paymentNonce).toBeTruthy();
    await pollOrder(first.receipt!.paymentNonce!);

    // Second call under the same key is short-circuited as a replay.
    const second = (await buy()) as { replayed?: boolean; order?: { state: string } };
    expect(second.replayed).toBe(true);
    expect(second.order?.state).toBe("SETTLED");

    // Exactly one order exists for ibuprofen under this run.
    const ibuprofenOrders = merchant.orders
      .all()
      .filter((o) => o.sku === "ibuprofen-200" && o.idempotencyKey === key);
    expect(ibuprofenOrders).toHaveLength(1);
  });
});
