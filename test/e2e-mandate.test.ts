/**
 * Phase 2 end-to-end: the merchant enforces the Human Authorization Mandate.
 * A human authenticates via the (local) OIDC issuer; the Authorization Service
 * issues a signed Intent binding that identity to the agent wallet + a scope.
 * The merchant settles only purchases that fall within that signed scope.
 */
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import type { AddressInfo } from "node:net";
import type { Server } from "node:http";
import { createMerchantApp, type MerchantApp } from "@agentic-payments/merchant";
import {
  createLocalSigner,
  createPayingFetch,
  type PaymentSigner,
} from "@agentic-payments/agent";
import {
  AuthorizationService,
  createSigningKeyPair,
  LocalOidcIssuer,
  localVerifier,
  MandateSigner,
  MandateVerifier,
  type IntentMandate,
  type SigningKeyPair,
} from "@agentic-payments/identity";

const MERCHANT = "0x1111111111111111111111111111111111111111" as const;

let merchant: MerchantApp;
let server: Server;
let base: string;
let asKey: SigningKeyPair;
let issuer: LocalOidcIssuer;
let service: AuthorizationService;

beforeAll(async () => {
  asKey = await createSigningKeyPair("auth-service-1");
  const oidcKey = await createSigningKeyPair("oidc-1");
  issuer = new LocalOidcIssuer("https://sandbox.local/", "agentic-payments", oidcKey);
  service = new AuthorizationService(localVerifier(issuer), new MandateSigner(asKey));

  const mandateVerifier = new MandateVerifier([
    { kid: asKey.kid, publicKey: asKey.publicKey },
  ]);
  merchant = createMerchantApp(
    { facilitatorMode: "mock", payTo: MERCHANT },
    { mandateVerifier },
  );
  await new Promise<void>((resolve) => {
    server = merchant.app.listen(0, resolve);
  });
  base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
});

afterAll(async () => {
  await new Promise<void>((resolve) => server.close(() => resolve()));
});

async function issueIntentFor(
  agentWallet: `0x${string}`,
  opts: { maxAmount: string; categories: string[] },
): Promise<IntentMandate> {
  const idToken = await issuer.mintIdToken({
    sub: "auth0|buyer",
    email: "buyer@example.com",
    emailVerified: true,
  });
  return service.issueIntent({
    idToken,
    agentWallet,
    scope: {
      maxAmount: opts.maxAmount,
      merchantAllowlist: [MERCHANT],
      allowedCategories: opts.categories,
    },
  });
}

async function buy(
  signer: PaymentSigner,
  sku: string,
  intent: IntentMandate | undefined,
  key: string,
): Promise<{ status: number; body: any }> {
  const payingFetch = await createPayingFetch(signer);
  const headers: Record<string, string> = { "Idempotency-Key": key };
  if (intent) {
    headers["X-Authorization-Mandate"] = Buffer.from(JSON.stringify(intent)).toString("base64");
  }
  try {
    const res = await payingFetch(`${base}/buy/${sku}`, { headers });
    return { status: res.status, body: await res.json().catch(() => ({})) };
  } catch (err) {
    return { status: -1, body: { error: String(err) } };
  }
}

async function pollSettled(nonce: string): Promise<string> {
  for (let i = 0; i < 20; i++) {
    const r = await fetch(`${base}/orders/by-nonce/${nonce}`);
    if (r.ok) {
      const order = (await r.json()) as { state: string };
      if (order.state === "SETTLED" || order.state === "FAILED") return order.state;
    }
    await new Promise((res) => setTimeout(res, 50));
  }
  throw new Error("did not settle");
}

describe("merchant enforces the Human Authorization Mandate", () => {
  it("settles a purchase that is within the signed scope", async () => {
    const signer = createLocalSigner();
    const intent = await issueIntentFor(signer.address, {
      maxAmount: "5000000",
      categories: ["otc-medicine", "vitamins"],
    });
    const { status, body } = await buy(signer, "allergy-relief-24", intent, "ok-1");
    expect(status).toBe(200);
    expect(body.receipt.state).toBe("AUTHORIZED");
    expect(await pollSettled(body.receipt.paymentNonce)).toBe("SETTLED");
  });

  it("rejects a purchase with no mandate (401)", async () => {
    const signer = createLocalSigner();
    const { status } = await buy(signer, "allergy-relief-24", undefined, "no-mandate-1");
    expect(status).toBe(401);
  });

  it("rejects a category outside the authorized scope (403)", async () => {
    const signer = createLocalSigner();
    const intent = await issueIntentFor(signer.address, {
      maxAmount: "5000000",
      categories: ["vitamins"], // allergy-relief is otc-medicine
    });
    const { status, body } = await buy(signer, "allergy-relief-24", intent, "cat-1");
    expect(status).toBe(403);
    expect(JSON.stringify(body.violations)).toMatch(/not authorized/);
  });

  it("rejects a purchase over the per-intent cap (403)", async () => {
    const signer = createLocalSigner();
    const intent = await issueIntentFor(signer.address, {
      maxAmount: "1000000", // $1.00 cap, allergy-relief is $1.50
      categories: ["otc-medicine"],
    });
    const { status, body } = await buy(signer, "allergy-relief-24", intent, "cap-1");
    expect(status).toBe(403);
    expect(JSON.stringify(body.violations)).toMatch(/exceeds? intent cap/);
  });

  it("rejects a tampered Intent (bad signature, 403)", async () => {
    const signer = createLocalSigner();
    const intent = await issueIntentFor(signer.address, {
      maxAmount: "1000000",
      categories: ["otc-medicine"],
    });
    const tampered = { ...intent, scope: { ...intent.scope, maxAmount: "9999999999" } };
    const { status, body } = await buy(signer, "allergy-relief-24", tampered, "tamper-1");
    expect(status).toBe(403);
    expect(JSON.stringify(body.violations)).toMatch(/signature is invalid/);
  });

  it("enforces the cumulative cap across multiple purchases", async () => {
    const signer = createLocalSigner();
    const intent = await issueIntentFor(signer.address, {
      maxAmount: "3500000", // $3.50 total
      categories: ["otc-medicine", "vitamins"],
    });
    // First: $2.25 vitamin — settles.
    const first = await buy(signer, "vitamin-d3-2000", intent, "cum-1");
    expect(first.status).toBe(200);
    expect(await pollSettled(first.body.receipt.paymentNonce)).toBe("SETTLED");

    // Second: $1.50 allergy — cumulative $3.75 > $3.50 cap — rejected.
    const second = await buy(signer, "allergy-relief-24", intent, "cum-2");
    expect(second.status).toBe(403);
    expect(JSON.stringify(second.body.violations)).toMatch(/exceed intent cap/);
  });
});
