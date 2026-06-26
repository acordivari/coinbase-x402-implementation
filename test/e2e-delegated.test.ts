/**
 * End-to-end for the DELEGATED mandate (autonomous) workflow: a verified human
 * makes ONE selective-disclosure presentation that authorizes a durable, scoped
 * *budget* (not a single payment). The Authorization Service issues one long-lived
 * HAM Intent, and the agent then settles MANY purchases over x402 with NO further
 * human approval — the presigned identity is the standing authorization. The
 * merchant's cumulative-cap enforcement stops an over-budget buy on its own.
 *
 * Runs fully offline (PROOF_MODE=local substrate, FACILITATOR_MODE=mock), since
 * the mandate machinery is identity-source-agnostic.
 */
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import type { AddressInfo } from "node:net";
import type { Server } from "node:http";
import { createMerchantApp, type MerchantApp } from "@agentic-payments/merchant";
import { createLocalSigner, createPayingFetch, type PaymentSigner } from "@agentic-payments/agent";
import { dollarsToAtomic } from "@agentic-payments/shared";
import {
  AuthorizationService,
  createSigningKeyPair,
  MandateSigner,
  MandateVerifier,
  type IntentMandate,
  type SigningKeyPair,
} from "@agentic-payments/identity";
import {
  buildPaymentMandateTransactionData,
  buildProofIdDcqlQuery,
  buildProofRequired,
  createEncryptor,
  createIdentityChallenge,
  encodeTransactionData,
  generateEs256Keys,
  localVcVerifier,
  LocalVcIssuer,
  LocalWallet,
  packPresentation,
  PROOF_BASIC_SCOPE,
  PROOF_CREDENTIAL_ID,
  PROOF_ID_CLAIM_KEYS,
  verifyAuthorization,
  type Encryptor,
  type Jwk,
  type VerifiableCredentialVerifier,
} from "@agentic-payments/credentials";

const MERCHANT = "0x3333333333333333333333333333333333333333" as const;
const VERIFIER_ID = "https://sandbox.local/merchant";
const ISSUER_ID = "https://issuer.sandbox.local";
const MANDATE_TTL = 86_400; // 24h durable mandate

let merchant: MerchantApp;
let server: Server;
let base: string;
let asKey: SigningKeyPair;
let service: AuthorizationService;
let issuerKeys: { publicJwk: Jwk; privateJwk: Jwk };
let issuer: LocalVcIssuer;
let vcVerifier: VerifiableCredentialVerifier;
let encryptor: Encryptor;

beforeAll(async () => {
  asKey = await createSigningKeyPair("auth-service-1");
  service = new AuthorizationService(
    { verify: async () => { throw new Error("OIDC disabled"); } } as never,
    new MandateSigner(asKey),
  );
  const mandateVerifier = new MandateVerifier([{ kid: asKey.kid, publicKey: asKey.publicKey }]);
  merchant = createMerchantApp({ facilitatorMode: "mock", payTo: MERCHANT }, { mandateVerifier });
  await new Promise<void>((resolve) => { server = merchant.app.listen(0, resolve); });
  base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;

  issuerKeys = await generateEs256Keys();
  issuer = new LocalVcIssuer({ issuerId: ISSUER_ID, privateJwk: issuerKeys.privateJwk });
  vcVerifier = localVcVerifier({ issuerId: ISSUER_ID, issuerPublicJwk: issuerKeys.publicJwk });
  encryptor = createEncryptor({ key: "e2e-delegated-encryptor-key-0123456789", purpose: "x401-delegated" });
});

afterAll(async () => {
  await new Promise<void>((resolve) => server.close(() => resolve()));
});

async function newWallet(): Promise<LocalWallet> {
  const holder = await generateEs256Keys();
  const wallet = new LocalWallet(holder.privateJwk, holder.publicJwk);
  const compact = await issuer.issue(
    { given_name: "Andrew", family_name: "Cordivari", birth_date: "1990-04-12", email: "andrew@example.com", age_over_21: true },
    wallet.publicJwk,
  );
  wallet.store({ id: PROOF_CREDENTIAL_ID, compact, claimNames: [...PROOF_ID_CLAIM_KEYS] });
  return wallet;
}

/** One human presentation that authorizes a *budget grant* (not a single buy). */
async function grantMandate(opts: {
  wallet: LocalWallet;
  agentWallet: `0x${string}`;
  budgetUsd: string;
  categories: string[];
  requestedClaims: string[];
}): Promise<IntentMandate> {
  const amount = dollarsToAtomic(opts.budgetUsd).toString();
  const td = encodeTransactionData(
    buildPaymentMandateTransactionData({
      amount, currency: "USDC", merchant: MERCHANT,
      sku: "mandate-grant", description: `Standing mandate: up to $${opts.budgetUsd}`,
    }),
  );
  const resource = `${VERIFIER_ID}/mandate/grant`;
  const challenge = await createIdentityChallenge({ encryptor, verifierId: VERIFIER_ID, resource, method: "GET", ttlSeconds: 600, transactionData: td });
  const { payload } = buildProofRequired({ challenge, tokenEndpoint: `${VERIFIER_ID}/oauth/token`, scope: PROOF_BASIC_SCOPE });
  const present = await opts.wallet.present({ query: buildProofIdDcqlQuery(opts.requestedClaims), nonce: challenge.value, audience: VERIFIER_ID });
  const { artifact } = packPresentation({ payload, agentId: opts.agentWallet, vpToken: present.vpToken });
  const authorization = await verifyAuthorization({
    artifact, encryptor, vcVerifier,
    expectedVerifierId: VERIFIER_ID, expectedResource: resource, expectedMethod: "GET",
    requiredClaims: opts.requestedClaims, transactionData: td,
  });
  expect(authorization.result.ok).toBe(true);
  expect(authorization.txDataBound).toBe(true);
  return service.issueIntentFromPresentation({
    authorization, agentWallet: opts.agentWallet,
    scope: { maxAmount: amount, merchantAllowlist: [MERCHANT], allowedCategories: opts.categories },
    ttlSeconds: MANDATE_TTL,
  });
}

/** The agent buys autonomously — same standing Intent, no re-presentation. */
async function buy(signer: PaymentSigner, sku: string, intent: IntentMandate, key: string) {
  const payingFetch = await createPayingFetch(signer);
  const res = await payingFetch(`${base}/buy/${sku}`, {
    headers: {
      "Idempotency-Key": key,
      "X-Authorization-Mandate": Buffer.from(JSON.stringify(intent)).toString("base64"),
    },
  });
  return { status: res.status, body: (await res.json().catch(() => ({}))) as any };
}

async function pollSettled(nonce: string): Promise<string> {
  for (let i = 0; i < 25; i++) {
    const r = await fetch(`${base}/orders/by-nonce/${nonce}`);
    if (r.ok) {
      const order = (await r.json()) as { state: string };
      if (order.state === "SETTLED" || order.state === "FAILED") return order.state;
    }
    await new Promise((res) => setTimeout(res, 50));
  }
  throw new Error("did not settle");
}

describe("delegated mandate (autonomous, presigned identity = authorization)", () => {
  it("one presentation issues a durable, broad-scope mandate", async () => {
    const signer = createLocalSigner();
    const wallet = await newWallet();
    const intent = await grantMandate({
      wallet, agentWallet: signer.address, budgetUsd: "5.00",
      categories: ["otc-medicine", "vitamins"], requestedClaims: ["given_name", "age_over_21"],
    });
    expect(intent.principal.verifiedVia).toBe("x401-vp");
    expect(intent.scope.maxAmount).toBe(dollarsToAtomic("5.00").toString());
    expect(intent.scope.allowedCategories).toEqual(["otc-medicine", "vitamins"]);
    // Durable: a full day, not the 1h single-purchase default.
    expect(intent.expiresAt - intent.issuedAt).toBe(MANDATE_TTL);
  });

  it("settles MANY autonomous purchases under ONE signed mandate, then stops at the cap", async () => {
    const signer = createLocalSigner();
    const wallet = await newWallet();
    // $4.00 budget across two categories — one human presentation.
    const intent = await grantMandate({
      wallet, agentWallet: signer.address, budgetUsd: "4.00",
      categories: ["otc-medicine", "vitamins"], requestedClaims: ["given_name", "age_over_21"],
    });

    // Autonomous buy #1: $1.50 (cumulative $1.50) — settles, no human in the loop.
    const a = await buy(signer, "allergy-relief-24", intent, "deleg-1");
    expect(a.status).toBe(200);
    expect(await pollSettled(a.body.receipt.paymentNonce)).toBe("SETTLED");

    // Autonomous buy #2: $2.25 (cumulative $3.75) — same Intent, still settles.
    const b = await buy(signer, "vitamin-d3-2000", intent, "deleg-2");
    expect(b.status).toBe(200);
    expect(await pollSettled(b.body.receipt.paymentNonce)).toBe("SETTLED");

    // Autonomous buy #3: $0.75 (cumulative $4.50 > $4.00 cap) — denied by the
    // merchant on its own, no human prompt.
    const c = await buy(signer, "ibuprofen-200", intent, "deleg-3");
    expect(c.status).toBe(403);
    expect(JSON.stringify(c.body.violations)).toMatch(/exceed intent cap/);
  });

  it("denies an out-of-scope category autonomously (no human prompt)", async () => {
    const signer = createLocalSigner();
    const wallet = await newWallet();
    const intent = await grantMandate({
      wallet, agentWallet: signer.address, budgetUsd: "10.00",
      categories: ["otc-medicine"], requestedClaims: ["given_name"],
    });
    // toothpaste-mint is personal-care — outside the granted scope.
    const r = await buy(signer, "toothpaste-mint", intent, "deleg-cat-1");
    expect(r.status).toBe(403);
    expect(JSON.stringify(r.body.violations)).toMatch(/not authorized/);
  });
});
