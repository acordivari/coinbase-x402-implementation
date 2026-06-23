/**
 * End-to-end for the x401 identity path: a verified human presents a Proof-shaped
 * SD-JWT-VC (selective disclosure) bound — via transaction_data — to a specific
 * payment. The Authorization Service verifies that presentation and issues a HAM
 * Intent, and the existing x402 rail settles it. This proves x401 can replace
 * OIDC as the identity source feeding HAM, end to end, with no network.
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

const MERCHANT = "0x2222222222222222222222222222222222222222" as const;
const VERIFIER_ID = "https://sandbox.local/merchant";
const ISSUER_ID = "https://issuer.sandbox.local";

let merchant: MerchantApp;
let server: Server;
let base: string;
let asKey: SigningKeyPair;
let service: AuthorizationService;
let issuerKeys: { publicJwk: Jwk; privateJwk: Jwk };
let issuer: LocalVcIssuer;
let vcVerifier: VerifiableCredentialVerifier;
let encryptor: Encryptor;
let prices: Record<string, string>;

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

  const cat = (await (await fetch(`${base}/catalog`)).json()) as { products: { sku: string; priceUsd: string; category: string }[] };
  prices = Object.fromEntries(cat.products.map((p) => [p.sku, p.priceUsd]));

  issuerKeys = await generateEs256Keys();
  issuer = new LocalVcIssuer({ issuerId: ISSUER_ID, privateJwk: issuerKeys.privateJwk });
  vcVerifier = localVcVerifier({ issuerId: ISSUER_ID, issuerPublicJwk: issuerKeys.publicJwk });
  encryptor = createEncryptor({ key: "e2e-x401-encryptor-key-0123456789", purpose: "x401-e2e" });
});

afterAll(async () => {
  await new Promise<void>((resolve) => server.close(() => resolve()));
});

/** A fresh holder wallet with a Proof-shaped credential issued into it. */
async function newWallet(persona = "andrew@example.com"): Promise<LocalWallet> {
  const holder = await generateEs256Keys();
  const wallet = new LocalWallet(holder.privateJwk, holder.publicJwk);
  const claims = persona === "andrew@example.com"
    ? { given_name: "Andrew", family_name: "Cordivari", birth_date: "1990-04-12", email: "andrew@example.com", age_over_21: true }
    : { given_name: "Sam", family_name: "Rivera", birth_date: "2006-09-30", email: "sam@example.com", age_over_21: false };
  const compact = await issuer.issue(claims, wallet.publicJwk);
  wallet.store({ id: PROOF_CREDENTIAL_ID, compact, claimNames: [...PROOF_ID_CLAIM_KEYS] });
  return wallet;
}

/** Phase A: present a credential bound to the sku's payment, return the verification. */
async function authorize(opts: {
  wallet: LocalWallet;
  agentWallet: `0x${string}`;
  sku: string;
  requestedClaims: string[];
  tamperPayment?: boolean;
}) {
  const amount = dollarsToAtomic(prices[opts.sku]!).toString();
  const td = encodeTransactionData(
    buildPaymentMandateTransactionData({ amount, currency: "USDC", merchant: MERCHANT, sku: opts.sku }),
  );
  const resource = `${VERIFIER_ID}/buy/${opts.sku}`;
  const challenge = await createIdentityChallenge({ encryptor, verifierId: VERIFIER_ID, resource, method: "GET", ttlSeconds: 600, transactionData: td });
  const { payload } = buildProofRequired({ challenge, tokenEndpoint: `${VERIFIER_ID}/oauth/token`, scope: PROOF_BASIC_SCOPE });
  const present = await opts.wallet.present({ query: buildProofIdDcqlQuery(opts.requestedClaims), nonce: challenge.value, audience: VERIFIER_ID });
  const { artifact } = packPresentation({ payload, agentId: opts.agentWallet, vpToken: present.vpToken });

  const verifyTd = opts.tamperPayment
    ? encodeTransactionData(buildPaymentMandateTransactionData({ amount: "9999999", currency: "USDC", merchant: MERCHANT }))
    : td;
  const authorization = await verifyAuthorization({
    artifact, encryptor, vcVerifier,
    expectedVerifierId: VERIFIER_ID, expectedResource: resource, expectedMethod: "GET",
    requiredClaims: opts.requestedClaims, transactionData: verifyTd,
  });
  return { authorization, present };
}

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

describe("x401 → HAM → x402 (identity-bound agentic payment)", () => {
  it("verifies a VC presentation, issues an Intent, and settles via x402", async () => {
    const signer = createLocalSigner();
    const wallet = await newWallet();
    const { authorization } = await authorize({
      wallet, agentWallet: signer.address, sku: "allergy-relief-24",
      requestedClaims: ["given_name", "family_name", "age_over_21"],
    });
    expect(authorization.result.ok).toBe(true);
    expect(authorization.txDataBound).toBe(true);

    const intent = await service.issueIntentFromPresentation({
      authorization, agentWallet: signer.address,
      scope: { maxAmount: dollarsToAtomic("5").toString(), merchantAllowlist: [MERCHANT], allowedCategories: ["otc-medicine"] },
    });
    expect(intent.principal.verifiedVia).toBe("x401-vp");
    expect([...(intent.principal.credential?.claimsDisclosed ?? [])].sort()).toEqual(
      ["age_over_21", "family_name", "given_name"],
    );

    const { status, body } = await buy(signer, "allergy-relief-24", intent, "x401-ok-1");
    expect(status).toBe(200);
    expect(await pollSettled(body.receipt.paymentNonce)).toBe("SETTLED");
  });

  it("refuses to issue an Intent when the payment binding is broken", async () => {
    const signer = createLocalSigner();
    const wallet = await newWallet();
    const { authorization } = await authorize({
      wallet, agentWallet: signer.address, sku: "allergy-relief-24",
      requestedClaims: ["given_name"], tamperPayment: true,
    });
    expect(authorization.txDataBound).toBe(false);
    await expect(
      service.issueIntentFromPresentation({
        authorization, agentWallet: signer.address,
        scope: { maxAmount: dollarsToAtomic("5").toString(), merchantAllowlist: [MERCHANT], allowedCategories: ["otc-medicine"] },
      }),
    ).rejects.toThrow(/not authorized/);
  });

  it("rejects a presentation that withholds a DCQL-required claim", async () => {
    const signer = createLocalSigner();
    const wallet = await newWallet();
    // Request given_name only at the wallet, but require email at the verifier.
    const amount = dollarsToAtomic(prices["allergy-relief-24"]!).toString();
    const td = encodeTransactionData(buildPaymentMandateTransactionData({ amount, currency: "USDC", merchant: MERCHANT }));
    const resource = `${VERIFIER_ID}/buy/allergy-relief-24`;
    const challenge = await createIdentityChallenge({ encryptor, verifierId: VERIFIER_ID, resource, method: "GET", ttlSeconds: 600, transactionData: td });
    const { payload } = buildProofRequired({ challenge, tokenEndpoint: `${VERIFIER_ID}/oauth/token`, scope: PROOF_BASIC_SCOPE });
    const present = await wallet.present({ query: buildProofIdDcqlQuery(["given_name"]), nonce: challenge.value, audience: VERIFIER_ID });
    const { artifact } = packPresentation({ payload, agentId: signer.address, vpToken: present.vpToken });
    const authorization = await verifyAuthorization({
      artifact, encryptor, vcVerifier,
      expectedVerifierId: VERIFIER_ID, expectedResource: resource, expectedMethod: "GET",
      requiredClaims: ["given_name", "email"], transactionData: td,
    });
    expect(authorization.result.ok).toBe(false);
  });
});
