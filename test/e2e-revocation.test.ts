/**
 * End-to-end for mandate REVOCATION. A delegated mandate is durable, so without
 * revocation a leaked Intent could be spent until its TTL. Here the issuer revokes
 * a still-valid Intent mid-life and the merchant refuses every further spend —
 * even though the Intent's signature, scope, cap headroom, and expiry are all fine.
 *
 * Offline: PROOF_MODE=local substrate, FACILITATOR_MODE=mock. The issuer and
 * merchant share one in-process RevocationRegistry (the swappable seam).
 */
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import type { AddressInfo } from "node:net";
import type { Server } from "node:http";
import express from "express";
import { createMerchantApp, type MerchantApp } from "@agentic-payments/merchant";
import { createLocalSigner, createPayingFetch, type PaymentSigner } from "@agentic-payments/agent";
import { dollarsToAtomic } from "@agentic-payments/shared";
import {
  AuthorizationService,
  createSigningKeyPair,
  httpRevocationChecker,
  MandateSigner,
  MandateVerifier,
  RevocationRegistry,
  type IntentMandate,
  type SigningKeyPair,
} from "@agentic-payments/identity";
import {
  buildProofIdDcqlQuery,
  buildProofRequest,
  buildPaymentMandateTransactionData,
  createEncryptor,
  createIdentityChallenge,
  encodeTransactionData,
  generateEs256Keys,
  localVcVerifier,
  LocalVcIssuer,
  LocalWallet,
  packCredentialResult,
  PROOF_BASIC_SCOPE,
  PROOF_CREDENTIAL_ID,
  PROOF_ID_CLAIM_KEYS,
  verifyAuthorization,
  type Encryptor,
  type Jwk,
  type VerifiableCredentialVerifier,
} from "@agentic-payments/credentials";

const MERCHANT = "0x4444444444444444444444444444444444444444" as const;
const VERIFIER_ID = "https://sandbox.local/merchant";
const ISSUER_ID = "https://issuer.sandbox.local";

let merchant: MerchantApp;
let server: Server;
let base: string;
let asKey: SigningKeyPair;
let service: AuthorizationService;
let revocations: RevocationRegistry;
let issuerKeys: { publicJwk: Jwk; privateJwk: Jwk };
let issuer: LocalVcIssuer;
let vcVerifier: VerifiableCredentialVerifier;
let encryptor: Encryptor;

beforeAll(async () => {
  asKey = await createSigningKeyPair("auth-service-1");
  // One registry, shared between the issuer (writer) and the merchant (reader).
  revocations = new RevocationRegistry();
  service = new AuthorizationService(
    { verify: async () => { throw new Error("OIDC disabled"); } } as never,
    new MandateSigner(asKey),
    undefined,
    revocations,
  );
  const mandateVerifier = new MandateVerifier([{ kid: asKey.kid, publicKey: asKey.publicKey }]);
  merchant = createMerchantApp(
    { facilitatorMode: "mock", payTo: MERCHANT },
    { mandateVerifier, revocation: revocations },
  );
  await new Promise<void>((resolve) => { server = merchant.app.listen(0, resolve); });
  base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;

  issuerKeys = await generateEs256Keys();
  issuer = new LocalVcIssuer({ issuerId: ISSUER_ID, privateJwk: issuerKeys.privateJwk });
  vcVerifier = localVcVerifier({ issuerId: ISSUER_ID, issuerPublicJwk: issuerKeys.publicJwk });
  encryptor = createEncryptor({ key: "e2e-revocation-encryptor-key-0123456789", purpose: "x401-revocation" });
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

/** Grant a durable, broad-scope mandate via one presentation. */
async function grantMandate(agentWallet: `0x${string}`): Promise<IntentMandate> {
  const wallet = await newWallet();
  const amount = dollarsToAtomic("10.00").toString();
  const td = encodeTransactionData(
    buildPaymentMandateTransactionData({ amount, currency: "USDC", merchant: MERCHANT, sku: "mandate-grant" }),
  );
  const resource = `${VERIFIER_ID}/mandate/grant`;
  const challenge = await createIdentityChallenge({ encryptor, verifierId: VERIFIER_ID, resource, method: "GET", ttlSeconds: 600, transactionData: td });
  const { payload } = buildProofRequest({ challenge, tokenEndpoint: `${VERIFIER_ID}/oauth/token`, scope: PROOF_BASIC_SCOPE });
  const present = await wallet.present({ query: buildProofIdDcqlQuery(["given_name", "age_over_21"]), nonce: challenge.value, audience: VERIFIER_ID });
  const { artifact } = packCredentialResult({ payload, agentId: agentWallet, vpToken: present.vpToken });
  const authorization = await verifyAuthorization({
    artifact, encryptor, vcVerifier,
    expectedVerifierId: VERIFIER_ID, expectedResource: resource, expectedMethod: "GET",
    requiredClaims: ["given_name", "age_over_21"], transactionData: td,
  });
  return service.issueIntentFromPresentation({
    authorization, agentWallet,
    scope: { maxAmount: amount, merchantAllowlist: [MERCHANT], allowedCategories: ["otc-medicine", "vitamins"] },
    ttlSeconds: 86_400,
  });
}

async function buy(signer: PaymentSigner, sku: string, intent: IntentMandate, key: string, baseUrl = base) {
  const payingFetch = await createPayingFetch(signer);
  const res = await payingFetch(`${baseUrl}/buy/${sku}`, {
    headers: {
      "Idempotency-Key": key,
      "X-Authorization-Mandate": Buffer.from(JSON.stringify(intent)).toString("base64"),
    },
  });
  return { status: res.status, body: (await res.json().catch(() => ({}))) as any };
}

async function pollSettled(nonce: string, baseUrl = base): Promise<string> {
  for (let i = 0; i < 25; i++) {
    const r = await fetch(`${baseUrl}/orders/by-nonce/${nonce}`);
    if (r.ok) {
      const order = (await r.json()) as { state: string };
      if (order.state === "SETTLED" || order.state === "FAILED") return order.state;
    }
    await new Promise((res) => setTimeout(res, 50));
  }
  throw new Error("did not settle");
}

describe("mandate revocation (issuer kills a still-valid mandate; merchant enforces)", () => {
  it("settles before revoke, then denies every spend after revoke", async () => {
    const signer = createLocalSigner();
    const intent = await grantMandate(signer.address);

    // Before revoke: a buy settles normally (signature + scope + cap all fine).
    const before = await buy(signer, "allergy-relief-24", intent, "rev-before");
    expect(before.status).toBe(200);
    expect(await pollSettled(before.body.receipt.paymentNonce)).toBe("SETTLED");

    // The issuer revokes the mandate mid-life.
    service.revokeIntent(intent.id, "leaked agent key");
    expect(revocations.isRevoked(intent.id)).toBe(true);

    // After revoke: the SAME (still validly-signed, in-scope, unexpired, under-cap)
    // Intent is refused by the merchant.
    const after = await buy(signer, "vitamin-d3-2000", intent, "rev-after");
    expect(after.status).toBe(403);
    expect(JSON.stringify(after.body.violations)).toMatch(/revoked/);
  });

  it("revoking one mandate does not affect another", async () => {
    const signerA = createLocalSigner();
    const signerB = createLocalSigner();
    const intentA = await grantMandate(signerA.address);
    const intentB = await grantMandate(signerB.address);

    service.revokeIntent(intentA.id);

    const a = await buy(signerA, "allergy-relief-24", intentA, "rev-iso-a");
    expect(a.status).toBe(403);
    expect(JSON.stringify(a.body.violations)).toMatch(/revoked/);

    const b = await buy(signerB, "allergy-relief-24", intentB, "rev-iso-b");
    expect(b.status).toBe(200);
    expect(await pollSettled(b.body.receipt.paymentNonce)).toBe("SETTLED");
  });
});

describe("revocation over the HTTP issuer status channel (fail-closed)", () => {
  let statusServer: Server;
  let httpMerchant: MerchantApp;
  let httpServer: Server;
  let httpBase: string;

  beforeAll(async () => {
    // The issuer's OCSP-style status endpoint, over the SAME registry the AS writes.
    const statusApp = express();
    statusApp.get("/revocations/:id", (req, res) => res.json({ revoked: revocations.isRevoked(req.params.id) }));
    statusServer = await new Promise<Server>((resolve) => { const s = statusApp.listen(0, () => resolve(s)); });
    const statusBase = `http://127.0.0.1:${(statusServer.address() as AddressInfo).port}`;

    // A merchant that reads revocation over HTTP (not the shared object).
    httpMerchant = createMerchantApp(
      { facilitatorMode: "mock", payTo: MERCHANT },
      {
        mandateVerifier: new MandateVerifier([{ kid: asKey.kid, publicKey: asKey.publicKey }]),
        revocation: httpRevocationChecker({ baseUrl: statusBase, timeoutMs: 1000 }),
      },
    );
    httpServer = await new Promise<Server>((resolve) => { const s = httpMerchant.app.listen(0, () => resolve(s)); });
    httpBase = `http://127.0.0.1:${(httpServer.address() as AddressInfo).port}`;
  });

  afterAll(async () => {
    await new Promise<void>((r) => httpServer.close(() => r()));
    if (statusServer.listening) await new Promise<void>((r) => statusServer.close(() => r()));
  });

  it("propagates a revocation over HTTP: settles before, denied after", async () => {
    const signer = createLocalSigner();
    const intent = await grantMandate(signer.address);

    const before = await buy(signer, "allergy-relief-24", intent, "http-before", httpBase);
    expect(before.status).toBe(200);
    expect(await pollSettled(before.body.receipt.paymentNonce, httpBase)).toBe("SETTLED");

    service.revokeIntent(intent.id, "revoked over HTTP");
    const after = await buy(signer, "vitamin-d3-2000", intent, "http-after", httpBase);
    expect(after.status).toBe(403);
    expect(JSON.stringify(after.body.violations)).toMatch(/revoked/);
  });

  it("FAILS CLOSED: denies a non-revoked mandate when the issuer is unreachable", async () => {
    const signer = createLocalSigner();
    const intent = await grantMandate(signer.address); // never revoked
    expect(revocations.isRevoked(intent.id)).toBe(false);

    // Take the issuer status endpoint down → the merchant can't confirm status.
    await new Promise<void>((r) => statusServer.close(() => r()));

    const res = await buy(signer, "allergy-relief-24", intent, "http-failclosed", httpBase);
    expect(res.status).toBe(403); // safety over availability: deny when unconfirmed
    expect(JSON.stringify(res.body.violations)).toMatch(/revoked/);
  });
});
