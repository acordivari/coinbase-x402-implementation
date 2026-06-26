/**
 * End-to-end for the DURABLE + GLOBAL spend-cap ledger. The in-memory ledger is
 * per-merchant-process, so an Intent scoped to several merchants could spend the
 * full cap at each. Here two merchants reserve/commit against ONE central,
 * file-durable ledger service, so the cumulative cap is enforced GLOBALLY across
 * merchants — and survives a "restart". And if the ledger is unreachable, the
 * spend FAILS CLOSED.
 *
 * Offline: PROOF_MODE=local substrate, FACILITATOR_MODE=mock.
 */
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import type { AddressInfo } from "node:net";
import type { Server } from "node:http";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import express from "express";
import {
  createMerchantApp,
  createSpendLedgerRouter,
  FileSpendLedger,
  httpSpendLedger,
  type MerchantApp,
} from "@agentic-payments/merchant";
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
  buildProofIdDcqlQuery,
  buildProofRequired,
  buildPaymentMandateTransactionData,
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

const MERCHANT_A = "0xaa11111111111111111111111111111111111111" as const;
const MERCHANT_B = "0xbb22222222222222222222222222222222222222" as const;
const VERIFIER_ID = "https://sandbox.local/merchant";
const ISSUER_ID = "https://issuer.sandbox.local";

let asKey: SigningKeyPair;
let service: AuthorizationService;
let issuer: LocalVcIssuer;
let vcVerifier: VerifiableCredentialVerifier;
let encryptor: Encryptor;

let dir: string;
let ledgerFile: string;
let ledgerServer: Server;
let ledgerBase: string;
let merchantA: MerchantApp;
let merchantB: MerchantApp;
let serverA: Server;
let serverB: Server;
let baseA: string;
let baseB: string;

beforeAll(async () => {
  asKey = await createSigningKeyPair("auth-service-1");
  service = new AuthorizationService(
    { verify: async () => { throw new Error("OIDC disabled"); } } as never,
    new MandateSigner(asKey),
  );
  const mandateVerifier = new MandateVerifier([{ kid: asKey.kid, publicKey: asKey.publicKey }]);
  const ik = await generateEs256Keys();
  issuer = new LocalVcIssuer({ issuerId: ISSUER_ID, privateJwk: ik.privateJwk });
  vcVerifier = localVcVerifier({ issuerId: ISSUER_ID, issuerPublicJwk: ik.publicJwk });
  encryptor = createEncryptor({ key: "e2e-ledger-encryptor-key-0123456789", purpose: "x401-ledger" });

  // One central, file-durable ledger service.
  dir = mkdtempSync(join(tmpdir(), "e2e-ledger-"));
  ledgerFile = join(dir, "ledger.json");
  const ledgerApp = express();
  ledgerApp.use(createSpendLedgerRouter(new FileSpendLedger(ledgerFile)));
  ledgerServer = await new Promise<Server>((resolve) => { const s = ledgerApp.listen(0, () => resolve(s)); });
  ledgerBase = `http://127.0.0.1:${(ledgerServer.address() as AddressInfo).port}`;

  // Two merchants, both reserving/committing against the SAME ledger.
  const mk = (payTo: `0x${string}`) =>
    createMerchantApp({ facilitatorMode: "mock", payTo }, { mandateVerifier, ledger: httpSpendLedger({ baseUrl: ledgerBase }) });
  merchantA = mk(MERCHANT_A);
  merchantB = mk(MERCHANT_B);
  serverA = await new Promise<Server>((resolve) => { const s = merchantA.app.listen(0, () => resolve(s)); });
  serverB = await new Promise<Server>((resolve) => { const s = merchantB.app.listen(0, () => resolve(s)); });
  baseA = `http://127.0.0.1:${(serverA.address() as AddressInfo).port}`;
  baseB = `http://127.0.0.1:${(serverB.address() as AddressInfo).port}`;
});

afterAll(async () => {
  for (const s of [serverA, serverB]) await new Promise<void>((r) => s.close(() => r()));
  if (ledgerServer.listening) await new Promise<void>((r) => ledgerServer.close(() => r()));
  if (dir) rmSync(dir, { recursive: true, force: true });
});

/** A durable, broad-scope mandate scoped to BOTH merchants, with a given cap. */
async function grantMandate(agentWallet: `0x${string}`, capUsd: string): Promise<IntentMandate> {
  const holder = await generateEs256Keys();
  const wallet = new LocalWallet(holder.privateJwk, holder.publicJwk);
  const compact = await issuer.issue(
    { given_name: "Andrew", family_name: "Cordivari", birth_date: "1990-04-12", email: "andrew@example.com", age_over_21: true },
    wallet.publicJwk,
  );
  wallet.store({ id: PROOF_CREDENTIAL_ID, compact, claimNames: [...PROOF_ID_CLAIM_KEYS] });

  const amount = dollarsToAtomic(capUsd).toString();
  const td = encodeTransactionData(buildPaymentMandateTransactionData({ amount, currency: "USDC", merchant: MERCHANT_A, sku: "mandate-grant" }));
  const resource = `${VERIFIER_ID}/mandate/grant`;
  const challenge = await createIdentityChallenge({ encryptor, verifierId: VERIFIER_ID, resource, method: "GET", ttlSeconds: 600, transactionData: td });
  const { payload } = buildProofRequired({ challenge, tokenEndpoint: `${VERIFIER_ID}/oauth/token`, scope: PROOF_BASIC_SCOPE });
  const present = await wallet.present({ query: buildProofIdDcqlQuery(["given_name", "age_over_21"]), nonce: challenge.value, audience: VERIFIER_ID });
  const { artifact } = packPresentation({ payload, agentId: agentWallet, vpToken: present.vpToken });
  const authorization = await verifyAuthorization({
    artifact, encryptor, vcVerifier,
    expectedVerifierId: VERIFIER_ID, expectedResource: resource, expectedMethod: "GET",
    requiredClaims: ["given_name", "age_over_21"], transactionData: td,
  });
  return service.issueIntentFromPresentation({
    authorization, agentWallet,
    scope: { maxAmount: amount, merchantAllowlist: [MERCHANT_A, MERCHANT_B], allowedCategories: ["otc-medicine", "vitamins"] },
    ttlSeconds: 86_400,
  });
}

async function buy(signer: PaymentSigner, sku: string, intent: IntentMandate, key: string, base: string) {
  const payingFetch = await createPayingFetch(signer);
  const res = await payingFetch(`${base}/buy/${sku}`, {
    headers: { "Idempotency-Key": key, "X-Authorization-Mandate": Buffer.from(JSON.stringify(intent)).toString("base64") },
  });
  return { status: res.status, body: (await res.json().catch(() => ({}))) as any };
}

async function pollSettled(nonce: string, base: string): Promise<string> {
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

describe("durable + global spend-cap ledger", () => {
  it("enforces the cap GLOBALLY across two merchants sharing one ledger", async () => {
    const signer = createLocalSigner();
    const intent = await grantMandate(signer.address, "2.00"); // $2.00 shared cap

    // Spend $1.50 at merchant A — settles, committed to the central ledger.
    const a = await buy(signer, "allergy-relief-24", intent, "led-a", baseA);
    expect(a.status).toBe(200);
    expect(await pollSettled(a.body.receipt.paymentNonce, baseA)).toBe("SETTLED");

    // A $0.75 buy at merchant B would push the GLOBAL total to $2.25 > $2.00 —
    // merchant B sees A's spend through the shared ledger and denies it.
    const b = await buy(signer, "ibuprofen-200", intent, "led-b", baseB);
    expect(b.status).toBe(403);
    expect(JSON.stringify(b.body.violations)).toMatch(/exceed intent cap/);

    // Durability: a fresh ledger from the same file (a "restart") still knows the
    // $1.50 already committed.
    const reloaded = new FileSpendLedger(ledgerFile);
    expect(reloaded.total(intent.id)).toBe(dollarsToAtomic("1.50"));
  });

  it("FAILS CLOSED when the central ledger is unreachable", async () => {
    const signer = createLocalSigner();
    const intent = await grantMandate(signer.address, "10.00"); // plenty of headroom

    // Take the ledger service down → the merchant can't confirm cap headroom.
    await new Promise<void>((r) => ledgerServer.close(() => r()));

    const res = await buy(signer, "allergy-relief-24", intent, "led-failclosed", baseA);
    expect(res.status).toBe(403); // safety over availability
    expect(JSON.stringify(res.body.violations)).toMatch(/ledger unavailable/);
  });
});
