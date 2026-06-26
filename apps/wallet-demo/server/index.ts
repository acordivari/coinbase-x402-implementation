/**
 * Orchestrator backend for the x401 + x402 wallet demo. One process wires the
 * whole flow so the browser only ever talks to us (no CORS):
 *
 *   - boots the mock-VeryGood-RX merchant in-process (HAM mandate enforcement ON),
 *     sharing the Authorization Service's signing key so issued Intents verify
 *   - hosts the x401 *verifier*: builds the PROOF-REQUIRED challenge with the
 *     payment's transaction_data sealed in, and verifies the returned
 *     presentation (challenge + VC + payment binding) before issuing an Intent
 *   - PROOF_MODE=local : issues self-issued SD-JWT-VCs to the in-browser wallet
 *     and verifies them against a local trust anchor (offline, deterministic)
 *   - PROOF_MODE=live  : returns a Proof authorize URL (hosted OID4VP redirect)
 *     and verifies the real Proof presentation
 *   - runs the headless agent to pay over x402 with the issued Intent
 *
 * Run: `npm run demo`  (defaults to PROOF_MODE=local, FACILITATOR_MODE=mock).
 */
import { randomUUID } from "node:crypto";
import type { Server } from "node:http";
import type { AddressInfo } from "node:net";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import express, { type Express } from "express";
import { dollarsToAtomic, loadEnv, type IntentMandate } from "@agentic-payments/shared";
import { createMerchantApp } from "@agentic-payments/merchant";
import { createLocalSigner, createPayingFetch } from "@agentic-payments/agent";
import {
  AuthorizationService,
  createSigningKeyPair,
  MandateSigner,
  MandateVerifier,
} from "@agentic-payments/identity";
import {
  buildPaymentMandateTransactionData,
  buildProofRequired,
  buildProofSdkAuthorizeUrl,
  proofTransactionData,
  createEncryptor,
  createIdentityChallenge,
  createVcVerifier,
  encodeTransactionData,
  generateEs256Keys,
  LocalVcIssuer,
  packPresentation,
  PROOF_BASIC_SCOPE,
  PROOF_CREDENTIAL_ID,
  PROOF_ID_CLAIM_KEYS,
  sha256Base64url,
  verifyAuthorization,
  type Jwk,
  type VerifiableCredentialVerifier,
  type VerifiedAuthorization,
  type X401Payload,
} from "@agentic-payments/credentials";

// Load the repo-root .env regardless of cwd (npm --workspace runs from the app dir).
const here = path.dirname(fileURLToPath(import.meta.url));
loadEnv(path.join(here, "..", "..", "..", ".env"));

const MERCHANT = (process.env.MERCHANT_PAY_TO ?? "0xc0ffee0000000000000000000000000000000000").toLowerCase() as `0x${string}`;
const MERCHANT_PORT = Number(process.env.MERCHANT_PORT ?? 4052); // 0 => ephemeral (tests)
const DEMO_PORT = Number(process.env.DEMO_PORT ?? 4040);
const VERIFIER_ID = process.env.X401_VERIFIER_ID ?? "https://sandbox.local/merchant";
const ISSUER_ID = process.env.X401_LOCAL_ISSUER_ID ?? "https://issuer.sandbox.local";
const MODE = (process.env.PROOF_MODE === "live" ? "live" : "local") as "live" | "local";
const publicDir = path.join(here, "..", "dist");

// --- the three selectable wallet workflows ---
//   self-issued : browser-held local SD-JWT-VC, per-purchase consent (offline)
//   proof-hosted: real Proof wallet via the proof-vc-common SDK, per-purchase
//   delegated   : one upfront grant -> a durable, scoped mandate the agent then
//                 spends autonomously (no per-purchase human approval)
const FLOWS = ["self-issued", "proof-hosted", "delegated"] as const;
type Flow = (typeof FLOWS)[number];
const DEFAULT_FLOW: Flow = (FLOWS as readonly string[]).includes(process.env.WALLET_FLOW ?? "")
  ? (process.env.WALLET_FLOW as Flow)
  : "self-issued";

// Delegated-mandate defaults: a long-lived budget the agent spends within.
const MANDATE_TTL = Number(process.env.MANDATE_TTL ?? 86_400); // 24h
const MANDATE_BUDGET_USD = process.env.MANDATE_BUDGET ?? "5.00";

// Live Proof SDK config (proof-vc-common): trust store + hosted-request settings.
const PROOF_TRUST_ROOT = process.env.PROOF_TRUST_ROOT === "production" ? "production" : "development";
const PROOF_ENVIRONMENT = process.env.PROOF_ENVIRONMENT ?? "sandbox"; // "sandbox" => api.fairfax.proof.com
const PROOF_RESPONSE_MODE = process.env.PROOF_RESPONSE_MODE === "direct_post" ? "direct_post" : "fragment";

// The built-in x401 encryptor key is for LOCAL/OFFLINE dev only. That key
// authenticates the challenge state that seals the payment binding — if it ever
// took its default value in a shared/live deployment, the binding would be
// forgeable. So fail closed: refuse to boot with the default when PROOF_MODE=live
// or NODE_ENV=production; only warn (and allow it) in the offline local demo.
const DEV_ENCRYPTOR_KEY = "dev-only-x401-encryptor-key-change-me";
function resolveEncryptorKey(): string {
  const key = process.env.X401_ENCRYPTOR_KEY;
  const usingDefault = !key || key === DEV_ENCRYPTOR_KEY;
  if (!usingDefault) return key;
  const prodLike = MODE === "live" || process.env.NODE_ENV === "production";
  if (prodLike) {
    throw new Error(
      "X401_ENCRYPTOR_KEY must be set to a strong, non-default value when PROOF_MODE=live " +
        "or NODE_ENV=production — it authenticates the x401 challenge state that seals the " +
        "payment binding. Refusing to boot with the built-in dev key.",
    );
  }
  if (process.env.NODE_ENV !== "test") {
    console.warn(
      "[demo] WARNING: using the built-in dev X401_ENCRYPTOR_KEY (local/offline only). " +
        "Set X401_ENCRYPTOR_KEY for any shared or live deployment.",
    );
  }
  return DEV_ENCRYPTOR_KEY;
}

interface CatalogProduct {
  sku: string;
  name: string;
  category: string;
  priceUsd: string;
}

interface IntentScopeInput {
  maxAmount: string;
  merchantAllowlist: `0x${string}`[];
  allowedCategories: string[];
}

interface Session {
  challengeValue: string;
  payload: X401Payload;
  transactionData: string;
  /** x401 resource the presentation authorizes (a sku buy, or a mandate grant). */
  resource: string;
  /** sku for a single-purchase flow; undefined for a delegated mandate grant. */
  sku?: string;
  /** true when this authorizes a durable budget grant rather than one purchase. */
  grant: boolean;
  /** scope to stamp on the issued Intent (single sku, or the broad mandate). */
  scope: IntentScopeInput;
  requestedClaims: string[];
  ttlSeconds: number;
}

export interface DemoApp {
  /** The orchestrator express app — caller decides whether/where to listen. */
  app: Express;
  /** The in-process merchant server (already listening on an ephemeral or fixed port). */
  merchantServer: Server;
  /** The headless agent's payment wallet address. */
  agentWallet: `0x${string}`;
  mode: "live" | "local";
  defaultFlow: Flow;
  /** Tear down the merchant server (the caller closes its own app listener). */
  close: () => Promise<void>;
}

/**
 * Build the demo orchestrator (and boot its in-process merchant) WITHOUT listening
 * the orchestrator itself — so tests can drive every endpoint over real HTTP on an
 * ephemeral port, and `main()` can listen it on DEMO_PORT for the live demo.
 */
export async function createDemoApp(): Promise<DemoApp> {
  // --- shared trust: the AS signs Intents; the merchant verifies them ---
  const asKey = await createSigningKeyPair("auth-service-1");
  const service = new AuthorizationService(
    // No OIDC verifier needed for the x401 path; the identity comes from the VC.
    { verify: async () => { throw new Error("OIDC path disabled in this demo"); } } as never,
    new MandateSigner(asKey),
  );
  const mandateVerifier = new MandateVerifier([{ kid: asKey.kid, publicKey: asKey.publicKey }]);

  // --- x401 verifier-side state ---
  const encryptor = createEncryptor({
    key: resolveEncryptorKey(),
    purpose: "x401-agentic-payments",
  });
  const issuerKeys = await generateEs256Keys();
  const localIssuer = new LocalVcIssuer({ issuerId: ISSUER_ID, privateJwk: issuerKeys.privateJwk });

  // --- VC verifiers (the swappable seam), one per identity substrate ---
  // local : self-issued SD-JWT-VC against our trust anchor (offline)
  // sdk   : real Proof presentation via @proof.com/proof-vc-common (verifyVPToken)
  const localVerifier = createVcVerifier({
    mode: "local",
    local: { issuerId: ISSUER_ID, issuerPublicJwk: issuerKeys.publicJwk },
  });
  const callbackUri = process.env.PROOF_REDIRECT_URI ?? `http://localhost:${DEMO_PORT}/proof/callback`;
  const proofLiveReady = Boolean(process.env.PROOF_CLIENT_ID && process.env.PROOF_CLIENT_SECRET);
  // Built once when Proof client creds are present; configures the SDK (trust
  // store + hosted-request PAR) so both verify and authorize go through it.
  const sdkVerifier: VerifiableCredentialVerifier | undefined = proofLiveReady
    ? createVcVerifier({
        mode: "live",
        proof: {
          useSdk: true,
          trustRoot: PROOF_TRUST_ROOT,
          sdkInit: {
            environment: PROOF_ENVIRONMENT as never,
            clientId: process.env.PROOF_CLIENT_ID,
            clientSecret: process.env.PROOF_CLIENT_SECRET,
            callbackUri,
            responseMode: PROOF_RESPONSE_MODE,
            usePushedAuthorizationRequest: true,
          },
        },
      })
    : undefined;

  // The selected workflow (mutable; switched via POST /api/flow).
  let flow: Flow = DEFAULT_FLOW;
  // Which flows use the real Proof identity (vs the local self-issued substrate):
  // proof-hosted always; delegated when PROOF_MODE=live (otherwise it grants off
  // the local credential so the autonomous demo runs fully offline).
  const usesProof = (f: Flow): boolean => f === "proof-hosted" || (f === "delegated" && MODE === "live");
  const verifierFor = (f: Flow): VerifiableCredentialVerifier => {
    if (usesProof(f)) {
      if (!sdkVerifier) throw new Error("proof identity needs PROOF_CLIENT_ID + PROOF_CLIENT_SECRET");
      return sdkVerifier;
    }
    return localVerifier;
  };

  const signer = createLocalSigner();

  // --- boot the in-process merchant (mandate enforcement ON) ---
  const merchant = createMerchantApp(
    { facilitatorMode: "mock", payTo: MERCHANT },
    { mandateVerifier },
  );
  const merchantServer = await new Promise<Server>((resolve) => {
    const s = merchant.app.listen(MERCHANT_PORT, () => resolve(s));
  });
  const merchantUrl = `http://localhost:${(merchantServer.address() as AddressInfo).port}`;
  const catalog: CatalogProduct[] = (
    (await (await fetch(`${merchantUrl}/catalog`)).json()) as { products: CatalogProduct[] }
  ).products;
  const findProduct = (sku: string) => catalog.find((p) => p.sku === sku);
  console.log(`[demo] merchant on ${merchantUrl} (mandate enforcement ON) · PROOF_MODE=${MODE}`);

  // --- single-user sandbox session ---
  let session: Session | undefined;
  let intent: IntentMandate | undefined;
  let lastVerification: VerifiedAuthorization | undefined;

  const intentSummary = () =>
    intent && {
      id: intent.id,
      principal: intent.principal,
      agentWallet: intent.agentWallet,
      scope: intent.scope,
      issuedAt: intent.issuedAt,
      expiresAt: intent.expiresAt,
      signed: Boolean(intent.proof),
    };

  async function pollOrder(nonce: string): Promise<unknown> {
    for (let i = 0; i < 40; i++) {
      const r = await fetch(`${merchantUrl}/orders/by-nonce/${nonce}`);
      if (r.ok) {
        const order = (await r.json()) as { state?: string };
        if (order.state === "SETTLED" || order.state === "FAILED") return order;
      }
      await new Promise((res) => setTimeout(res, 50));
    }
    return undefined;
  }

  const app = express();
  app.use(express.json({ limit: "1mb" }));
  app.use(express.static(publicDir));

  app.get("/api/me", (_req, res) => {
    res.json({
      mode: MODE,
      flow,
      flows: FLOWS,
      proofLiveReady,
      identity: usesProof(flow) ? "proof" : "local",
      delegated: flow === "delegated",
      agentWallet: signer.address,
      merchant: MERCHANT,
      verifierId: VERIFIER_ID,
      claimUniverse: PROOF_ID_CLAIM_KEYS,
      budgetUsd: MANDATE_BUDGET_USD,
      mandateTtl: MANDATE_TTL,
      sku: session?.sku,
      intent: intentSummary(),
      verification: lastVerification && summarizeVerification(lastVerification),
    });
  });

  // --- switch the active workflow (resets any in-flight authorization) ---
  app.post("/api/flow", (req, res) => {
    const next = req.body?.flow as Flow;
    if (!(FLOWS as readonly string[]).includes(next)) {
      return res.status(400).json({ error: `flow must be one of ${FLOWS.join(", ")}` });
    }
    if (usesProof(next) && !proofLiveReady) {
      return res.status(400).json({ error: `${next} needs PROOF_CLIENT_ID + PROOF_CLIENT_SECRET (and PROOF_MODE=live)` });
    }
    flow = next;
    session = undefined;
    intent = undefined;
    lastVerification = undefined;
    res.json({ flow });
  });

  app.get("/api/catalog", (_req, res) => res.json({ products: catalog, merchant: MERCHANT }));
  app.get("/api/orders", async (_req, res) =>
    res.json(await (await fetch(`${merchantUrl}/orders`)).json()),
  );

  // --- LOCAL mode: issue a self-issued credential to the in-browser wallet ---
  app.post("/api/wallet/issue", async (req, res) => {
    if (usesProof(flow)) return res.status(400).json({ error: "wallet issuance is for the local-identity flows only" });
    const { holderPublicJwk, claims } = req.body ?? {};
    if (!holderPublicJwk || !claims) return res.status(400).json({ error: "holderPublicJwk + claims required" });
    try {
      const compact = await localIssuer.issue(claims, holderPublicJwk as Jwk);
      res.json({ credential: { id: PROOF_CREDENTIAL_ID, compact, claimNames: PROOF_ID_CLAIM_KEYS }, issuer: ISSUER_ID });
    } catch (err) {
      res.status(400).json({ error: String(err) });
    }
  });

  // --- start authorization: build the payment (single buy) or budget grant
  //     (delegated), seal it into an x401 challenge, return PROOF-REQUIRED ---
  app.post("/api/authorize/start", async (req, res) => {
    const { sku, requestedClaims, ttlSeconds, budgetUsd, categories } = req.body ?? {};
    const claims: string[] = Array.isArray(requestedClaims) && requestedClaims.length
      ? requestedClaims
      : ["given_name", "family_name", "email", "age_over_21"];
    const network = process.env.X402_NETWORK ?? "eip155:84532";
    const grant = flow === "delegated";

    // Build the payment binding + intent scope: one product, or a standing budget.
    let resource: string;
    let scope: IntentScopeInput;
    let ttl: number;
    let td: ReturnType<typeof buildPaymentMandateTransactionData>;
    let amountUsd: string;
    let promptSummary: string;
    if (grant) {
      // Validate the budget: a positive, finite USDC amount (avoids a hung
      // request from dollarsToAtomic throwing on garbage). Normalize to cents.
      const budgetNum = Number(budgetUsd ?? MANDATE_BUDGET_USD);
      if (!Number.isFinite(budgetNum) || budgetNum <= 0 || budgetNum > 1_000_000) {
        return res.status(400).json({ error: "budgetUsd must be a positive number up to 1,000,000 USDC" });
      }
      const budget = budgetNum.toFixed(2);
      // Restrict the granted scope to real catalog categories.
      const allCats = [...new Set(catalog.map((p) => p.category))];
      let cats: string[];
      if (categories === undefined) {
        cats = allCats;
      } else if (Array.isArray(categories) && categories.every((c) => typeof c === "string")) {
        cats = (categories as string[]).filter((c) => allCats.includes(c));
        if (cats.length === 0) {
          return res.status(400).json({ error: `categories must include at least one of: ${allCats.join(", ")}` });
        }
      } else {
        return res.status(400).json({ error: "categories must be an array of strings" });
      }
      amountUsd = budget;
      promptSummary = `Standing mandate: authorize this agent to spend up to $${budget} at Mock VeryGood-RX across ${cats.join(", ")}.`;
      td = buildPaymentMandateTransactionData({
        amount: dollarsToAtomic(budget).toString(), currency: "USDC", merchant: MERCHANT,
        network, sku: "mandate-grant", description: promptSummary,
      });
      resource = `${VERIFIER_ID}/mandate/grant`;
      ttl = MANDATE_TTL;
      scope = { maxAmount: dollarsToAtomic(budget).toString(), merchantAllowlist: [MERCHANT], allowedCategories: cats };
    } else {
      const product = findProduct(sku);
      if (!product) return res.status(400).json({ error: "unknown sku" });
      amountUsd = product.priceUsd;
      promptSummary = `Authorize Mock VeryGood-RX to charge $${product.priceUsd} for ${product.name}.`;
      td = buildPaymentMandateTransactionData({
        amount: dollarsToAtomic(product.priceUsd).toString(), currency: "USDC", merchant: MERCHANT,
        network, sku: product.sku, description: product.name,
      });
      resource = `${VERIFIER_ID}/buy/${product.sku}`;
      ttl = Number(ttlSeconds ?? 600);
      scope = { maxAmount: dollarsToAtomic(product.priceUsd).toString(), merchantAllowlist: [MERCHANT], allowedCategories: [product.category] };
    }
    const transactionData = encodeTransactionData(td);

    const challenge = await createIdentityChallenge({
      encryptor, verifierId: VERIFIER_ID, resource, method: "GET",
      ttlSeconds: ttl, transactionData,
    });
    const { payload, header } = buildProofRequired({
      challenge, tokenEndpoint: `${VERIFIER_ID}/oauth/token`,
      scope: PROOF_BASIC_SCOPE, requestId: "proof-id-v1",
    });

    intent = undefined;
    lastVerification = undefined;
    session = {
      challengeValue: challenge.value, payload, transactionData, resource,
      ...(grant ? {} : { sku }), grant, scope,
      requestedClaims: claims, ttlSeconds: ttl,
    };

    const common = {
      mode: MODE,
      flow,
      grant,
      proofRequired: header,
      nonce: challenge.value,
      audience: VERIFIER_ID,
      requestedClaims: claims,
      dcql: { credentials: [{ id: PROOF_CREDENTIAL_ID, format: "dc+sd-jwt", claims: claims.map((c) => ({ path: [c] })) }] },
      transactionData: td, // decoded, for display
      payment: { ...td.payload, amountUsd },
      scope,
    };

    if (usesProof(flow)) {
      // Hosted Proof presentation via the official SDK: the human selectively
      // discloses identity AND signs the payment-mandate on Proof's screen. Our
      // own x401 payment binding (sealed above) is enforced regardless.
      try {
        const proofTd = proofTransactionData.paymentMandate({
          payment_instrument: {
            type: process.env.PROOF_PAYMENT_INSTRUMENT_TYPE ?? "crypto",
            id: process.env.PROOF_PAYMENT_INSTRUMENT_ID ?? `usdc:${network}:${signer.address}`,
            description: "Agent USDC wallet (Base Sepolia)",
          },
          payee: { name: "Mock VeryGood-RX", website: "https://verygood-rx.example" },
          prompt_summary: promptSummary,
          amount: Number(amountUsd),
          currency: process.env.PROOF_PAYMENT_CURRENCY ?? "USD",
        });
        const authorizeUrl = await buildProofSdkAuthorizeUrl({
          nonce: challenge.value,
          loginHint: process.env.PROOF_LOGIN_HINT ?? "",
          state: randomUUID(),
          transactionData: proofTd,
        });
        return res.json({ ...common, authorizeUrl, redirectUri: callbackUri });
      } catch (err) {
        return res.status(502).json({ ...common, error: `Proof authorize failed: ${String(err)}` });
      }
    }
    res.json(common);
  });

  // --- complete authorization: verify the presentation, issue the Intent ---
  app.post("/api/authorize/complete", async (req, res) => {
    if (!session) return res.status(400).json({ error: "no authorization in progress" });
    const { vpToken } = req.body ?? {};
    if (!vpToken) return res.status(400).json({ error: "vpToken required" });
    const { resource } = session;
    const proofIdentity = usesProof(flow);
    console.log(`[demo] /api/authorize/complete: vp_token received (len=${String(vpToken).length}) for ${session.grant ? "mandate-grant" : `sku=${session.sku}`} (flow=${flow})`);
    try {
      const { artifact } = packPresentation({ payload: session.payload, agentId: signer.address, vpToken });
      const verification = await verifyAuthorization({
        artifact, encryptor, vcVerifier: verifierFor(flow),
        expectedVerifierId: VERIFIER_ID, expectedResource: resource, expectedMethod: "GET",
        // Local identity controls the exact claim names; live Proof decides which
        // claims its scope returns (e.g. age_equal_or_over vs age_over_21), so we
        // report what was disclosed rather than hard-requiring our names.
        ...(proofIdentity ? {} : { requiredClaims: session.requestedClaims }),
        transactionData: session.transactionData,
      });
      lastVerification = verification;
      console.log(`[demo] verification:`, JSON.stringify(summarizeVerification(verification)));
      if (!verification.result.ok) {
        return res.status(403).json({ error: "presentation rejected", verification: summarizeVerification(verification) });
      }
      const presentationDigest = await sha256Base64url(vpToken);
      // Single purchase -> a one-shot scope; delegated grant -> the broad,
      // long-lived budget the agent then spends autonomously.
      intent = await service.issueIntentFromPresentation({
        authorization: verification,
        agentWallet: signer.address,
        scope: session.scope,
        ttlSeconds: session.ttlSeconds,
        presentationDigest,
      });
      res.json({ verification: summarizeVerification(verification), intent: intentSummary() });
    } catch (err) {
      res.status(400).json({ error: String(err) });
    }
  });

  // --- live fragment callback: forward the vp_token from the URL fragment ---
  app.get("/proof/callback", (_req, res) => {
    console.log("[demo] /proof/callback hit (browser will POST the vp_token from the fragment)");
    res.type("html").send(CALLBACK_HTML);
  });

  // --- pay via x402 with the issued Intent (the existing payment rail) ---
  app.post("/api/buy", async (req, res) => {
    const sku = req.body?.sku ?? session?.sku;
    if (!sku) return res.status(400).json({ error: "sku required" });
    if (!intent) return res.status(401).json({ error: "authorize first (no signed Intent)" });
    const payingFetch = await createPayingFetch(signer);
    const headers: Record<string, string> = {
      "Idempotency-Key": randomUUID(),
      "X-Authorization-Mandate": Buffer.from(JSON.stringify(intent)).toString("base64"),
    };
    try {
      const r = await payingFetch(`${merchantUrl}/buy/${sku}`, { headers });
      const body = (await r.json().catch(() => ({}))) as { receipt?: { paymentNonce?: string } };
      const nonce = body?.receipt?.paymentNonce;
      const settled = r.ok && nonce ? await pollOrder(nonce) : undefined;
      res.json({ ok: r.ok, status: r.status, body, settled });
    } catch (err) {
      res.json({ ok: false, status: 0, body: { error: String(err) } });
    }
  });

  // --- delegated mandate: the agent buys autonomously under one standing Intent,
  //     NO per-purchase human approval. The human's presigned presentation (the
  //     signed Intent) IS the authorization; the merchant enforces the cumulative
  //     cap, so an over-budget buy is denied without anyone in the loop. ---
  app.post("/api/agent/run", async (req, res) => {
    // Autonomous spending is a delegated-only capability — don't let a
    // single-purchase Intent from another flow drive the multi-buy loop.
    if (flow !== "delegated") {
      return res.status(400).json({ error: "agent/run is only available in the delegated workflow" });
    }
    // Validate the requested skus up front (bound the loop; reject malformed input).
    const rawSkus = req.body?.skus;
    if (rawSkus !== undefined &&
        (!Array.isArray(rawSkus) || rawSkus.length === 0 || rawSkus.length > 20 ||
         !rawSkus.every((s: unknown) => typeof s === "string"))) {
      return res.status(400).json({ error: "skus must be a non-empty array of up to 20 sku strings" });
    }
    if (!intent) return res.status(401).json({ error: "no standing mandate — grant one first" });
    const requested: string[] = (rawSkus as string[] | undefined) ??
      ["allergy-relief-24", "vitamin-d3-2000", "ibuprofen-200", "toothpaste-mint"];
    const payingFetch = await createPayingFetch(signer);
    const mandateHeader = Buffer.from(JSON.stringify(intent)).toString("base64");
    const capAtomic = BigInt(intent.scope.maxAmount);
    let spentAtomic = 0n;
    const purchases: unknown[] = [];

    for (const sku of requested) {
      const product = findProduct(sku);
      if (!product) { purchases.push({ sku, ok: false, status: 400, reason: "unknown sku" }); continue; }
      const headers: Record<string, string> = {
        "Idempotency-Key": randomUUID(),
        "X-Authorization-Mandate": mandateHeader,
      };
      try {
        const r = await payingFetch(`${merchantUrl}/buy/${sku}`, { headers });
        const body = (await r.json().catch(() => ({}))) as { receipt?: { paymentNonce?: string }; error?: string; violations?: string[] };
        const nonce = body?.receipt?.paymentNonce;
        const order = r.ok && nonce ? (await pollOrder(nonce)) as { state?: string } | undefined : undefined;
        const settled = order?.state === "SETTLED";
        if (settled) spentAtomic += dollarsToAtomic(product.priceUsd);
        purchases.push({
          sku, name: product.name, priceUsd: product.priceUsd, category: product.category,
          ok: r.ok, status: r.status, settled,
          ...(r.ok ? {} : { reason: body?.error ?? "denied", violations: body?.violations ?? [] }),
        });
      } catch (err) {
        purchases.push({ sku, ok: false, status: 0, reason: String(err) });
      }
    }

    res.json({
      intent: intentSummary(),
      capAtomic: capAtomic.toString(),
      spentAtomic: spentAtomic.toString(),
      remainingAtomic: (capAtomic - spentAtomic).toString(),
      purchases,
    });
  });

  app.post("/api/reset", (_req, res) => {
    session = undefined; intent = undefined; lastVerification = undefined;
    res.json({ ok: true });
  });

  return {
    app,
    merchantServer,
    agentWallet: signer.address,
    mode: MODE,
    defaultFlow: DEFAULT_FLOW,
    close: () => new Promise<void>((resolve) => merchantServer.close(() => resolve())),
  };
}

async function main() {
  const demo = await createDemoApp();
  demo.app.listen(DEMO_PORT, () => console.log(`[demo] open http://localhost:${DEMO_PORT}  (PROOF_MODE=${demo.mode})`));
}

function summarizeVerification(v: VerifiedAuthorization) {
  return {
    ok: v.result.ok,
    violations: v.result.ok ? [] : v.result.violations,
    challengeOk: v.challengeOk,
    txDataBound: v.txDataBound,
    nonceBound: v.proof?.nonceBound ?? false,
    holderBound: v.proof?.holderBound ?? false,
    issuer: v.proof?.issuer,
    issuerCert: v.proof?.issuerCert,
    disclosed: v.proof?.claimsDisclosed ?? [],
    subject: v.proof?.subject ?? {},
    // The payment the holder cryptographically approved, from the KB-JWT.
    paymentApproved: v.proof?.paymentApproved,
  };
}

/**
 * The page Proof redirects to (fragment mode). It reads the vp_token from the URL
 * fragment and — because it is same-origin — completes the authorization by
 * POSTing it straight to our API. No cross-window handoff (postMessage/opener),
 * which proved unreliable. It then notifies any opener and returns to the app.
 */
const CALLBACK_HTML = `<!doctype html><meta charset="utf-8"><title>Proof callback</title>
<body style="font:14px ui-sans-serif,system-ui;background:#0b0f1a;color:#e8eef9;padding:28px">
<h3 style="margin:0 0 8px">x401 · returning your presentation</h3>
<p id="out" style="color:#93a3c4">Reading presentation…</p>
<pre id="dbg" style="color:#5b8cff;white-space:pre-wrap;font-size:12px"></pre>
<script>
(async () => {
  const out = document.getElementById("out"), dbg = document.getElementById("dbg");
  const params = new URLSearchParams(location.hash.slice(1) || location.search.slice(1));
  const vpToken = params.get("vp_token");
  if (!vpToken) { out.textContent = "No vp_token found in the callback URL."; dbg.textContent = "hash=" + location.hash.slice(0, 300); return; }
  out.textContent = "Verifying presentation with the merchant…";
  try {
    const r = await fetch("/api/authorize/complete", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ vpToken }) });
    const j = await r.json();
    if (r.ok && !j.error) {
      out.innerHTML = "✓ Verified. Identity + payment authorized — returning to the demo…";
      dbg.textContent = JSON.stringify(j.verification, null, 2);
    } else {
      out.innerHTML = "✗ Presentation rejected: " + (j.error || "unknown");
      dbg.textContent = JSON.stringify(j.verification || j, null, 2);
    }
    try { if (window.opener) window.opener.postMessage({ type: "x401:done" }, location.origin); } catch (e) {}
    if (window.opener) setTimeout(() => window.close(), 2000);
    else setTimeout(() => location.replace("/"), 2500);
  } catch (e) { out.textContent = "Error completing authorization: " + e; }
})();
</script></body>`;

// Only boot the listener when run as a script (not when imported by tests).
const invokedAsScript = process.argv[1] !== undefined && import.meta.url === pathToFileURL(process.argv[1]).href;
if (invokedAsScript) {
  main().catch((err) => { console.error(err); process.exit(1); });
}
