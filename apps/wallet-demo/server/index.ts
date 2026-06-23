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
import path from "node:path";
import { fileURLToPath } from "node:url";
import express from "express";
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
  buildProofPaymentMandate,
  buildSessionTransactionData,
  buildProofAuthorizeUrl,
  resolveProofAuthorizeRedirect,
  createProofTokenProvider,
  buildProofRequired,
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
  type VerifiedAuthorization,
  type X401Payload,
} from "@agentic-payments/credentials";

// Load the repo-root .env regardless of cwd (npm --workspace runs from the app dir).
const here = path.dirname(fileURLToPath(import.meta.url));
loadEnv(path.join(here, "..", "..", "..", ".env"));

const MERCHANT = (process.env.MERCHANT_PAY_TO ?? "0xc0ffee0000000000000000000000000000000000").toLowerCase() as `0x${string}`;
const MERCHANT_PORT = Number(process.env.MERCHANT_PORT ?? 4052);
const DEMO_PORT = Number(process.env.DEMO_PORT ?? 4040);
const merchantUrl = `http://localhost:${MERCHANT_PORT}`;
const VERIFIER_ID = process.env.X401_VERIFIER_ID ?? "https://sandbox.local/merchant";
const ISSUER_ID = process.env.X401_LOCAL_ISSUER_ID ?? "https://issuer.sandbox.local";
const MODE = (process.env.PROOF_MODE === "live" ? "live" : "local") as "live" | "local";
const publicDir = path.join(here, "..", "dist");

interface CatalogProduct {
  sku: string;
  name: string;
  category: string;
  priceUsd: string;
}

interface Session {
  challengeValue: string;
  payload: X401Payload;
  transactionData: string;
  sku: string;
  requestedClaims: string[];
  ttlSeconds: number;
}

async function main() {
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
    key: process.env.X401_ENCRYPTOR_KEY ?? "dev-only-x401-encryptor-key-change-me",
    purpose: "x401-agentic-payments",
  });
  const issuerKeys = await generateEs256Keys();
  const localIssuer = new LocalVcIssuer({ issuerId: ISSUER_ID, privateJwk: issuerKeys.privateJwk });
  const vcVerifier = createVcVerifier(
    MODE === "live"
      ? { mode: "live", proof: { ...(process.env.PROOF_ISSUER ? { expectedIssuer: process.env.PROOF_ISSUER } : {}) } }
      : { mode: "local", local: { issuerId: ISSUER_ID, issuerPublicJwk: issuerKeys.publicJwk } },
  );

  const signer = createLocalSigner();

  // --- Proof OAuth (client-credentials) token provider for the live path ---
  const proofApiBase = process.env.PROOF_API_BASE ?? "https://api.proof.com";
  const proofTokens =
    MODE === "live" && process.env.PROOF_CLIENT_SECRET
      ? createProofTokenProvider({
          tokenEndpoint: process.env.PROOF_TOKEN_ENDPOINT ?? `${proofApiBase}/oauth/v2/token`,
          clientId: process.env.PROOF_CLIENT_ID ?? "",
          clientSecret: process.env.PROOF_CLIENT_SECRET,
          ...(process.env.PROOF_OAUTH_SCOPE ? { scope: process.env.PROOF_OAUTH_SCOPE } : {}),
        })
      : undefined;

  // --- boot the in-process merchant (mandate enforcement ON) ---
  const merchant = createMerchantApp(
    { facilitatorMode: "mock", payTo: MERCHANT },
    { mandateVerifier },
  );
  await new Promise<void>((resolve) => merchant.app.listen(MERCHANT_PORT, resolve));
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
      agentWallet: signer.address,
      merchant: MERCHANT,
      verifierId: VERIFIER_ID,
      claimUniverse: PROOF_ID_CLAIM_KEYS,
      sku: session?.sku,
      intent: intentSummary(),
      verification: lastVerification && summarizeVerification(lastVerification),
    });
  });

  app.get("/api/catalog", (_req, res) => res.json({ products: catalog, merchant: MERCHANT }));
  app.get("/api/orders", async (_req, res) =>
    res.json(await (await fetch(`${merchantUrl}/orders`)).json()),
  );

  // --- LOCAL mode: issue a self-issued credential to the in-browser wallet ---
  app.post("/api/wallet/issue", async (req, res) => {
    if (MODE !== "local") return res.status(400).json({ error: "wallet issuance is local-mode only" });
    const { holderPublicJwk, claims } = req.body ?? {};
    if (!holderPublicJwk || !claims) return res.status(400).json({ error: "holderPublicJwk + claims required" });
    try {
      const compact = await localIssuer.issue(claims, holderPublicJwk as Jwk);
      res.json({ credential: { id: PROOF_CREDENTIAL_ID, compact, claimNames: PROOF_ID_CLAIM_KEYS }, issuer: ISSUER_ID });
    } catch (err) {
      res.status(400).json({ error: String(err) });
    }
  });

  // --- start authorization: build payment + x401 challenge + PROOF-REQUIRED ---
  app.post("/api/authorize/start", async (req, res) => {
    const { sku, requestedClaims, ttlSeconds } = req.body ?? {};
    const product = findProduct(sku);
    if (!product) return res.status(400).json({ error: "unknown sku" });
    const claims: string[] = Array.isArray(requestedClaims) && requestedClaims.length
      ? requestedClaims
      : ["given_name", "family_name", "email", "age_over_21"];

    const amount = dollarsToAtomic(product.priceUsd).toString();
    const td = buildPaymentMandateTransactionData({
      amount,
      currency: "USDC",
      merchant: MERCHANT,
      network: process.env.X402_NETWORK ?? "eip155:84532",
      sku: product.sku,
      description: product.name,
    });
    const transactionData = encodeTransactionData(td);
    const resource = `${VERIFIER_ID}/buy/${product.sku}`;

    const challenge = await createIdentityChallenge({
      encryptor, verifierId: VERIFIER_ID, resource, method: "GET",
      ttlSeconds: Number(ttlSeconds ?? 600), transactionData,
    });
    const { payload, header } = buildProofRequired({
      challenge, tokenEndpoint: `${VERIFIER_ID}/oauth/token`,
      scope: PROOF_BASIC_SCOPE, requestId: "proof-id-v1",
    });

    intent = undefined;
    lastVerification = undefined;
    session = {
      challengeValue: challenge.value, payload, transactionData,
      sku: product.sku, requestedClaims: claims, ttlSeconds: Number(ttlSeconds ?? 600),
    };

    const common = {
      mode: MODE,
      proofRequired: header,
      nonce: challenge.value,
      audience: VERIFIER_ID,
      requestedClaims: claims,
      dcql: { credentials: [{ id: PROOF_CREDENTIAL_ID, format: "dc+sd-jwt", claims: claims.map((c) => ({ path: [c] })) }] },
      transactionData: td, // decoded, for display
      payment: { ...td.payload, amountUsd: product.priceUsd },
    };

    if (MODE === "live") {
      // The transaction_data SENT TO PROOF is configurable (PROOF_TX_DATA):
      //   session  -> session-data (works in the live sandbox today)
      //   payment-mandate -> Proof's payment-mandate:v1 (needs a real
      //                      payment_instrument; otherwise Proof 500s)
      //   none     -> omit transaction_data
      // Our OWN payment binding (sealed into the x401 challenge above) is
      // independent of this and always enforced.
      const txMode = process.env.PROOF_TX_DATA ?? "payment-mandate";
      let proofTd: string | undefined;
      if (txMode === "payment-mandate") {
        const network = process.env.X402_NETWORK ?? "eip155:84532";
        proofTd = encodeTransactionData(
          buildProofPaymentMandate({
            amount: Number(product.priceUsd),
            currency: process.env.PROOF_PAYMENT_CURRENCY ?? "USD",
            payeeName: "Mock VeryGood-RX",
            payeeWebsite: "https://verygood-rx.example",
            promptSummary: `Authorize Mock VeryGood-RX to charge $${product.priceUsd} for ${product.name}.`,
            instrument: {
              type: process.env.PROOF_PAYMENT_INSTRUMENT_TYPE ?? "crypto",
              id: process.env.PROOF_PAYMENT_INSTRUMENT_ID ?? `usdc:${network}:${signer.address}`,
            },
          }),
        );
      } else if (txMode !== "none") {
        proofTd = encodeTransactionData(
          buildSessionTransactionData({ ip_address: "203.0.113.0", device_id: `x402-${product.sku}` }),
        );
      }
      const authInput = {
        clientId: process.env.PROOF_CLIENT_ID ?? "",
        loginHint: process.env.PROOF_LOGIN_HINT ?? "",
        nonce: challenge.value,
        responseMode: "fragment" as const,
        redirectUri: process.env.PROOF_REDIRECT_URI ?? `http://localhost:${DEMO_PORT}/proof/callback`,
        ...(proofTd !== undefined ? { transactionData: proofTd } : {}),
        state: randomUUID(),
        ...(process.env.PROOF_API_BASE ? { apiBase: process.env.PROOF_API_BASE } : {}),
      };
      try {
        // Confidential client: mint a client-credentials access token (server-side)
        // and resolve the hosted URL with it as a Bearer — neither the token nor
        // the client secret reaches the browser. Public client (no secret): hand
        // the browser the authorize URL directly.
        const bearerToken = proofTokens ? await proofTokens.getToken() : undefined;
        const authorizeUrl = bearerToken
          ? await resolveProofAuthorizeRedirect({ ...authInput, bearerToken })
          : buildProofAuthorizeUrl(authInput);
        return res.json({ ...common, authorizeUrl, redirectUri: authInput.redirectUri });
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
    const product = findProduct(session.sku)!;
    const resource = `${VERIFIER_ID}/buy/${product.sku}`;
    try {
      const { artifact } = packPresentation({ payload: session.payload, agentId: signer.address, vpToken });
      const verification = await verifyAuthorization({
        artifact, encryptor, vcVerifier,
        expectedVerifierId: VERIFIER_ID, expectedResource: resource, expectedMethod: "GET",
        // Local mode controls the exact claim names; live Proof decides which
        // claims its scope returns (e.g. age_equal_or_over vs age_over_21), so we
        // report what was disclosed rather than hard-requiring our names.
        ...(MODE === "local" ? { requiredClaims: session.requestedClaims } : {}),
        transactionData: session.transactionData,
      });
      lastVerification = verification;
      if (!verification.result.ok) {
        return res.status(403).json({ error: "presentation rejected", verification: summarizeVerification(verification) });
      }
      const presentationDigest = await sha256Base64url(vpToken);
      intent = await service.issueIntentFromPresentation({
        authorization: verification,
        agentWallet: signer.address,
        scope: {
          maxAmount: dollarsToAtomic(product.priceUsd).toString(),
          merchantAllowlist: [MERCHANT],
          allowedCategories: [product.category],
        },
        ttlSeconds: session.ttlSeconds,
        presentationDigest,
      });
      res.json({ verification: summarizeVerification(verification), intent: intentSummary() });
    } catch (err) {
      res.status(400).json({ error: String(err) });
    }
  });

  // --- live fragment callback: forward the vp_token from the URL fragment ---
  app.get("/proof/callback", (_req, res) => res.type("html").send(CALLBACK_HTML));

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

  app.post("/api/reset", (_req, res) => {
    session = undefined; intent = undefined; lastVerification = undefined;
    res.json({ ok: true });
  });

  app.listen(DEMO_PORT, () => console.log(`[demo] open http://localhost:${DEMO_PORT}  (PROOF_MODE=${MODE})`));
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

main().catch((err) => { console.error(err); process.exit(1); });
