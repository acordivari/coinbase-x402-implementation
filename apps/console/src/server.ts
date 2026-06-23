/**
 * Demo console — a single runnable process that wires the whole sandbox so the
 * buyer + merchant experiences can be validated in a browser:
 *
 *   - boots the mock-VeryGood-RX merchant in-process (mandate enforcement ON), sharing
 *     the Authorization Service's signing key so Intents verify
 *   - hosts the local OIDC issuer + Authorization Service (human "login" + sign
 *     Intent)
 *   - runs the headless agent server-side to buy over x402
 *   - serves a vanilla-JS console (buyer panel + merchant panel) and proxies the
 *     merchant API so the browser never hits CORS
 *
 * Run: `npm run console` then open http://localhost:4040
 */
import { randomUUID } from "node:crypto";
import path from "node:path";
import { fileURLToPath } from "node:url";
import express from "express";
import { dollarsToAtomic, type IntentMandate } from "@agentic-payments/shared";
import { createMerchantApp } from "@agentic-payments/merchant";
import { createLocalSigner, createPayingFetch } from "@agentic-payments/agent";
import {
  AuthorizationService,
  createSigningKeyPair,
  LocalOidcIssuer,
  localVerifier,
  MandateSigner,
  MandateVerifier,
} from "@agentic-payments/identity";

const MERCHANT = "0xc0ffee0000000000000000000000000000000000" as const;
const MERCHANT_PORT = Number(process.env.MERCHANT_PORT ?? 4051);
const CONSOLE_PORT = Number(process.env.CONSOLE_PORT ?? 4040);
const merchantUrl = `http://localhost:${MERCHANT_PORT}`;
const publicDir = path.join(path.dirname(fileURLToPath(import.meta.url)), "..", "public");

// Single-user sandbox session state.
let idToken: string | undefined;
let principal: unknown;
let intent: IntentMandate | undefined;

async function main() {
  const asKey = await createSigningKeyPair("auth-service-1");
  const oidcKey = await createSigningKeyPair("oidc-1");
  const issuer = new LocalOidcIssuer("https://sandbox.local/", "agentic-payments", oidcKey);
  const service = new AuthorizationService(localVerifier(issuer), new MandateSigner(asKey));
  const verifier = new MandateVerifier([{ kid: asKey.kid, publicKey: asKey.publicKey }]);
  const signer = createLocalSigner();

  const merchant = createMerchantApp(
    { facilitatorMode: "mock", payTo: MERCHANT },
    { mandateVerifier: verifier },
  );
  await new Promise<void>((resolve) => merchant.app.listen(MERCHANT_PORT, resolve));
  console.log(`[console] mock-VeryGood-RX merchant on ${merchantUrl} (mandate enforcement ON)`);

  const intentSummary = () =>
    intent && {
      id: intent.id,
      principalSub: intent.principal.sub,
      agentWallet: intent.agentWallet,
      scope: intent.scope,
      issuedAt: intent.issuedAt,
      expiresAt: intent.expiresAt,
      signed: Boolean(intent.proof),
    };

  async function pollOrder(nonce: string): Promise<unknown> {
    for (let i = 0; i < 30; i++) {
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
  app.use(express.json());
  app.use(express.static(publicDir));

  app.get("/api/me", (_req, res) => {
    res.json({ agentWallet: signer.address, merchant: MERCHANT, principal, intent: intentSummary() });
  });

  app.post("/api/login", async (req, res) => {
    const { sub, email } = req.body ?? {};
    if (!sub) return res.status(400).json({ error: "sub required" });
    idToken = await issuer.mintIdToken({ sub, email, emailVerified: true });
    principal = { sub, email, emailVerified: true, idp: issuer.issuer };
    intent = undefined; // a new login must re-authorize
    res.json({ principal });
  });

  app.post("/api/intent", async (req, res) => {
    if (!idToken) return res.status(401).json({ error: "log in first" });
    const { maxAmountUsd, categories, ttlSeconds } = req.body ?? {};
    try {
      intent = await service.issueIntent({
        idToken,
        agentWallet: signer.address,
        scope: {
          maxAmount: dollarsToAtomic(String(maxAmountUsd ?? "0")).toString(),
          merchantAllowlist: [MERCHANT],
          allowedCategories: Array.isArray(categories) ? categories : [],
        },
        ttlSeconds: Number(ttlSeconds ?? 3600),
      });
      res.json({ intent: intentSummary() });
    } catch (err) {
      res.status(400).json({ error: String(err) });
    }
  });

  app.post("/api/buy", async (req, res) => {
    const { sku } = req.body ?? {};
    if (!sku) return res.status(400).json({ error: "sku required" });
    const payingFetch = await createPayingFetch(signer);
    const headers: Record<string, string> = { "Idempotency-Key": randomUUID() };
    if (intent) {
      headers["X-Authorization-Mandate"] = Buffer.from(JSON.stringify(intent)).toString("base64");
    }
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

  // --- merchant API proxies (browser only talks to the console) ---
  app.get("/api/catalog", async (_req, res) => {
    res.json(await (await fetch(`${merchantUrl}/catalog`)).json());
  });
  app.get("/api/orders", async (_req, res) => {
    res.json(await (await fetch(`${merchantUrl}/orders`)).json());
  });

  app.listen(CONSOLE_PORT, () => {
    console.log(`[console] open http://localhost:${CONSOLE_PORT}`);
  });
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
