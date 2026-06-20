import { beforeAll, describe, expect, it } from "vitest";
import type { CartItem } from "@agentic-payments/shared";
import {
  AuthorizationService,
  buildCartMandate,
  buildPaymentMandate,
  createSigningKeyPair,
  LocalOidcIssuer,
  localVerifier,
  MandateSigner,
  MandateVerifier,
  verifyMandateChain,
  type SigningKeyPair,
} from "../src/index.ts";

const MERCHANT = "0x1111111111111111111111111111111111111111" as const;
const OTHER = "0x3333333333333333333333333333333333333333" as const;
const AGENT_WALLET = "0x2222222222222222222222222222222222222222" as const;
const USDC = "0x036cbd53842c5426634e7929541ec2318f3dcf7e" as const;
const NOW = 1_900_000_000;

let asKey: SigningKeyPair;
let oidcKey: SigningKeyPair;
let issuer: LocalOidcIssuer;
let service: AuthorizationService;
let verifier: MandateVerifier;

beforeAll(async () => {
  asKey = await createSigningKeyPair("auth-service-1");
  oidcKey = await createSigningKeyPair("oidc-1");
  issuer = new LocalOidcIssuer("https://sandbox.local/", "agentic-payments", oidcKey);
  service = new AuthorizationService(
    localVerifier(issuer),
    new MandateSigner(asKey),
    () => NOW,
  );
  verifier = new MandateVerifier([asKey]);
});

async function issueIntent(maxAmount = "5000000") {
  const idToken = await issuer.mintIdToken({
    sub: "auth0|abc",
    email: "buyer@example.com",
    emailVerified: true,
  });
  return service.issueIntent({
    idToken,
    agentWallet: AGENT_WALLET,
    scope: {
      maxAmount,
      merchantAllowlist: [MERCHANT],
      allowedCategories: ["otc-medicine", "vitamins"],
    },
  });
}

const item = (over: Partial<CartItem> = {}): CartItem => ({
  sku: "allergy-relief-24",
  name: "Allergy Relief",
  category: "otc-medicine",
  unitPrice: "1500000",
  quantity: 1,
  ...over,
});

function chainFor(intent: Awaited<ReturnType<typeof issueIntent>>, items: CartItem[]) {
  const cart = buildCartMandate({ intentId: intent.id, merchant: MERCHANT, items, nowSeconds: NOW });
  const payment = buildPaymentMandate({
    cartId: cart.id,
    payTo: MERCHANT,
    asset: USDC,
    amount: cart.total,
    network: "eip155:84532",
    nonce: "0xabc",
  });
  return { cart, payment };
}

describe("OIDC + Intent issuance", () => {
  it("binds the verified OIDC principal into a signed Intent", async () => {
    const intent = await issueIntent();
    expect(intent.principal.sub).toBe("auth0|abc");
    expect(intent.principal.idp).toBe("https://sandbox.local/");
    expect(intent.principal.emailVerified).toBe(true);
    expect(intent.agentWallet).toBe(AGENT_WALLET);
    expect(await verifier.verifyProof(intent)).toBe(true);
  });

  it("rejects an ID token with the wrong audience", async () => {
    const badIssuer = new LocalOidcIssuer("https://sandbox.local/", "wrong-aud", oidcKey);
    const token = await badIssuer.mintIdToken({ sub: "x" });
    await expect(
      service.issueIntent({
        idToken: token,
        agentWallet: AGENT_WALLET,
        scope: { maxAmount: "1", merchantAllowlist: [MERCHANT], allowedCategories: ["x"] },
      }),
    ).rejects.toThrow();
  });
});

describe("mandate signature verification", () => {
  it("detects tampering with a signed Intent", async () => {
    const intent = await issueIntent();
    const tampered = { ...intent, scope: { ...intent.scope, maxAmount: "999999999" } };
    expect(await verifier.verifyProof(tampered)).toBe(false);
  });

  it("rejects an Intent signed by an untrusted key", async () => {
    const rogueKey = await createSigningKeyPair("rogue-1");
    const rogue = new AuthorizationService(localVerifier(issuer), new MandateSigner(rogueKey), () => NOW);
    const idToken = await issuer.mintIdToken({ sub: "auth0|abc" });
    const intent = await rogue.issueIntent({
      idToken,
      agentWallet: AGENT_WALLET,
      scope: { maxAmount: "5000000", merchantAllowlist: [MERCHANT], allowedCategories: ["otc-medicine"] },
    });
    expect(await verifier.verifyProof(intent)).toBe(false); // verifier only trusts asKey
  });
});

describe("verifyMandateChain (Payment ⊆ Cart ⊆ Intent + signature)", () => {
  it("accepts a fully valid, in-scope chain", async () => {
    const intent = await issueIntent();
    const { cart, payment } = chainFor(intent, [item()]);
    const res = await verifyMandateChain(verifier, { intent, cart, payment, nowSeconds: NOW });
    expect(res).toEqual({ ok: true });
  });

  it("rejects a cart over the intent cap", async () => {
    const intent = await issueIntent("1000000"); // $1 cap
    const { cart, payment } = chainFor(intent, [item({ unitPrice: "1500000" })]);
    const res = await verifyMandateChain(verifier, { intent, cart, payment, nowSeconds: NOW });
    expect(res.ok).toBe(false);
    expect(res.ok === false && res.violations.join()).toMatch(/exceeds intent cap/);
  });

  it("rejects a disallowed category", async () => {
    const intent = await issueIntent();
    const { cart, payment } = chainFor(intent, [item({ category: "beverages" })]);
    const res = await verifyMandateChain(verifier, { intent, cart, payment, nowSeconds: NOW });
    expect(res.ok === false && res.violations.join()).toMatch(/categories not authorized/);
  });

  it("rejects when the intent has expired", async () => {
    const intent = await issueIntent();
    const { cart, payment } = chainFor(intent, [item()]);
    const res = await verifyMandateChain(verifier, {
      intent,
      cart,
      payment,
      nowSeconds: intent.expiresAt + 1,
    });
    expect(res.ok === false && res.violations.join()).toMatch(/expired/);
  });

  it("rejects when the signature is invalid (tampered intent)", async () => {
    const intent = await issueIntent();
    const tampered = { ...intent, scope: { ...intent.scope, maxAmount: "999999999" } };
    const { cart, payment } = chainFor(tampered, [item()]);
    const res = await verifyMandateChain(verifier, { intent: tampered, cart, payment, nowSeconds: NOW });
    expect(res.ok === false && res.violations.join()).toMatch(/signature is invalid/);
  });

  it("rejects a payment to a different merchant than the cart", async () => {
    const intent = await issueIntent();
    const cart = buildCartMandate({ intentId: intent.id, merchant: MERCHANT, items: [item()], nowSeconds: NOW });
    const payment = buildPaymentMandate({
      cartId: cart.id,
      payTo: OTHER,
      asset: USDC,
      amount: cart.total,
      network: "eip155:84532",
      nonce: "0xabc",
    });
    const res = await verifyMandateChain(verifier, { intent, cart, payment, nowSeconds: NOW });
    expect(res.ok === false && res.violations.join()).toMatch(/does not match cart merchant/);
  });
});
