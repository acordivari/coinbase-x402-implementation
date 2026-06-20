/**
 * Regression test for the reservation-leak fix: the gate reserves cap spend for
 * an authorized purchase, but if the request does NOT end 200 (e.g. the x402
 * paywall later rejects the payment), the reservation must be released on
 * response finish — otherwise phantom reservations would exhaust the cap.
 */
import { EventEmitter } from "node:events";
import { beforeAll, describe, expect, it, vi } from "vitest";
import { USDC_ADDRESS, X402_NETWORK } from "@agentic-payments/shared";
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
import { createMandateGate, IntentSpendLedger } from "../src/mandate-gate.ts";

const MERCHANT = "0x1111111111111111111111111111111111111111" as const;
const AGENT = "0x2222222222222222222222222222222222222222" as const;
const PRICE = 1_500_000n; // allergy-relief-24

let asKey: SigningKeyPair;
let verifier: MandateVerifier;
let intent: IntentMandate;

beforeAll(async () => {
  asKey = await createSigningKeyPair("as-1");
  const oidcKey = await createSigningKeyPair("oidc-1");
  const issuer = new LocalOidcIssuer("https://sandbox.local/", "aud", oidcKey);
  const service = new AuthorizationService(localVerifier(issuer), new MandateSigner(asKey));
  verifier = new MandateVerifier([{ kid: asKey.kid, publicKey: asKey.publicKey }]);
  const idToken = await issuer.mintIdToken({ sub: "auth0|x" });
  intent = await service.issueIntent({
    idToken,
    agentWallet: AGENT,
    scope: { maxAmount: "5000000", merchantAllowlist: [MERCHANT], allowedCategories: ["otc-medicine"] },
  });
});

function b64(obj: unknown): string {
  return Buffer.from(JSON.stringify(obj)).toString("base64");
}

function fakeReq(nonce: string) {
  const headers: Record<string, string> = {
    "x-authorization-mandate": b64(intent),
    "x-payment": b64({
      payload: { authorization: { from: AGENT, to: MERCHANT, value: PRICE.toString(), nonce } },
    }),
  };
  return {
    path: "/allergy-relief-24",
    header: (name: string) => headers[name.toLowerCase()],
  } as any;
}

function fakeRes() {
  const res = new EventEmitter() as any;
  res.statusCode = 200;
  res.status = (code: number) => {
    res.statusCode = code;
    return res;
  };
  res.json = (body: unknown) => {
    res.body = body;
    return res;
  };
  return res;
}

describe("mandate gate reservation lifecycle", () => {
  it("reserves on authorize, then releases when the response is not 200", async () => {
    const ledger = new IntentSpendLedger();
    const gate = createMandateGate({
      verifier,
      merchant: MERCHANT,
      asset: USDC_ADDRESS,
      network: X402_NETWORK,
      ledger,
    });
    const req = fakeReq("0xnonce-leak");
    const res = fakeRes();
    const next = vi.fn();

    await gate(req, res, next);
    expect(next).toHaveBeenCalledOnce();
    expect(ledger.total(intent.id)).toBe(PRICE); // reserved

    // The x402 paywall rejects after the gate (non-200) -> reservation released.
    res.statusCode = 402;
    res.emit("finish");
    expect(ledger.total(intent.id)).toBe(0n); // no phantom reservation
  });

  it("keeps the reservation when the response is 200 (settle hooks own it)", async () => {
    const ledger = new IntentSpendLedger();
    const gate = createMandateGate({
      verifier,
      merchant: MERCHANT,
      asset: USDC_ADDRESS,
      network: X402_NETWORK,
      ledger,
    });
    const req = fakeReq("0xnonce-ok");
    const res = fakeRes();

    await gate(req, res, vi.fn());
    expect(ledger.total(intent.id)).toBe(PRICE);

    res.statusCode = 200; // authorized; commit/release happens via settle hooks
    res.emit("finish");
    expect(ledger.total(intent.id)).toBe(PRICE);
  });
});
