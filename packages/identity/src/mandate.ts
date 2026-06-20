/**
 * Mandate signing, verification, and issuance — the cryptographic heart of the
 * Human Authorization Mandate (HAM). The Authorization Service verifies the
 * human's OIDC ID token and issues a *signed* Intent mandate binding that
 * verified Principal to an agent wallet and a spending scope. The merchant
 * later verifies the signature + the Payment ⊆ Cart ⊆ Intent scope chain
 * (scope logic lives in @agentic-payments/shared).
 */
import { randomUUID } from "node:crypto";
import { CompactSign, compactVerify, type KeyLike } from "jose";
import {
  cartItemsTotal,
  collect,
  nowSeconds,
  validateCartAgainstIntent,
  validatePaymentAgainstCart,
  type CartItem,
  type CartMandate,
  type IntentMandate,
  type PaymentMandate,
  type ValidationResult,
} from "@agentic-payments/shared";
import type { SigningKeyPair } from "./keys.ts";
import type { IdentityVerifier } from "./oidc.ts";

type Signable = IntentMandate | CartMandate | PaymentMandate;

/** Deterministic JSON: object keys sorted recursively, `proof` excluded. */
export function canonicalize(mandate: Signable): string {
  const { proof: _omit, ...rest } = mandate as Signable & { proof?: unknown };
  return stableStringify(rest);
}

function stableStringify(value: unknown): string {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(stableStringify).join(",")}]`;
  const entries = Object.entries(value as Record<string, unknown>)
    .filter(([, v]) => v !== undefined)
    .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));
  return `{${entries.map(([k, v]) => `${JSON.stringify(k)}:${stableStringify(v)}`).join(",")}}`;
}

/** Signs mandates with a single EdDSA key (e.g. the Authorization Service). */
export class MandateSigner {
  constructor(private readonly key: SigningKeyPair) {}

  async sign<T extends Signable>(mandate: T): Promise<T> {
    const jws = await new CompactSign(
      new TextEncoder().encode(canonicalize(mandate)),
    )
      .setProtectedHeader({ alg: this.key.alg, kid: this.key.kid })
      .sign(this.key.privateKey);
    return { ...mandate, proof: { alg: this.key.alg, kid: this.key.kid, signature: jws } };
  }
}

/** A trust anchor: just the public half of a signing key. */
export type TrustedKey = Pick<SigningKeyPair, "kid" | "publicKey">;

/** Verifies mandate proofs against a set of trusted public keys (by kid). */
export class MandateVerifier {
  private readonly keys = new Map<string, KeyLike>();

  constructor(trusted: TrustedKey[]) {
    for (const k of trusted) this.keys.set(k.kid, k.publicKey);
  }

  /** True iff the mandate carries a valid signature over its canonical form. */
  async verifyProof(mandate: Signable): Promise<boolean> {
    const proof = (mandate as { proof?: { signature: string; kid: string } }).proof;
    if (!proof) return false;
    const key = this.keys.get(proof.kid);
    if (!key) return false;
    try {
      const { payload } = await compactVerify(proof.signature, key);
      return new TextDecoder().decode(payload) === canonicalize(mandate);
    } catch {
      return false;
    }
  }
}

export interface IntentScope {
  maxAmount: string; // atomic USDC cap for the whole intent
  merchantAllowlist: `0x${string}`[];
  allowedCategories: string[];
}

export interface IssueIntentRequest {
  idToken: string;
  agentWallet: `0x${string}`;
  scope: IntentScope;
  ttlSeconds?: number;
}

/**
 * Issues signed Intent mandates after verifying the human's OIDC identity. This
 * is the trust anchor: the merchant only needs the Authorization Service's
 * public key to verify that a real, known human authorized the agent + scope.
 */
export class AuthorizationService {
  constructor(
    private readonly identity: IdentityVerifier,
    private readonly signer: MandateSigner,
    private readonly now: () => number = nowSeconds,
  ) {}

  async issueIntent(req: IssueIntentRequest): Promise<IntentMandate> {
    const principal = await this.identity.verify(req.idToken);
    const issuedAt = this.now();
    const ttl = req.ttlSeconds ?? 3600;
    const intent: IntentMandate = {
      type: "IntentMandate",
      id: randomUUID(),
      principal,
      agentWallet: req.agentWallet,
      scope: {
        maxAmount: req.scope.maxAmount,
        currency: "USDC",
        merchantAllowlist: req.scope.merchantAllowlist,
        allowedCategories: req.scope.allowedCategories,
      },
      issuedAt,
      expiresAt: issuedAt + ttl,
      nonce: randomUUID(),
    };
    return this.signer.sign(intent);
  }
}

/** Build a Cart mandate from line items (total computed from items). */
export function buildCartMandate(input: {
  intentId: string;
  merchant: `0x${string}`;
  items: CartItem[];
  nowSeconds: number;
  ttlSeconds?: number;
}): CartMandate {
  const total = cartItemsTotal(input.items);
  return {
    type: "CartMandate",
    id: randomUUID(),
    intentId: input.intentId,
    merchant: input.merchant,
    items: input.items,
    total: total.toString(),
    currency: "USDC",
    issuedAt: input.nowSeconds,
    expiresAt: input.nowSeconds + (input.ttlSeconds ?? 600),
    nonce: randomUUID(),
  };
}

/** Build a Payment mandate from a settled/authorized x402 payment. */
export function buildPaymentMandate(input: {
  cartId: string;
  payTo: `0x${string}`;
  asset: `0x${string}`;
  amount: string;
  network: PaymentMandate["network"];
  nonce: string;
}): PaymentMandate {
  return {
    type: "PaymentMandate",
    id: randomUUID(),
    cartId: input.cartId,
    payTo: input.payTo,
    asset: input.asset,
    amount: input.amount,
    network: input.network,
    nonce: input.nonce,
  };
}

export interface ChainVerifyInput {
  intent: IntentMandate;
  cart: CartMandate;
  payment: PaymentMandate;
  nowSeconds: number;
}

/**
 * Full authorization check: the Intent signature is valid AND
 * Payment ⊆ Cart ⊆ Intent (scope, cap, merchant, categories, expiry).
 * Cumulative-cap enforcement across multiple purchases is the caller's job
 * (see the merchant's intent spend ledger).
 */
export async function verifyMandateChain(
  verifier: MandateVerifier,
  input: ChainVerifyInput,
): Promise<ValidationResult> {
  const intentSigOk = await verifier.verifyProof(input.intent);
  const cart = validateCartAgainstIntent(input.cart, input.intent, input.nowSeconds);
  const payment = validatePaymentAgainstCart(input.payment, input.cart);

  return collect([
    intentSigOk ? null : "intent mandate signature is invalid or untrusted",
    ...(cart.ok ? [] : cart.violations),
    ...(payment.ok ? [] : payment.violations),
  ]);
}
