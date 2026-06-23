/**
 * OID4VP `transaction_data` — the mechanism that turns a plain identity
 * presentation into proof that *this human authorized this payment*. Proof's
 * presentation flow accepts a `payment-mandate` transaction_data object the
 * End-User explicitly approves; the returned vp_token is bound to its digest.
 * We build the same object for the live path AND for the local seam, so the
 * 401↔402 join is identical in both.
 */
import { encodeJsonB64url, sha256Base64url } from "./crypto.ts";
import { PROOF_CREDENTIAL_ID } from "./proof-credential.ts";

export const PAYMENT_MANDATE_TX_TYPE =
  "urn:proof:params:vc:transaction-data:payment-mandate:v1" as const;
export const SESSION_DATA_TX_TYPE =
  "urn:proof:params:vc:transaction-data:session-data" as const;

/** The common OID4VP transaction_data envelope (any type). */
export interface ProofTransactionData {
  type: string;
  credential_ids: string[];
  payload: object;
}

/**
 * Our internal payment record. This is what we seal into the x401 challenge and
 * re-verify, regardless of which transaction_data type Proof is sent — so the
 * agent's payment is always bound at the x401 layer.
 */
export interface PaymentMandatePayload {
  amount: string; // atomic USDC units
  currency: string; // "USDC"
  merchant: string; // 0x receiving address
  asset?: string; // token contract
  network?: string; // e.g. eip155:84532
  sku?: string;
  description?: string;
}

export interface PaymentMandateTransactionData extends ProofTransactionData {
  type: typeof PAYMENT_MANDATE_TX_TYPE;
  payload: PaymentMandatePayload;
}

/** Build our internal payment transaction_data (sealed into the x401 challenge). */
export function buildPaymentMandateTransactionData(
  payload: PaymentMandatePayload,
): PaymentMandateTransactionData {
  return { type: PAYMENT_MANDATE_TX_TYPE, credential_ids: [PROOF_CREDENTIAL_ID], payload };
}

/**
 * Proof's `payment-mandate:v1` transaction_data, per the Proof docs
 * (transaction-data-templates#payment-mandate). The End-User approves this on
 * Proof's hosted flow. NOTE: `amount` is a bare number and `currency` is a
 * separate top-level string (an `amount` object is rejected/500s).
 */
export interface ProofPaymentMandateInput {
  amount: number; // e.g. 1.50
  currency: string; // e.g. "USD"
  payeeName: string;
  payeeWebsite?: string;
  promptSummary: string;
  instrument: { id: string; type: string; description?: string };
}
export function buildProofPaymentMandate(input: ProofPaymentMandateInput): ProofTransactionData {
  return {
    type: PAYMENT_MANDATE_TX_TYPE,
    credential_ids: [PROOF_CREDENTIAL_ID],
    payload: {
      payment_instrument: input.instrument,
      payee: { name: input.payeeName, ...(input.payeeWebsite ? { website: input.payeeWebsite } : {}) },
      prompt_summary: input.promptSummary,
      amount: input.amount,
      currency: input.currency,
    },
  };
}

/** Proof `session-data` transaction_data (the documented, sandbox-ready type). */
export function buildSessionTransactionData(payload: Record<string, unknown>): ProofTransactionData {
  return { type: SESSION_DATA_TX_TYPE, credential_ids: [PROOF_CREDENTIAL_ID], payload };
}

/** Encode transaction_data for the wire (base64url JSON), per the Proof API. */
export function encodeTransactionData(td: ProofTransactionData): string {
  return encodeJsonB64url(td);
}

/** Decode a base64url-encoded transaction_data blob. */
export function decodeTransactionData(encoded: string): ProofTransactionData {
  const json = new TextDecoder().decode(
    Uint8Array.from(atobUrl(encoded), (c) => c.charCodeAt(0)),
  );
  return JSON.parse(json) as ProofTransactionData;
}

/** sha-256 digest (base64url) of the *encoded* transaction_data string. */
export function transactionDataDigest(encoded: string): Promise<string> {
  return sha256Base64url(encoded);
}

/** base64url → binary string (browser/Node-safe, no Buffer dependency). */
function atobUrl(b64url: string): string {
  const b64 = b64url.replace(/-/g, "+").replace(/_/g, "/").padEnd(
    Math.ceil(b64url.length / 4) * 4,
    "=",
  );
  return typeof atob === "function"
    ? atob(b64)
    : Buffer.from(b64, "base64").toString("binary");
}
