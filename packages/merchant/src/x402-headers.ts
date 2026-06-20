/**
 * One decoder for the inbound x402 payment header, shared by the order ledger
 * and the mandate gate. Having a single parser means a header-format change can
 * never update one reader and silently leave the other returning empty (which
 * would make a paid request look unpaid and bypass the gate).
 */
import type { Request } from "express";

export interface PaymentAuthorization {
  from?: string;
  to?: string;
  value?: string;
  nonce?: string;
}

/** Decode the EIP-3009 authorization from the request's x402 payment header. */
export function decodePaymentAuthorization(req: Request): PaymentAuthorization {
  const header = req.header("x-payment") ?? req.header("payment-signature");
  if (!header) return {};
  try {
    const decoded = JSON.parse(Buffer.from(header, "base64").toString("utf8"));
    const auth = decoded?.payload?.authorization;
    if (!auth) return {};
    return { from: auth.from, to: auth.to, value: auth.value, nonce: auth.nonce };
  } catch {
    return {};
  }
}
