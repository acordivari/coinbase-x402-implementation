/**
 * Wraps `fetch` with x402 payment handling. On a 402 the client uses the
 * agent's signer to produce an EIP-3009 authorization and retries the request
 * automatically — so the buyer flow just calls `fetchWithPayment(url)`.
 */
import { x402Client, wrapFetchWithPayment } from "@x402/fetch";
import { registerExactEvmScheme } from "@x402/evm/exact/client";
import { X402_NETWORK, type PaymentSigner } from "@agentic-payments/shared";

export interface X402ClientOptions {
  /** Optional RPC URL for the exact EVM scheme (Base Sepolia). */
  rpcUrl?: string;
}

export async function createPayingFetch(
  signer: PaymentSigner,
  opts: X402ClientOptions = {},
): Promise<typeof fetch> {
  const account = await signer.getAccount();
  const client = new x402Client();
  registerExactEvmScheme(client, {
    signer: account as never,
    networks: [X402_NETWORK],
    ...(opts.rpcUrl ? { schemeOptions: { rpcUrl: opts.rpcUrl } } : {}),
  });
  return wrapFetchWithPayment(fetch, client) as typeof fetch;
}
