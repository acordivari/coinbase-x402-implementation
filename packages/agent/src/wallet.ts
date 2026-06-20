/**
 * Wallet factory for the headless buyer agent. Both implementations satisfy the
 * shared PaymentSigner seam, so the buyer flow is identical regardless of which
 * one backs it.
 *
 *  - CDP Server Wallet (default): headless MPC, no seed phrase, native to x402.
 *    Needs free CDP API keys (testnet has no cost).
 *  - viem local key: a throwaway private key. Zero external accounts — used for
 *    offline tests and as a no-dependency fallback.
 */
import { type Account } from "viem";
import { generatePrivateKey, privateKeyToAccount } from "viem/accounts";
import type { PaymentSigner } from "@agentic-payments/shared";

export type WalletMode = "cdp" | "local";

/** A throwaway local signer. Generates a fresh key if none is supplied. */
export function createLocalSigner(privateKey?: `0x${string}`): PaymentSigner {
  const account = privateKeyToAccount(privateKey ?? generatePrivateKey());
  return {
    address: account.address.toLowerCase() as `0x${string}`,
    getAccount: () => account as Account,
    label: "local:throwaway",
  };
}

/**
 * CDP Server Wallet signer. Lazily imports the CDP SDK so the local path has no
 * dependency on CDP credentials. Reads CDP_API_KEY_ID / CDP_API_KEY_SECRET /
 * CDP_WALLET_SECRET from the environment.
 */
export async function createCdpSigner(
  name = "buyer-agent",
): Promise<PaymentSigner> {
  const { CdpClient } = await import("@coinbase/cdp-sdk");
  const { toAccount } = await import("viem/accounts");
  const cdp = new CdpClient();
  const cdpAccount = await cdp.evm.getOrCreateAccount({ name });
  const account = toAccount(cdpAccount as never) as Account;
  return {
    address: account.address.toLowerCase() as `0x${string}`,
    getAccount: () => account,
    label: `cdp:${name}`,
  };
}

export async function createSigner(
  env: NodeJS.ProcessEnv = process.env,
): Promise<PaymentSigner> {
  const mode = (env.WALLET_MODE as WalletMode) ?? "cdp";
  if (mode === "local") {
    return createLocalSigner(env.AGENT_PRIVATE_KEY as `0x${string}` | undefined);
  }
  return createCdpSigner(env.CDP_WALLET_NAME ?? "buyer-agent");
}
