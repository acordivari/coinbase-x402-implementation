/**
 * One-shot setup for the LIVE Base Sepolia path. After you put your CDP API key
 * in .env, run `npm run setup:live`. It will:
 *   1. create (or reuse) the agent + merchant CDP Server Wallets
 *   2. pull testnet USDC into the agent wallet from the CDP faucet
 *   3. print the MERCHANT_PAY_TO and the exact commands to run the live demo
 *
 * No real funds: everything is Base Sepolia testnet.
 */
import { CdpClient } from "@coinbase/cdp-sdk";

const NETWORK = "base-sepolia" as const;

async function main() {
  // Load CDP_API_KEY_ID / CDP_API_KEY_SECRET / CDP_WALLET_SECRET from .env.
  try {
    process.loadEnvFile(".env");
  } catch {
    /* .env optional if vars already exported */
  }
  if (!process.env.CDP_API_KEY_ID || !process.env.CDP_WALLET_SECRET) {
    throw new Error(
      "Missing CDP credentials. Set CDP_API_KEY_ID, CDP_API_KEY_SECRET, and CDP_WALLET_SECRET in .env first.",
    );
  }

  const cdp = new CdpClient();

  console.log("Creating / loading CDP Server Wallets…");
  const agent = await cdp.evm.getOrCreateAccount({ name: "buyer-agent" });
  const merchant = await cdp.evm.getOrCreateAccount({ name: "merchant-cvs" });
  console.log(`  agent wallet (payer):    ${agent.address}`);
  console.log(`  merchant wallet (payTo): ${merchant.address}`);

  console.log("\nRequesting testnet USDC for the agent from the CDP faucet…");
  try {
    const res = await cdp.evm.requestFaucet({
      address: agent.address,
      network: NETWORK,
      token: "usdc",
    });
    console.log(`  faucet tx: ${res.transactionHash ?? JSON.stringify(res)}`);
    console.log("  (faucet can take ~10-30s to land)");
  } catch (err) {
    console.warn(
      `  faucet request failed (${String(err)}).\n` +
        `  You can instead fund ${agent.address} from https://faucet.circle.com (Base Sepolia).`,
    );
  }

  // Best-effort balance read.
  try {
    const balances = await cdp.evm.listTokenBalances({ address: agent.address, network: NETWORK });
    console.log(`\nAgent token balances: ${JSON.stringify(balances.balances ?? balances, null, 0).slice(0, 400)}`);
  } catch {
    /* non-fatal */
  }

  console.log(`
─────────────────────────────────────────────────────────────
Next steps for the LIVE Base Sepolia demo:

1) Put this in your .env:
     MERCHANT_PAY_TO=${merchant.address}
     FACILITATOR_MODE=http
     WALLET_MODE=cdp

2) Start the merchant (live facilitator):
     FACILITATOR_MODE=http MERCHANT_PAY_TO=${merchant.address} npm run merchant

3) In another terminal, run the agent (real settlement on Base Sepolia):
     WALLET_MODE=cdp MERCHANT_URL=http://localhost:4021 npm run agent allergy-relief-24

Watch for a real settlement tx hash in the receipt / order. Track the wallets
on https://sepolia.basescan.org/address/${agent.address}
─────────────────────────────────────────────────────────────`);
}

main().catch((err) => {
  console.error("\nsetup:live failed:", err instanceof Error ? err.message : err);
  process.exit(1);
});
