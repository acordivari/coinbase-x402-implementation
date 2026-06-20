/**
 * Merchant configuration, read once from the environment. Centralizing this
 * keeps env-var names in a single place (DRY) and gives the rest of the
 * merchant a typed config object instead of scattered process.env reads.
 */
import {
  DEFAULT_FACILITATOR_URL,
  USDC_ADDRESS,
  X402_NETWORK,
} from "@agentic-payments/shared";

export type FacilitatorMode = "http" | "mock";

export interface MerchantConfig {
  port: number;
  /** Address that receives USDC (the merchant's wallet). */
  payTo: `0x${string}`;
  network: typeof X402_NETWORK;
  asset: `0x${string}`;
  facilitatorMode: FacilitatorMode;
  facilitatorUrl: string;
  /** Settlement retry policy (see ResilientFacilitatorClient). */
  settleMaxAttempts: number;
  settleBaseDelayMs: number;
}

/** Placeholder recipient used until a real MERCHANT_PAY_TO is supplied. */
export const PLACEHOLDER_PAY_TO =
  "0x000000000000000000000000000000000000dead" as const;

export function loadMerchantConfig(
  env: NodeJS.ProcessEnv = process.env,
): MerchantConfig {
  const mode = (env.FACILITATOR_MODE as FacilitatorMode) ?? "http";
  return {
    port: Number(env.MERCHANT_PORT ?? 4021),
    payTo: (env.MERCHANT_PAY_TO ?? PLACEHOLDER_PAY_TO).toLowerCase() as `0x${string}`,
    network: X402_NETWORK,
    asset: USDC_ADDRESS,
    facilitatorMode: mode,
    facilitatorUrl: env.X402_FACILITATOR_URL ?? DEFAULT_FACILITATOR_URL,
    settleMaxAttempts: Number(env.SETTLE_MAX_ATTEMPTS ?? 4),
    settleBaseDelayMs: Number(env.SETTLE_BASE_DELAY_MS ?? 250),
  };
}

/**
 * Validate a fully-resolved config (after overrides). The live HTTP facilitator
 * settles real USDC, so it must have a real recipient — fail fast otherwise.
 */
export function assertConfigValid(config: MerchantConfig): void {
  if (config.facilitatorMode === "http" && config.payTo === PLACEHOLDER_PAY_TO) {
    throw new Error(
      "MERCHANT_PAY_TO is required for live (http) facilitator mode — refusing to settle to the placeholder address",
    );
  }
}
