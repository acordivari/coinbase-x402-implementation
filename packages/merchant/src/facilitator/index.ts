/**
 * Facilitator factory. Picks the inner facilitator (live HTTP vs offline mock)
 * from config and always wraps it in the ResilientFacilitatorClient, so the
 * retry/idempotency/transaction-lock guarantees apply on both paths.
 */
import { HTTPFacilitatorClient, type FacilitatorClient } from "@x402/core/server";
import type { MerchantConfig } from "../config.ts";
import { MockFacilitator } from "./mock.ts";
import {
  ResilientFacilitatorClient,
  type ResilientFacilitatorOptions,
} from "./resilient.ts";

export function buildFacilitator(
  config: MerchantConfig,
  opts: ResilientFacilitatorOptions = {},
): { inner: FacilitatorClient; resilient: ResilientFacilitatorClient } {
  const inner: FacilitatorClient =
    config.facilitatorMode === "mock"
      ? new MockFacilitator()
      : new HTTPFacilitatorClient({ url: config.facilitatorUrl });

  const resilient = new ResilientFacilitatorClient(inner, {
    maxAttempts: config.settleMaxAttempts,
    baseDelayMs: config.settleBaseDelayMs,
    ...opts,
  });

  return { inner, resilient };
}

export { MockFacilitator } from "./mock.ts";
export { ResilientFacilitatorClient } from "./resilient.ts";
export * from "./errors.ts";
