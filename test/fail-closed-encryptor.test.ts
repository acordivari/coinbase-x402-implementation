/**
 * Security regression: the demo's x401 encryptor key authenticates the challenge
 * state that seals the payment binding. The built-in dev default is acceptable
 * only in the offline local demo — booting `PROOF_MODE=live` with the default (or
 * an unset/empty) key must FAIL CLOSED rather than run with a forgeable binding.
 */
import { describe, expect, it } from "vitest";

describe("x401 encryptor key fail-closed (server boot guard)", () => {
  it("refuses to boot in live mode with the default/empty key", async () => {
    // Set BEFORE importing the module — its consts read process.env at import,
    // and loadEnv() never overrides an already-set var.
    process.env.PROOF_MODE = "live";
    process.env.X401_ENCRYPTOR_KEY = ""; // would fall back to the dev default
    process.env.PROOF_CLIENT_ID = "";
    process.env.PROOF_CLIENT_SECRET = "";

    const { createDemoApp } = await import("../apps/wallet-demo/server/index.ts");
    await expect(createDemoApp()).rejects.toThrow(/X401_ENCRYPTOR_KEY/);
  });
});
