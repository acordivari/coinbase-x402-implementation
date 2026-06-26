/**
 * Unit coverage for the proof-vc-common SDK verifier adapter (`proofSdkVcVerifier`).
 * The full happy path needs a real Proof-issued vp_token + the live trust root, so
 * it is exercised by the live-gated demo (see docs/X401-PROTOCOL.md), not here.
 * Offline we assert the adapter satisfies the seam and fails *gracefully* (mapped
 * to a ValidationResult, never throwing) on an unverifiable token — the same
 * contract every other VerifiableCredentialVerifier honours.
 */
import { describe, expect, it } from "vitest";
import { proofSdkVcVerifier } from "../src/proof-sdk.ts";
import type { VerifiableCredentialVerifier } from "../src/types.ts";

describe("proofSdkVcVerifier (proof-vc-common adapter)", () => {
  const verifier: VerifiableCredentialVerifier = proofSdkVcVerifier({ trustRoot: "development" });

  it("implements the VerifiableCredentialVerifier seam", () => {
    expect(typeof verifier.verifyPresentation).toBe("function");
  });

  it("rejects an unverifiable vp_token without throwing", async () => {
    const proof = await verifier.verifyPresentation({ vpToken: "not-a-real-vp-token", nonce: "n0nce" });
    expect(proof.result.ok).toBe(false);
    expect(proof.holderBound).toBe(false);
    expect(proof.nonceBound).toBe(false);
    expect(proof.claimsDisclosed).toEqual([]);
    expect(proof.result.ok ? [] : proof.result.violations.join(" ")).toMatch(/presentation verification failed/);
  });
});
