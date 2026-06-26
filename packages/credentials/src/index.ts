/**
 * Public surface of the verifiable-credentials (x401 + Proof) seam.
 *
 * Layers:
 *   - crypto / issuer / wallet : SD-JWT-VC issue, hold, selective-disclose
 *   - dcql                     : build/evaluate DCQL credential queries
 *   - transaction-data         : payment-mandate binding (the 401↔402 join)
 *   - verifier                 : VerifiableCredentialVerifier seam (local|proof)
 *   - x401                     : @proof.com/x401-node wire wrappers + end-to-end
 *                                presentation verification
 *   - proof-oid4vp             : live Proof presentation-request URL builder
 */
export * from "./crypto.ts";
export * from "./proof-credential.ts";
export * from "./transaction-data.ts";
export * from "./dcql.ts";
export * from "./issuer.ts";
export * from "./wallet.ts";
export * from "./types.ts";
export * from "./verifier.ts";
export * from "./x401.ts";
export * from "./proof-oid4vp.ts";
export * from "./proof-oauth.ts";
export * from "./proof-sdk.ts";

import { localVcVerifier, proofVcVerifier } from "./verifier.ts";
import { proofSdkVcVerifier, type ProofSdkVerifierOptions } from "./proof-sdk.ts";
import type { VerifiableCredentialVerifier } from "./types.ts";
import type { Jwk } from "./crypto.ts";

export type ProofMode = "local" | "live";

export interface VcVerifierConfig {
  mode: ProofMode;
  /** local mode: the trusted self-issuer id + public key. */
  local?: { issuerId: string; issuerPublicJwk: Jwk };
  /** live mode: Proof issuer + CA trust pinning (hand-rolled x5c verifier). */
  proof?: {
    expectedIssuer?: string;
    trustedCaFingerprints?: string[];
    trustedRootPems?: string[];
    /**
     * Verify via the official `@proof.com/proof-vc-common` SDK (`verifyVPToken`)
     * instead of the hand-rolled x5c chain walk. Pins Proof's committed Root CA
     * via `trustRoot`.
     */
    useSdk?: boolean;
    /** SDK trust store ("development" | "production") when `useSdk`. */
    trustRoot?: ProofSdkVerifierOptions["trustRoot"];
    /** Extra SDK init (clientId/secret/callbackUri) when this process also builds requests. */
    sdkInit?: ProofSdkVerifierOptions["init"];
  };
}

/**
 * Select the VC verifier from config (`PROOF_MODE` + `proof.useSdk`), mirroring
 * `buildFacilitator` and `localVerifier|auth0Verifier`. Callers depend only on the
 * interface. Live mode picks the SDK verifier (`proof.useSdk`) or the hand-rolled
 * x5c verifier; both implement the same seam.
 */
export function createVcVerifier(config: VcVerifierConfig): VerifiableCredentialVerifier {
  if (config.mode === "live") {
    const proof = config.proof ?? {};
    if (proof.useSdk) {
      return proofSdkVcVerifier({
        ...(proof.trustRoot !== undefined ? { trustRoot: proof.trustRoot } : {}),
        ...(proof.sdkInit !== undefined ? { init: proof.sdkInit } : {}),
      });
    }
    return proofVcVerifier(proof);
  }
  if (!config.local) throw new Error("local VC verifier requires { issuerId, issuerPublicJwk }");
  return localVcVerifier(config.local);
}
