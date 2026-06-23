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

import { localVcVerifier, proofVcVerifier } from "./verifier.ts";
import type { VerifiableCredentialVerifier } from "./types.ts";
import type { Jwk } from "./crypto.ts";

export type ProofMode = "local" | "live";

export interface VcVerifierConfig {
  mode: ProofMode;
  /** local mode: the trusted self-issuer id + public key. */
  local?: { issuerId: string; issuerPublicJwk: Jwk };
  /** live mode: optionally require an exact Proof issuer (`iss`). */
  proof?: { expectedIssuer?: string };
}

/**
 * Select the VC verifier from config (`PROOF_MODE`), mirroring `buildFacilitator`
 * and `localVerifier|auth0Verifier`. Callers depend only on the interface.
 */
export function createVcVerifier(config: VcVerifierConfig): VerifiableCredentialVerifier {
  if (config.mode === "live") {
    return proofVcVerifier(config.proof ?? {});
  }
  if (!config.local) throw new Error("local VC verifier requires { issuerId, issuerPublicJwk }");
  return localVcVerifier(config.local);
}
