/**
 * Shared result types for the verifiable-credentials seam.
 */
import type { ValidationResult } from "@agentic-payments/shared";

/** What a verifier learns from a verified VC presentation. */
export interface PresentationProof {
  /** ok, or the list of reasons the presentation was rejected. */
  result: ValidationResult;
  /** The disclosed claim values (subset the holder chose to reveal). */
  subject: Record<string, unknown>;
  /** Claim names actually revealed in this presentation. */
  claimsDisclosed: string[];
  /** The credential issuer (`iss`), once parsed. */
  issuer?: string;
  /** The credential was bound to a holder key (`cnf`). */
  holderBound: boolean;
  /** The key-binding JWT's nonce matched the verifier's challenge. */
  nonceBound: boolean;
  /**
   * The payment the holder authorized, as carried IN the (holder-signed)
   * key-binding JWT — Proof binds the payment-mandate here, so this is
   * cryptographic proof the human approved this exact payment. Undefined if the
   * presentation carried no payment mandate.
   */
  paymentApproved?: unknown;
  /** Subject/issuer of the issuer's signing certificate (x5c leaf), if present. */
  issuerCert?: { subject?: string; issuer?: string };
}

export interface VerifyPresentationInput {
  /** The vp_token: compact SD-JWT-VC + KB-JWT. */
  vpToken: string;
  /** Expected key-binding nonce (the x401 challenge value). */
  nonce: string;
  /** Claim names that MUST be disclosed (DCQL-derived); verification fails otherwise. */
  requiredClaims?: string[];
}

/** The swappable VC-verification seam: local (self-issued) vs Proof (live). */
export interface VerifiableCredentialVerifier {
  verifyPresentation(input: VerifyPresentationInput): Promise<PresentationProof>;
}
