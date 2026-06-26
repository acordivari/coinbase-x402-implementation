/**
 * Live Proof path built on the official `@proof.com/proof-vc-common` SDK, rather
 * than the hand-rolled equivalents in `proof-oid4vp.ts` / `proof-oauth.ts` /
 * `verifier.ts`. Two server-side capabilities:
 *
 *   - `proofSdkVcVerifier()` : a `VerifiableCredentialVerifier` that delegates to
 *     the SDK's `verifyVPToken`. The SDK decodes the DCQL `vp_token` envelope,
 *     verifies each SD-JWT-VC's issuer x5c chain against Proof's committed trust
 *     store (`trustRoot`), and verifies the holder KB-JWT against the nonce — so
 *     it both replaces our X.509 chain walk and resolves the open trust-pinning
 *     item (we pin Proof's actual Root CA via `trustRoot`, not the intermediate).
 *   - `buildProofSdkAuthorizeUrl()` : builds the hosted OID4VP authorize URL via
 *     the SDK's `getAuthorizationRequestURL` (with Pushed Authorization Requests,
 *     so the client secret never leaves the server and the payment-mandate URL
 *     stays small) — replacing the manual OAuth token mint + URL assembly.
 *
 * Server-only (handles the client secret + Node trust store), so this lives in
 * the node barrel (`index.ts`) and NOT the browser barrel — same rule as
 * `proof-oauth.ts`. The x401 challenge/binding layer (`x401.ts`) composes around
 * this exactly as `@proof.com/x401-node` prescribes.
 */
import { X509Certificate } from "node:crypto";
import {
  init as proofInit,
  getAuthorizationRequestURL,
  verifyVPToken,
  transactionData as proofTransactionData,
  type NodeInitParams,
  type TransactionData,
} from "@proof.com/proof-vc-common";
import { collect } from "@agentic-payments/shared";
import { PROOF_BASIC_SCOPE, PROOF_CREDENTIAL_ID } from "./proof-credential.ts";
import type {
  PresentationProof,
  VerifiableCredentialVerifier,
  VerifyPresentationInput,
} from "./types.ts";

/** Re-export the SDK's transaction-data builders (payment-mandate, etc.). */
export { proofTransactionData };
export type { TransactionData as ProofSdkTransactionData };

/** JWT registered / SD-JWT-VC claims that are not user-disclosed attributes. */
const RESERVED_CLAIMS = new Set([
  "iss", "vct", "vct#integrity", "cnf", "iat", "exp", "nbf", "sub", "status", "_sd", "_sd_alg",
]);

/**
 * The SDK keeps a module-level singleton client, so we init it once. Re-init is a
 * no-op (and the SDK itself throws on a second production init), so we guard it.
 */
let configured = false;
export function configureProofSdk(params: NodeInitParams): void {
  if (configured) return;
  proofInit(params);
  configured = true;
}

export interface ProofSdkVerifierOptions {
  /** Proof trust store to pin the issuer chain to. Default: "development" (sandbox). */
  trustRoot?: NodeInitParams["trustRoot"];
  /** Extra init params (clientId/secret/callbackUri) when this process also builds requests. */
  init?: Omit<NodeInitParams, "trustRoot">;
}

/**
 * Verify a real Proof `vp_token` via the SDK. On success the credential is fully
 * verified (issuer chain trusted, holder-bound, nonce-bound); we surface the
 * disclosed claims and the holder-approved payment for the HAM Intent.
 */
export function proofSdkVcVerifier(opts: ProofSdkVerifierOptions = {}): VerifiableCredentialVerifier {
  configureProofSdk({ trustRoot: opts.trustRoot ?? "development", ...(opts.init ?? {}) });

  return {
    async verifyPresentation(input: VerifyPresentationInput): Promise<PresentationProof> {
      const violations: string[] = [];
      const subject: Record<string, unknown> = {};
      const claimsDisclosed: string[] = [];
      let issuer: string | undefined;
      let holderBound = false;
      let nonceBound = false;
      let paymentApproved: unknown;
      let issuerCert: { subject?: string; issuer?: string } | undefined;

      try {
        const vpt = await verifyVPToken({ encodedVPToken: input.vpToken, nonce: input.nonce });
        const cred = vpt[PROOF_CREDENTIAL_ID]?.[0];
        if (!cred) throw new Error(`vp_token carried no '${PROOF_CREDENTIAL_ID}' credential`);

        const claims = cred.getClaims();
        issuer = typeof claims.iss === "string" ? claims.iss : undefined;
        holderBound = Boolean(claims.cnf);
        for (const [k, v] of Object.entries(claims)) {
          if (!RESERVED_CLAIMS.has(k)) {
            claimsDisclosed.push(k);
            subject[k] = v;
          }
        }

        // The KB-JWT (holder-signed) carries the nonce binding and — when a
        // payment-mandate transaction_data was presented — the approved payment.
        const decoded = cred.getSDJWT() as {
          kbJwt?: { payload?: Record<string, unknown> };
          jwt?: { header?: Record<string, unknown> };
        };
        const kb = decoded.kbJwt?.payload;
        nonceBound = kb?.nonce === input.nonce;
        paymentApproved = kb?.payment_mandate_v1;
        issuerCert = leafCertSummary(decoded.jwt?.header?.x5c);

        // The SDK already enforced these (it throws otherwise); assert for parity
        // with the local verifier's surfaced flags.
        if (!holderBound) violations.push("credential is not bound to a holder key (cnf)");
        if (!nonceBound) violations.push("key-binding nonce does not match the challenge");
      } catch (err) {
        violations.push(`presentation verification failed: ${(err as Error).message}`);
      }

      return {
        result: collect(violations),
        subject,
        claimsDisclosed,
        ...(issuer !== undefined ? { issuer } : {}),
        holderBound,
        nonceBound,
        ...(paymentApproved !== undefined ? { paymentApproved } : {}),
        ...(issuerCert !== undefined ? { issuerCert } : {}),
      };
    },
  };
}

export interface ProofSdkAuthorizeInput {
  /** The OID4VP nonce — pass the x401 challenge value so the two bind together. */
  nonce: string;
  /** The verified End-User's email (Proof's `login_hint`). */
  loginHint?: string;
  state?: string;
  scope?: string;
  /** Encoded transaction_data string, or an SDK transaction-data object. */
  transactionData?: TransactionData | string;
}

/**
 * Build the hosted Proof authorize URL via the SDK. Requires the SDK to have been
 * configured with the request config (clientId/secret/callbackUri/PAR), either at
 * construction of `proofSdkVcVerifier({ init })` or via `configureProofSdk`.
 */
export async function buildProofSdkAuthorizeUrl(input: ProofSdkAuthorizeInput): Promise<string> {
  return getAuthorizationRequestURL({
    scope: (input.scope ?? PROOF_BASIC_SCOPE) as never,
    nonce: input.nonce,
    ...(input.state !== undefined ? { state: input.state } : {}),
    ...(input.loginHint !== undefined ? { loginHint: input.loginHint } : {}),
    ...(input.transactionData !== undefined ? { transactionData: input.transactionData } : {}),
  });
}

/** Summarize the leaf x5c certificate (subject/issuer) for display, best-effort. */
function leafCertSummary(x5c: unknown): { subject?: string; issuer?: string } | undefined {
  if (!Array.isArray(x5c) || typeof x5c[0] !== "string") return undefined;
  try {
    const cert = new X509Certificate(Buffer.from(x5c[0], "base64"));
    return { subject: cert.subject, issuer: cert.issuer };
  } catch {
    return undefined;
  }
}
