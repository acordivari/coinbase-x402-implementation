/**
 * The verifiable-credentials verification seam. Two implementations behind one
 * interface (mirroring the identity/facilitator seams):
 *
 *   - localVcVerifier : verifies a self-issued SD-JWT-VC against a known trust
 *                       anchor (offline; the test/CI + offline-demo substrate)
 *   - proofVcVerifier : verifies a real Proof SD-JWT-VC presentation
 *
 * Both check the issuer signature, the holder key-binding (KB-JWT) against the
 * verifier's nonce, and surface the disclosed claims. Real Proof tokens differ
 * from our local ones in two ways we handle here:
 *   1. the vp_token is base64url(JSON { credId: [ "<sd-jwt-vc>" ] }) — a DCQL
 *      response envelope — not a bare compact SD-JWT.
 *   2. the issuer signs ES256 with an X.509 chain in the JWT `x5c` header (not a
 *      resolvable JWKS), so we take the signing key from the leaf certificate.
 */
import { X509Certificate, verify as nodeVerify } from "node:crypto";
import { collect } from "@agentic-payments/shared";
import type { Verifier } from "@sd-jwt/types";
import { createSdJwtVc, type Jwk } from "./crypto.ts";
import type {
  PresentationProof,
  VerifiableCredentialVerifier,
  VerifyPresentationInput,
} from "./types.ts";

/** Resolve an issuer's public verification key from its `iss` value. */
export type IssuerKeyResolver = (iss: string) => Promise<Jwk>;

/** JWT registered/SD-JWT-VC claims that are not user-disclosed attributes. */
const RESERVED_CLAIMS = new Set([
  "iss", "vct", "vct#integrity", "cnf", "iat", "exp", "nbf", "sub", "status", "_sd", "_sd_alg",
]);

interface VerifierOptions {
  /** For non-x5c (local) credentials: resolve the issuer key from `iss`. */
  resolveIssuerKey?: IssuerKeyResolver;
  /** Allow taking the signing key from the JWT `x5c` header (Proof). */
  allowX5c?: boolean;
  /** If set, the credential's `iss` must equal this. */
  expectedIssuer?: string;
}

class SdJwtVcVerifier implements VerifiableCredentialVerifier {
  constructor(private readonly opts: VerifierOptions) {}

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
      const compact = unwrapVpToken(input.vpToken);
      const header = parseJwtHeader(compact);
      issuer = readIssuer(compact);
      if (this.opts.expectedIssuer && issuer !== this.opts.expectedIssuer) {
        throw new Error(`untrusted issuer ${issuer} (expected ${this.opts.expectedIssuer})`);
      }

      let issuerVerifier: Verifier;
      const x5c = Array.isArray(header.x5c) ? (header.x5c as string[]) : undefined;
      if (x5c && x5c.length > 0) {
        if (!this.opts.allowX5c) throw new Error("issuer x5c cert chain is not accepted by this verifier");
        const { verifier, cert } = es256VerifierFromX5c(x5c);
        issuerVerifier = verifier;
        issuerCert = cert;
      } else {
        if (!this.opts.resolveIssuerKey) throw new Error("no issuer key resolver configured");
        const key = await this.opts.resolveIssuerKey(issuer);
        issuerVerifier = await jwkVerifier(key);
      }

      const sdjwt = await createSdJwtVc({ issuerVerifier });
      const res = await sdjwt.verify(compact, {
        keyBindingNonce: input.nonce,
        ...(input.requiredClaims ? { requiredClaimKeys: input.requiredClaims } : {}),
      });

      const payload = res.payload as Record<string, unknown>;
      holderBound = Boolean(payload.cnf);
      nonceBound = res.kb?.payload?.nonce === input.nonce;
      paymentApproved = (res.kb?.payload as Record<string, unknown> | undefined)?.payment_mandate_v1;

      for (const [k, v] of Object.entries(payload)) {
        if (!RESERVED_CLAIMS.has(k)) {
          claimsDisclosed.push(k);
          subject[k] = v;
        }
      }

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
  }
}

/** Verifier for self-issued credentials trusting a single issuer key. */
export function localVcVerifier(opts: {
  issuerId: string;
  issuerPublicJwk: Jwk;
}): VerifiableCredentialVerifier {
  return new SdJwtVcVerifier({
    expectedIssuer: opts.issuerId,
    resolveIssuerKey: async () => opts.issuerPublicJwk,
  });
}

export interface ProofVcVerifierOptions {
  /** Require this exact issuer (e.g. https://api.fairfax.proof.com). */
  expectedIssuer?: string;
}

/**
 * Verifier for live Proof credentials. Proof signs with an ES256 X.509 chain in
 * the JWT `x5c` header, so the signing key comes from the leaf certificate.
 */
export function proofVcVerifier(opts: ProofVcVerifierOptions = {}): VerifiableCredentialVerifier {
  return new SdJwtVcVerifier({
    allowX5c: true,
    ...(opts.expectedIssuer ? { expectedIssuer: opts.expectedIssuer } : {}),
  });
}

/**
 * Unwrap a vp_token to a compact SD-JWT-VC. A compact token contains `~`
 * separators; Proof instead returns base64url(JSON { credId: [ "<compact>" ] }).
 */
export function unwrapVpToken(vpToken: string): string {
  if (vpToken.includes("~")) return vpToken; // already a compact SD-JWT-VC
  try {
    const obj = JSON.parse(b64urlToString(vpToken)) as Record<string, unknown>;
    for (const value of Object.values(obj)) {
      if (Array.isArray(value) && typeof value[0] === "string") return value[0];
      if (typeof value === "string" && value.includes("~")) return value;
    }
  } catch {
    /* not a wrapped token */
  }
  return vpToken;
}

/** Read the `iss` claim from a (possibly wrapped) vp_token without verifying. */
export function readIssuer(vpToken: string): string {
  const compact = unwrapVpToken(vpToken);
  const payloadSeg = compact.split("~")[0]?.split(".")[1];
  if (!payloadSeg) throw new Error("malformed vp_token: missing JWT payload");
  const iss = (JSON.parse(b64urlToString(payloadSeg)) as { iss?: string }).iss;
  if (!iss) throw new Error("vp_token has no issuer (iss)");
  return iss;
}

function parseJwtHeader(compact: string): Record<string, unknown> {
  const headerSeg = compact.split("~")[0]?.split(".")[0];
  if (!headerSeg) throw new Error("malformed vp_token: missing JWT header");
  return JSON.parse(b64urlToString(headerSeg)) as Record<string, unknown>;
}

/**
 * Build an ES256 signature verifier from an x5c chain (leaf first). Verifies the
 * JWS against the leaf certificate's public key and checks the chain links
 * (leaf issued by the next cert). Pinning the chain to a Proof root CA is a
 * hardening follow-up; this proves the credential was signed by the key in a
 * well-formed Proof-issued certificate.
 */
function es256VerifierFromX5c(x5c: string[]): {
  verifier: Verifier;
  cert: { subject?: string; issuer?: string };
} {
  const leaf = new X509Certificate(Buffer.from(x5c[0]!, "base64"));
  for (let i = 0; i < x5c.length - 1; i++) {
    const child = new X509Certificate(Buffer.from(x5c[i]!, "base64"));
    const parent = new X509Certificate(Buffer.from(x5c[i + 1]!, "base64"));
    if (!child.checkIssued(parent)) {
      throw new Error("x5c chain is not internally consistent (broken issuer link)");
    }
  }
  const key = leaf.publicKey;
  const verifier: Verifier = (data, sig) => {
    const signature = Buffer.from(sig.replace(/-/g, "+").replace(/_/g, "/"), "base64");
    return nodeVerify("sha256", Buffer.from(data), { key, dsaEncoding: "ieee-p1363" }, signature);
  };
  return { verifier, cert: { subject: leaf.subject, issuer: leaf.issuer } };
}

/** Build an @sd-jwt Verifier from a public JWK (ES256). */
async function jwkVerifier(jwk: Jwk): Promise<Verifier> {
  const { ES256 } = await import("@owf/crypto");
  const v = await ES256.getVerifier(jwk);
  return (data, sig) => v(data, sig);
}

function b64urlToString(b64url: string): string {
  const b64 = b64url.replace(/-/g, "+").replace(/_/g, "/");
  if (typeof atob === "function") return atob(b64);
  return Buffer.from(b64, "base64").toString("binary");
}
