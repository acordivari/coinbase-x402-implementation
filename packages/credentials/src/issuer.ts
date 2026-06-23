/**
 * Local SD-JWT-VC issuer — the offline counterpart to Proof's hosted issuer.
 * It mints a `proof_id_default`-shaped credential with the holder's public key
 * bound in (`cnf`) and every claim selectively disclosable, so the local seam
 * exercises the exact verification path as a live Proof credential.
 */
import { nowSeconds } from "@agentic-payments/shared";
import type { DisclosureFrame } from "@sd-jwt/types";
import { createSdJwtVc, type Jwk } from "./crypto.ts";
import {
  PROOF_VCT,
  proofIdDisclosureFrame,
  type ProofIdClaims,
} from "./proof-credential.ts";

export interface LocalVcIssuerOptions {
  /** Issuer identifier placed in `iss` (e.g. a local issuer URL). */
  issuerId: string;
  /** Issuer ES256 private key (JWK). */
  privateJwk: Jwk;
  /** Credential type; defaults to the Proof ID vct. */
  vct?: string;
  /** Clock override (testing). */
  now?: () => number;
}

export class LocalVcIssuer {
  private readonly vct: string;
  private readonly now: () => number;

  constructor(private readonly opts: LocalVcIssuerOptions) {
    this.vct = opts.vct ?? PROOF_VCT;
    this.now = opts.now ?? nowSeconds;
  }

  /**
   * Issue a credential to a holder. Returns the compact SD-JWT-VC the holder
   * stores in their wallet (issuer-signed JWT + all disclosures, no KB-JWT yet).
   */
  async issue(claims: ProofIdClaims, holderPublicJwk: Jwk, ttlSeconds = 31_536_000): Promise<string> {
    const sdjwt = await createSdJwtVc({ issuerPrivateJwk: this.opts.privateJwk });
    const iat = this.now();
    const payload = {
      iss: this.opts.issuerId,
      vct: this.vct,
      iat,
      exp: iat + ttlSeconds,
      cnf: { jwk: holderPublicJwk },
      ...claims,
    };
    const frame = proofIdDisclosureFrame(claims) as DisclosureFrame<typeof payload>;
    return sdjwt.issue(payload, frame);
  }
}
