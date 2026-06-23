/**
 * Local holder wallet — the in-browser wallet we build (the piece x401 leaves to
 * "the Agent"). It stores SD-JWT-VCs, evaluates a DCQL query to choose which
 * claims to reveal, and produces a vp_token (compact SD-JWT + key-binding JWT)
 * bound to the verifier's nonce. In live mode Proof's hosted wallet plays this
 * role; this implementation drives the offline demo + all tests, and the same
 * selective-disclosure logic powers the browser visualization.
 */
import { nowSeconds } from "@agentic-payments/shared";
import { createSdJwtVc, type Jwk } from "./crypto.ts";
import { selectDisclosures, type DcqlQuery } from "./dcql.ts";

export interface HeldCredential {
  /** Credential id (e.g. proof_id_default). */
  id: string;
  /** The compact issuer-signed SD-JWT-VC (with all disclosures). */
  compact: string;
  /** The claim names this credential carries (for DCQL evaluation/UX). */
  claimNames: string[];
}

export interface PresentInput {
  query: DcqlQuery;
  /** OID4VP nonce (the x401 challenge value). Bound into the KB-JWT. */
  nonce: string;
  /** Intended audience (the verifier id). */
  audience: string;
  now?: () => number;
}

export interface PresentResult {
  /** The vp_token: compact SD-JWT-VC + KB-JWT, disclosing only selected claims. */
  vpToken: string;
  /** Claims revealed to the verifier. */
  disclosed: string[];
  /** Requested claims this credential could not satisfy. */
  missing: string[];
  /** Claims held but deliberately withheld (not requested). */
  withheld: string[];
}

export class LocalWallet {
  private readonly credentials = new Map<string, HeldCredential>();

  constructor(
    private readonly holderPrivateJwk: Jwk,
    private readonly holderPublicJwk: Jwk,
  ) {}

  /** The holder public key to bind into issued credentials (`cnf`). */
  get publicJwk(): Jwk {
    return this.holderPublicJwk;
  }

  store(credential: HeldCredential): void {
    this.credentials.set(credential.id, credential);
  }

  list(): HeldCredential[] {
    return [...this.credentials.values()];
  }

  get(id: string): HeldCredential | undefined {
    return this.credentials.get(id);
  }

  /**
   * Build a presentation answering a DCQL query: reveal only the requested
   * claims the matching credential holds, signing a KB-JWT over the verifier's
   * nonce so the verifier knows the holder authorized *this* request.
   */
  async present(input: PresentInput): Promise<PresentResult> {
    const credId = input.query.credentials[0]?.id;
    const held = credId ? this.credentials.get(credId) : this.list()[0];
    if (!held) throw new Error(`wallet holds no credential for query ${credId ?? "(any)"}`);

    const { disclose, missing } = selectDisclosures(input.query, held.claimNames);
    const sdjwt = await createSdJwtVc({ holderPrivateJwk: this.holderPrivateJwk });
    const presentationFrame = Object.fromEntries(disclose.map((k) => [k, true]));
    const now = (input.now ?? nowSeconds)();

    const vpToken = await sdjwt.present(held.compact, presentationFrame, {
      kb: { payload: { iat: now, aud: input.audience, nonce: input.nonce } },
    });

    return {
      vpToken,
      disclosed: disclose,
      missing,
      withheld: held.claimNames.filter((c) => !disclose.includes(c)),
    };
  }
}
