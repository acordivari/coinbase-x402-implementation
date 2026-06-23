/**
 * Minimal DCQL (Digital Credentials Query Language) support — the piece x401
 * deliberately leaves out (it treats the query as opaque). A verifier builds a
 * DCQL query naming exactly which claims it wants; a wallet evaluates the query
 * against a held credential to decide which disclosures to reveal. This is where
 * the "flexibility in what information from the wallet is shared" lives.
 */
import { PROOF_CREDENTIAL_ID, PROOF_VCT } from "./proof-credential.ts";

/** An OID4VP DCQL query (the subset we emit/consume). */
export interface DcqlQuery {
  credentials: DcqlCredentialQuery[];
}

export interface DcqlCredentialQuery {
  id: string;
  format: string; // "dc+sd-jwt"
  meta?: { vct_values?: string[] };
  claims?: { path: (string | number)[] }[];
}

export const SD_JWT_VC_FORMAT = "dc+sd-jwt";

/**
 * Build a DCQL query requesting the named top-level claims from a Proof ID
 * credential. The verifier decides the policy (e.g. "name + age_over_21 only").
 */
export function buildProofIdDcqlQuery(
  claimNames: string[],
  opts: { id?: string; vct?: string } = {},
): DcqlQuery {
  return {
    credentials: [
      {
        id: opts.id ?? PROOF_CREDENTIAL_ID,
        format: SD_JWT_VC_FORMAT,
        meta: { vct_values: [opts.vct ?? PROOF_VCT] },
        claims: claimNames.map((name) => ({ path: [name] })),
      },
    ],
  };
}

/** The flat list of top-level claim names a DCQL query requests. */
export function requestedClaimNames(query: DcqlQuery): string[] {
  const names = new Set<string>();
  for (const cred of query.credentials) {
    for (const claim of cred.claims ?? []) {
      const head = claim.path[0];
      if (typeof head === "string") names.add(head);
    }
  }
  return [...names];
}

/**
 * Given a DCQL query and the claims a wallet actually holds, decide which to
 * disclose (intersection) and which were requested-but-absent. The wallet only
 * ever reveals requested claims — never the whole credential.
 */
export function selectDisclosures(
  query: DcqlQuery,
  heldClaimNames: string[],
): { disclose: string[]; missing: string[] } {
  const requested = requestedClaimNames(query);
  const held = new Set(heldClaimNames);
  return {
    disclose: requested.filter((c) => held.has(c)),
    missing: requested.filter((c) => !held.has(c)),
  };
}
