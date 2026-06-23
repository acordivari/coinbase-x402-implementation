/**
 * The Proof "digital passport" credential shape (`proof_id_default`). These are
 * the claims a real Proof SD-JWT-VC carries; in local mode we self-issue the
 * same shape so the wallet, DCQL selection, and verifier exercise identical
 * code paths to the live Proof flow. Every claim is selectively disclosable.
 */

/** Proof's credential id, targeted by the `:basic` scope and transaction_data. */
export const PROOF_CREDENTIAL_ID = "proof_id_default";

/** The SD-JWT-VC type (`vct`) for a Proof ID credential (local default). */
export const PROOF_VCT = "https://credentials.proof.com/v1/proof_id_default";

/** The OID4VP scope that Proof maps to the proof_id_default DCQL query. */
export const PROOF_BASIC_SCOPE = "urn:proof:params:scope:verifiable-credentials:basic";

/** Selectively-disclosable claims of a Proof ID credential. */
export interface ProofIdClaims {
  given_name: string;
  family_name: string;
  birth_date: string; // ISO 8601 date (YYYY-MM-DD)
  email: string;
  document_number?: string;
  nationality?: string;
  issuing_country?: string;
  age_over_18?: boolean;
  age_over_21?: boolean;
}

/** The set of claim names that can be requested/disclosed, in display order. */
export const PROOF_ID_CLAIM_KEYS: (keyof ProofIdClaims)[] = [
  "given_name",
  "family_name",
  "birth_date",
  "email",
  "document_number",
  "nationality",
  "issuing_country",
  "age_over_18",
  "age_over_21",
];

/** Build the @sd-jwt disclosure frame marking every present claim as SD. */
export function proofIdDisclosureFrame(claims: ProofIdClaims): { _sd: (keyof ProofIdClaims)[] } {
  return {
    _sd: (Object.keys(claims) as (keyof ProofIdClaims)[]).filter(
      (k) => claims[k] !== undefined,
    ),
  };
}

/**
 * Demo holders for local mode. Mirrors the console's "Andrew / Sam" personas so
 * the two demos line up. Real mode uses the user's actual Proof credential.
 */
export const DEMO_HOLDERS: Record<string, ProofIdClaims> = {
  "andrew@example.com": {
    given_name: "Andrew",
    family_name: "Cordivari",
    birth_date: "1990-04-12",
    email: "andrew@example.com",
    document_number: "P1234567",
    nationality: "US",
    issuing_country: "US",
    age_over_18: true,
    age_over_21: true,
  },
  "sam@example.com": {
    given_name: "Sam",
    family_name: "Rivera",
    birth_date: "2006-09-30",
    email: "sam@example.com",
    document_number: "P7654321",
    nationality: "US",
    issuing_country: "US",
    age_over_18: false,
    age_over_21: false,
  },
};
