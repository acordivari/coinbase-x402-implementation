/**
 * Isomorphic SD-JWT-VC crypto, built on @owf/crypto — the exact primitives Proof
 * itself uses (WebCrypto under the hood, so this runs unchanged in Node ≥20 and
 * in the browser wallet). We wire @owf/crypto's ES256 signer/verifier + hasher
 * into the callback shapes @sd-jwt/* expects, and provide the key-binding (KB-JWT)
 * verifier that pulls the holder's public key from the credential's `cnf` claim.
 */
import { ES256, getHasher } from "@owf/crypto";
import {
  base64urlEncode,
  uint8ArrayToBase64Url,
} from "@owf/identity-common";
import { SDJwtVcInstance } from "@sd-jwt/sd-jwt-vc";
import type { Hasher, KbVerifier, SaltGenerator, Verifier } from "@sd-jwt/types";

/** A JSON Web Key (public or private). */
export type Jwk = Record<string, unknown>;

export const HASH_ALG = "sha-256";
const owfHash = getHasher(HASH_ALG);

/** @sd-jwt Hasher backed by @owf/crypto. */
export const hasher: Hasher = (data, _alg) =>
  owfHash(typeof data === "string" ? data : new TextDecoder().decode(data));

/**
 * @sd-jwt SaltGenerator. 16 random bytes → base64url. (We avoid @owf/crypto's
 * generateSalt to keep salt encoding identical across Node + browser.)
 */
export const saltGenerator: SaltGenerator = (length) =>
  uint8ArrayToBase64Url(crypto.getRandomValues(new Uint8Array(length)));

/** sha-256(input) → base64url. Used for OID4VP transaction_data digests. */
export async function sha256Base64url(input: string): Promise<string> {
  return uint8ArrayToBase64Url(await owfHash(input));
}

/** Generate a fresh ES256 (P-256) key pair as JWKs. */
export async function generateEs256Keys(): Promise<{ publicJwk: Jwk; privateJwk: Jwk }> {
  const { publicKey, privateKey } = await ES256.generateKeyPair();
  return { publicJwk: publicKey as Jwk, privateJwk: privateKey as Jwk };
}

/**
 * KB-JWT verifier: the holder proves possession of the key bound into the
 * credential's `cnf.jwk`. @sd-jwt hands us the *credential* payload (with `cnf`)
 * as the third arg, so we resolve the holder key from there.
 */
export const kbVerifier: KbVerifier = async (data, sig, payload) => {
  const jwk = (payload as { cnf?: { jwk?: Jwk } })?.cnf?.jwk;
  if (!jwk) return false;
  const verify = await ES256.getVerifier(jwk);
  return verify(data, sig);
};

export interface SdJwtVcKeys {
  /** Issuer private key — present on the issuing side. */
  issuerPrivateJwk?: Jwk;
  /** Issuer public key — present on the verifying side (built into a verifier). */
  issuerPublicJwk?: Jwk;
  /**
   * A prebuilt issuer-signature verifier. Takes precedence over issuerPublicJwk.
   * Used for Proof credentials, whose signing key comes from the x5c cert chain
   * in the JWT header rather than a resolvable JWK.
   */
  issuerVerifier?: Verifier;
  /** Holder private key — present on the wallet/holder side (signs the KB-JWT). */
  holderPrivateJwk?: Jwk;
}

/**
 * Build an `SDJwtVcInstance` configured for whatever role the caller plays
 * (issue / hold+present / verify), depending on which keys are supplied. Network
 * metadata fetching is disabled so verification is fully offline/deterministic.
 */
export async function createSdJwtVc(keys: SdJwtVcKeys): Promise<SDJwtVcInstance> {
  const config: Record<string, unknown> = {
    hasher,
    saltGenerator,
    hashAlg: HASH_ALG,
    kbVerifier,
    loadTypeMetadataFormat: false,
  };
  if (keys.issuerPrivateJwk) {
    config.signer = await ES256.getSigner(keys.issuerPrivateJwk);
    config.signAlg = ES256.alg;
  }
  if (keys.issuerVerifier) {
    config.verifier = keys.issuerVerifier;
  } else if (keys.issuerPublicJwk) {
    config.verifier = await ES256.getVerifier(keys.issuerPublicJwk);
  }
  if (keys.holderPrivateJwk) {
    config.kbSigner = await ES256.getSigner(keys.holderPrivateJwk);
    config.kbSignAlg = ES256.alg;
  }
  return new SDJwtVcInstance(config);
}

/** base64url-encode a JSON value (used for transaction_data and wire blobs). */
export function encodeJsonB64url(value: unknown): string {
  return base64urlEncode(JSON.stringify(value));
}
