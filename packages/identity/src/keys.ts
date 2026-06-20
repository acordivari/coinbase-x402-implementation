/**
 * Key material for the sandbox. Two signing roles, both EdDSA (Ed25519):
 *   - the local OIDC issuer (mints ID tokens in offline mode)
 *   - the Authorization Service (signs Intent mandates)
 *
 * Keys are generated in-process for the sandbox. For persistence/real
 * deployments, load a private JWK from the environment instead (loadKeyPair).
 */
import { exportJWK, generateKeyPair, importJWK, type JWK, type KeyLike } from "jose";

export interface SigningKeyPair {
  kid: string;
  alg: "EdDSA";
  publicKey: KeyLike;
  privateKey: KeyLike;
  publicJwk: JWK;
}

/** Generate a fresh Ed25519 signing key with a stable kid. */
export async function createSigningKeyPair(kid: string): Promise<SigningKeyPair> {
  const { publicKey, privateKey } = await generateKeyPair("EdDSA", {
    extractable: true,
  });
  const publicJwk = { ...(await exportJWK(publicKey)), kid, alg: "EdDSA", use: "sig" };
  return { kid, alg: "EdDSA", publicKey, privateKey, publicJwk };
}

/** Rebuild a key pair from a private JWK (e.g. read from an env secret). */
export async function loadKeyPair(privateJwk: JWK, kid: string): Promise<SigningKeyPair> {
  const privateKey = (await importJWK(privateJwk, "EdDSA")) as KeyLike;
  const publicJwkBase = { ...privateJwk };
  delete (publicJwkBase as Record<string, unknown>).d; // strip the private scalar
  const publicJwk = { ...publicJwkBase, kid, alg: "EdDSA", use: "sig" };
  const publicKey = (await importJWK(publicJwk, "EdDSA")) as KeyLike;
  return { kid, alg: "EdDSA", publicKey, privateKey, publicJwk };
}

/** A JWKS document exposing one or more public keys for verification. */
export function toJwks(...pairs: SigningKeyPair[]): { keys: JWK[] } {
  return { keys: pairs.map((p) => p.publicJwk) };
}
