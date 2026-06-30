/**
 * Vendored Verifier Challenge + Encryptor.
 *
 * `@proof.com/x401-node` shipped these primitives through 0.1.0, then removed
 * them in 0.2.0 when the wire format moved to the Digital Credentials API model
 * (the OID4VP nonce now lives inside the Verifier-composed request, not an x401
 * challenge string). We still rely on them: our payment binding seals the
 * `transaction_data` digest into an encrypted, authenticated challenge that
 * doubles as the OID4VP nonce, so the verifier can later prove the presentation
 * authorized *this* payment. This module is a faithful port of the removed 0.1.0
 * `challenge.ts` + `encryptor.ts`, kept under our control so `x401.ts` keeps that
 * property while everything else tracks the current x401 wire names.
 *
 * Built on the same `@owf/identity-common` byte helpers and WebCrypto AES-GCM the
 * SDK used, so it runs unchanged in Node ≥20 and the browser.
 */
import {
  base64UrlToUint8Array,
  base64urlDecode,
  base64urlEncode,
  concatBytes,
  stringToBytes,
  uint8ArrayToBase64Url,
} from "@owf/identity-common";

export type JsonPrimitive = string | number | boolean | null;
export type JsonValue = JsonPrimitive | JsonValue[] | { [key: string]: JsonValue };
export type JsonObject = { [key: string]: JsonValue };

// --- Encryptor (authenticated encryption of the challenge state) ---

export interface EncryptorOptions {
  /** Secret key material. A string is UTF-8 encoded before key derivation. */
  key: string | Uint8Array;
  /** Domain-separation label mixed into key derivation and bound as additional authenticated data. */
  purpose?: string;
}

export interface Encryptor {
  /** Encrypt and authenticate a claims object into a single base64url token. */
  encrypt(claims: JsonObject): Promise<string>;
  /** Authenticate and decrypt a token back into its claims. Throws if authentication fails. */
  decrypt(token: string): Promise<JsonObject>;
}

const ENCRYPTOR_VERSION = 1;
const IV_BYTES = 12;

function bytes(value: Uint8Array): Uint8Array {
  return new Uint8Array(value);
}

async function deriveKey(material: Uint8Array, purpose: string) {
  const base = await crypto.subtle.importKey("raw", material, "HKDF", false, ["deriveKey"]);
  return crypto.subtle.deriveKey(
    {
      name: "HKDF",
      hash: "SHA-256",
      salt: bytes(stringToBytes("x401-encryptor")),
      info: bytes(stringToBytes(purpose)),
    },
    base,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"],
  );
}

export function createEncryptor(options: EncryptorOptions): Encryptor {
  const purpose = options.purpose ?? "x401";
  const material = bytes(
    typeof options.key === "string" ? stringToBytes(options.key) : options.key,
  );
  const aad = bytes(stringToBytes(`x401-encryptor.v${ENCRYPTOR_VERSION}.${purpose}`));
  let keyPromise: ReturnType<typeof deriveKey> | null = null;
  const getKey = () => (keyPromise ??= deriveKey(material, purpose));

  return {
    async encrypt(claims: JsonObject): Promise<string> {
      const key = await getKey();
      const iv = crypto.getRandomValues(new Uint8Array(IV_BYTES));
      const ciphertext = new Uint8Array(
        await crypto.subtle.encrypt(
          { name: "AES-GCM", iv, additionalData: aad },
          key,
          bytes(stringToBytes(JSON.stringify(claims))),
        ),
      );
      return uint8ArrayToBase64Url(
        concatBytes(new Uint8Array([ENCRYPTOR_VERSION]), iv, ciphertext),
      );
    },
    async decrypt(token: string): Promise<JsonObject> {
      const raw = base64UrlToUint8Array(token);
      if (raw.length < 1 + IV_BYTES + 1 || raw[0] !== ENCRYPTOR_VERSION) {
        throw new Error("x401 encryptor: malformed token.");
      }
      const key = await getKey();
      const iv = bytes(raw.subarray(1, 1 + IV_BYTES));
      const ciphertext = bytes(raw.subarray(1 + IV_BYTES));
      let plaintext: ArrayBuffer;
      try {
        plaintext = await crypto.subtle.decrypt(
          { name: "AES-GCM", iv, additionalData: aad },
          key,
          ciphertext,
        );
      } catch {
        throw new Error("x401 encryptor: authentication failed.");
      }
      return JSON.parse(new TextDecoder().decode(new Uint8Array(plaintext))) as JsonObject;
    },
  };
}

// --- Verifier Challenge (the OID4VP nonce, with sealed verifier state) ---

/** The created challenge: an opaque value the agent echoes back, plus its expiry. */
export interface VerifierChallenge {
  value: string;
  expires_at: string;
}

export interface CreateChallengeInput {
  /** Verifier identifier (e.g. HTTPS origin or DID). Encoded into the challenge value and sealed into the nonce. */
  verifierId: string;
  /** Route/resource the challenge is bound to. */
  resource: string;
  /** HTTP method the challenge is bound to. */
  method: string;
  /** Encryptor used to encrypt the challenge state into the nonce segment. */
  encryptor: Encryptor;
  /** Challenge lifetime in seconds. */
  ttlSeconds: number;
  /** Override the current time (testing). */
  now?: Date;
  /** Additional verifier-defined context bound into the challenge (e.g. the transaction_data digest). */
  context?: JsonObject;
}

export type VerifyChallengeResult =
  | {
      ok: true;
      verifierId: string;
      resource: string;
      method: string;
      expiresAt: string;
      claims: JsonObject;
    }
  | { ok: false; reason: string };

export interface VerifyChallengeInput {
  /** The returned challenge value (from the Result Artifact or token-exchange request). */
  value: string;
  /** The same encryptor used to create the challenge. */
  encryptor: Encryptor;
  /** Reject the challenge unless its sealed verifier identifier equals this value. */
  expectedVerifierId?: string;
  /** Reject the challenge unless its sealed resource equals this value. */
  expectedResource?: string;
  /** Reject the challenge unless its sealed method equals this value (case-insensitive). */
  expectedMethod?: string;
  /** Override the current time (testing). */
  now?: Date;
}

const CHALLENGE_PREFIX = "x401";
const CHALLENGE_RANDOM_BYTES = 16;

export async function createChallenge(input: CreateChallengeInput): Promise<VerifierChallenge> {
  const now = input.now ?? new Date();
  const expiresAt = new Date(now.getTime() + input.ttlSeconds * 1000);
  const rnd = uint8ArrayToBase64Url(crypto.getRandomValues(new Uint8Array(CHALLENGE_RANDOM_BYTES)));
  const claims: JsonObject = {
    vid: input.verifierId,
    rnd,
    resource: input.resource,
    method: input.method.toUpperCase(),
    exp: Math.floor(expiresAt.getTime() / 1000),
    ...(input.context !== undefined && { context: input.context }),
  };
  const nonce = await input.encryptor.encrypt(claims);
  return {
    value: `${CHALLENGE_PREFIX}:${base64urlEncode(input.verifierId)}:${nonce}`,
    expires_at: expiresAt.toISOString(),
  };
}

function parseChallengeValue(value: string): { verifierId: string; nonce: string } {
  const first = value.indexOf(":");
  const second = value.indexOf(":", first + 1);
  if (first < 0 || second < 0 || value.slice(0, first) !== CHALLENGE_PREFIX) {
    throw new Error("x401: malformed Verifier Challenge value.");
  }
  return {
    verifierId: base64urlDecode(value.slice(first + 1, second)),
    nonce: value.slice(second + 1),
  };
}

export async function verifyChallenge(input: VerifyChallengeInput): Promise<VerifyChallengeResult> {
  let parsed: { verifierId: string; nonce: string };
  try {
    parsed = parseChallengeValue(input.value);
  } catch (error) {
    return { ok: false, reason: (error as Error).message };
  }
  let claims: JsonObject;
  try {
    claims = await input.encryptor.decrypt(parsed.nonce);
  } catch (error) {
    return { ok: false, reason: (error as Error).message };
  }
  const vid = typeof claims.vid === "string" ? claims.vid : undefined;
  const resource = typeof claims.resource === "string" ? claims.resource : undefined;
  const method = typeof claims.method === "string" ? claims.method : undefined;
  const exp = typeof claims.exp === "number" ? claims.exp : undefined;
  if (vid === undefined || resource === undefined || method === undefined || exp === undefined) {
    return { ok: false, reason: "protected challenge state is incomplete" };
  }
  if (vid !== parsed.verifierId) {
    return { ok: false, reason: "verifier identifier mismatch" };
  }
  if (input.expectedVerifierId !== undefined && vid !== input.expectedVerifierId) {
    return { ok: false, reason: "verifier identifier mismatch" };
  }
  const now = input.now ?? new Date();
  if (now.getTime() / 1000 > exp) {
    return { ok: false, reason: "challenge expired" };
  }
  if (input.expectedResource !== undefined && resource !== input.expectedResource) {
    return { ok: false, reason: "resource mismatch" };
  }
  if (input.expectedMethod !== undefined && method !== input.expectedMethod.toUpperCase()) {
    return { ok: false, reason: "method mismatch" };
  }
  return {
    ok: true,
    verifierId: vid,
    resource,
    method,
    expiresAt: new Date(exp * 1000).toISOString(),
    claims,
  };
}
