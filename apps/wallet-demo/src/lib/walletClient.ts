/**
 * The in-browser holder wallet. This is where the "wow" lives: real SD-JWT-VC
 * selective disclosure runs client-side via @sd-jwt + @owf/crypto (WebCrypto),
 * so the browser — not a server — decides which claims to reveal and signs the
 * key-binding JWT over the verifier's nonce. In live mode Proof's hosted wallet
 * plays this role; we then decode the returned presentation here to visualize
 * exactly what was disclosed.
 */
import {
  createSdJwtVc,
  generateEs256Keys,
  selectDisclosures,
  PROOF_ID_CLAIM_KEYS,
  type DcqlQuery,
  type Jwk,
} from "@agentic-payments/credentials/browser";

const LS_KEYS = "x401.holderKeys";
const LS_CRED = "x401.credential";

export interface HeldCredential {
  id: string;
  compact: string;
  claimNames: string[];
}

export interface HolderKeys {
  publicJwk: Jwk;
  privateJwk: Jwk;
}

/** Load (or generate + persist) the holder key pair for this browser. */
export async function ensureHolderKeys(): Promise<HolderKeys> {
  const cached = localStorage.getItem(LS_KEYS);
  if (cached) return JSON.parse(cached) as HolderKeys;
  const keys = await generateEs256Keys();
  localStorage.setItem(LS_KEYS, JSON.stringify(keys));
  return keys;
}

export function saveCredential(cred: HeldCredential): void {
  localStorage.setItem(LS_CRED, JSON.stringify(cred));
}
export function loadCredential(): HeldCredential | undefined {
  const raw = localStorage.getItem(LS_CRED);
  return raw ? (JSON.parse(raw) as HeldCredential) : undefined;
}
export function clearWallet(): void {
  localStorage.removeItem(LS_KEYS);
  localStorage.removeItem(LS_CRED);
}

export interface PresentResult {
  vpToken: string;
  disclosed: string[];
  withheld: string[];
  missing: string[];
}

/** Selectively disclose the DCQL-requested claims, bound to the nonce. */
export async function presentInBrowser(input: {
  privateJwk: Jwk;
  credential: HeldCredential;
  query: DcqlQuery;
  nonce: string;
  audience: string;
}): Promise<PresentResult> {
  const inst = await createSdJwtVc({ holderPrivateJwk: input.privateJwk });
  const { disclose, missing } = selectDisclosures(input.query, input.credential.claimNames);
  const presentationFrame = Object.fromEntries(disclose.map((k) => [k, true]));
  const vpToken = await inst.present(input.credential.compact, presentationFrame, {
    kb: { payload: { iat: Math.floor(Date.now() / 1000), aud: input.audience, nonce: input.nonce } },
  });
  return {
    vpToken,
    disclosed: disclose,
    missing,
    withheld: input.credential.claimNames.filter((c) => !disclose.includes(c)),
  };
}

/** Decode a vp_token (no verification) to show which claims it reveals. */
export async function decodeDisclosed(vpToken: string): Promise<{ disclosed: string[]; subject: Record<string, unknown> }> {
  const inst = await createSdJwtVc({});
  const claims = (await inst.getClaims(vpToken)) as Record<string, unknown>;
  const disclosed = PROOF_ID_CLAIM_KEYS.filter((k) => k in claims);
  const subject: Record<string, unknown> = {};
  for (const k of disclosed) subject[k] = claims[k];
  return { disclosed, subject };
}
