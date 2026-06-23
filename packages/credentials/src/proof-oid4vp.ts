/**
 * Build the live Proof OID4VP presentation request. Proof's
 * `/verifiable-credentials/v1/presentation/authorize` GET endpoint 302-redirects
 * the End-User to Proof's hosted wallet, where they selectively disclose their
 * credential and authorize the attached payment (transaction_data). The
 * vp_token returns to `redirect_uri` (fragment) or `response_uri` (direct_post).
 */
import { PROOF_BASIC_SCOPE } from "./proof-credential.ts";

export const PROOF_API_BASE = "https://api.proof.com";
export const PROOF_AUTHORIZE_PATH = "/verifiable-credentials/v1/presentation/authorize";

export interface ProofAuthorizeInput {
  clientId: string;
  /** The verified End-User's email (required by Proof). */
  loginHint: string;
  /** The OID4VP nonce — pass the x401 challenge value so the two bind together. */
  nonce: string;
  responseMode: "fragment" | "direct_post";
  /** Required for fragment mode. */
  redirectUri?: string;
  /** Required for direct_post mode. */
  responseUri?: string;
  /** Encoded transaction_data (payment-mandate) to bind into the presentation. */
  transactionData?: string;
  state?: string;
  scope?: string;
  apiBase?: string;
}

/** Build the absolute Proof authorize URL (the 302 target the agent opens). */
export function buildProofAuthorizeUrl(input: ProofAuthorizeInput): string {
  const url = new URL(PROOF_AUTHORIZE_PATH, input.apiBase ?? PROOF_API_BASE);
  const q = url.searchParams;
  q.set("client_id", input.clientId);
  q.set("response_type", "vp_token");
  q.set("response_mode", input.responseMode);
  q.set("scope", input.scope ?? PROOF_BASIC_SCOPE);
  q.set("login_hint", input.loginHint);
  q.set("nonce", input.nonce);
  if (input.responseMode === "fragment") {
    if (!input.redirectUri) throw new Error("redirect_uri is required for response_mode=fragment");
    q.set("redirect_uri", input.redirectUri);
  } else {
    if (!input.responseUri) throw new Error("response_uri is required for response_mode=direct_post");
    q.set("response_uri", input.responseUri);
  }
  if (input.transactionData !== undefined) q.set("transaction_data", input.transactionData);
  if (input.state !== undefined) q.set("state", input.state);
  return url.toString();
}

export interface ResolveAuthorizeInput extends ProofAuthorizeInput {
  /**
   * OAuth access token (from the client-credentials grant) sent as
   * `Authorization: Bearer …`. Server-side only — never exposed to the browser.
   * Omit for a public client.
   */
  bearerToken?: string;
  fetchImpl?: typeof fetch;
}

/**
 * Server-side: call Proof's authorize endpoint with the OAuth bearer token and
 * return the hosted-flow URL from the 302 `Location`. Keeping this on the server
 * means the token (and the client secret that minted it) never reach the browser
 * — the browser only ever opens the returned hosted URL.
 */
export async function resolveProofAuthorizeRedirect(input: ResolveAuthorizeInput): Promise<string> {
  const url = buildProofAuthorizeUrl(input);
  const headers: Record<string, string> = {};
  if (input.bearerToken) headers.Authorization = `Bearer ${input.bearerToken}`;
  const res = await (input.fetchImpl ?? fetch)(url, { method: "GET", redirect: "manual", headers });
  const location = res.headers.get("location");
  if (res.status >= 300 && res.status < 400 && location) return location;
  const body = await res.text().catch(() => "");
  throw new Error(
    `Proof authorize did not redirect (status ${res.status})${body ? `: ${body.slice(0, 300)}` : ""}`,
  );
}

/** Parse a `vp_token` (and optional `state`) from a fragment-mode callback URL. */
export function parseFragmentCallback(urlOrFragment: string): {
  vpToken?: string;
  state?: string;
} {
  const hash = urlOrFragment.includes("#")
    ? urlOrFragment.slice(urlOrFragment.indexOf("#") + 1)
    : urlOrFragment.replace(/^#/, "");
  const params = new URLSearchParams(hash);
  return {
    ...(params.get("vp_token") ? { vpToken: params.get("vp_token")! } : {}),
    ...(params.get("state") ? { state: params.get("state")! } : {}),
  };
}

/** base64 of an ASCII string (Node + browser). */
export function asciiBase64(s: string): string {
  return typeof btoa === "function" ? btoa(s) : Buffer.from(s, "utf8").toString("base64");
}
