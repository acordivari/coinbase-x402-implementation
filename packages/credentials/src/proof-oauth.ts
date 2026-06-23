/**
 * Proof OAuth 2.0 client-credentials flow. The Bearer token used on the
 * `/presentation/authorize` request is short-lived and minted from the
 * confidential client's id + secret:
 *
 *   POST {tokenEndpoint}            (api.proof.com/oauth/v2/token, or fairfax sandbox)
 *   Content-Type: application/x-www-form-urlencoded
 *   Authorization: Basic base64(client_id:client_secret)
 *   body: grant_type=client_credentials[&scope=…]
 *
 * This is server-side only (it handles the client secret), so it lives outside
 * the browser barrel. We cache the token until shortly before it expires.
 */
import { asciiBase64 } from "./proof-oid4vp.ts";

export interface ProofTokenRequest {
  tokenEndpoint: string;
  clientId: string;
  clientSecret: string;
  scope?: string;
  fetchImpl?: typeof fetch;
}

export interface ProofAccessToken {
  accessToken: string;
  tokenType: string;
  /** Absolute expiry, unix seconds. */
  expiresAt: number;
  scope?: string;
}

/** Mint a Proof access token via the client-credentials grant. */
export async function fetchProofAccessToken(req: ProofTokenRequest): Promise<ProofAccessToken> {
  const body = new URLSearchParams({ grant_type: "client_credentials" });
  if (req.scope) body.set("scope", req.scope);
  const res = await (req.fetchImpl ?? fetch)(req.tokenEndpoint, {
    method: "POST",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded",
      Authorization: `Basic ${asciiBase64(`${req.clientId}:${req.clientSecret}`)}`,
    },
    body: body.toString(),
  });
  if (!res.ok) {
    const text = await res.text().catch(() => "");
    throw new Error(`Proof token request failed (${res.status})${text ? `: ${text.slice(0, 300)}` : ""}`);
  }
  const json = (await res.json()) as {
    access_token?: string;
    token_type?: string;
    expires_in?: number;
    scope?: string;
  };
  if (!json.access_token) throw new Error("Proof token response had no access_token");
  const nowSec = Math.floor(Date.now() / 1000);
  return {
    accessToken: json.access_token,
    tokenType: json.token_type ?? "Bearer",
    expiresAt: nowSec + (json.expires_in ?? 3600),
    ...(json.scope !== undefined ? { scope: json.scope } : {}),
  };
}

export interface ProofTokenProvider {
  /** A valid access token, minting/refreshing as needed. */
  getToken(): Promise<string>;
  /** Drop the cached token (e.g. after a 401 from the API). */
  reset(): void;
}

/** A caching token provider that refreshes shortly before expiry. */
export function createProofTokenProvider(
  req: ProofTokenRequest & { skewSeconds?: number },
): ProofTokenProvider {
  const skew = req.skewSeconds ?? 60;
  let cached: ProofAccessToken | undefined;
  let inflight: Promise<ProofAccessToken> | undefined;
  return {
    async getToken(): Promise<string> {
      const nowSec = Math.floor(Date.now() / 1000);
      if (cached && cached.expiresAt - skew > nowSec) return cached.accessToken;
      // Coalesce concurrent refreshes into one request.
      inflight ??= fetchProofAccessToken(req).finally(() => { inflight = undefined; });
      cached = await inflight;
      return cached.accessToken;
    },
    reset() {
      cached = undefined;
    },
  };
}
