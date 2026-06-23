/**
 * The verifiable-credentials seam — the highest-complexity, multi-state piece
 * (issue → hold → DCQL-select → present → verify, plus payment binding). These
 * tests run the full local round trip with no network and assert the failure
 * modes the protocol must catch: selective disclosure, holder/nonce binding,
 * tampering, and the transaction_data (payment) binding that makes this 401+402.
 */
import { beforeAll, describe, expect, it } from "vitest";
import {
  buildPaymentMandateTransactionData,
  buildProofIdDcqlQuery,
  createEncryptor,
  createIdentityChallenge,
  buildProofRequired,
  detectRequirement,
  packPresentation,
  verifyAuthorization,
  encodeTransactionData,
  generateEs256Keys,
  localVcVerifier,
  resolveProofAuthorizeRedirect,
  fetchProofAccessToken,
  createProofTokenProvider,
  LocalVcIssuer,
  LocalWallet,
  DEMO_HOLDERS,
  PROOF_CREDENTIAL_ID,
  PROOF_ID_CLAIM_KEYS,
  type Jwk,
  type VerifiableCredentialVerifier,
  type X401Payload,
} from "../src/index.ts";

const ISSUER_ID = "https://issuer.sandbox.local";
const VERIFIER_ID = "https://merchant.sandbox.local";
const RESOURCE = "https://merchant.sandbox.local/buy/allergy-relief-24";
const TOKEN_ENDPOINT = "https://merchant.sandbox.local/oauth/token";

let issuerKeys: { publicJwk: Jwk; privateJwk: Jwk };
let issuer: LocalVcIssuer;
let wallet: LocalWallet;
let vcVerifier: VerifiableCredentialVerifier;

function encryptor() {
  return createEncryptor({ key: "credentials-test-key-0123456789", purpose: "x401-test" });
}

const txData = () =>
  encodeTransactionData(
    buildPaymentMandateTransactionData({
      amount: "1500000",
      currency: "USDC",
      merchant: "0xc0ffee0000000000000000000000000000000000",
      network: "eip155:84532",
      sku: "allergy-relief-24",
    }),
  );

/** Build PROOF-REQUIRED, present from the wallet, return the PROOF-PRESENTATION header. */
async function authorize(opts: {
  enc: ReturnType<typeof encryptor>;
  requested: string[];
  transactionData?: string;
}): Promise<{ presentationHeader: string; payload: X401Payload; disclosed: string[]; withheld: string[]; missing: string[] }> {
  const challenge = await createIdentityChallenge({
    encryptor: opts.enc,
    verifierId: VERIFIER_ID,
    resource: RESOURCE,
    method: "GET",
    ttlSeconds: 600,
    ...(opts.transactionData !== undefined ? { transactionData: opts.transactionData } : {}),
  });
  const { payload, header } = buildProofRequired({
    challenge,
    tokenEndpoint: TOKEN_ENDPOINT,
    scope: "urn:proof:params:scope:verifiable-credentials:basic",
    requestId: "proof-id-v1",
  });
  const detected = detectRequirement({ "PROOF-REQUIRED": header });
  expect(detected).toBeTruthy();
  const present = await wallet.present({
    query: buildProofIdDcqlQuery(opts.requested),
    nonce: detected!.payload.proof.challenge.value,
    audience: VERIFIER_ID,
  });
  const { header: presentationHeader } = packPresentation({
    payload,
    agentId: "did:web:agent.sandbox.local",
    vpToken: present.vpToken,
  });
  return { presentationHeader, payload, ...present };
}

beforeAll(async () => {
  issuerKeys = await generateEs256Keys();
  const holderKeys = await generateEs256Keys();
  issuer = new LocalVcIssuer({ issuerId: ISSUER_ID, privateJwk: issuerKeys.privateJwk });
  wallet = new LocalWallet(holderKeys.privateJwk, holderKeys.publicJwk);
  const compact = await issuer.issue(DEMO_HOLDERS["andrew@example.com"]!, wallet.publicJwk);
  wallet.store({ id: PROOF_CREDENTIAL_ID, compact, claimNames: [...PROOF_ID_CLAIM_KEYS] });
  vcVerifier = localVcVerifier({ issuerId: ISSUER_ID, issuerPublicJwk: issuerKeys.publicJwk });
});

describe("DCQL selective disclosure", () => {
  it("reveals only the requested claims and withholds the rest", async () => {
    const { disclosed, withheld, missing } = await authorize({
      enc: encryptor(),
      requested: ["given_name", "family_name", "age_over_21"],
    });
    expect(disclosed.sort()).toEqual(["age_over_21", "family_name", "given_name"]);
    expect(withheld).toContain("email");
    expect(withheld).toContain("birth_date");
    expect(missing).toEqual([]);
  });

  it("reports requested-but-unheld claims as missing", async () => {
    const { missing } = await authorize({ enc: encryptor(), requested: ["given_name", "passport_photo"] });
    expect(missing).toEqual(["passport_photo"]);
  });
});

describe("verifyAuthorization (x401 challenge + VC + payment binding)", () => {
  it("verifies a valid presentation bound to the payment", async () => {
    const enc = encryptor();
    const td = txData();
    const { presentationHeader } = await authorize({ enc, requested: ["given_name", "family_name", "age_over_21"], transactionData: td });
    const v = await verifyAuthorization({
      presentationHeader,
      encryptor: enc,
      vcVerifier,
      expectedVerifierId: VERIFIER_ID,
      expectedResource: RESOURCE,
      expectedMethod: "GET",
      requiredClaims: ["given_name", "family_name", "age_over_21"],
      transactionData: td,
    });
    expect(v.result.ok).toBe(true);
    expect(v.challengeOk).toBe(true);
    expect(v.txDataBound).toBe(true);
    expect(v.proof?.nonceBound).toBe(true);
    expect(v.proof?.holderBound).toBe(true);
    expect(v.proof?.issuer).toBe(ISSUER_ID);
    expect(v.proof?.subject).toEqual({ given_name: "Andrew", family_name: "Cordivari", age_over_21: true });
  });

  it("rejects when the payment is tampered (transaction_data binding broken)", async () => {
    const enc = encryptor();
    const { presentationHeader } = await authorize({ enc, requested: ["given_name"], transactionData: txData() });
    const tamperedTd = encodeTransactionData(
      buildPaymentMandateTransactionData({ amount: "9900000", currency: "USDC", merchant: "0xc0ffee0000000000000000000000000000000000" }),
    );
    const v = await verifyAuthorization({
      presentationHeader,
      encryptor: enc,
      vcVerifier,
      expectedVerifierId: VERIFIER_ID,
      expectedResource: RESOURCE,
      expectedMethod: "GET",
      requiredClaims: ["given_name"],
      transactionData: tamperedTd,
    });
    expect(v.txDataBound).toBe(false);
    expect(v.result.ok).toBe(false);
  });

  it("rejects when a DCQL-required claim was not disclosed", async () => {
    const enc = encryptor();
    const { presentationHeader } = await authorize({ enc, requested: ["given_name"] });
    const v = await verifyAuthorization({
      presentationHeader,
      encryptor: enc,
      vcVerifier,
      expectedVerifierId: VERIFIER_ID,
      expectedResource: RESOURCE,
      expectedMethod: "GET",
      requiredClaims: ["given_name", "email"],
    });
    expect(v.result.ok).toBe(false);
    expect(v.result.ok === false && v.result.violations.join()).toMatch(/email/);
  });

  it("rejects a challenge replayed against a different resource", async () => {
    const enc = encryptor();
    const { presentationHeader } = await authorize({ enc, requested: ["given_name"] });
    const v = await verifyAuthorization({
      presentationHeader,
      encryptor: enc,
      vcVerifier,
      expectedVerifierId: VERIFIER_ID,
      expectedResource: "https://merchant.sandbox.local/buy/something-else",
      expectedMethod: "GET",
      requiredClaims: ["given_name"],
    });
    expect(v.challengeOk).toBe(false);
    expect(v.result.ok).toBe(false);
  });

  it("rejects a presentation verified under a different challenge encryptor", async () => {
    const { presentationHeader } = await authorize({ enc: encryptor(), requested: ["given_name"] });
    const v = await verifyAuthorization({
      presentationHeader,
      encryptor: createEncryptor({ key: "a-totally-different-secret-key", purpose: "x401-test" }),
      vcVerifier,
      expectedVerifierId: VERIFIER_ID,
      expectedResource: RESOURCE,
      expectedMethod: "GET",
      requiredClaims: ["given_name"],
    });
    expect(v.result.ok).toBe(false);
  });

  it("rejects a credential from an untrusted issuer", async () => {
    const enc = encryptor();
    const { presentationHeader } = await authorize({ enc, requested: ["given_name"] });
    const strangerVerifier = localVcVerifier({
      issuerId: "https://evil.example.com",
      issuerPublicJwk: issuerKeys.publicJwk,
    });
    const v = await verifyAuthorization({
      presentationHeader,
      encryptor: enc,
      vcVerifier: strangerVerifier,
      expectedVerifierId: VERIFIER_ID,
      expectedResource: RESOURCE,
      expectedMethod: "GET",
      requiredClaims: ["given_name"],
    });
    expect(v.result.ok).toBe(false);
  });
});

describe("Proof payment-mandate transaction_data shape", () => {
  it("emits amount as a bare number with a separate currency (not an object)", async () => {
    const { buildProofPaymentMandate } = await import("../src/index.ts");
    const td = buildProofPaymentMandate({
      amount: 1.5, currency: "USD", payeeName: "Mock VeryGood-RX", payeeWebsite: "https://verygood-rx.example",
      promptSummary: "Authorize Mock VeryGood-RX to charge $1.50.",
      instrument: { type: "crypto", id: "usdc:eip155:84532:0xabc" },
    });
    expect(td.type).toBe("urn:proof:params:vc:transaction-data:payment-mandate:v1");
    expect(td.credential_ids).toEqual(["proof_id_default"]);
    const p = td.payload as any;
    expect(typeof p.amount).toBe("number");
    expect(p.amount).toBe(1.5);
    expect(p.currency).toBe("USD");
    expect(p.amount.value).toBeUndefined(); // amount must NOT be an object
    expect(p.payment_instrument).toEqual({ type: "crypto", id: "usdc:eip155:84532:0xabc" });
    expect(p.payee).toEqual({ name: "Mock VeryGood-RX", website: "https://verygood-rx.example" });
    expect(p.prompt_summary).toContain("$1.50");
  });
});

describe("Proof OAuth client-credentials token", () => {
  it("POSTs form-encoded with Basic auth and parses the access token", async () => {
    let seen: { url: string; init: any } | undefined;
    const fakeFetch = (async (url: string, init: any) => {
      seen = { url, init };
      return { ok: true, status: 200, json: async () => ({ access_token: "at-123", token_type: "Bearer", expires_in: 7200, scope: "read write" }) } as Response;
    }) as unknown as typeof fetch;
    const tok = await fetchProofAccessToken({
      tokenEndpoint: "https://api.proof.com/oauth/v2/token",
      clientId: "caornykn4", clientSecret: "s3cr3t", fetchImpl: fakeFetch,
    });
    expect(tok.accessToken).toBe("at-123");
    expect(tok.tokenType).toBe("Bearer");
    expect(seen!.init.method).toBe("POST");
    expect(seen!.init.headers["Content-Type"]).toBe("application/x-www-form-urlencoded");
    expect(seen!.init.headers.Authorization).toBe("Basic " + Buffer.from("caornykn4:s3cr3t").toString("base64"));
    expect(seen!.init.body).toContain("grant_type=client_credentials");
  });

  it("throws on a non-2xx token response", async () => {
    const fakeFetch = (async () =>
      ({ ok: false, status: 401, text: async () => '{"error":"invalid_client"}' }) as Response) as unknown as typeof fetch;
    await expect(
      fetchProofAccessToken({ tokenEndpoint: "https://api.proof.com/oauth/v2/token", clientId: "x", clientSecret: "bad", fetchImpl: fakeFetch }),
    ).rejects.toThrow(/invalid_client/);
  });

  it("caches the token and refreshes only after expiry", async () => {
    let calls = 0;
    const fakeFetch = (async () => {
      calls++;
      return { ok: true, status: 200, json: async () => ({ access_token: `at-${calls}`, token_type: "Bearer", expires_in: 7200 }) } as Response;
    }) as unknown as typeof fetch;
    const provider = createProofTokenProvider({ tokenEndpoint: "https://t", clientId: "x", clientSecret: "y", fetchImpl: fakeFetch });
    const a = await provider.getToken();
    const b = await provider.getToken();
    expect(a).toBe("at-1");
    expect(b).toBe("at-1"); // cached, no second mint
    expect(calls).toBe(1);
    provider.reset();
    const c = await provider.getToken();
    expect(c).toBe("at-2");
  });
});

describe("Proof authorize redirect", () => {
  const base = { clientId: "caornykn4", loginHint: "u@example.com", nonce: "x401:a:b", responseMode: "fragment" as const, redirectUri: "https://app/cb" };

  it("sends the OAuth Bearer token and returns the 302 Location", async () => {
    let seenAuth: string | null = null;
    let seenUrl = "";
    const fakeFetch = (async (url: string, init: any) => {
      seenUrl = url;
      seenAuth = init.headers.Authorization;
      return { status: 302, headers: new Headers({ location: "https://proof.example/hosted/xyz" }) } as Response;
    }) as unknown as typeof fetch;
    const loc = await resolveProofAuthorizeRedirect({ ...base, bearerToken: "at-123", fetchImpl: fakeFetch });
    expect(loc).toBe("https://proof.example/hosted/xyz");
    expect(seenUrl).toContain("client_id=caornykn4");
    expect(seenAuth).toBe("Bearer at-123");
  });

  it("throws (rather than leak) when Proof does not redirect", async () => {
    const fakeFetch = (async () =>
      ({ status: 400, headers: new Headers(), text: async () => '{"errors":{"request":["unauthorized_client"]}}' }) as Response) as unknown as typeof fetch;
    await expect(
      resolveProofAuthorizeRedirect({ ...base, bearerToken: "bad", fetchImpl: fakeFetch }),
    ).rejects.toThrow(/unauthorized_client/);
  });
});
