/**
 * x401 wire integration — thin wrappers over @proof.com/x401-node that bind the
 * SDK's PROOF-REQUEST / PROOF-RESPONSE handshake to our VC verifier and to the
 * payment.
 *
 * x401 (v0.3 wire names) owns the Verifier-composed Digital Credentials request
 * (`credential_requirements.digital`), the Result Artifact, and the PROOF-REQUEST
 * / PROOF-RESPONSE / PROOF-RESULT headers. The SDK no longer ships a Verifier
 * Challenge or encryptor (removed in 0.2.0), so we vendor that primitive locally
 * (`./x401-binding.ts`) to add the two things x401 leaves out: (1) sealing the
 * payment's `transaction_data` digest into an encrypted, authenticated challenge
 * that doubles as the OID4VP nonce, and (2) actually verifying the returned
 * credential.
 *
 * A Result Artifact is opaque to x401, so we carry the credential result as
 * `{ vp_token, challenge }` in `credential_result.data`: the wallet's vp_token
 * plus the (self-authenticating) challenge value the verifier re-verifies on the
 * protected-route retry.
 */
import { collect, type ValidationResult } from "@agentic-payments/shared";
import { DC_API_PROTOCOL, agent, verifier } from "@proof.com/x401-node";
import type { CredentialResult, JsonValue, ResultArtifact, X401Payload } from "@proof.com/x401-node";
import {
  createChallenge,
  verifyChallenge,
  type Encryptor,
  type VerifierChallenge,
} from "./x401-binding.ts";
import { transactionDataDigest } from "./transaction-data.ts";
import type { PresentationProof, VerifiableCredentialVerifier } from "./types.ts";

export { createEncryptor } from "./x401-binding.ts";
export type { Encryptor, VerifierChallenge } from "./x401-binding.ts";
export type { ResultArtifact, X401Payload } from "@proof.com/x401-node";

/** The (opaque-to-x401) request parameters we seal into `digital.requests[0].data`. */
interface X401RequestData {
  /** The Verifier Challenge value — the OID4VP nonce the wallet binds into the KB-JWT. */
  nonce: string;
  /** RFC 3339 expiry of the challenge, mirrored for the agent. */
  expires_at: string;
  /** OAuth scope the proof satisfies. */
  scope: string;
  [key: string]: JsonValue;
}

/** The (opaque-to-x401) credential result we carry in `credential_result.data`. */
interface X401CredentialResultData {
  /** The wallet's vp_token (compact SD-JWT-VC + KB-JWT). */
  vp_token: string;
  /** The self-authenticating Verifier Challenge the verifier re-verifies. */
  challenge: string;
  [key: string]: JsonValue;
}

/** The DC API protocol our request/result entries use. */
const X401_REQUEST_PROTOCOL = DC_API_PROTOCOL.SIGNED;

export interface CreateIdentityChallengeInput {
  encryptor: Encryptor;
  verifierId: string;
  resource: string;
  method: string;
  ttlSeconds: number;
  /** Encoded transaction_data to bind into the challenge (payment authorization). */
  transactionData?: string;
  now?: Date;
}

/**
 * Create an x401 Verifier Challenge, sealing the payment transaction_data digest
 * into its (encrypted, authenticated) context. The challenge value becomes the
 * OID4VP nonce the wallet/Proof binds into the key-binding JWT.
 */
export async function createIdentityChallenge(
  input: CreateIdentityChallengeInput,
): Promise<VerifierChallenge> {
  const tdDigest = input.transactionData
    ? await transactionDataDigest(input.transactionData)
    : undefined;
  return createChallenge({
    verifierId: input.verifierId,
    resource: input.resource,
    method: input.method,
    encryptor: input.encryptor,
    ttlSeconds: input.ttlSeconds,
    ...(tdDigest !== undefined ? { context: { td: tdDigest } } : {}),
    ...(input.now !== undefined ? { now: input.now } : {}),
  });
}

export interface BuildProofRequestInput {
  challenge: VerifierChallenge;
  tokenEndpoint: string;
  scope: string;
  requestId?: string;
}

/** Build the PROOF-REQUEST payload + its encoded header value. */
export function buildProofRequest(input: BuildProofRequestInput): {
  payload: X401Payload;
  header: string;
} {
  const data: X401RequestData = {
    nonce: input.challenge.value,
    expires_at: input.challenge.expires_at,
    scope: input.scope,
  };
  const payload = verifier.buildPayload({
    credentialRequirements: {
      digital: { requests: [{ protocol: X401_REQUEST_PROTOCOL, data }] },
    },
    oauth: { token_endpoint: input.tokenEndpoint },
    ...(input.requestId !== undefined ? { requestId: input.requestId } : {}),
  });
  return { payload, header: verifier.encodePayload(payload) };
}

/** Agent-side: detect a PROOF-REQUEST from headers/body. */
export function detectRequirement(
  headers?: Record<string, string | string[] | undefined>,
  body?: string,
) {
  return agent.detectProofRequirement({
    ...(headers !== undefined ? { headers } : {}),
    ...(body !== undefined ? { body } : {}),
  });
}

/** Read the Verifier Challenge (= the OID4VP nonce) the verifier sealed into the request. */
export function getRequestChallenge(payload: X401Payload): VerifierChallenge {
  const data = agent.getDigitalCredentialRequest(payload).requests[0]?.data as
    | Partial<X401RequestData>
    | undefined;
  if (!data || typeof data.nonce !== "string") {
    throw new Error("x401 PROOF-REQUEST carries no challenge nonce");
  }
  return {
    value: data.nonce,
    expires_at: typeof data.expires_at === "string" ? data.expires_at : "",
  };
}

/** Agent-side: package a wallet vp_token into a Result Artifact + PROOF-RESPONSE header. */
export function packCredentialResult(input: {
  payload: X401Payload;
  agentId: string;
  vpToken: string;
}): { artifact: ResultArtifact; header: string } {
  const challenge = getRequestChallenge(input.payload);
  const credentialResult: CredentialResult = {
    protocol: X401_REQUEST_PROTOCOL,
    data: { vp_token: input.vpToken, challenge: challenge.value } satisfies X401CredentialResultData,
  };
  const artifact = agent.buildResultArtifact({
    credentialResult,
    agentId: input.agentId,
    ...(input.payload.request_id !== undefined ? { requestId: input.payload.request_id } : {}),
  });
  return { artifact, header: agent.encodeResultArtifact(artifact) };
}

export interface VerifyAuthorizationInput {
  /** PROOF-RESPONSE header value, or a decoded Result Artifact. */
  resultHeader?: string;
  artifact?: ResultArtifact;
  encryptor: Encryptor;
  vcVerifier: VerifiableCredentialVerifier;
  expectedVerifierId: string;
  expectedResource: string;
  expectedMethod: string;
  /** DCQL-required claim names that must be disclosed. */
  requiredClaims?: string[];
  /** The encoded transaction_data the verifier intended to bind (payment). */
  transactionData?: string;
  now?: Date;
}

export interface VerifiedAuthorization {
  result: ValidationResult;
  /** The x401 challenge (resource/method/expiry/verifier) verified. */
  challengeOk: boolean;
  /** The credential result cryptographically authorized the intended payment. */
  txDataBound: boolean;
  /** The verified credential proof (claims, holder/nonce binding). */
  proof?: PresentationProof;
  agentId?: string;
}

/** Read the `{ vp_token, challenge }` we carried in the Result Artifact. */
function readCredentialResult(artifact: ResultArtifact): Partial<X401CredentialResultData> {
  const data = artifact.credential_result?.data;
  return data && typeof data === "object" && !Array.isArray(data)
    ? (data as Partial<X401CredentialResultData>)
    : {};
}

/**
 * Verify an x401 Result Artifact end to end: the challenge (resource/method/
 * expiry/verifier), the credential (issuer signature, holder key-binding, nonce,
 * required claims), and — when a payment was attached — that the presentation is
 * bound to that exact payment via the transaction_data digest sealed into the
 * challenge.
 */
export async function verifyAuthorization(
  input: VerifyAuthorizationInput,
): Promise<VerifiedAuthorization> {
  const violations: string[] = [];
  const artifact = input.artifact ?? verifier.decodeResultArtifact(input.resultHeader ?? "");
  const result = readCredentialResult(artifact);
  const challengeValue = typeof result.challenge === "string" ? result.challenge : "";
  const vpToken = typeof result.vp_token === "string" ? result.vp_token : "";

  const challenge = await verifyChallenge({
    value: challengeValue,
    encryptor: input.encryptor,
    expectedVerifierId: input.expectedVerifierId,
    expectedResource: input.expectedResource,
    expectedMethod: input.expectedMethod,
    ...(input.now !== undefined ? { now: input.now } : {}),
  });
  const challengeOk = challenge.ok;
  if (!challenge.ok) violations.push(`challenge invalid: ${challenge.reason}`);

  // transaction_data binding: recompute the digest and compare to the value
  // sealed (and authenticated) inside the challenge.
  let txDataBound = true;
  if (input.transactionData !== undefined) {
    const sealed =
      challenge.ok && typeof (challenge.claims.context as { td?: unknown })?.td === "string"
        ? (challenge.claims.context as { td: string }).td
        : undefined;
    const digest = await transactionDataDigest(input.transactionData);
    txDataBound = sealed === digest;
    if (!txDataBound)
      violations.push("credential result is not bound to the intended payment (transaction_data)");
  }

  const proof = await input.vcVerifier.verifyPresentation({
    vpToken,
    nonce: challengeValue,
    ...(input.requiredClaims ? { requiredClaims: input.requiredClaims } : {}),
  });
  if (!proof.result.ok) violations.push(...proof.result.violations);

  return {
    result: collect(violations),
    challengeOk,
    txDataBound,
    proof,
    ...(artifact.agent_id !== undefined ? { agentId: artifact.agent_id } : {}),
  };
}
