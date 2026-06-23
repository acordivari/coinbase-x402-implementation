/**
 * x401 wire integration — thin wrappers over @proof.com/x401-node that bind the
 * SDK's challenge/presentation handshake to our VC verifier and to the payment.
 *
 * x401 owns the encrypted Verifier Challenge (= the OID4VP nonce), the VP
 * Artifact, and the PROOF-REQUIRED/PRESENTATION headers. We add the two things
 * x401 leaves out: (1) sealing the payment's `transaction_data` digest into the
 * challenge so the verifier can later prove the presentation authorized *this*
 * payment, and (2) actually verifying the returned credential.
 */
import { collect, type ValidationResult } from "@agentic-payments/shared";
import { agent, verifier, type Encryptor } from "@proof.com/x401-node";
import type { VPArtifact, X401Payload } from "@proof.com/x401-node";
import { transactionDataDigest } from "./transaction-data.ts";
import type { PresentationProof, VerifiableCredentialVerifier } from "./types.ts";

export { createEncryptor } from "@proof.com/x401-node";
export type { Encryptor, VPArtifact, X401Payload } from "@proof.com/x401-node";

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
export async function createIdentityChallenge(input: CreateIdentityChallengeInput) {
  const tdDigest = input.transactionData
    ? await transactionDataDigest(input.transactionData)
    : undefined;
  return verifier.createChallenge({
    verifierId: input.verifierId,
    resource: input.resource,
    method: input.method,
    encryptor: input.encryptor,
    ttlSeconds: input.ttlSeconds,
    ...(tdDigest !== undefined ? { context: { td: tdDigest } } : {}),
    ...(input.now !== undefined ? { now: input.now } : {}),
  });
}

export interface BuildProofRequiredInput {
  challenge: Awaited<ReturnType<typeof createIdentityChallenge>>;
  tokenEndpoint: string;
  scope: string;
  requestId?: string;
}

/** Build the PROOF-REQUIRED payload + its encoded header value. */
export function buildProofRequired(input: BuildProofRequiredInput): {
  payload: X401Payload;
  header: string;
} {
  const payload = verifier.buildPayload({
    proof: {
      challenge: input.challenge,
      oauth: { token_endpoint: input.tokenEndpoint },
      scope: input.scope,
      ...(input.requestId !== undefined ? { request_id: input.requestId } : {}),
    },
  });
  return { payload, header: verifier.encodePayload(payload) };
}

/** Agent-side: detect a PROOF-REQUIRED challenge from headers/body. */
export function detectRequirement(
  headers?: Record<string, string | string[] | undefined>,
  body?: string,
) {
  return agent.detectProofRequirement({
    ...(headers !== undefined ? { headers } : {}),
    ...(body !== undefined ? { body } : {}),
  });
}

/** Agent-side: package a wallet vp_token into a PROOF-PRESENTATION header. */
export function packPresentation(input: {
  payload: X401Payload;
  agentId: string;
  vpToken: string;
}): { artifact: VPArtifact; header: string } {
  const artifact = agent.buildVPArtifact({
    payload: input.payload,
    agentId: input.agentId,
    vpToken: input.vpToken,
  });
  return { artifact, header: agent.encodeVPArtifact(artifact) };
}

export interface VerifyAuthorizationInput {
  /** PROOF-PRESENTATION header value, or a decoded VP Artifact. */
  presentationHeader?: string;
  artifact?: VPArtifact;
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
  /** The presentation cryptographically authorized the intended payment. */
  txDataBound: boolean;
  /** The verified credential proof (claims, holder/nonce binding). */
  proof?: PresentationProof;
  agentId?: string;
}

/**
 * Verify an x401 presentation end to end: the challenge (resource/method/expiry),
 * the credential (issuer signature, holder key-binding, nonce, required claims),
 * and — when a payment was attached — that the presentation is bound to that
 * exact payment via the transaction_data digest sealed into the challenge.
 */
export async function verifyAuthorization(
  input: VerifyAuthorizationInput,
): Promise<VerifiedAuthorization> {
  const violations: string[] = [];
  const artifact = input.artifact ?? verifier.decodeVPArtifact(input.presentationHeader ?? "");

  const challenge = await verifier.verifyChallenge({
    value: artifact.challenge,
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
        ? ((challenge.claims.context as { td: string }).td)
        : undefined;
    const digest = await transactionDataDigest(input.transactionData);
    txDataBound = sealed === digest;
    if (!txDataBound) violations.push("presentation is not bound to the intended payment (transaction_data)");
  }

  const proof = await input.vcVerifier.verifyPresentation({
    vpToken: String(artifact.vp_token),
    nonce: artifact.challenge,
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
