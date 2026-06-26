/**
 * Mandate revocation. A signed Intent is durable (it carries its own expiry), so
 * a long-lived delegated mandate would otherwise be unstoppable until it expires.
 * The issuer (Authorization Service) is the revocation authority; the merchant
 * enforces it at /buy time. This is the swappable seam for that channel:
 *
 *   - `RevocationRegistry` : the authoritative writer+reader (in-process for the
 *     demo). The issuer calls `revoke(id)`; it records who/when/why.
 *   - `RevocationChecker`  : the narrow READER the merchant gate depends on, so a
 *     real deployment can swap in an HTTP-backed reader (an issuer status
 *     endpoint) without touching the gate. `isRevoked` may be async for that.
 *
 * Revocation is keyed by the Intent `id`, permanent, and idempotent — there is no
 * un-revoke (a killed mandate stays killed; re-authorize to get a fresh one).
 */
import { nowSeconds } from "@agentic-payments/shared";

export interface RevocationRecord {
  /** The revoked Intent mandate `id`. */
  intentId: string;
  /** Unix seconds when it was revoked. */
  revokedAt: number;
  /** Optional human-readable reason, for the audit trail. */
  reason?: string;
}

/** The reader the merchant depends on (in-process or, later, HTTP-backed). */
export interface RevocationChecker {
  isRevoked(intentId: string): boolean | Promise<boolean>;
}

/** Authoritative, in-memory revocation list. Writer lives with the issuer. */
export class RevocationRegistry implements RevocationChecker {
  private readonly revoked = new Map<string, RevocationRecord>();

  constructor(private readonly now: () => number = nowSeconds) {}

  /** Revoke an Intent by id. Idempotent: the first revocation's record stands. */
  revoke(intentId: string, reason?: string): RevocationRecord {
    const existing = this.revoked.get(intentId);
    if (existing) return existing;
    const record: RevocationRecord = {
      intentId,
      revokedAt: this.now(),
      ...(reason !== undefined ? { reason } : {}),
    };
    this.revoked.set(intentId, record);
    return record;
  }

  isRevoked(intentId: string): boolean {
    return this.revoked.has(intentId);
  }

  get(intentId: string): RevocationRecord | undefined {
    return this.revoked.get(intentId);
  }

  list(): RevocationRecord[] {
    return [...this.revoked.values()];
  }
}
