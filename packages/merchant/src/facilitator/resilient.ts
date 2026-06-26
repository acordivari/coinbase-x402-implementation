/**
 * ResilientFacilitatorClient — wraps ANY FacilitatorClient (the live HTTP
 * client or the offline mock) and adds the safety guarantees the sandbox is
 * meant to validate, all at the single settlement boundary:
 *
 *   1. Retry: transient settle failures are retried with exponential backoff.
 *      Terminal failures (invalid payment) are never retried.
 *   2. Idempotency: settlement is keyed on the EIP-3009 authorization nonce.
 *      A nonce that already settled returns the cached result — it is never
 *      settled twice, even if the request is replayed.
 *   3. Transaction lock: concurrent settle calls for the same nonce coalesce
 *      onto one in-flight settlement, so a retry storm can't double-charge.
 *
 * Pure and deterministic: clock + sleep are injectable so tests run instantly.
 */
import type { FacilitatorClient } from "@x402/core/server";
import type {
  PaymentPayload,
  PaymentRequirements,
  SettleResponse,
  SupportedResponse,
  VerifyResponse,
} from "@x402/core/types";
import { isTransient } from "./errors.ts";

export interface SettleHooks {
  onSettleStart?: (nonce: string) => void | Promise<void>;
  onSettleSuccess?: (nonce: string, res: SettleResponse) => void | Promise<void>;
  onSettleFailure?: (nonce: string, err: unknown) => void | Promise<void>;
}

export interface ResilientFacilitatorOptions {
  maxAttempts?: number; // total settle attempts before giving up (default 4)
  baseDelayMs?: number; // backoff base; delay = baseDelayMs * 2^(attempt-1)
  sleep?: (ms: number) => Promise<void>;
  hooks?: SettleHooks;
}

function nonceOf(payload: PaymentPayload): string {
  const nonce = (payload as { payload?: { authorization?: { nonce?: string } } })
    .payload?.authorization?.nonce;
  if (!nonce) throw new Error("payment payload missing authorization nonce");
  return nonce.toLowerCase();
}

export class ResilientFacilitatorClient implements FacilitatorClient {
  private readonly maxAttempts: number;
  private readonly baseDelayMs: number;
  private readonly sleep: (ms: number) => Promise<void>;
  private readonly hooks: SettleHooks;

  /** Completed settlements, keyed by nonce — the idempotency cache. */
  private readonly settled = new Map<string, SettleResponse>();
  /** In-flight settlements, keyed by nonce — the transaction lock. */
  private readonly inFlight = new Map<string, Promise<SettleResponse>>();

  constructor(
    private readonly inner: FacilitatorClient,
    opts: ResilientFacilitatorOptions = {},
  ) {
    this.maxAttempts = opts.maxAttempts ?? 4;
    this.baseDelayMs = opts.baseDelayMs ?? 250;
    this.sleep = opts.sleep ?? ((ms) => new Promise((r) => setTimeout(r, ms)));
    this.hooks = opts.hooks ?? {};
  }

  /** The settlement result for an already-settled nonce, if any. */
  getSettlement(nonce: string): SettleResponse | undefined {
    return this.settled.get(nonce.toLowerCase());
  }

  /** Nonces with a cached settlement (debug/inspection). */
  settledNonces(): string[] {
    return [...this.settled.keys()];
  }

  verify(
    payload: PaymentPayload,
    requirements: PaymentRequirements,
  ): Promise<VerifyResponse> {
    return this.inner.verify(payload, requirements);
  }

  getSupported(): Promise<SupportedResponse> {
    return this.inner.getSupported();
  }

  async settle(
    payload: PaymentPayload,
    requirements: PaymentRequirements,
  ): Promise<SettleResponse> {
    const nonce = nonceOf(payload);

    // (2) Idempotency: this nonce already settled — return the same result.
    const done = this.settled.get(nonce);
    if (done) return done;

    // (3) Transaction lock: a settlement for this nonce is already running.
    const running = this.inFlight.get(nonce);
    if (running) return running;

    const attempt = this.settleWithRetry(nonce, payload, requirements);
    this.inFlight.set(nonce, attempt);
    try {
      const result = await attempt;
      this.settled.set(nonce, result);
      return result;
    } finally {
      this.inFlight.delete(nonce);
    }
  }

  private async settleWithRetry(
    nonce: string,
    payload: PaymentPayload,
    requirements: PaymentRequirements,
  ): Promise<SettleResponse> {
    this.hooks.onSettleStart?.(nonce);
    let lastErr: unknown;
    for (let attempt = 1; attempt <= this.maxAttempts; attempt++) {
      try {
        const res = await this.inner.settle(payload, requirements);
        // A non-throwing-but-unsuccessful response is a terminal failure.
        if (!res.success) {
          await this.hooks.onSettleFailure?.(nonce, res);
          return res;
        }
        await this.hooks.onSettleSuccess?.(nonce, res);
        return res;
      } catch (err) {
        lastErr = err;
        // (1) Only transient errors are retried; terminal errors bail now.
        if (!isTransient(err) || attempt === this.maxAttempts) {
          await this.hooks.onSettleFailure?.(nonce, err);
          throw err;
        }
        await this.sleep(this.baseDelayMs * 2 ** (attempt - 1));
      }
    }
    // Unreachable, but keeps the type checker happy.
    throw lastErr;
  }
}
