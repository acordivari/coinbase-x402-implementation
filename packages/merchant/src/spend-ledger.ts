/**
 * Spend-cap ledger — tracks committed + reserved spend per Intent so cumulative
 * spend can't exceed the Intent cap. This is the swappable seam:
 *
 *   - `InMemorySpendLedger` : per-process, non-durable (the default; offline/tests).
 *   - `FileSpendLedger`     : DURABLE — committed spend survives a restart (JSON file).
 *   - `httpSpendLedger`     : GLOBAL — many merchants reserve/commit against ONE
 *                             central ledger service, so the cap is enforced across
 *                             merchants/processes (the production shape).
 *   - `createSpendLedgerRouter` : exposes a ledger over HTTP for that service.
 *
 * The interface methods are `T | Promise<T>` so the in-memory path stays synchronous
 * (the gate just `await`s the result) while the HTTP path is async. Failure policy
 * mirrors revocation: `reserve`/`total` fail **closed** (deny when status can't be
 * confirmed); `commit`/`release` are best-effort and **fail-safe** (a lost one leaves
 * spend reserved → over-counts → denies more, never over-spends).
 */
import express, { Router, type Request as ExRequest, type Response as ExResponse } from "express";
import { readFileSync, writeFileSync } from "node:fs";
import { collect, type ValidationResult } from "@agentic-payments/shared";

export interface SpendLedger {
  /** Atomically check headroom and reserve `amount` against the cap. */
  reserve(intentId: string, nonce: string, amount: bigint, cap: bigint): ValidationResult | Promise<ValidationResult>;
  /** Move a reservation to committed (on settle success). */
  commit(nonce: string): void | Promise<void>;
  /** Drop a reservation (on settle failure / non-authorized request). */
  release(nonce: string): void | Promise<void>;
  /** Committed + currently-reserved spend for an intent. */
  total(intentId: string): bigint | Promise<bigint>;
}

/** In-process ledger. Reserve → exactly one commit or release. Non-durable. */
export class InMemorySpendLedger implements SpendLedger {
  protected readonly committed = new Map<string, bigint>();
  protected readonly reservations = new Map<string, { intentId: string; amount: bigint }>();

  reserve(intentId: string, nonce: string, amount: bigint, cap: bigint): ValidationResult {
    const projected = this.total(intentId) + amount;
    if (projected > cap) {
      return collect([`cumulative spend ${projected} would exceed intent cap ${cap}`]);
    }
    this.reservations.set(nonce.toLowerCase(), { intentId, amount });
    return { ok: true };
  }

  commit(nonce: string): void {
    const key = nonce.toLowerCase();
    const r = this.reservations.get(key);
    if (!r) return;
    this.committed.set(r.intentId, (this.committed.get(r.intentId) ?? 0n) + r.amount);
    this.reservations.delete(key);
  }

  release(nonce: string): void {
    this.reservations.delete(nonce.toLowerCase());
  }

  total(intentId: string): bigint {
    let sum = this.committed.get(intentId) ?? 0n;
    for (const r of this.reservations.values()) {
      if (r.intentId === intentId) sum += r.amount;
    }
    return sum;
  }
}

/** Back-compat alias — the old name for the in-memory ledger. */
export { InMemorySpendLedger as IntentSpendLedger };

/**
 * Durable ledger: committed spend is persisted to a JSON file (and reloaded on
 * construct), so the cap survives a restart. Reservations stay in-memory — an
 * unsettled reserve simply frees when the process restarts; only committed spend
 * must be durable. bigint is stored as a decimal string (JSON has no bigint).
 */
export class FileSpendLedger extends InMemorySpendLedger {
  constructor(private readonly filePath: string) {
    super();
    try {
      const raw = JSON.parse(readFileSync(filePath, "utf8")) as Record<string, string>;
      for (const [intentId, amount] of Object.entries(raw)) this.committed.set(intentId, BigInt(amount));
    } catch {
      /* no file yet — start empty */
    }
  }

  override commit(nonce: string): void {
    super.commit(nonce);
    this.persist();
  }

  private persist(): void {
    const obj: Record<string, string> = {};
    for (const [intentId, amount] of this.committed) obj[intentId] = amount.toString();
    writeFileSync(this.filePath, JSON.stringify(obj));
  }
}

export interface HttpSpendLedgerOptions {
  /** Central ledger service base URL. */
  baseUrl: string;
  /** Per-call timeout in ms (default 2000). */
  timeoutMs?: number;
  /** Injectable fetch (tests). */
  fetchImpl?: typeof fetch;
}

/**
 * Global ledger client: reserve/commit/release/total against a central service,
 * so the cumulative cap is shared across merchants. FAIL-CLOSED on the decision
 * paths (`reserve`/`total`); FAIL-SAFE on bookkeeping (`commit`/`release`).
 */
export function httpSpendLedger(opts: HttpSpendLedgerOptions): SpendLedger {
  const doFetch = opts.fetchImpl ?? fetch;
  const timeoutMs = opts.timeoutMs ?? 2000;
  const base = opts.baseUrl.replace(/\/$/, "");
  const call = async (path: string, init?: RequestInit): Promise<Response> => {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    try {
      return await doFetch(`${base}${path}`, { ...init, signal: controller.signal });
    } finally {
      clearTimeout(timer);
    }
  };
  const postJson = (path: string, body: unknown) =>
    call(path, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body) });

  return {
    async reserve(intentId, nonce, amount, cap): Promise<ValidationResult> {
      try {
        const res = await postJson("/ledger/reserve", {
          intentId, nonce, amount: amount.toString(), cap: cap.toString(),
        });
        if (!res.ok) return collect(["spend ledger unavailable"]); // fail closed
        const body = (await res.json().catch(() => undefined)) as { ok?: boolean; violations?: string[] } | undefined;
        if (body?.ok === true) return { ok: true };
        return collect(body?.violations ?? ["spend ledger denied the reservation"]);
      } catch {
        return collect(["spend ledger unavailable"]); // unreachable / timeout -> deny
      }
    },
    async commit(nonce): Promise<void> {
      try { await postJson("/ledger/commit", { nonce }); } catch { /* fail-safe: leaves spend reserved */ }
    },
    async release(nonce): Promise<void> {
      try { await postJson("/ledger/release", { nonce }); } catch { /* fail-safe */ }
    },
    async total(intentId): Promise<bigint> {
      // Throws on any error -> the gate's try/catch denies (fail-closed).
      const res = await call(`/ledger/total/${encodeURIComponent(intentId)}`);
      if (!res.ok) throw new Error(`spend ledger total failed (${res.status})`);
      const body = (await res.json()) as { total: string };
      return BigInt(body.total);
    },
  };
}

/** Expose a `SpendLedger` over HTTP (the central ledger service). */
export function createSpendLedgerRouter(ledger: SpendLedger): Router {
  const router = Router();
  router.use(express.json());
  const bad = (res: ExResponse, msg: string) => res.status(400).json({ error: msg });

  router.post("/ledger/reserve", async (req: ExRequest, res: ExResponse) => {
    const { intentId, nonce, amount, cap } = req.body ?? {};
    let result: ValidationResult;
    try {
      result = await ledger.reserve(String(intentId), String(nonce), BigInt(amount), BigInt(cap));
    } catch {
      return bad(res, "invalid reserve request");
    }
    res.json(result.ok ? { ok: true } : { ok: false, violations: result.violations });
  });

  router.post("/ledger/commit", async (req: ExRequest, res: ExResponse) => {
    await ledger.commit(String(req.body?.nonce));
    res.json({ ok: true });
  });

  router.post("/ledger/release", async (req: ExRequest, res: ExResponse) => {
    await ledger.release(String(req.body?.nonce));
    res.json({ ok: true });
  });

  router.get("/ledger/total/:id", async (req: ExRequest, res: ExResponse) => {
    const total = await ledger.total(req.params.id ?? "");
    res.json({ total: total.toString() });
  });

  return router;
}
