import { afterEach, describe, expect, it } from "vitest";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  FileSpendLedger,
  httpSpendLedger,
  InMemorySpendLedger,
} from "../src/spend-ledger.ts";

const CAP = 1000n;

describe("InMemorySpendLedger", () => {
  it("reserves within cap, denies over cap (committed + reserved)", () => {
    const l = new InMemorySpendLedger();
    expect(l.reserve("i1", "n1", 600n, CAP).ok).toBe(true);
    expect(l.total("i1")).toBe(600n);
    // 600 reserved + 500 would exceed 1000.
    const over = l.reserve("i1", "n2", 500n, CAP);
    expect(over.ok).toBe(false);
    expect(JSON.stringify(over)).toMatch(/exceed intent cap/);
  });

  it("commit keeps spend; release frees it", () => {
    const l = new InMemorySpendLedger();
    l.reserve("i1", "n1", 600n, CAP);
    l.commit("n1");
    expect(l.total("i1")).toBe(600n); // committed persists in total
    l.reserve("i1", "n2", 300n, CAP);
    l.release("n2");
    expect(l.total("i1")).toBe(600n); // released reservation dropped
  });
});

describe("FileSpendLedger (durable)", () => {
  let dir: string;
  let file: string;
  afterEach(() => { if (dir) rmSync(dir, { recursive: true, force: true }); });

  it("persists committed spend and reloads it after a 'restart'", () => {
    dir = mkdtempSync(join(tmpdir(), "ledger-"));
    file = join(dir, "ledger.json");

    const l1 = new FileSpendLedger(file);
    l1.reserve("i1", "n1", 700n, CAP);
    l1.commit("n1"); // -> written to disk

    // A fresh instance from the same file = a process restart.
    const l2 = new FileSpendLedger(file);
    expect(l2.total("i1")).toBe(700n); // committed survived
    // The cap is still enforced across the restart.
    expect(l2.reserve("i1", "n2", 400n, CAP).ok).toBe(false);
    expect(l2.reserve("i1", "n3", 300n, CAP).ok).toBe(true);
  });
});

describe("httpSpendLedger (fail-closed reserve/total, fail-safe commit/release)", () => {
  const withFetch = (impl: (path: string) => Promise<unknown>) =>
    httpSpendLedger({ baseUrl: "http://ledger.local", fetchImpl: (async (url: string) => impl(url)) as unknown as typeof fetch });

  it("reserve: permits on {ok:true}", async () => {
    const l = withFetch(async () => ({ ok: true, json: async () => ({ ok: true }) }));
    expect((await l.reserve("i", "n", 1n, CAP)).ok).toBe(true);
  });

  it("reserve: denies (fail-closed) on a non-200", async () => {
    const l = withFetch(async () => ({ ok: false, json: async () => ({}) }));
    const r = await l.reserve("i", "n", 1n, CAP);
    expect(r.ok).toBe(false);
    expect(JSON.stringify(r)).toMatch(/unavailable/);
  });

  it("reserve: denies (fail-closed) on a network error", async () => {
    const l = withFetch(async () => { throw new Error("ECONNREFUSED"); });
    expect((await l.reserve("i", "n", 1n, CAP)).ok).toBe(false);
  });

  it("reserve: surfaces a service denial (over-cap) as not-ok", async () => {
    const l = withFetch(async () => ({ ok: true, json: async () => ({ ok: false, violations: ["cumulative spend would exceed intent cap"] }) }));
    const r = await l.reserve("i", "n", 1n, CAP);
    expect(r.ok).toBe(false);
    expect(JSON.stringify(r)).toMatch(/exceed intent cap/);
  });

  it("total: returns the value on success", async () => {
    const l = withFetch(async () => ({ ok: true, json: async () => ({ total: "42" }) }));
    expect(await l.total("i")).toBe(42n);
  });

  it("total: throws (fail-closed) on error so the gate denies", async () => {
    const l = withFetch(async () => ({ ok: false, json: async () => ({}) }));
    await expect(l.total("i")).rejects.toThrow();
  });

  it("commit/release: best-effort, never throw on a network error (fail-safe)", async () => {
    const l = withFetch(async () => { throw new Error("down"); });
    await expect(l.commit("n")).resolves.toBeUndefined();
    await expect(l.release("n")).resolves.toBeUndefined();
  });
});
