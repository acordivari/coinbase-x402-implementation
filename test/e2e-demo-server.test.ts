/**
 * HTTP-level end-to-end for the wallet-demo orchestrator (`createDemoApp`). Unlike
 * e2e-delegated (which exercises the credentials/identity/merchant libraries
 * directly), this drives the ACTUAL server endpoints over real HTTP — the flow
 * selector, the grant branch of /api/authorize/start, /api/authorize/complete,
 * and the autonomous /api/agent/run — so the demo's own orchestration code is
 * covered, not just the logic it wraps.
 *
 * Fully offline: PROOF_MODE=local, FACILITATOR_MODE=mock (the merchant is always
 * mock), no Proof creds. The browser's selective-disclosure step is reproduced
 * in-process with LocalWallet against the challenge the server returns.
 */
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import type { AddressInfo } from "node:net";
import type { Server } from "node:http";
import {
  generateEs256Keys,
  LocalWallet,
  buildProofIdDcqlQuery,
  PROOF_CREDENTIAL_ID,
  PROOF_ID_CLAIM_KEYS,
} from "@agentic-payments/credentials";

// Configure the module BEFORE importing it: its top-level consts read process.env
// at import time, and loadEnv() never overrides an already-set var. Force a fully
// offline, delegated-by-default, no-Proof-creds setup with an ephemeral merchant.
process.env.PROOF_MODE = "local";
process.env.WALLET_FLOW = "delegated";
process.env.MERCHANT_PORT = "0";
process.env.MANDATE_BUDGET = "4.00";
process.env.MANDATE_TTL = "86400";
process.env.PROOF_CLIENT_ID = ""; // proofLiveReady = false
process.env.PROOF_CLIENT_SECRET = "";

const PERSONA = {
  given_name: "Andrew", family_name: "Cordivari", birth_date: "1990-04-12",
  email: "andrew@example.com", age_over_21: true,
};

let base: string;
let demoServer: Server;
let closeDemo: () => Promise<void>;

beforeAll(async () => {
  const { createDemoApp } = await import("../apps/wallet-demo/server/index.ts");
  const demo = await createDemoApp();
  closeDemo = demo.close;
  demoServer = await new Promise<Server>((resolve) => {
    const s = demo.app.listen(0, () => resolve(s));
  });
  base = `http://127.0.0.1:${(demoServer.address() as AddressInfo).port}`;
});

afterAll(async () => {
  await new Promise<void>((r) => demoServer.close(() => r()));
  await closeDemo();
});

async function api(path: string, body?: unknown): Promise<{ status: number; body: any }> {
  const res = await fetch(`${base}${path}`, {
    method: body !== undefined ? "POST" : "GET",
    ...(body !== undefined
      ? { headers: { "content-type": "application/json" }, body: JSON.stringify(body) }
      : {}),
  });
  return { status: res.status, body: (await res.json().catch(() => ({}))) as any };
}

/** Reproduce the browser's selective disclosure: issue a credential to a fresh
 * holder key via the server, then present it bound to the returned challenge. */
async function presentFor(authStart: any): Promise<string> {
  const holder = await generateEs256Keys();
  const issued = await api("/api/wallet/issue", { holderPublicJwk: holder.publicJwk, claims: PERSONA });
  expect(issued.status).toBe(200);
  const wallet = new LocalWallet(holder.privateJwk, holder.publicJwk);
  wallet.store({ id: PROOF_CREDENTIAL_ID, compact: issued.body.credential.compact, claimNames: [...PROOF_ID_CLAIM_KEYS] });
  const present = await wallet.present({
    query: buildProofIdDcqlQuery(authStart.requestedClaims),
    nonce: authStart.nonce,
    audience: authStart.audience,
  });
  return present.vpToken;
}

describe("wallet-demo orchestrator over HTTP", () => {
  it("starts on the WALLET_FLOW default and advertises the three flows", async () => {
    const me = await api("/api/me");
    expect(me.body.flow).toBe("delegated");
    expect(me.body.flows).toEqual(["self-issued", "proof-hosted", "delegated"]);
    expect(me.body.identity).toBe("local"); // offline: no Proof creds
    expect(me.body.proofLiveReady).toBe(false);
  });

  it("blocks switching to proof-hosted when Proof creds are absent", async () => {
    const r = await api("/api/flow", { flow: "proof-hosted" });
    expect(r.status).toBe(400);
    expect(r.body.error).toMatch(/PROOF_CLIENT_ID/);
    // unchanged — still on a usable flow
    expect((await api("/api/me")).body.flow).toBe("delegated");
  });

  it("rejects an unknown flow", async () => {
    const r = await api("/api/flow", { flow: "nonsense" });
    expect(r.status).toBe(400);
  });

  it("self-issued: start → present → complete → buy settles over x402", async () => {
    expect((await api("/api/flow", { flow: "self-issued" })).body.flow).toBe("self-issued");
    const start = await api("/api/authorize/start", {
      sku: "allergy-relief-24", requestedClaims: ["given_name", "age_over_21"], ttlSeconds: 600,
    });
    expect(start.status).toBe(200);
    expect(start.body.grant).toBe(false);

    const vpToken = await presentFor(start.body);
    const complete = await api("/api/authorize/complete", { vpToken });
    expect(complete.status).toBe(200);
    expect(complete.body.verification.ok).toBe(true);
    expect(complete.body.intent.scope.maxAmount).toBe("1500000");

    const buy = await api("/api/buy", { sku: "allergy-relief-24" });
    expect(buy.body.ok).toBe(true);
    expect(buy.body.settled?.state).toBe("SETTLED");
  });

  it("delegated: one grant → many autonomous buys, with the cap denying the over-budget one", async () => {
    expect((await api("/api/flow", { flow: "delegated" })).body.flow).toBe("delegated");
    const start = await api("/api/authorize/start", {
      budgetUsd: "4.00", requestedClaims: ["given_name", "age_over_21"],
    });
    expect(start.status).toBe(200);
    expect(start.body.grant).toBe(true);
    expect(start.body.scope.maxAmount).toBe("4000000");

    const vpToken = await presentFor(start.body);
    const complete = await api("/api/authorize/complete", { vpToken });
    expect(complete.status).toBe(200);
    const intent = complete.body.intent;
    expect(intent.principal.verifiedVia).toBe("x401-vp");
    expect(intent.scope.allowedCategories.length).toBeGreaterThan(1); // broad mandate
    expect(intent.expiresAt - intent.issuedAt).toBe(86_400); // durable

    // One signed mandate; the agent buys repeatedly with no further approval.
    const run = await api("/api/agent/run", {
      skus: ["allergy-relief-24", "vitamin-d3-2000", "ibuprofen-200", "toothpaste-mint"],
    });
    expect(run.status).toBe(200);
    const settled = run.body.purchases.filter((p: any) => p.settled).map((p: any) => p.sku);
    const denied = run.body.purchases.filter((p: any) => !p.ok).map((p: any) => p.sku);
    // $1.50 + $2.25 = $3.75 settle; $0.75 would push to $4.50 > $4 cap → denied.
    expect(settled).toEqual(["allergy-relief-24", "vitamin-d3-2000"]);
    expect(denied).toContain("ibuprofen-200");
    expect(run.body.spentAtomic).toBe("3750000");
    expect(run.body.remainingAtomic).toBe("250000");
  });

  it("agent/run requires a standing mandate (401 after reset)", async () => {
    await api("/api/reset", {});
    const r = await api("/api/agent/run", {});
    expect(r.status).toBe(401);
  });
});
