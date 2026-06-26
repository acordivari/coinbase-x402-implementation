import { describe, expect, it } from "vitest";
import { httpRevocationChecker, RevocationRegistry } from "../src/revocation.ts";

describe("RevocationRegistry", () => {
  it("reports not-revoked until an id is revoked", () => {
    const r = new RevocationRegistry();
    expect(r.isRevoked("m1")).toBe(false);
    r.revoke("m1");
    expect(r.isRevoked("m1")).toBe(true);
  });

  it("records reason + revokedAt, and is idempotent (first record stands)", () => {
    let t = 1000;
    const r = new RevocationRegistry(() => t);
    const rec = r.revoke("m1", "leaked key");
    expect(rec).toEqual({ intentId: "m1", revokedAt: 1000, reason: "leaked key" });
    t = 2000;
    const again = r.revoke("m1", "different reason");
    expect(again).toEqual(rec); // unchanged — permanent + idempotent
    expect(r.get("m1")?.reason).toBe("leaked key");
  });

  it("only affects the revoked id", () => {
    const r = new RevocationRegistry();
    r.revoke("a");
    expect(r.isRevoked("a")).toBe(true);
    expect(r.isRevoked("b")).toBe(false);
  });

  it("lists revoked records", () => {
    const r = new RevocationRegistry();
    r.revoke("a", "x");
    r.revoke("b");
    expect(r.list().map((x) => x.intentId).sort()).toEqual(["a", "b"]);
  });
});

describe("httpRevocationChecker (fail-closed)", () => {
  const withFetch = (impl: () => Promise<unknown>) =>
    httpRevocationChecker({ baseUrl: "http://issuer.local", fetchImpl: (async () => impl()) as unknown as typeof fetch });

  it("permits ONLY on an explicit 200 {revoked:false}", async () => {
    const c = withFetch(async () => ({ ok: true, json: async () => ({ revoked: false }) }));
    expect(await c.isRevoked("m")).toBe(false);
  });

  it("denies on revoked:true", async () => {
    const c = withFetch(async () => ({ ok: true, json: async () => ({ revoked: true }) }));
    expect(await c.isRevoked("m")).toBe(true);
  });

  it("denies on a non-200 (status unconfirmed)", async () => {
    const c = withFetch(async () => ({ ok: false, json: async () => ({}) }));
    expect(await c.isRevoked("m")).toBe(true);
  });

  it("denies on a 200 with a missing/ambiguous field", async () => {
    const c = withFetch(async () => ({ ok: true, json: async () => ({}) }));
    expect(await c.isRevoked("m")).toBe(true);
  });

  it("denies on a malformed body", async () => {
    const c = withFetch(async () => ({ ok: true, json: async () => { throw new Error("bad json"); } }));
    expect(await c.isRevoked("m")).toBe(true);
  });

  it("denies on a network error / unreachable issuer", async () => {
    const c = withFetch(async () => { throw new Error("ECONNREFUSED"); });
    expect(await c.isRevoked("m")).toBe(true);
  });
});
