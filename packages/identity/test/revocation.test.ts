import { describe, expect, it } from "vitest";
import { RevocationRegistry } from "../src/revocation.ts";

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
