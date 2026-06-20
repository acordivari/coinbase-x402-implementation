import { describe, expect, it } from "vitest";
import { IntentSpendLedger } from "../src/mandate-gate.ts";

describe("IntentSpendLedger", () => {
  it("reserves within the cap and rejects over it", () => {
    const led = new IntentSpendLedger();
    expect(led.reserve("intent-1", "0xa", 1_500_000n, 3_000_000n).ok).toBe(true);
    // committed not updated until commit(); a second reservation sees the first.
    const second = led.reserve("intent-1", "0xb", 2_000_000n, 3_000_000n);
    expect(second.ok).toBe(false);
  });

  it("commit moves a reservation into committed spend", () => {
    const led = new IntentSpendLedger();
    led.reserve("intent-1", "0xa", 1_500_000n, 3_000_000n);
    led.commit("0xa");
    expect(led.total("intent-1")).toBe(1_500_000n);
    // a new reservation now stacks on committed
    expect(led.reserve("intent-1", "0xb", 1_500_000n, 3_000_000n).ok).toBe(true);
    expect(led.reserve("intent-1", "0xc", 1n, 3_000_000n).ok).toBe(false);
  });

  it("release frees a reservation (e.g. on settle failure)", () => {
    const led = new IntentSpendLedger();
    led.reserve("intent-1", "0xa", 3_000_000n, 3_000_000n);
    expect(led.total("intent-1")).toBe(3_000_000n);
    led.release("0xa");
    expect(led.total("intent-1")).toBe(0n);
  });

  it("tracks intents independently", () => {
    const led = new IntentSpendLedger();
    led.reserve("intent-1", "0xa", 1_000_000n, 5_000_000n);
    led.reserve("intent-2", "0xb", 4_000_000n, 5_000_000n);
    expect(led.total("intent-1")).toBe(1_000_000n);
    expect(led.total("intent-2")).toBe(4_000_000n);
  });

  it("is case-insensitive on the nonce key", () => {
    const led = new IntentSpendLedger();
    led.reserve("intent-1", "0xABC", 1_000_000n, 5_000_000n);
    led.commit("0xabc");
    expect(led.total("intent-1")).toBe(1_000_000n);
  });
});
