import { describe, expect, it } from "vitest";
import { computeTokenHash, computeWormHash } from "@modules/control-plane";

describe("Control Plane Hashing", () => {
  it("computes deterministic SHA-256 token hashes", async () => {
    const digest = await computeTokenHash("worker-secret");
    expect(digest).toBe("6fb46f7a92742970166379ed5195e79c4493a7cc5664280c039cfd4095ba5faf");
  });

  it("computes deterministic WORM chain hashes", async () => {
    const digest = await computeWormHash("GENESIS", { eventType: "USER_VAULTED" }, "idempotency_1");
    expect(digest).toBe("d06c8ddf3262cfa65d87bd0f15ad81d7af6f41985452ce9a937a7bba7ceef089");
  });

  it("canonicalizes payload key ordering before hashing", async () => {
    const left = await computeWormHash(
      "GENESIS",
      { b: "second", a: "first", nested: { y: 2, x: 1 } },
      "idem_key"
    );
    const right = await computeWormHash(
      "GENESIS",
      { nested: { x: 1, y: 2 }, a: "first", b: "second" },
      "idem_key"
    );
    expect(left).toBe(right);
  });
});
