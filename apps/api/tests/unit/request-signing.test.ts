import { describe, expect, it } from "vitest";
import { computeRequestSignature } from "@/http";

describe("worker request signing", () => {
  it("computes deterministic HMAC signatures for identical request envelopes", async () => {
    const left = await computeRequestSignature(
      "signing-secret",
      "POST",
      "/api/v1/worker/outbox",
      "worker-1",
      "1713600000000",
      '{"hello":"world"}'
    );
    const right = await computeRequestSignature(
      "signing-secret",
      "POST",
      "/api/v1/worker/outbox",
      "worker-1",
      "1713600000000",
      '{"hello":"world"}'
    );
    expect(left).toBe(right);
  });

  it("binds the optional nonce into the HMAC signature for multi-worker replay safety", async () => {
    const first = await computeRequestSignature(
      "signing-secret",
      "GET",
      "/api/v1/worker/sync",
      "00000000-0000-4000-8000-000000000001",
      "1713600000000",
      "",
      "nonce-1"
    );
    const second = await computeRequestSignature(
      "signing-secret",
      "GET",
      "/api/v1/worker/sync",
      "00000000-0000-4000-8000-000000000001",
      "1713600000000",
      "",
      "nonce-2"
    );

    expect(first).not.toBe(second);
  });
});
