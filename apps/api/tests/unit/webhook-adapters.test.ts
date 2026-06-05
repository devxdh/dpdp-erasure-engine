import { Hono } from "hono";
import { describe, expect, it } from "vitest";
import { ZendeskAdapter } from "@modules/webhooks";

const encoder = new TextEncoder();

function bytesToBase64(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }
  return btoa(binary);
}

async function sign(secret: string, value: string): Promise<string> {
  const key = await crypto.subtle.importKey(
    "raw",
    encoder.encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  return bytesToBase64(new Uint8Array(await crypto.subtle.sign("HMAC", key, encoder.encode(value))));
}

async function verifyZendesk(headers: Record<string, string>, body: string): Promise<boolean> {
  const adapter = new ZendeskAdapter();
  const app = new Hono();
  app.post("/", async (c) => {
    const rawBody = await c.req.text();
    return c.json({
      verified: await adapter.verifySignature(c.req, rawBody, "zendesk-secret"),
    });
  });

  const response = await app.request("/", {
    method: "POST",
    headers: {
      "content-type": "application/json",
      ...headers,
    },
    body,
  });
  const payload = await response.json() as { verified: boolean };
  return payload.verified;
}

describe("provider webhook adapters", () => {
  it("verifies Zendesk signatures over timestamp plus raw body", async () => {
    const body = JSON.stringify({ event_id: "zd-1", requester: { id: "opaque-user" } });
    const timestamp = String(Date.now());
    const signature = await sign("zendesk-secret", `${timestamp}${body}`);

    await expect(
      verifyZendesk({
        "x-zendesk-webhook-signature-timestamp": timestamp,
        "x-zendesk-webhook-signature": signature,
      }, body)
    ).resolves.toBe(true);
  });

  it("rejects Zendesk signatures that omit the timestamp binding", async () => {
    const body = JSON.stringify({ event_id: "zd-2", requester: { id: "opaque-user" } });
    const timestamp = String(Date.now());
    const bodyOnlySignature = await sign("zendesk-secret", body);

    await expect(
      verifyZendesk({
        "x-zendesk-webhook-signature-timestamp": timestamp,
        "x-zendesk-webhook-signature": bodyOnlySignature,
      }, body)
    ).resolves.toBe(false);
  });

  it("rejects stale Zendesk delivery timestamps before normalization", async () => {
    const body = JSON.stringify({ event_id: "zd-3", requester: { id: "opaque-user" } });
    const timestamp = String(Date.now() - 10 * 60 * 1000);
    const signature = await sign("zendesk-secret", `${timestamp}${body}`);

    await expect(
      verifyZendesk({
        "x-zendesk-webhook-signature-timestamp": timestamp,
        "x-zendesk-webhook-signature": signature,
      }, body)
    ).resolves.toBe(false);
  });
});
