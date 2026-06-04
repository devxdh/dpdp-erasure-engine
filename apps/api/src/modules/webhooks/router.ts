import { Hono } from "hono";
import type { HonoRequest } from "hono";
import { fail } from "@/errors";
import { getWebhookAdapter, normalizeWebhookProvider } from "./adapters";
import { readBoundedTextBody } from "./security";
import { getWebhookClient, ingestWebhookTransaction } from "./transactions";
import type { WebhookAdapter, WebhookClient } from "./types";
import type { Sql } from "@/types";

export interface CreateWebhookRouterOptions {
  sql: Sql;
  controlSchema: string;
  maxBodyBytes?: number;
  now?: () => Date;
}

const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

async function verifyWithActiveSecret(
  adapter: WebhookAdapter,
  req: HonoRequest,
  rawBody: string,
  client: WebhookClient,
  now: Date
): Promise<boolean> {
  if (client.webhook_signing_secret && await adapter.verifySignature(req, rawBody, client.webhook_signing_secret)) {
    return true;
  }

  if (
    client.webhook_previous_signing_secret &&
    client.webhook_previous_secret_expires_at &&
    client.webhook_previous_secret_expires_at > now
  ) {
    return adapter.verifySignature(req, rawBody, client.webhook_previous_signing_secret);
  }

  return false;
}

/**
 * Creates the unified provider webhook ingestion router.
 *
 * @param options - Database, schema, body limit, and clock dependencies.
 * @returns Hono router mounted at `/api/v1/webhooks`.
 */
export function createUnifiedWebhookRouter(options: CreateWebhookRouterOptions) {
  const router = new Hono();
  const maxBodyBytes = options.maxBodyBytes ?? 64 * 1024;
  const now = options.now ?? (() => new Date());

  router.post("/:provider/:client_id", async (c) => {
    const provider = normalizeWebhookProvider(c.req.param("provider"));
    const clientId = c.req.param("client_id");
    if (!UUID_PATTERN.test(clientId)) {
      fail({
        code: "API_WEBHOOK_CLIENT_ID_INVALID",
        title: "Invalid webhook client id",
        detail: "client_id must be a UUID.",
        status: 400,
        category: "validation",
        retryable: false,
      });
    }

    const client = await getWebhookClient(options.sql, options.controlSchema, clientId);
    if (!client?.is_active || !client.webhook_signing_secret) {
      fail({
        code: "API_WEBHOOK_CLIENT_UNAUTHORIZED",
        title: "Webhook client unauthorized",
        detail: "Webhook target client is inactive, missing, or lacks a signing secret.",
        status: 401,
        category: "authentication",
        retryable: false,
      });
    }

    const adapter = getWebhookAdapter(provider);
    const rawBody = await readBoundedTextBody(c.req.raw, maxBodyBytes);
    const requestNow = now();
    const verified = await verifyWithActiveSecret(adapter, c.req, rawBody, client, requestNow);
    if (!verified) {
      fail({
        code: "API_WEBHOOK_SIGNATURE_INVALID",
        title: "Invalid webhook signature",
        detail: "Webhook HMAC verification failed.",
        status: 401,
        category: "authentication",
        retryable: false,
      });
    }

    let payload: unknown;
    try {
      payload = JSON.parse(rawBody);
    } catch (error) {
      fail({
        code: "API_WEBHOOK_PAYLOAD_INVALID",
        title: "Invalid webhook payload",
        detail: "Webhook body must be valid JSON.",
        status: 400,
        category: "validation",
        retryable: false,
        cause: error,
      });
    }

    const normalized = await adapter.normalize(payload);

    const result = await ingestWebhookTransaction(options.sql, options.controlSchema, {
      provider,
      client,
      normalized,
      now: requestNow,
    });

    return c.json(result, result.duplicate ? 200 : 202);
  });

  return router;
}
