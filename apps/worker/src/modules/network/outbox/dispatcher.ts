import { outboxLogger } from "@/utils";
import { fail, workerError } from "@/errors";
import { computeRequestSignature } from "../request-signing";
import type { FetchDispatcherOptions, OutboxEvent } from "./types";

interface ControlPlaneOutboxPayload {
  request_id?: string | null;
  subject_opaque_id?: string | null;
  event_timestamp?: string | null;
  [key: string]: unknown;
}


function isRetryableProblemBody(body: unknown): boolean {
  if (!body || typeof body !== "object") {
    return false;
  }

  const record = body as Record<string, unknown>;
  if (record.retryable === true || record.code === "API_OUTBOX_PREVIOUS_HASH_INVALID") {
    return true;
  }

  const error = record.error;
  if (!error || typeof error !== "object") {
    return false;
  }

  const errorRecord = error as Record<string, unknown>;
  return errorRecord.retryable === true || errorRecord.code === "API_OUTBOX_PREVIOUS_HASH_INVALID";
}

async function readRetryableProblem(response: Response): Promise<boolean> {
  try {
    const body = await response.clone().json() as unknown;
    return isRetryableProblemBody(body);
  } catch {
    return false;
  }
}

function buildControlPlaneRequestBody(event: OutboxEvent) {
  if (!event.payload || typeof event.payload !== "object" || Array.isArray(event.payload)) {
    fail({
      code: "OUTBOX_PAYLOAD_INVALID",
      title: "Invalid outbox payload",
      detail: `Outbox payload for event ${event.id} must be an object.`,
      category: "integrity",
      retryable: false,
      fatal: true,
      context: { eventId: event.id },
    });
  }

  const payload = event.payload as ControlPlaneOutboxPayload;
  if (!payload.request_id || !payload.subject_opaque_id || !payload.event_timestamp) {
    fail({
      code: "OUTBOX_PROTOCOL_REJECTED",
      title: "Outbox payload missing control-plane envelope",
      detail: `Outbox event ${event.id} is missing request_id, subject_opaque_id, or event_timestamp.`,
      category: "integrity",
      retryable: false,
      fatal: true,
      context: { eventId: event.id },
    });
  }

  return {
    idempotency_key: event.idempotency_key,
    request_id: payload.request_id,
    subject_opaque_id: payload.subject_opaque_id,
    event_type: event.event_type,
    payload,
    previous_hash: event.previous_hash,
    current_hash: event.current_hash,
    event_timestamp: payload.event_timestamp,
  };
}

/**
 * No-op dispatcher used by tests and local execution when no HTTP transport is injected.
 *
 * @param event - Outbox event to "send".
 * @returns Always `true` after logging.
 */
export async function sendToAPI(event: OutboxEvent): Promise<boolean> {
  outboxLogger.info({ eventId: event.id, eventType: event.event_type }, "Outbox event synced");
  return true;
}

/**
 * Creates an HTTP dispatcher that publishes worker outbox events to the Control Plane.
 *
 * @param options - Endpoint URL, auth headers, and timeout configuration.
 * @returns Dispatcher function compatible with `processOutbox`.
 */
export function createFetchDispatcher(options: FetchDispatcherOptions) {
  const timeoutMs = options.timeoutMs ?? 10_000;

  return async function dispatch(event: OutboxEvent): Promise<boolean> {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    const body = buildControlPlaneRequestBody(event);

    try {
      const bodyText = JSON.stringify(body);
      const requestSigningSecret = (options as FetchDispatcherOptions).requestSigningSecret;
      const clientId = options.clientId ?? fail({
        code: "DISPATCHER_CONFIG_INVALID",
        title: "Missing Client Identifier",
        detail: "Cannot create fetch dispatcher because clientId is missing from options.",
        category: "integrity",
        retryable: false,
        fatal: true,
      });

      const signingHeaders = requestSigningSecret
        ? (async () => {
          const timestamp = String(Date.now());
          return await computeRequestSignature(
            requestSigningSecret,
            "POST",
            new URL(options.url).pathname,
            clientId,
            timestamp,
            bodyText
          ).then((signature) => ({
            "x-dpdp-timestamp": timestamp,
            "x-dpdp-signature": signature
          }));
        })()
        : Promise.resolve({});

      const signedHeaders = await signingHeaders;
      const response = await fetch(options.url, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          ...(options.clientId ? { "x-client-id": options.clientId } : {}),
          ...(options.token ? { authorization: `Bearer ${options.token}` } : {}),
          ...signedHeaders,
        },
        body: bodyText,
        signal: controller.signal,
        redirect: "error",
      });

      if (!response.ok) {
        const retryableProblem = await readRetryableProblem(response);
        const retryable = response.status >= 500 || response.status === 429 || retryableProblem;
        throw workerError({
          code:
            response.status === 401 || response.status === 403
              ? "OUTBOX_AUTH_REJECTED"
              : retryable
                ? "OUTBOX_DELIVERY_FAILED"
                : "OUTBOX_PROTOCOL_REJECTED",
          title:
            response.status === 401 || response.status === 403
              ? "Control Plane authentication rejected outbox event"
              : "Control Plane rejected outbox event",
          detail: `Brain API responded with HTTP ${response.status}.`,
          category:
            response.status === 401 || response.status === 403
              ? "configuration"
              : retryable
                ? "network"
                : "external",
          retryable,
          fatal: !retryable,
          context: {
            status: response.status,
            url: options.url,
          },
        });
      }

      return true;
    } finally {
      clearTimeout(timer);
    }
  };
}