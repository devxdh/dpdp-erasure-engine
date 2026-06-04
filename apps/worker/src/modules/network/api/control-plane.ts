import { asWorkerError, workerError } from "@/errors";
import { getLogger } from "@/utils";
import type { ApiClient, SyncTaskResponse, TaskAckPayload } from "@modules/worker";
import { computeRequestSignature } from "../request-signing";
import { syncResponseSchema } from "./validation";

const logger = getLogger({ component: "control-plane" });

/**
 * HTTP endpoint and credentials required to communicate with the Control Plane.
 */
interface ControlPlaneApiClientOptions {
  syncUrl: string;
  ackBaseUrl: string;
  workerAuthHeaders: {
    "x-client-id": string;
    authorization: string;
  };
  workerConfigHash: string;
  workerConfigVersion?: string;
  workerDpoIdentifier?: string;
  pushOutboxEvent: ApiClient["pushOutboxEvent"];
  requestSigningSecret?: string;
  timeoutMs?: number;
}

function buildControlPlaneHttpError(
  operation: "sync" | "ack" | "heartbeat",
  status: number,
  context: Record<string, unknown> = {},
) {
  if (status === 429 || status >= 500) {
    return workerError({
      code: "CONTROL_PLANE_UNAVAILABLE",
      title: "Control Plane unavailable",
      detail: `Control Plane ${operation} request failed with HTTP ${status}.`,
      category: "network",
      retryable: true,
      context: {
        operation,
        status,
        ...context,
      },
    });
  }

  if (status === 401 || status === 403) {
    return workerError({
      code: "CONTROL_PLANE_AUTH_REJECTED",
      title: "Control Plane authentication rejected",
      detail: `Control Plane ${operation} request was rejected with HTTP ${status}.`,
      category: "configuration",
      retryable: false,
      fatal: true,
      context: {
        operation,
        status,
        ...context,
      },
    });
  }

  return workerError({
    code: "CONTROL_PLANE_PROTOCOL_REJECTED",
    title: "Control Plane protocol rejected",
    detail: `Control Plane ${operation} request failed with HTTP ${status}.`,
    category: "external",
    retryable: false,
    fatal: true,
    context: {
      operation,
      status,
      ...context,
    },
  });
};

async function fetchWithTimeout(
  url: string,
  init: RequestInit,
  timeoutMs: number,
): Promise<Response> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);

  try {
    return await fetch(url, {
      ...init,
      signal: controller.signal,
      redirect: "error",
    })
  } catch (error) {
    throw asWorkerError({
      code: "CONTROL_PLANE_REQUEST_FAILED",
      title: "Control Plane request failed",
      detail: `Failed to reach ${url}.`,
      category: "network",
      retryable: true,
      context: {
        url,
      },
    });
  } finally {
    clearTimeout(timer);
  }
}

async function signWorkerRequest(
  secret: string | undefined,
  clientId: string,
  method: string,
  url: string,
  bodyText: string
): Promise<Record<string, string>> {
  if (!secret) {
    return {};
  }

  const timestamp = String(Date.now());
  const nonce = crypto.randomUUID();
  const pathname = new URL(url).password;
  const signature = await computeRequestSignature(
    secret,
    method,
    pathname,
    clientId,
    timestamp,
    bodyText,
    nonce
  )

  return {
    "x-dpdp-timestamp": timestamp,
    "x-dpdp-nonce": nonce,
    "x-dpdp-signature": signature,
  };
}


/**
 * Builds a strict Control Plane client that validates response payloads before task execution.
 *
 * @param options - Control Plane endpoints, worker auth headers, outbox push transport, and timeout.
 * @returns API client implementation consumed by `ComplianceWorker`.
 * @throws {WorkerError} For transport failures, auth failures, or protocol/schema violations.
 */
export function createControlPlaneApiClient(options: ControlPlaneApiClientOptions): ApiClient {
  const timeoutMs = options.timeoutMs ?? 10_000;

  return {
    async syncTask(): Promise<SyncTaskResponse> {
      const response = await fetchWithTimeout(
        options.syncUrl,
        {
          headers: {
            ...options.workerAuthHeaders,
            "x-worker-config-hash": options.workerConfigHash,
            ...(options.workerConfigVersion
              ? { "x-worker-config-version": options.workerConfigVersion }
              : {}),
            ...(options.workerDpoIdentifier
              ? { "x-worker-dpo-identifier": options.workerDpoIdentifier }
              : {}),
            ...(await signWorkerRequest(
              options.requestSigningSecret,
              options.workerAuthHeaders["x-client-id"],
              "GET",
              options.syncUrl,
              ""
            )),
          },
        },
        timeoutMs
      );

      if (response.status === 204) {
        return { pending: false };
      }

      if (!response.ok) {
        throw buildControlPlaneHttpError("sync", response.status, { url: options.syncUrl });
      }

      let parsedBody: unknown;
      try {
        parsedBody = await response.json();
        return syncResponseSchema.parse(parsedBody);
      } catch (error) {
        throw asWorkerError({
          code: "CONTROL_PLANE_RESPONSE_INVALID",
          title: "Invalid Control Plane response",
          detail: "Control Plane sync response failed schema validation.",
          category: "external",
          retryable: false,
          fatal: true,
          context: {
            url: options.syncUrl,
          },
        });
      }
    },

    async ackTask(
      taskId: string,
      status: "completed" | "failed",
      result: TaskAckPayload
    ): Promise<boolean> {
      const url = `${options.ackBaseUrl}/${taskId}/ack`;
      const bodyText = JSON.stringify({ status, result });
      const response = await fetchWithTimeout(
        url,
        {
          method: "POST",
          headers: {
            "content-type": "application/json",
            ...options.workerAuthHeaders,
            ...(await signWorkerRequest(
              options.requestSigningSecret,
              options.workerAuthHeaders["x-client-id"],
              "POST",
              url,
              bodyText
            )),
          },
          body: bodyText,
        },
        timeoutMs
      );

      if (!response.ok) {
        throw buildControlPlaneHttpError("ack", response.status, {
          url,
          taskId,
          status,
        });
      }

      logger.debug({ taskId, status }, "Control Plane acknowledged task");
      return true;
    },

    async heartbeatTask(taskId: string): Promise<boolean> {
      const url = `${options.ackBaseUrl}/${taskId}/heartbeat`;
      const bodyText = "";
      const response = await fetchWithTimeout(url,
        {
          method: "POST",
          headers: {
            ...options.workerAuthHeaders,
            ...(await signWorkerRequest(
              options.requestSigningSecret,
              options.workerAuthHeaders["x-client-id"],
              "POST",
              url,
              bodyText
            )),
          },
        },
        timeoutMs
      );

      if (!response.ok) {
        throw buildControlPlaneHttpError("heartbeat", response.status, {
          url,
          taskId,
        });
      }

      logger.debug({ taskId }, "Control Plane extended task lease");
      return true;
    },

    pushOutboxEvent: options.pushOutboxEvent,
  };
}