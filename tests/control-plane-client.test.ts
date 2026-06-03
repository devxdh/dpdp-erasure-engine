import { describe, expect, it, vi } from "vitest";
import { createControlPlaneApiClient } from "@modules/network";

describe("Control Plane API client", () => {
  it("accepts offset-form ISO timestamps in worker sync payloads", async () => {
    const fetchMock = vi.fn(async () => ({
      ok: true,
      status: 200,
      json: async () => ({
        pending: true,
        task: {
          id: "task-notify-1",
          task_type: "NOTIFY_USER",
          payload: {
            request_id: "01ce9849-189c-4c3d-ab91-b35eff852b9f",
            subject_opaque_id: "usr_local_zero",
            idempotency_key: "9943912a-1897-4860-ad9c-d32e9b3c2876",
            trigger_source: "USER_CONSENT_WITHDRAWAL",
            actor_opaque_id: "usr_local_zero",
            legal_framework: "DPDP_2023",
            request_timestamp: "2026-04-20T14:49:04.477+00:00",
            cooldown_days: 0,
            shadow_mode: false,
          },
        },
      }),
    }));

    vi.spyOn(globalThis, "fetch").mockImplementation(fetchMock as any);

    const client = createControlPlaneApiClient({
      syncUrl: "https://control-plane.example/api/v1/worker/sync",
      ackBaseUrl: "https://control-plane.example/api/v1/worker/tasks",
      workerAuthHeaders: {
        "x-client-id": "worker-1",
        authorization: "Bearer worker-secret",
      },
      workerConfigHash: "ab".repeat(32),
      workerConfigVersion: "v-test",
      workerDpoIdentifier: "dpo@example.com",
      pushOutboxEvent: async () => true,
    });

    const response = await client.syncTask();
    expect(response).toEqual({
      pending: true,
      task: {
        id: "task-notify-1",
        task_type: "NOTIFY_USER",
        payload: {
          request_id: "01ce9849-189c-4c3d-ab91-b35eff852b9f",
          subject_opaque_id: "usr_local_zero",
          idempotency_key: "9943912a-1897-4860-ad9c-d32e9b3c2876",
          trigger_source: "USER_CONSENT_WITHDRAWAL",
          actor_opaque_id: "usr_local_zero",
          legal_framework: "DPDP_2023",
          request_timestamp: "2026-04-20T14:49:04.477+00:00",
          cooldown_days: 0,
          shadow_mode: false,
        },
      },
    });

    expect(globalThis.fetch).toHaveBeenCalledWith(
      "https://control-plane.example/api/v1/worker/sync",
      expect.objectContaining({
        headers: expect.objectContaining({
          "x-worker-config-hash": "ab".repeat(32),
          "x-worker-config-version": "v-test",
          "x-worker-dpo-identifier": "dpo@example.com",
        }),
      })
    );
  });

  it("sends authenticated task heartbeat requests to extend long-running leases", async () => {
    const fetchMock = vi.fn(async () => ({
      ok: true,
      status: 200,
      json: async () => ({ ok: true }),
    }));

    vi.spyOn(globalThis, "fetch").mockImplementation(fetchMock as any);

    const client = createControlPlaneApiClient({
      syncUrl: "https://control-plane.example/api/v1/worker/sync",
      ackBaseUrl: "https://control-plane.example/api/v1/worker/tasks",
      workerAuthHeaders: {
        "x-client-id": "worker-1",
        authorization: "Bearer worker-secret",
      },
      workerConfigHash: "ab".repeat(32),
      pushOutboxEvent: async () => true,
    });

    await expect(client.heartbeatTask?.("task-long-1")).resolves.toBe(true);
    expect(globalThis.fetch).toHaveBeenCalledWith(
      "https://control-plane.example/api/v1/worker/tasks/task-long-1/heartbeat",
      expect.objectContaining({
        method: "POST",
        headers: expect.objectContaining({
          "x-client-id": "worker-1",
          authorization: "Bearer worker-secret",
        }),
      })
    );
  });
});
