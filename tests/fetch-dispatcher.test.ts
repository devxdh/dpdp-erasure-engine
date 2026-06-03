import { describe, expect, it, vi } from "vitest";
import { createFetchDispatcher } from "@modules/network";

const apiUrl = "https://api.compliance.io/outbox";
type FetchMock = (input: string | URL | Request, init?: RequestInit) => Promise<Response>;
describe("Fetch Dispatcher Integration", () => {
  /**
   * Layman Terms:
   * Tests the mailman. We make sure that when he tries to deliver a postcard (an HTTP POST request),
   * he correctly tells us if the house accepted it (Status 200 OK) or if the door was locked (Error).
   *
   * Technical Terms:
   * Validates the `createFetchDispatcher` transport layer. It mocks the global `fetch` API to ensure
   * headers, abort signals, and payload serializations are correctly formatted according to the Outbox
   * event contract.
  */
  it("successfully dispatches an outbox event and parses a 200 OK", async () => {
    const mockFetch = vi.fn<FetchMock>(async () => new Response(null, { status: 200 }));
    vi.spyOn(globalThis, "fetch").mockImplementation(mockFetch as any);

    const dispatcher = createFetchDispatcher({
      url: apiUrl,
      token: "secret-token",
      clientId: "worker-tenant-1",
    });

    const success = await dispatcher({
      id: "evt-123",
      idempotency_key: "ik-123",
      user_uuid_hash: "hash-456",
      event_type: "USER_VAULTED",
      payload: {
        request_id: "3dc5c993-2297-4138-906f-f8569d60c611",
        subject_opaque_id: "usr_1",
        event_timestamp: "2026-04-19T10:00:00.000Z",
      },
      previous_hash: "GENESIS",
      current_hash: "abcd",
      chain_status: "finalized",
      status: "pending",
      attempt_count: 0,
      lease_token: null,
      lease_expires_at: null,
      next_attempt_at: new Date(),
      processed_at: null,
      last_error: null,
      created_at: new Date(),
      updated_at: new Date(),
    });

    expect(success).toBe(true);
    expect(mockFetch).toHaveBeenCalledTimes(1);

    // Verify headers and body
    const [url, requestInit] = mockFetch.mock.calls[0] as [string, RequestInit];
    expect(url).toBe(apiUrl);
    expect(requestInit.headers).toEqual({
      "content-type": "application/json",
      "x-client-id": "worker-tenant-1",
      authorization: "Bearer secret-token",
    });
    expect(requestInit.redirect).toBe("error");
    expect(JSON.parse(String(requestInit.body))).toMatchObject({
      idempotency_key: "ik-123",
      event_type: "USER_VAULTED",
      request_id: "3dc5c993-2297-4138-906f-f8569d60c611",
      subject_opaque_id: "usr_1",
      payload: {
        request_id: "3dc5c993-2297-4138-906f-f8569d60c611",
        subject_opaque_id: "usr_1",
        event_timestamp: "2026-04-19T10:00:00.000Z",
      },
    });
  });

  it("classifies 500 responses as retryable transport failures", async () => {
    const mockFetch = vi.fn<FetchMock>(async () => new Response(null, { status: 500 }));

    vi.spyOn(globalThis, "fetch").mockImplementation(mockFetch as any);

    const dispatcher = createFetchDispatcher({
      url: apiUrl,
      token: "secret-token-2",
      clientId: "worker-tenant-2",
    });

    await expect(
      dispatcher({
        id: "evt-123",
        idempotency_key: "ik-123",
        user_uuid_hash: "hash-456",
        event_type: "USER_VAULTED",
        payload: {
          request_id: "3dc5c993-2297-4138-906f-f8569d60c611",
          subject_opaque_id: "usr_1",
          event_timestamp: "2026-04-19T10:00:00.000Z",
        },
        previous_hash: "GENESIS",
        current_hash: "abcd",
        chain_status: "finalized",
        status: "pending",
        attempt_count: 0,
        lease_token: null,
        lease_expires_at: null,
        next_attempt_at: new Date(),
        processed_at: null,
        last_error: null,
        created_at: new Date(),
        updated_at: new Date(),
      })
    ).rejects.toMatchObject({
      code: "OUTBOX_DELIVERY_FAILED",
      retryable: true,
      fatal: false,
    });
  });

  it("classifies 401 responses as fatal configuration failures", async () => {
    const mockFetch = vi.fn<FetchMock>(async () => new Response(null, { status: 401 }));

    vi.spyOn(globalThis, "fetch").mockImplementation(mockFetch as any);

    const dispatcher = createFetchDispatcher({
      url: apiUrl,
      token: "secret-token-2",
      clientId: "worker-tenant-3",
    });

    await expect(
      dispatcher({
        id: "evt-401",
        idempotency_key: "ik-401",
        user_uuid_hash: "hash-401",
        event_type: "USER_VAULTED",
        payload: {
          request_id: "3dc5c993-2297-4138-906f-f8569d60c611",
          subject_opaque_id: "usr_1",
          event_timestamp: "2026-04-19T10:00:00.000Z",
        },
        previous_hash: "GENESIS",
        current_hash: "abcd",
        chain_status: "finalized",
        status: "pending",
        attempt_count: 0,
        lease_token: null,
        lease_expires_at: null,
        next_attempt_at: new Date(),
        processed_at: null,
        last_error: null,
        created_at: new Date(),
        updated_at: new Date(),
      })
    ).rejects.toMatchObject({
      code: "OUTBOX_AUTH_REJECTED",
      retryable: false,
      fatal: true,
    });
  });

  it("classifies stale WORM chain heads as retryable concurrency failures", async () => {
    const mockFetch = vi.fn<FetchMock>(
      async () =>
        new Response(
          JSON.stringify({
            code: "API_OUTBOX_PREVIOUS_HASH_INVALID",
            retryable: false,
          }),
          {
            status: 409,
            headers: { "content-type": "application/json" },
          }
        )
    );

    vi.spyOn(globalThis, "fetch").mockImplementation(mockFetch as any);

    const dispatcher = createFetchDispatcher({
      url: apiUrl,
      token: "secret-token-3",
      clientId: "worker-tenant-4",
    });

    await expect(
      dispatcher({
        id: "evt-409",
        idempotency_key: "ik-409",
        user_uuid_hash: "hash-409",
        event_type: "NOTIFICATION_SENT",
        payload: {
          request_id: "3dc5c993-2297-4138-906f-f8569d60c611",
          subject_opaque_id: "usr_1",
          event_timestamp: "2026-04-19T10:00:00.000Z",
        },
        previous_hash: "stale-head",
        current_hash: "abcd",
        chain_status: "finalized",
        status: "pending",
        attempt_count: 0,
        lease_token: null,
        lease_expires_at: null,
        next_attempt_at: new Date(),
        processed_at: null,
        last_error: null,
        created_at: new Date(),
        updated_at: new Date(),
      })
    ).rejects.toMatchObject({
      code: "OUTBOX_DELIVERY_FAILED",
      retryable: true,
      fatal: false,
    });
  });
});
