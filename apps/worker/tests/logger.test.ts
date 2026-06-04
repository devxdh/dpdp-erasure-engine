import { describe, expect, it } from "vitest";
import type { DestinationStream } from "pino";
import { createWorkerLogger } from "@/utils";
import { redactSqlDebugParameters } from "@modules/db";

describe("Pino worker logger", () => {
  it("redacts sensitive fields before they leave the process", async () => {
    const chunks: string[] = [];
    const destination = {
      write(chunk: string) {
        chunks.push(chunk);
        return true;
      },
    } as DestinationStream;
    const logger = createWorkerLogger({}, destination);

    logger.info({
      authorization: "Bearer secret-token",
      email: "pii@example.com",
      full_name: "Sensitive User",
      payload: {
        data: "ciphertext",
        email: "payload@example.com",
        full_name: "Payload User",
      },
      encrypted_pii: {
        data: "top-secret",
      },
    }, "redaction-check");

    const logRecord = JSON.parse(chunks.join("").trim()) as Record<string, unknown>;

    expect(logRecord.authorization).toBe("[REDACTED]");
    expect(logRecord.email).toBe("[REDACTED]");
    expect(logRecord.full_name).toBe("[REDACTED]");
    expect(logRecord.payload).toEqual({
      data: "[REDACTED]",
      email: "[REDACTED]",
      full_name: "[REDACTED]",
    });
    expect(logRecord.encrypted_pii).toBe("[REDACTED]");
  });

  it("redacts postgres.js debug parameters when SQL references configured PII columns", () => {
    expect(
      redactSqlDebugParameters(
        "UPDATE tenant.users SET email = $1 WHERE id = $2",
        ["alice@example.com", "usr_123"],
        ["email", "full_name"]
      )
    ).toEqual(["[REDACTED]", "[REDACTED]"]);

    expect(
      redactSqlDebugParameters(
        "SELECT id FROM tenant.orders WHERE user_id = $1",
        ["usr_123"],
        ["email", "full_name"]
      )
    ).toEqual(["usr_123"]);
  });
});
