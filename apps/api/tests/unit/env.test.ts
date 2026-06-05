import { describe, expect, it } from "vitest";
import { readApiEnv } from "@/config";

describe("API environment hardening", () => {
  it("fails closed in production when default development secrets are used", async () => {
    await expect(
      readApiEnv({
        NODE_ENV: "production",
        DATABASE_URL: "postgres://postgres:postgres@localhost:5432/postgres",
        WORKER_SHARED_SECRET: "worker-secret",
        ADMIN_API_TOKEN: "admin-secret",
      })
    ).rejects.toThrow(/production secret source|local development database/i);
  });

  it("accepts explicit production secrets and non-local database configuration", async () => {
    const env = await readApiEnv({
      NODE_ENV: "production",
      DATABASE_URL: "postgres://avantii:secret@postgres.internal:5432/avantii",
      WORKER_SHARED_SECRET: "worker-secret-prod-32-bytes",
      WORKER_REQUEST_SIGNING_SECRET: "worker-request-signing-prod-32-bytes",
      ADMIN_API_TOKEN: "admin-token-prod-32-bytes",
      COE_PRIVATE_KEY_PKCS8_BASE64: "private-key-material-base64",
      COE_PUBLIC_KEY_SPKI_BASE64: "public-key-material-base64",
    });

    expect(env.NODE_ENV).toBe("production");
    expect(env.DATABASE_URL).toContain("postgres.internal");
  });

  it("requires archive target configuration when certificate archival is enabled", async () => {
    await expect(
      readApiEnv({
        ARCHIVE_S3_ENABLED: "true",
      })
    ).rejects.toThrow(/ARCHIVE_S3_BUCKET/i);
  });
});
