import type { Sql } from "@/types";
import { detectSchemaDrift } from "@modules/db";
import { fail } from "@/errors";

/**
 * Validates runtime schema fingerprint against the expected hash from worker configuration.
 *
 * @param sql - Postgres pool used to inspect `information_schema`.
 * @param appSchema - Application schema expected by the worker.
 * @param expectedSchemaHash - Expected SHA-256 schema fingerprint from config.
 * @returns Detected schema hash when validation succeeds.
 * @throws {WorkerError} When detected hash does not match expected hash.
 */
export async function assertSchemaIntegrity(
  sql: Sql,
  appSchema: string,
  expectedSchemaHash: string
): Promise<string> {
  const detectedSchemaHash = await detectSchemaDrift(sql, appSchema);

  if (detectedSchemaHash !== expectedSchemaHash) {
    fail({
      code: "SCHEMA_DRIFT_DETECTED",
      title: "Schema drift detected",
      detail: `Schema drift detected for ${appSchema}. Expected ${expectedSchemaHash}, received ${detectedSchemaHash}. Refusing to start.`,
      category: "integrity",
      retryable: false,
      fatal: true,
      context: {
        appSchema,
        expectedSchemaHash,
        detectedSchemaHash,
      },
    });
  }

  return detectedSchemaHash;
}