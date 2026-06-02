import postgres from "postgres";
import path from "node:path";
import { UI, exitWithError } from "./ui";
import { assertSchemaIntegrity } from "@modules/bootstrap";
import { assertConfigSchemaCompatibility, readWorkerConfig } from "@modules/config";

/**
 * Runs fail-closed integrity validation for CI/CD and worker boot gates.
 *
 * @param options - Manifest path and database URL.
 * @returns Resolves only when schema hash and compiled DAG checks pass.
 */
export async function checkIntegrityAction(options: { config: string; url?: string }) {
  UI.header("Fail-Closed Integrity Check");

  const dbUrl = options.url || process.env.DATABASE_URL;
  if (!dbUrl) {
    exitWithError("Database URL required.", "Provide --url or set DATABASE_URL env.");
  }

  const configPath = path.resolve(options.config);
  const mockEnv = {
    ...process.env,
    DPDP_MASTER_KEY: process.env.DPDP_MASTER_KEY || "0".repeat(64),
    DPDP_HMAC_KEY: process.env.DPDP_HMAC_KEY || "0".repeat(64),
  };

  const config = await readWorkerConfig(mockEnv, configPath);
  const expectedSchemaHash =
    config.legal_attestation.schema_hash ?? config.integrity.expected_schema_hash;
  const sql = postgres(dbUrl);

  try {
    const detectedHash = await assertSchemaIntegrity(
      sql,
      config.database.app_schema,
      expectedSchemaHash
    );
    await assertConfigSchemaCompatibility(sql, config);

    UI.keyValue("Live Schema Hash", detectedHash);
    UI.success("Schema hash, legal attestation, and compiled DAG are current.");
  } catch (error) {
    exitWithError("Integrity check failed", error instanceof Error ? error.message : String(error));
  } finally {
    await sql.end();
  }
}
