import postgres from "postgres";
import pc from "picocolors";
import { UI, exitWithError } from "./ui";
import path from "node:path";
import { assertConfigSchemaCompatibility, readWorkerConfig } from "../config";
import { detectSchemaDrift } from "../db";
import { verifySignedWorkerConfig } from "@/secrets/signature";

/**
 * Validates the local manifest against the database and signing keys.
 */
export async function verifyAction(options: { config: string; url?: string }) {
  UI.header("Integrity Verification");

  const dbUrl = options.url || process.env.DATABASE_URL;
  if (!dbUrl) exitWithError("Database URL required.", "Provide --url or set DATABASE_URL env.");

  const configPath = path.resolve(options.config);
  UI.info(`Verifying manifest: ${pc.bold(options.config)}`);

  // Use dummy keys if not provided for verification path
  const mockEnv = {
    ...process.env,
    DPDP_MASTER_KEY: process.env.DPDP_MASTER_KEY || "0".repeat(64),
    DPDP_HMAC_KEY: process.env.DPDP_HMAC_KEY || "0".repeat(64),
  };

  let config;
  try {
    config = await readWorkerConfig(mockEnv, configPath);
  } catch (err) {
    exitWithError("Validation failed", err instanceof Error ? err.message : String(err));
  }

  const sql = postgres(dbUrl);

  try {
    UI.step(1, "Database Schema Compatibility");
    const compatSpinner = UI.spinner("Checking existence of configured objects...");
    try {
      await assertConfigSchemaCompatibility(sql, config);
      compatSpinner.succeed("All configured tables and columns verified.");
    } catch (err) {
      compatSpinner.fail("Schema mismatch detected.");
      console.log(pc.red(`   ${err instanceof Error ? err.message : String(err)}`));
    }

    UI.step(2, "Schema Drift Detection");
    const hashSpinner = UI.spinner("Computing SHA-256 fingerprint...");
    const liveHash = await detectSchemaDrift(sql, config.database.app_schema);
    const expectedHash = config.integrity.expected_schema_hash;
    hashSpinner.stop();

    UI.keyValue("Manifest Hash", expectedHash);
    UI.keyValue("Live Schema Hash", liveHash);

    if (liveHash === expectedHash) {
      UI.success("Fingerprints match. Configuration is current.");
    } else {
      UI.error("DRIFT DETECTED: Database structure has changed.");
      UI.hint(`If this was intended, update 'integrity.expected_schema_hash' to: ${pc.bold(liveHash)}`);
    }

    UI.step(3, "Cryptographic Signatures");
    if (process.env.DPDP_CONFIG_SIGNING_PUBLIC_KEY_SPKI_BASE64) {
      const sigSpinner = UI.spinner("Verifying detached Ed25519 signature...");
      try {
        await verifySignedWorkerConfig(process.env, configPath);
        sigSpinner.succeed("Signature valid. Manifest is untampered.");
      } catch (err) {
        sigSpinner.fail("Signature verification failed.");
        console.log(pc.red(`   ${err instanceof Error ? err.message : String(err)}`));
      }
    } else {
      UI.info("Skipped: DPDP_CONFIG_SIGNING_PUBLIC_KEY_SPKI_BASE64 not set.");
    }

    UI.divider();
    UI.success("Verification pipeline concluded.");
  } catch (err) {
    exitWithError("System failure", err instanceof Error ? err.message : String(err));
  } finally {
    await sql.end();
  }
}
