import postgres from "postgres";
import { verifySchemaIntegrity } from "@modules/introspector";
import { UI, exitWithError } from "./ui";

/**
 * Executes the CI/CD Privacy-as-Code schema gate.
 *
 * @param options - Manifest path and database URL.
 * @returns Resolves only when the live schema hash matches legal attestation.
 */
export async function verifySchemaAction(options: { config: string; url?: string }): Promise<void> {
  UI.header("Privacy-as-Code Schema Verification");

  const dbUrl = options.url ?? process.env.DATABASE_URL;
  if (!dbUrl) {
    exitWithError("Database URL required.", "Pass --url or set DATABASE_URL.");
  }

  const sql = postgres(dbUrl, { max: 1 });
  const spinner = UI.spinner(`Comparing live schema to ${options.config}...`);
  try {
    const liveHash = await verifySchemaIntegrity({ sql, configPath: options.config });
    spinner.succeed("Schema hash matches legal attestation");
    UI.keyValue("Live Schema Hash", liveHash);
  } catch (error) {
    spinner.fail("Schema verification failed");
    exitWithError("Privacy-as-Code gate failed", error instanceof Error ? error.message : String(error));
  } finally {
    await sql.end();
  }
}
