import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { setTimeout as sleep } from "node:timers/promises";
import { detectSchemaDrift } from "dpdp-erasure-cli/src/modules/db";
import postgres from "postgres";

const templatePath = resolve("deploy/local/compliance.worker.template.yml");
const outputPath = resolve("deploy/local/generated/compliance.worker.yml");
const databaseUrl = process.env.LOCAL_DATABASE_URL ?? "postgres://dpdp:dpdp@127.0.0.1:55432/dpdp_local";
const appSchema = process.env.LOCAL_APP_SCHEMA ?? "mock_app";

async function main(): Promise<void> {
  const sql = postgres(databaseUrl, {
    max: 1,
    idle_timeout: 5,
    connect_timeout: 5,
  });

  try {
    let expectedSchemaHash: string | null = null;
    let lastError: unknown;
    for (let attempt = 1; attempt <= 30; attempt += 1) {
      try {
        expectedSchemaHash = await detectSchemaDrift(sql, appSchema);
        break;
      } catch (error) {
        lastError = error;
        await sleep(1_000);
      }
    }

    if (!expectedSchemaHash) {
      throw lastError instanceof Error ? lastError : new Error("Failed to compute schema drift hash.");
    }

    const template = readFileSync(templatePath, "utf8");
    const rendered = template.replace("__EXPECTED_SCHEMA_HASH__", expectedSchemaHash);
    mkdirSync(dirname(outputPath), { recursive: true });
    writeFileSync(outputPath, rendered, "utf8");
    console.log(`Rendered ${outputPath} with schema hash ${expectedSchemaHash}`);
  } finally {
    await sql.end();
  }
}

await main();
