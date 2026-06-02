import postgres from "postgres";
import pc from "picocolors";
import { UI, exitWithError } from "./ui";
import path from "node:path";
import { readWorkerConfig } from "../config";
import { vaultUser } from "../engine";

/**
 * Preview the results of a vault operation for a specific subject ID.
 */
export async function dryRunAction(options: {
  id: string,
  config: string,
  url?: string,
}) {
  UI.header("Vault Simulation");

  const dbUrl = options.url || process.env.DATABASE_URL;
  if (!dbUrl) exitWithError("Database URL required.", "Provider --url or set DATABASE_URL env.");

  const configPath = path.resolve(options.config);
  UI.info(`Subject  : ${pc.bold(options.id)}`);
  UI.info(`Manifest : ${pc.bold(options.config)}`);

  const mockEnv = {
    ...process.env,
    DPDP_MASTER_KEY: process.env.DPDP_MASTER_KEY || "0".repeat(64),
    DPDP_HMAC_KEY: process.env.DPDP_HMAC_KEY || "0".repeat(64),
  };

  let config;
  try {
    config = await readWorkerConfig(mockEnv, configPath);
  } catch (err) {
    exitWithError("Config load failed", err instanceof Error ? err.message : String(err));
  }

  const spinner = UI.spinner(`Executing dry-run pipeline for ${options.id}`);
  const sql = postgres(dbUrl);

  try {
    const result = await vaultUser(sql, options.id, {
      kek: config.masterKey,
      hmacKey: config.hmacKey,
    }, {
      appSchema: config.database.app_schema,
      engineSchema: config.database.engine_schema,
      defaultRetentionYears: config.compliance_policy.default_retention_years,
      noticeWindowHours: config.compliance_policy.notice_window_hours,
      graphMaxDepth: config.graph.max_depth,
      rootTable: config.graph.root_table,
      rootIdColumn: config.graph.root_id_column,
      rootPiiColumns: config.graph.root_pii_columns,
      satelliteTargets: config.satellite_targets,
      blobTargets: config.blob_targets,
      retentionRules: config.compliance_policy.retention_rules,
      dryRun: true,
      now: new Date(),
    });
    spinner.stop();

    if (!result.plan) exitWithError("Internal Error", "Vault engine failed to return a plan.");

    UI.step(1, "Executive Summary");
    UI.subStep(result.plan.summary);

    UI.step(2, "Integrity Checks");
    result.plan.checks.forEach(c => UI.subStep(c));

    UI.step(3, "Cryptographic Pipeline");
    result.plan.cryptoSteps.forEach(s => UI.subStep(pc.yellow(s)));

    UI.step(4, "Proposed SQL Transactions");
    result.plan.sqlSteps.forEach(s => UI.subStep(pc.magenta(s)));

    UI.divider();
    UI.info("FINAL PREVIEW:");
    UI.keyValue("Planned Action", result.action);
    UI.keyValue("Worker Hash", result.userHash || "N/A");
    UI.keyValue("Dependencies", result.dependencyCount.toString());
    UI.keyValue("Retention", `${result.retentionYears ?? 0} years (${result.appliedRuleName})`);

    UI.success("Dry-run complete. No production data was modified.");
  } catch (err) {
    spinner.fail("Simulation failed");
    exitWithError("Dry-run error", err instanceof Error ? err.message : String(err));
  } finally {
    await sql.end();
  }
}