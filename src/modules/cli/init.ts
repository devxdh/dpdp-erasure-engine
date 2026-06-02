import { input, number } from "@inquirer/prompts";
import yaml from "js-yaml";
import { UI, exitWithError } from "./ui";

/**
 * Interactive Configuration Wizard.
 * Forces explicit data entry for critical legal fields to ensure liability shift.
 */
export async function initAction() {
  UI.header("Configuration Setup");

  UI.info("This wizard will help you generate 'compliance.worker.yml'.");
  UI.info("This manifest acts as the legal contract for your Data Plane Worker.");

  try {
    const appSchema = await input({
      message: "Application Schema (e.g. 'public'):",
      validate: (v) => v.trim().length > 0 || "Required.",
    });

    const engineSchema = await input({
      message: "Compliance Engine Schema (e.g. 'compliance_engine'):",
      default: "compliance_engine",
    });

    const rootTable = await input({
      message: "Root Table for Graph Discovery (e.g. 'users'):",
      validate: (v) => v.trim().length > 0 || "Required.",
    });

    const rootIdColumn = await input({
      message: "Root Primary Key Column (e.g. 'id'):",
      default: "id",
    });

    const dpoIdentifier = await input({
      message: "DPO Identifier (Email or UID):",
      validate: (v) => v.trim().length > 0 || "Required for legal audit trail.",
    });

    const defaultRetention = await number({
      message: "Default Retention Period (years):",
      validate: (v) => (v !== undefined && v >= 0) || "Must be 0 or greater.",
    });

    const config = {
      version: "1.0",
      database: {
        app_schema: appSchema.trim(),
        engine_schema: engineSchema.trim(),
      },
      compliance_policy: {
        default_retention_years: defaultRetention,
        notice_window_hours: 48,
        retention_rules: [
          {
            rule_name: "PMLA_FINANCIAL_EXAMPLE",
            legal_citation: "E.g. Sec 12 of PMLA 2002",
            if_has_data_in: ["transactions"],
            retention_years: 10
          }
        ],
      },
      graph: {
        root_table: rootTable.trim(),
        root_id_column: rootIdColumn.trim(),
        max_depth: 32,
        root_pii_columns: {
          email: "HMAC",
          full_name: "STATIC_MASK"
        },
      },
      satellite_targets: [],
      blob_targets: [],
      outbox: {
        batch_size: 10,
        lease_seconds: 60,
        max_attempts: 10,
        base_backoff_ms: 1000,
      },
      security: {
        notification_lease_seconds: 120,
      },
      integrity: {
        expected_schema_hash: "0".repeat(64),
      },
      legal_attestation: {
        dpo_identifier: dpoIdentifier.trim(),
        configuration_version: "1.0.0",
        legal_review_date: new Date().toISOString().split("T")[0],
        acknowledgment: "I confirm this configuration accurately reflects our legal data retention obligations.",
      },
    };

    const yamlText = yaml.dump(config, {
      indent: 2,
      lineWidth: -1,
      quotingType: '"',
    });

    await Bun.write("compliance.worker.yml", yamlText);

    UI.success("Manifest generated: compliance.worker.yml");

    UI.info("\nRECOMMENDED NEXT STEPS:");
    UI.step(1, "PII Discovery: Run 'compliance-worker scan' to identify sensitive columns.");
    UI.step(2, "Integrity Check: Run 'compliance-worker verify' to compute the schema hash.");
    UI.step(3, "Simulation: Run 'compliance-worker dry-run --id <id>' to preview effects.");
  } catch (err) {
    if (err instanceof Error && err.name === "ExitPromptError") {
      process.exit(0);
    }
    exitWithError("Initialization failed", err instanceof Error ? err.message : String(err));
  }
}
