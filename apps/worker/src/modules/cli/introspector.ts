import postgres from "postgres";
import pc from "picocolors";
import type { IntrospectorCliOptions } from "../introspector/types";
import { exitWithError, UI } from "./ui";
import { runIntrospector, verifySchemaIntegrity } from "../introspector";
import { readWorkerConfig } from "../config";
import { buildIntrospectorReport, renderIntrospectorJson, renderIntrospectorMarkdown } from "../introspector/report";

function parseNumber(value: string | undefined, fallback: number): number {
  if (value === undefined) {
    return fallback;
  }

  const parsed = Number(value);
  if (!Number.isFinite(parsed)) {
    exitWithError("Invalid numeric option.", `${value} is not a finite number.`);
  }
  return parsed;
}

/**
 * Executes the offline Introspector CLI and writes `compliance.worker.yml.draft`.
 *
 * @param options - CLI flags provided by Commander.
 */
export async function introspectAction(options: IntrospectorCliOptions): Promise<void> {
  UI.header("Offline Introspector");

  const dbUrl = options.url ?? process.env.DATABASE_URL;
  if (!dbUrl) {
    exitWithError("Database URL required.", "Pass --url or set DATABASE_URL env");
  }

  if (options.verifyOnly) {
    const sql = postgres(dbUrl);
    const configPath = options.config ?? "compliance.worker.yml";
    const spinner = UI.spinner(`Verifying schema hash against ${configPath}`);
    try {
      const liveHash = await verifySchemaIntegrity({ sql, configPath });
      spinner.succeed("Schema hash matches legal attestation");
      UI.keyValue("Live Schema Hash", liveHash);
      return;
    } catch (err) {
      spinner.fail("Schema verification failed");
      exitWithError("Privacy-as-Code gate failed", err instanceof Error ? err.message : String(err));
    } finally {
      await sql.end();
    }
  }

  let rootTable = options.root;
  let appSchema = options.schema;
  if (!rootTable || !appSchema) {
    try {
      const config = await readWorkerConfig(process.env);
      rootTable = rootTable ?? `${config.database.app_schema}.${config.graph.root_table}`;
      appSchema = appSchema ?? config.database.app_schema;
      UI.info(`Detected root table from manifest: ${pc.bold(rootTable)}`);
    } catch (err) {
      if (!rootTable) {
        exitWithError("Root table required.", "Pass --root public.users or provide compliance.worker.yml");
      }
      appSchema = appSchema ?? "public";
    }
  }

  const output = options.output ?? "compliance.worker.yml.draft";
  const sql = postgres(dbUrl, { max: 1 });
  const spinner = UI.spinner(`Compiling static DAG and bounded PII taxomony for ${rootTable}...`);

  try {
    const { draft, yaml } = await runIntrospector({
      sql,
      rootTable,
      defaultSchema: appSchema,
      maxDepth: parseNumber(options.maxDepth, 32),
      samplePercent: parseNumber(options.samplePercent, 1),
      sampleLimit: parseNumber(options.sampleLimit, 100),
      threshold: parseNumber(options.threshold, 0.75),
    });

    await Bun.write(output, yaml);
    const report = await buildIntrospectorReport(draft);
    const markdownReportPath = options.report ?? `${output}.report.md`;
    await Bun.write(markdownReportPath, renderIntrospectorMarkdown(report));
    if (options.jsonReport) {
      await Bun.write(options.jsonReport, renderIntrospectorJson(report));
    }

    spinner.succeed("Introspector draft generated");
    UI.keyValue("Output", output);
    UI.keyValue("Report", markdownReportPath);
    if (options.jsonReport) {
      UI.keyValue("JSON Report", options.jsonReport);
    }
    UI.keyValue("Root", `${draft.root.schema}.${draft.root.table}`);
    UI.keyValue("Targets", String(draft.targets.length));
    UI.keyValue("PII Columns", String(report.summary.piiColumnCount));
    UI.keyValue("Review Findings", String(report.summary.reviewRequiredCount));
    UI.keyValue("Logical Links", String(report.summary.potentialLogicalLinkCount));
    UI.warn("Draft is not a production manifest. DPO review and legal attestation are mandatory before use.");
    if (
      options.failOnReview &&
      (report.summary.reviewRequiredCount > 0 || report.summary.potentialLogicalLinkCount > 0)
    ) {
      exitWithError(
        "Manual review required.",
        "The draft contains lower-confidence PII findings or potential logical links. Review the report before CI promotion."
      );
    }
  } catch (err) {
    spinner.fail("Introspector failed");
    exitWithError("Offline introspection error", err instanceof Error ? err.message : String(err));
  } finally {
    await sql.end();
  }
}