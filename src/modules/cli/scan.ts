import postgres from "postgres";
import pc from "picocolors";
import { readWorkerConfig } from "@modules/config";
import { metadataScore } from "@modules/introspector";
import { UI, exitWithError } from "./ui";

interface ScanOptions {
  url?: string;
  schema?: string;
  threshold?: string;
  json?: string;
}

interface ScanColumnRow {
  table_name: string;
  column_name: string;
  data_type: string;
}

interface ScanFinding {
  table: string;
  column: string;
  dataType: string;
  metadataScore: number;
}

function parseThreshold(value: string | undefined): number {
  const threshold = Number(value ?? "0.6");
  if (!Number.isFinite(threshold) || threshold < 0 || threshold > 1) {
    exitWithError("Invalid metadata threshold.", "Use a numeric value between 0 and 1.");
  }

  return threshold;
}

function groupFindings(findings: readonly ScanFinding[]): Map<string, ScanFinding[]> {
  const grouped = new Map<string, ScanFinding[]>();
  for (const finding of findings) {
    const existing = grouped.get(finding.table) ?? [];
    existing.push(finding);
    grouped.set(finding.table, existing);
  }

  return grouped;
}

/**
 * Scans column names with the same metadata taxonomy used by the full Introspector.
 *
 * @param options - Database URL, schema, threshold, and optional JSON output path.
 * @returns Resolves after printing or writing metadata-only findings.
 */
export async function scanAction(options: ScanOptions): Promise<void> {
  UI.header("Metadata PII Scanner");

  const dbUrl = options.url || process.env.DATABASE_URL;
  if (!dbUrl) exitWithError("Database URL required.", "Pass --url or set DATABASE_URL env.");

  let appSchema = options.schema;
  if (!appSchema) {
    try {
      const config = await readWorkerConfig(process.env);
      appSchema = config.database.app_schema;
      UI.info(`Target schema detected: ${pc.bold(appSchema)}`);
    } catch (error) {
      exitWithError("Application schema missing.", "Provide --schema or ensure compliance.worker.yml exists");
    }
  }

  const threshold = parseThreshold(options.threshold);
  const spinner = UI.spinner(`Scanning information_schema for ${appSchema}...`);
  const sql = postgres(dbUrl);

  try {
    const columns = await sql<ScanColumnRow[]>`
      SELECT table_name, column_name, data_type
      FROM information_schema.columns
      WHERE table_schema = ${appSchema}
      ORDER BY table_name, column_name
    `;
    spinner.stop();

    const table = UI.table(["Table Name", "Sensitive Column Candidates"]);
    const findings = columns
      .map((column): ScanFinding => ({
        table: column.table_name,
        column: column.column_name,
        dataType: column.data_type,
        metadataScore: metadataScore(column.column_name)
      }))
      .filter((finding) => finding.metadataScore >= threshold)
      .sort((left, right) => {
        const byScore = right.metadataScore - left.metadataScore;
        if (byScore !== 0) return byScore;
        return `${left.table}.${left.column}`.localeCompare(`${right.table}.${right.column}`);
      });

    if (options.json) {
      await Bun.write(options.json, `${JSON.stringify({ schema: appSchema, threshold, findings }, null, 2)}\n`)
      UI.keyValue("JSON Output", options.json);
    }

    const grouped = groupFindings(findings);
    if (grouped.size === 0) {
      UI.success("Audit complete: Zero potention PII columns found.");
    } else {
      for (const [tableName, tableFindings] of grouped.entries()) {
        table.push([
          tableName,
          tableFindings
            .map((finding) => `${finding.column} (${finding.metadataScore.toFixed(2)})`)
            .join(","),
        ]);
      }
      console.log(table.toString());
      UI.warn(`${grouped.size} tables contain metadata-level sensitive data candidates.`);
      UI.info("Run compliance-worker introspect for bounded content sampling and YAML generation.");
    }

  } catch (err) {
    spinner.fail("Scan failed");
    exitWithError("Database audit error", err instanceof Error ? err.message : String(err));
  } finally {
    await sql.end();
  }
}