import { MAX_DEPTH } from "@/constants";
import { formatQualifiedTable, parseQualifiedTable } from "./naming";
import type {
  IntrospectorDraft,
  IntrospectorTargetDraft,
  RunIntrospectorOptions,
  VerifySchemaIntegrityOptions
} from "./types";
import { compileStaticDag, discoverPotentialLogicalLinks } from "./dag";
import { classifyDagTargets } from "./classifier";
import { detectSchemaDrift } from "@/modules/db";
import { renderIntrospectorYaml } from "./yaml";
import { fail } from "@/errors";
import { readWorkerConfig } from "../config";

function targetKey(schema: string, table: string): string {
  return `${schema}.${table}`;
}

/**
 * Runs the offline Introspector pipeline: static DAG compilation, bounded PII
 * classification, and deterministic YAML draft rendering.
 *
 * @param options - SQL handle, root table, sampling controls, and output timestamp.
 * @returns Draft model and rendered YAML content.
 */
export async function runIntrospector(options: RunIntrospectorOptions): Promise<{
  draft: IntrospectorDraft;
  yaml: string;
}> {
  const maxDepth = options.maxDepth ?? MAX_DEPTH;
  const root = parseQualifiedTable(options.rootTable, options.defaultSchema);

  const dag = await compileStaticDag({
    sql: options.sql,
    rootTable: formatQualifiedTable(root),
    defaultSchema: root.schema,
    maxDepth,
  });

  const classifiedColumns = await classifyDagTargets({
    sql: options.sql,
    targets: dag,
    samplePercent: options.samplePercent,
    sampleLimit: options.sampleLimit,
    threshold: options.threshold,
  });

  const [schemaHash, potentialLogicalLinks] = await Promise.all([
    detectSchemaDrift(options.sql, root.schema),
    discoverPotentialLogicalLinks(
      {
        sql: options.sql,
        rootTable: formatQualifiedTable(root),
        defaultSchema: root.schema
      },
      dag,
    ),
  ]);

  const targets: IntrospectorTargetDraft[] = dag.map((target) => ({
    table: target.table,
    parentTable: target.parentTable,
    fkCondition: target.fkCondition,
    childColumns: target.childColumns,
    parentColumns: target.parentColumns,
    depth: target.depth,
    piiColumns: classifiedColumns.get(targetKey(target.table.schema, target.table.table)) ?? [],
  }));

  const draft: IntrospectorDraft = {
    root,
    maxDepth,
    generatedAt: (options.generatedAt ?? new Date()).toISOString(),
    schemaHash,
    targets,
    potentialLogicalLinks,
  };

  return {
    draft,
    yaml: renderIntrospectorYaml(draft),
  };
}

/**
 * Verifies that the live schema still matches the DPO-attested manifest hash.
 *
 * @param options - SQL handle, manifest path, and optional env map for key placeholders.
 * @returns Live schema hash when the manifest is current.
 * @throws {WorkerError} When the legal attestation hash is absent or stale.
 */
export async function verifySchemaIntegrity(options: VerifySchemaIntegrityOptions): Promise<string> {
  const config = await readWorkerConfig(
    {
      ...process.env,
      ...options.env,
      DPDP_MASTER_KEY: options.env?.DPDP_MASTER_KEY ?? process.env.DPDP_MASTER_KEY ?? "0".repeat(64),
      DPDP_HMAC_KEY: options.env?.DPDP_HMAC_KEY ?? process.env.DPDP_HMAC_KEY ?? "0".repeat(64),
    },
    options.configPath
  );
  const expectedHash = config.legal_attestation.schema_hash ?? config.integrity.expected_schema_hash;
  const liveHash = await detectSchemaDrift(options.sql, config.database.app_schema);

  if (liveHash !== expectedHash) {
    fail({
      code: "DPDP_INTROSPECTOR_SCHEMA_VERIFY_FAILED",
      title: "Schema verification failed",
      detail: `Live schema hash ${liveHash} does not match legal attestation hash ${expectedHash}.`,
      category: "integrity",
      retryable: false,
      fatal: true,
      context: {
        appSchema: config.database.app_schema,
        expectedHash,
        liveHash,
      },
    });
  }

  return liveHash;
}