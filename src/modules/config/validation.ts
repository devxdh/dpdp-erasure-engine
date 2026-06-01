import { z } from "zod";
import { assertIdentifier } from "@/utils";
import { keySourceSchema } from "@/secrets";

const isError = (err: unknown, msg: string): string => {
  if (err instanceof Error) {
    return err.message;
  }
  return msg;
}

const mutationRuleSchema = z.enum(["HMAC", "STATIC_MASK", "NULLIFY"]);

export type MutationRule = z.infer<typeof mutationRuleSchema>;
export type RootPiiColumns = Record<string, MutationRule>;

const rootPiiColumnsSchema = z
  .record(z.string().min(1), mutationRuleSchema)
  .superRefine((value, ctx) => {
    const entries = Object.entries(value);
    if (entries.length === 0) {
      ctx.addIssue({
        code: "custom",
        message: "graph.root_pii_columns must contain at least one column mapping.",
      });
      return;
    }

    for (const [column] of entries) {
      try {
        assertIdentifier(column, "graph root pii column");
      } catch (error) {
        ctx.addIssue({
          code: "custom",
          message: isError(error, "Invalid graph root pii column."),
        });
      }
    }
  });

const satelliteTargetSchema = z
  .object({
    table: z.string().min(1),
    lookup_column: z.string().min(1),
    action: z.enum(["redact", "hard_delete"]),
    masking_rules: z.record(z.string().min(1), mutationRuleSchema).optional(),
  })
  .strict()
  .superRefine((value, ctx) => {
    try {
      assertIdentifier(value.table, "satellite table name");
    } catch (error) {
      ctx.addIssue({
        code: "custom",
        message: isError(error, "Invalid satellite table name."),
        path: ["table"],
      });
    }

    try {
      assertIdentifier(value.lookup_column, "satellite lookup column");
    } catch (error) {
      ctx.addIssue({
        code: "custom",
        message: isError(error, "Invalid satellite lookup column."),
        path: ["lookup_column"],
      });
    }

    if (value.action === "redact" && (!value.masking_rules || Object.keys(value.masking_rules).length === 0)) {
      ctx.addIssue({
        code: "custom",
        message: "satellite target masking_rules is required for redact actions.",
        path: ["masking_rules"],
      });
      return;
    }

    if (!value.masking_rules) {
      return;
    }

    for (const column of Object.keys(value.masking_rules)) {
      try {
        assertIdentifier(column, "satellite masking rule column");
      } catch (error) {
        ctx.addIssue({
          code: "custom",
          message: isError(error, "Invalid satellite masking rule column."),
          path: ["masking_rules", column],
        });
      }
    }
  });

export type SatelliteTarget = z.infer<typeof satelliteTargetSchema>;

const blobTargetSchema = z
  .object({
    table: z.string().min(1),
    column: z.string().min(1),
    lookup_column: z.string().min(1).optional(),
    provider: z.literal("aws_s3"),
    region: z.string().min(1),
    action: z.enum(["versioned_hard_delete", "hard_delete", "overwrite", "legal_hold_only"]),
    retention_mode: z.enum(["governance", "compliance"]).default("governance"),
    expected_bucket_owner: z.string().regex(/^\d{12}$/).optional(),
    require_version_id: z.boolean().default(true),
    masking_blob_path: z.string().min(1).optional(),
  })
  .strict()
  .superRefine((value, ctx) => {
    try {
      assertIdentifier(value.table, "blob target table name");
    } catch (error) {
      ctx.addIssue({
        code: "custom",
        message: isError(error, "Invalid blob target table name."),
        path: ["table"],
      });
    }

    try {
      assertIdentifier(value.column, "blob target column name");
    } catch (error) {
      ctx.addIssue({
        code: "custom",
        message: isError(error, "Invalid blob target column name."),
        path: ["column"],
      });
    }

    if (value.lookup_column) {
      try {
        assertIdentifier(value.lookup_column, "blob target lookup column");
      } catch (error) {
        ctx.addIssue({
          code: "custom",
          message: isError(error, "Invalid blob target lookup column."),
          path: ["lookup_column"],
        });
      }
    }

    if (value.action === "overwrite" && !value.masking_blob_path) {
      ctx.addIssue({
        code: "custom",
        message: "blob target masking_blob_path is required for overwrite actions.",
        path: ["masking_blob_path"],
      });
    }
  });

export type BlobTarget = z.infer<typeof blobTargetSchema>;

const qualifiedIdentifierSchema = z.string().min(1).superRefine((value, ctx) => {
  const parts = value.split(".");
  if (parts.length > 2 || parts.some((part) => part.trim().length === 0)) {
    ctx.addIssue({
      code: "custom",
      message: `Invalid qualified table reference: "${value}". Use table or schema.table.`,
    });
    return;
  }

  for (const part of parts) {
    try {
      assertIdentifier(part, "compiled DAG table reference");
    } catch (error) {
      ctx.addIssue({
        code: "custom",
        message: isError(error, "Invalid compiled DAG table reference."),
      });
    }
  }
});

const compiledExecutionTargetSchema = z
  .object({
    table: qualifiedIdentifierSchema,
    parent: qualifiedIdentifierSchema.optional(),
    join: z.string().min(1).optional(),
    fk_condition: z.string().min(1).optional(),
    parent_columns: z.array(z.string().min(1)).default([]),
    child_columns: z.array(z.string().min(1)).default([]),
    primary_key_columns: z.array(z.string().min(1)).default([]),
    action: z.enum(["redact", "hard_delete"]).optional(),
    mutation_rules: z.record(z.string().min(1), mutationRuleSchema).optional(),
    pii_columns: z.array(z.string().min(1)).default([]),
  })
  .strict()
  .superRefine((value, ctx) => {
    for (const [index, column] of value.parent_columns.entries()) {
      try {
        assertIdentifier(column, "compiled DAG parent column");
      } catch (error) {
        ctx.addIssue({
          code: "custom",
          message: isError(error, "Invalid compiled DAG parent column."),
          path: ["parent_columns", index],
        });
      }
    }

    for (const [index, column] of value.child_columns.entries()) {
      try {
        assertIdentifier(column, "compiled DAG child column");
      } catch (error) {
        ctx.addIssue({
          code: "custom",
          message: isError(error, "Invalid compiled DAG child column."),
          path: ["child_columns", index],
        });
      }
    }

    for (const [index, column] of value.primary_key_columns.entries()) {
      try {
        assertIdentifier(column, "compiled DAG primary key column");
      } catch (error) {
        ctx.addIssue({
          code: "custom",
          message: isError(error, "Invalid compiled DAG primary key column."),
          path: ["primary_key_columns", index],
        });
      }
    }

    for (const [index, column] of value.pii_columns.entries()) {
      try {
        assertIdentifier(column, "compiled DAG PII column");
      } catch (error) {
        ctx.addIssue({
          code: "custom",
          message: isError(error, "Invalid compiled DAG PII column."),
          path: ["pii_columns", index],
        });
      }
    }

    for (const column of Object.keys(value.mutation_rules ?? {})) {
      try {
        assertIdentifier(column, "compiled DAG mutation column");
      } catch (error) {
        ctx.addIssue({
          code: "custom",
          message: isError(error, "Invalid compiled DAG mutation column."),
          path: ["mutation_rules", column],
        });
      }
    }

    if (
      value.action === "redact"
      && (!value.mutation_rules || Object.keys(value.mutation_rules).length === 0)
    ) {
      ctx.addIssue({
        code: "custom",
        message: "compiled DAG mutation_rules is required for redact actions.",
        path: ["mutation_rules"],
      });
    }
  });

const compiledExecutionRuleSchema = z
  .object({
    id: z.string().min(1),
    root_table: qualifiedIdentifierSchema.optional(),
    max_depth: z.number().int().min(1).max(32).optional(),
    targets: z.array(compiledExecutionTargetSchema).min(1),
  })
  .strict();

export type CompiledExecutionTarget = z.output<typeof compiledExecutionTargetSchema>;
export type CompiledExecutionTargetInput = z.input<typeof compiledExecutionTargetSchema>;
export type CompiledExecutionRule = z.infer<typeof compiledExecutionRuleSchema>;

const retentionRuleSchema = z
  .object({
    rule_name: z.string().min(1),
    legal_citation: z.string().min(1),
    if_has_data_in: z.array(z.string().min(1)),
    retention_years: z.number().int().min(0),
  })
  .strict()
  .superRefine((value, ctx) => {
    if (value.if_has_data_in.length === 0) {
      ctx.addIssue({
        code: "custom",
        message: "retention rule must reference at least one evidence table.",
        path: ["if_has_data_in"],
      });
      return;
    }

    for (const table of value.if_has_data_in) {
      try {
        assertIdentifier(table, "retention rule evidence table");
      } catch (error) {
        ctx.addIssue({
          code: "custom",
          message: isError(error, "Invalid retention rule evidence table."),
          path: ["if_has_data_in"],
        });
      }
    }
  });

export type RetentionRule = z.infer<typeof retentionRuleSchema>;

const legalAttestationSchema = z
  .object({
    dpo_identifier: z.string().min(1),
    configuration_version: z.string().min(1),
    legal_review_date: z.iso.date(),
    schema_hash: z.string().regex(/^[0-9a-fA-F]{64}$/).optional(),
    generated_by: z.string().min(1).optional(),
    acknowledgment: z.string().min(1),
  })
  .strict();

export type LegalAttestation = z.infer<typeof legalAttestationSchema>;

export const workerYamlSchema = z
  .object({
    version: z.string().min(1),
    database: z
      .object({
        app_schema: z.string().min(1),
        engine_schema: z.string().min(1),
        replica_db_url: z.string().min(1).optional(),
      })
      .strict(),
    compliance_policy: z
      .object({
        default_retention_years: z.number().int().min(0),
        notice_window_hours: z.number().int().min(1),
        retention_rules: z.array(retentionRuleSchema),
      })
      .strict(),
    graph: z
      .object({
        root_table: z.string().min(1),
        root_id_column: z.string().min(1),
        max_depth: z.number().int().min(1).max(32),
        root_pii_columns: rootPiiColumnsSchema,
        notice_email_column: z.string().min(1).optional(),
        notice_name_column: z.string().min(1).optional(),
      })
      .strict(),
    satellite_targets: z.array(satelliteTargetSchema).default([]),
    blob_targets: z.array(blobTargetSchema).default([]),
    rules: z.array(compiledExecutionRuleSchema).default([]),
    outbox: z
      .object({
        batch_size: z.number().int().min(1),
        lease_seconds: z.number().int().min(1),
        max_attempts: z.number().int().min(1),
        base_backoff_ms: z.number().int().min(1).default(1000),
      })
      .strict(),
    security: z
      .object({
        notification_lease_seconds: z.number().int().min(1).default(120),
        master_key_env: z.string().min(1).default("MASTER_KEY"),
        hmac_key_env: z.string().min(1).default("HMAC_KEY"),
        master_key_source: keySourceSchema.optional(),
        hmac_key_source: keySourceSchema.optional(),
      })
      .strict(),
    integrity: z
      .object({
        expected_schema_hash: z.string().regex(/^[0-9a-fA-F]{64}$/),
      })
      .strict(),
    legal_attestation: legalAttestationSchema,
    legal_disclaimer: z
      .object({
        text: z.string().min(1),
      })
      .strict()
      .optional(),
  })
  .strict()
  .superRefine((value, ctx) => {
    try {
      assertIdentifier(value.database.app_schema, "application schema name");
    } catch (error) {
      ctx.addIssue({
        code: "custom",
        message: isError(error, "Invalid application schema name."),
        path: ["database", "app_schema"],
      });
    }

    try {
      assertIdentifier(value.database.engine_schema, "engine schema name");
    } catch (error) {
      ctx.addIssue({
        code: "custom",
        message: isError(error, "Invalid engine schema name."),
        path: ["database", "engine_schema"],
      });
    }

    try {
      assertIdentifier(value.graph.root_table, "graph root table");
    } catch (error) {
      ctx.addIssue({
        code: "custom",
        message: isError(error, "Invalid graph root table."),
        path: ["graph", "root_table"],
      });
    }

    try {
      assertIdentifier(value.graph.root_id_column, "graph root id column");
    } catch (error) {
      ctx.addIssue({
        code: "custom",
        message: isError(error, "Invalid graph root id column."),
        path: ["graph", "root_id_column"],
      });
    }

    if (value.graph.notice_email_column) {
      try {
        assertIdentifier(value.graph.notice_email_column, "graph notice email column");
      } catch (error) {
        ctx.addIssue({
          code: "custom",
          message: isError(error, "Invalid graph notice email column."),
          path: ["graph", "notice_email_column"],
        });
      }
    }

    if (value.graph.notice_name_column) {
      try {
        assertIdentifier(value.graph.notice_name_column, "graph notice name column");
      } catch (error) {
        ctx.addIssue({
          code: "custom",
          message: isError(error, "Invalid graph notice name column."),
          path: ["graph", "notice_name_column"],
        });
      }
    }

    for (const [index, target] of value.blob_targets.entries()) {
      if (target.table !== value.graph.root_table && !target.lookup_column) {
        ctx.addIssue({
          code: "custom",
          message: "blob target lookup_column is required when table is not the graph root table.",
          path: ["blob_targets", index, "lookup_column"],
        });
      }
    }
  });

export type WorkerYamlConfig = z.infer<typeof workerYamlSchema>;

export interface WorkerConfig extends Omit<WorkerYamlConfig, "rules"> {
  rules?: CompiledExecutionRule[];
  masterKey: Uint8Array;
  hmacKey: Uint8Array;
}

/**
 * Sanitizes and validates the worker configuration for database safety.
 * 
 * Validates: Ensures all table and column names are safe identifiers.
 * Normalizes: Trims whitespace and standardizes string casing.
 * Verifies: Recursively checks the DAG rules and compliance policies.
 * 
 * @param config - The raw YAML-parsed configuration.
 * @returns Sanitized configuration object.
 * @throws {WorkerError} If any identifier fails security validation.
 */
export function normalizeWorkerYaml(config: WorkerYamlConfig): WorkerYamlConfig {
  return {
    ...config,
    database: {
      ...config.database,
      app_schema: assertIdentifier(config.database.app_schema, "application schema name"),
      engine_schema: assertIdentifier(config.database.engine_schema, "engine schema name"),
      replica_db_url: config.database.replica_db_url?.trim() || undefined,
    },
    graph: {
      ...config.graph,
      root_table: assertIdentifier(config.graph.root_table, "graph root table"),
      root_id_column: assertIdentifier(config.graph.root_id_column, "graph root id column"),
      notice_email_column: config.graph.notice_email_column
        ? assertIdentifier(config.graph.notice_email_column, "graph notice email column")
        : undefined,
      notice_name_column: config.graph.notice_name_column
        ? assertIdentifier(config.graph.notice_name_column, "graph notice name column")
        : undefined,
      root_pii_columns: Object.fromEntries(
        Object.entries(config.graph.root_pii_columns).map(([column, rule]) => [
          assertIdentifier(column, "graph root pii column"),
          rule,
        ])
      ),
    },
    satellite_targets: config.satellite_targets.map((target) => ({
      ...target,
      table: assertIdentifier(target.table, "satellite table name"),
      lookup_column: assertIdentifier(target.lookup_column, "satellite lookup column"),
      masking_rules: target.masking_rules
        ? Object.fromEntries(
          Object.entries(target.masking_rules).map(([column, rule]) => [
            assertIdentifier(column, "satellite masking rule column"),
            rule,
          ])
        )
        : undefined,
    })),
    blob_targets: config.blob_targets.map((target) => ({
      ...target,
      table: assertIdentifier(target.table, "blob target table name"),
      column: assertIdentifier(target.column, "blob target column name"),
      lookup_column: target.lookup_column
        ? assertIdentifier(target.lookup_column, "blob target lookup column")
        : undefined,
      region: target.region.trim(),
      masking_blob_path: target.masking_blob_path?.trim(),
    })),
    rules: config.rules.map((rule) => ({
      ...rule,
      root_table: rule.root_table?.trim(),
      targets: rule.targets.map((target) => ({
        ...target,
        table: target.table.trim(),
        parent: target.parent?.trim(),
        join: target.join?.trim(),
        fk_condition: target.fk_condition?.trim(),
        parent_columns: target.parent_columns.map((column) =>
          assertIdentifier(column, "compiled DAG parent column")
        ),
        child_columns: target.child_columns.map((column) =>
          assertIdentifier(column, "compiled DAG child column")
        ),
        primary_key_columns: target.primary_key_columns.map((column) =>
          assertIdentifier(column, "compiled DAG primary key column")
        ),
        mutation_rules: target.mutation_rules
          ? Object.fromEntries(
            Object.entries(target.mutation_rules).map(([column, rule]) => [
              assertIdentifier(column, "compiled DAG mutation column"),
              rule,
            ])
          )
          : undefined,
        pii_columns: target.pii_columns.map((column) =>
          assertIdentifier(column, "compiled DAG PII column")
        ),
      })),
    })),
    compliance_policy: {
      ...config.compliance_policy,
      retention_rules: config.compliance_policy.retention_rules.map((rule) => ({
        ...rule,
        legal_citation: rule.legal_citation.trim(),
        if_has_data_in: rule.if_has_data_in.map((table) =>
          assertIdentifier(table, "retention rule evidence table")
        ),
      })),
    },
    legal_attestation: {
      ...config.legal_attestation,
      dpo_identifier: config.legal_attestation.dpo_identifier.trim(),
      configuration_version: config.legal_attestation.configuration_version.trim(),
      legal_review_date: config.legal_attestation.legal_review_date,
      acknowledgment: config.legal_attestation.acknowledgment.trim(),
      schema_hash: config.legal_attestation.schema_hash?.toLowerCase(),
      generated_by: config.legal_attestation.generated_by?.trim(),
    },
  };
}