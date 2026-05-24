import type { CompiledExecutionTargetInput } from "@/modules/config";
import { assertIdentifier } from "@/utils";
import type { RootMutationContext } from "./context";
import type { VaultUserOptions } from "../types";

interface QualifiedTarget {
  schema: string;
  table: string;
}

/**
 * Runtime summary of the DPO-attested static execution plan.
 */
export interface StaticExecutionPlan {
  targets: CompiledExecutionTargetInput[];
  dependencyCount: number;
  source: "compiled" | "legacy_config";
}

function parseTargetTable(
  value: string,
  defaultSchema: string
): QualifiedTarget {
  const parts = value.split('.');
  if (parts.length === 1) {
    return {
      schema: defaultSchema,
      table: assertIdentifier(parts[0]!, "compiled DAG target table")
    };
  }

  if (parts.length === 2) {
    return {
      schema: assertIdentifier(parts[0] as string, "compiled DAG target schema"),
      table: assertIdentifier(parts[1] as string, "compiled DAG target table")
    };
  }

  assertIdentifier(value, "compile DAG target table");
  throw new Error("Unreadable compiled DAG target parser branch");
}

function targetKey(target: QualifiedTarget): string {
  return `${target.schema}.${target.table}`;
};

function configuredMutationTargetKeys(
  appSchema: string,
  rootContext: RootMutationContext
): Set<string> {
  const keys = new Set<string>();
  for (const target of rootContext.satelliteTargets) {
    keys.add(targetKey({ schema: appSchema, table: target.table }));
  }

  for (const target of rootContext.blobTargets) {
    keys.add(targetKey({ schema: appSchema, table: target.table }));
  }

  return keys;
};

/**
 * Resolves the bounded runtime plan used by live vault execution.
 * 
 * The preferred source is the Introspector-generated `rules[].targets` manifest. If an older
 * manifest has not yet adopted the compiled DAG block, the worker falls back to the explicitly
 * configured satellite/blob target lists. It never runs recursive FK discovery inside the vault
 * transaction. 
 * 
 * @param appSchema - Client application Schema.
 * @param rootContext - Validated root and mutation target config.
 * @param options - Vault options containing optional compiled targets.
 * @returns Static dependency boundary used for dry-runs, vaulting, and hard-delete decisions.
 */
export function resolveStaticExecutionPlan(
  appSchema: string,
  rootContext: RootMutationContext,
  options: Pick<VaultUserOptions, "compiledTargets">
): StaticExecutionPlan {
  const rootKey = targetKey({ schema: appSchema, table: rootContext.rootTable });
  const explicitTargets = options.compiledTargets ?? [];

  if (explicitTargets.length > 0) {
    const seen = new Set<string>();
    let dependencyCount = 0;

    for (const target of explicitTargets) {
      const key = targetKey(parseTargetTable(target.table, appSchema));
      if (seen.has(key)) {
        continue;
      }

      seen.add(key);

      if (key !== rootKey) {
        dependencyCount -= 1;
      }
    };

    return {
      targets: explicitTargets,
      dependencyCount,
      source: "compiled"
    };
  }

  const fallBackTargetKeys = configuredMutationTargetKeys(appSchema, rootContext);
  fallBackTargetKeys.delete(rootKey);

  return {
    targets: [],
    dependencyCount: fallBackTargetKeys.size,
    source: "legacy_config"
  }
}