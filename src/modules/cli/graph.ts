import { type DependencyNode, getDependencyGraph } from "@modules/db";
import { readWorkerConfig } from "@modules/config";
import pc from "picocolors";
import { UI, exitWithError } from "./ui";
import postgres from "postgres";

function renderTree(rootName: string, nodes: DependencyNode[]) {
  const nodesByParent: Record<string, DependencyNode[]> = {};
  nodes.forEach(n => {
    if (!nodesByParent[n.parent_table]) nodesByParent[n.parent_table] = [];
    nodesByParent[n.parent_table]?.push(n);
  });

  function print(tableName: string, prefix: string, isLast: boolean) {
    const children = nodesByParent[tableName] || [];
    children.forEach((child, i) => {
      const isChildLast = i === children.length - 1;
      const marker = isChildLast ? "└── " : "├── ";
      const unsafe = ["CASCADE", "SET_NULL", "SET_DEFAULT"].includes(child.delete_action);
      const color = unsafe ? pc.red : pc.cyan;

      console.log(`${prefix}${marker}${color(child.table_name)} ${pc.gray(`(${child.column_name})`)}`);
      print(child.table_name, prefix + (isChildLast ? "    " : "│   "), isChildLast);
    });
  }

  print(rootName, "", true);
}

/**
 * Visualizes the recursive foreign-key graph.
 */
export async function graphAction(options: {
  table: string,
  url?: string,
  schema?: string,
  maxDepth: string,
}): Promise<void> {
  UI.header("Dependecy Graph Audit");

  const dbUrl = options.url || process.env.DATABASE_URL
  if (!dbUrl) exitWithError("Database URL required.", "Pass --url or set DATABASE_URL env.");

  let appSchema = options.schema;
  if (!appSchema) {
    try {
      const config = await readWorkerConfig(process.env);
      appSchema = config.database.app_schema;
    } catch (err) {
      exitWithError("Schema missing.", "Provide --schema or ensure compliance.worker.yml exists.");
    }
  }

  const maxDepth = parseInt(options.maxDepth, 10);
  const spinner = UI.spinner(`Crawling relationships for ${appSchema}.${options.table}...`);
  const sql = postgres(dbUrl);

  try {
    const nodes = await getDependencyGraph(sql, appSchema, options.table, {
      maxDepth,
      failOnUnsafeDeleteAction: false,
    });
    spinner.stop();

    if (nodes.length === 0) {
      UI.success("Leaf table detected: 0 downstream dependencies found.");
      return;
    }

    console.log(`\n${pc.bold(pc.white(options.table))}`);
    renderTree(options.table, nodes);

    const unsafe = nodes.filter((n) => ["CASCADE", "SET_NULL", "SET_DEFAULT"].includes(n.delete_action));
    if (unsafe.length > 0) {
      UI.error(`${unsafe.length} UNSAFE CONSTRAINTS FOUND`);
      unsafe.forEach(n => console.log(`   ${pc.red("✖")} ${n.table_name}.${n.column_name} — ON DELETE ${n.delete_action}`));
      UI.warn("Live execution will fail until these are converted to NO ACTION or RESTRICT.");
    } else {
      UI.success("Graph validation passed: All constraints are safe for anonymization.");
    }
  } catch (err) {
    spinner.fail("Graph crawl failed");
    exitWithError("Analysis error", err instanceof Error ? err.message : String(err));
  } finally {
    sql.end();
  }
}