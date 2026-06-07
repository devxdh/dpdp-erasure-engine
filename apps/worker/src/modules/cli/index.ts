#!/usr/bin/env bun
import { Command } from "commander";
import pc from "picocolors";

const pkgPath = new URL("../../../package.json", import.meta.url);
const pkg = await Bun.file(pkgPath).json();

const program = new Command();

program
  .name("worker")
  .description("Compliance Engine Operator CLI - Safe & Professional Data Auditing.")
  .version(pkg.version);

program
  .command("init")
  .description("Interactively provision a legal compliance manifest.")
  .action(async () => {
    const { initAction } = await import("./init")
  });

program
  .command("scan")
  .description("Metadata-only schema scan for potential PII columns.")
  .option("-u, --url <url>", "PostgreSQL Connection DSN")
  .option("-s, --schema <schema>", "Database schema to target")
  .option("--threshold <score>", "Metadata confidence threshold", "0.6")
  .option("--json <path>", "Write machine-readable scan findings")
  .action(async (options) => {
    const { scanAction } = await import("./scan");
    await scanAction(options);
  });

program
  .command("introspect")
  .description("Offline compile FK DAG and draft PII mappings without mutating data.")
  .option("-u, --url <url>", "PostgreSQL Connection DSN")
  .option("-r, --root <table>", "Root table, e.g. public.users")
  .option("-s, --schema <schema>", "Default database schema")
  .option("-o, --output <path>", "Draft YAML output path", "compliance.worker.yml.draft")
  .option("-d, --max-depth <depth>", "Recursive FK depth breaker", "32")
  .option("--sample-percent <percent>", "Postgres TABLESAMPLE SYSTEM percentage", "1")
  .option("--sample-limit <rows>", "Maximum sampled rows per column", "100")
  .option("--threshold <score>", "PII confidence threshold", "0.75")
  .option("--report <path>", "Markdown review report path")
  .option("--json-report <path>", "Machine-readable JSON review report path")
  .option("--fail-on-review", "Exit non-zero when findings need human review")
  .option("-c, --config <path>", "Manifest path for --verify-only", "compliance.worker.yml")
  .option("--verify-only", "Verify schema hash instead of generating a draft")
  .action(async (options) => {
    const { introspectAction } = await import("./introspector");
    await introspectAction(options);
  });

program
  .command("verify-schema")
  .description("CI/CD gate: fail when live schema differs from legal attestation hash.")
  .option("-c, --config <path>", "Manifest path", "compliance.worker.yml")
  .option("-u, --url <url>", "PostgreSQL Connection DSN")
  .action(async (options) => {
    const { verifySchemaAction } = await import("./verify-schema");
    await verifySchemaAction(options);
  });

program
  .command("graph")
  .description("Visualize recursive table dependencies for a specific root.")
  .requiredOption("-t, --table <table>", "Root table name")
  .option("-u, --url <url>", "PostgreSQL Connection DSN")
  .option("-s, --schema <schema>", "Database schema to target")
  .option("-d, --max-depth <depth>", "Safety recursion limit", "32")
  .action(async (options) => {
    const { graphAction } = await import("./graph");
    await graphAction(options);
  });

program
  .command("inspect")
  .description("Inspect a worker manifest and summarize legal/configuration coverage.")
  .option("-c, --config <path>", "Manifest path", "compliance.worker.yml")
  .action(async (options) => {
    const { inspectAction } = await import("./inspect");
    await inspectAction(options);
  });

program
  .command("check-integrity")
  .description("Fail closed unless schema hash and compiled DAG match the live database.")
  .option("-c, --config <path>", "Manifest path", "compliance.worker.yml")
  .option("-u, --url <url>", "PostgreSQL Connection DSN")
  .action(async (options) => {
    const { checkIntegrityAction } = await import("./check-integrity");
    await checkIntegrityAction(options);
  });

program
  .command("verify")
  .description("Perform integrity checks and compute mandatory schema hashes.")
  .option("-c, --config <path>", "Manifest path", "compliance.worker.yml")
  .option("-u, --url <url>", "PostgreSQL Connection DSN")
  .action(async (options) => {
    const { verifyAction } = await import("./verify");
    await verifyAction(options);
  });

program
  .command("dry-run")
  .description("Simulate a vault operation without mutating production data.")
  .requiredOption("-i, --id <id>", "Root subject ID (e.g. 1042)")
  .option("-c, --config <path>", "Manifest path", "compliance.worker.yml")
  .option("-u, --url <url>", "PostgreSQL Connection DSN")
  .action(async (options) => {
    const { dryRunAction } = await import("./dry-run");
    await dryRunAction(options);
  });

program
  .command("keygen")
  .description("Provision Ed25519 keys for configuration signing.")
  .action(async () => {
    const { keygenAction } = await import("./keygen");
    await keygenAction();
  });

program
  .command("sign")
  .description("Apply a cryptographically secure signature to the manifest.")
  .option("-c, --config <path>", "Manifest path", "compliance.worker.yml")
  .option("-k, --key <path>", "Private key file path")
  .action(async (options) => {
    const { signAction } = await import("./sign");
    await signAction(options);
  });

program.on("command:*", () => {
  console.error(pc.red(`\nInvalid command: ${pc.bold(program.args.join(" "))}`));
  console.error(`Refer to ${pc.cyan("compliance-worker --help")} for available utilities.\n`);
  process.exit(1);
});

const rawArgs = process.argv.slice(2);

if (rawArgs.length === 0) {
  if (process.stdout.isTTY) {
    try {
      const { select } = await import("@inquirer/prompts");
      console.log(pc.cyan(`\n💼 Compliance Engine Operator Interactive Console [v${pkg.version}]`));

      const choice = await select({
        message: "Select a compliance operation utility to run:",
        choices: [
          { name: "Initialize legal compliance manifest (init)", value: "init" },
          { name: "Metadata-only schema scan for PII (scan)", value: "scan" },
          { name: "Offline compile FK DAG and draft mappings (introspect)", value: "introspect" },
          { name: "CI/CD check: Verify schema integrity (verify-schema)", value: "verify-schema" },
          { name: "Visualize recursive table dependencies (graph)", value: "graph" },
          { name: "Simulate an erasure/mutation safely (dry-run)", value: "dry-run" },
          { name: "Exit Console", value: "exit" },
        ],
      });

      if (choice === "exit") {
        process.exit(0);
      }

      const simulatedArgv: string[] = [
        Bun.argv[0] ?? "bun",
        Bun.argv[1] ?? import.meta.path,
        choice
      ];
      program.parse(simulatedArgv);

    } catch {
      process.exit(0);
    }
  } else {
    program.outputHelp();
    process.exit(0);
  }
} else {
  program.parse(process.argv);
}

program.parse();