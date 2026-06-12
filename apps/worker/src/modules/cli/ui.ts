import pc from "picocolors";
import ora, { type Ora } from "ora";
import Table from "cli-table3";
import boxen from "boxen";

/**
 * Standardized UI components for the Compliance Worker CLI.
 * Designed for professional output in diverse terminal environments.
 */
export const UI = {
  header: (title: string) => {
    console.log(
      boxen(pc.bold(pc.cyan(`COMPLIANCE WORKER — ${title.toUpperCase()}`)), {
        padding: { top: 0, bottom: 0, left: 2, right: 2 },
        margin: { top: 1, bottom: 1 },
        borderStyle: "round",
        borderColor: "cyan",
      })
    );
  },

  divider: () => console.log(pc.gray("─".repeat(process.stdout.columns || 60))),

  spinner: (text: string): Ora => ora({ text, color: "cyan" }).start(),

  success: (msg: string) => console.log(`\n${pc.green("✔")} ${pc.bold(msg)}`),
  error: (msg: string) => console.error(`\n${pc.red("✖")} ${pc.bold(msg)}`),
  warn: (msg: string) => console.log(`\n${pc.yellow("⚠")} ${pc.bold(msg)}`),
  info: (msg: string) => console.log(`\n${pc.cyan("ℹ")} ${msg}`),

  step: (n: number, msg: string) => {
    console.log(`\n${pc.bold(pc.white(`${n}. ${msg}`))}`);
  },

  subStep: (msg: string, indent = 3) => {
    console.log(`${" ".repeat(indent)}${pc.gray("└─")} ${pc.white(msg)}`);
  },

  keyValue: (key: string, val: string) => {
    console.log(`   ${pc.gray(key.padEnd(20))}: ${pc.bold(val)}`);
  },

  table: (head: string[]) => {
    return new Table({
      head: head.map((h) => pc.bold(pc.white(h))),
      style: { head: [], border: ["gray"] },
    });
  },

  hint: (msg: string) => {
    console.log(pc.italic(pc.gray(`\nPRO-TIP: ${msg}`)));
  },
};

export function exitWithError(msg: string, detail?: string): never {
  UI.error(msg);
  if (detail) {
    console.error(pc.gray(`\n${pc.bold("Detail:")}\n${detail}\n`));
  }
  process.exit(1);
}
