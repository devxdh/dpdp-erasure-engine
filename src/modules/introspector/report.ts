import { formatQualifiedTable } from "./naming";
import type {
  IntrospectorDraft,
  IntrospectorReport,
  IntrospectorReportFinding,
  IntrospectorReportSummary,
} from "./types";

const HIGH_CONFIDENCE_THRESHOLD = 0.9;

function formatScore(value: number): string {
  return value.toFixed(3);
}

function findingKey(finding: IntrospectorReportFinding): string {
  return `${finding.table}.${finding.column}`;
}

function sortFindings(
  left: IntrospectorReportFinding,
  right: IntrospectorReportFinding
): number {
  const byConfidence = right.confidence - left.confidence;
  if (byConfidence !== 0) {
    return byConfidence;
  }

  return findingKey(left).localeCompare(findingKey(right));
}

/**
 * Builds a stable developer review report from an introspector draft.
 *
 * @param draft - Static DAG, PII taxonomy, and schema metadata produced by the introspector.
 * @returns A report object suitable for CLI output, JSON export, or Markdown review artifacts.
 */
export function buildIntrospectorReport(draft: IntrospectorDraft): IntrospectorReport {
  const findings = draft.targets.flatMap((target) =>
    target.piiColumns.map((column): IntrospectorReportFinding => ({
      table: formatQualifiedTable(target.table),
      column: column.column,
      dataType: column.dataType,
      confidence: column.confidence,
      metadataScore: column.metadataScore,
      contentMatchRatio: column.contentMatchRatio,
      sampleSize: column.sampleSize,
      matchedSignatures: column.matchedSignatures,
    }))
  ).sort(sortFindings);

  const tablesWithPii = new Set(findings.map((finding) => finding.table));
  const summary: IntrospectorReportSummary = {
    rootTable: formatQualifiedTable(draft.root),
    generatedAt: draft.generatedAt,
    schemaHash: draft.schemaHash,
    targetCount: draft.targets.length,
    tablesWithPii: tablesWithPii.size,
    piiColumnCount: findings.length,
    highConfidenceCount: findings.filter((finding) => finding.confidence >= HIGH_CONFIDENCE_THRESHOLD).length,
    reviewRequiredCount: findings.filter((finding) => finding.confidence < HIGH_CONFIDENCE_THRESHOLD).length,
    potentialLogicalLinkCount: draft.potentialLogicalLinks.length,
  };

  return {
    summary,
    findings,
    potentialLogicalLinks: draft.potentialLogicalLinks,
    nextSteps: [
      "Review every PII column and potential logical link with the application owner.",
      "Copy reviewed targets into compliance.worker.yml and complete legal_attestation.",
      "Run avantii-worker check-integrity before allowing live worker boot.",
      "Sign the reviewed manifest with avantii-worker sign after DPO approval.",
    ],
  };
}

/**
 * Renders a Markdown report for DPO/developer review.
 *
 * @param report - Report model created by `buildIntrospectorReport`.
 * @returns Markdown content containing summary, findings, review warnings, and next steps.
 */
export function renderIntrospectorMarkdown(report: IntrospectorReport): string {
  const lines = [
    "# Avantii Introspector Report",
    "",
    "## Summary",
    "",
    `- Root table: \`${report.summary.rootTable}\``,
    `- Generated at: \`${report.summary.generatedAt}\``,
    `- Schema hash: \`${report.summary.schemaHash}\``,
    `- DAG targets: ${report.summary.targetCount}`,
    `- Tables with PII: ${report.summary.tablesWithPii}`,
    `- PII columns: ${report.summary.piiColumnCount}`,
    `- High-confidence findings: ${report.summary.highConfidenceCount}`,
    `- Review-required findings: ${report.summary.reviewRequiredCount}`,
    `- Potential logical links: ${report.summary.potentialLogicalLinkCount}`,
    "",
    "## PII Findings",
    "",
  ];

  if (report.findings.length === 0) {
    lines.push("No PII columns crossed the configured confidence threshold.", "");
  } else {
    lines.push("| Table | Column | Type | Confidence | Metadata | Content | Signatures |");
    lines.push("| --- | --- | --- | ---: | ---: | ---: | --- |");
    for (const finding of report.findings) {
      lines.push([
        `| \`${finding.table}\``,
        `\`${finding.column}\``,
        `\`${finding.dataType}\``,
        formatScore(finding.confidence),
        formatScore(finding.metadataScore),
        formatScore(finding.contentMatchRatio),
        finding.matchedSignatures.length > 0 ? finding.matchedSignatures.join(", ") : "metadata",
        "|",
      ].join(" "));
    }
    lines.push("");
  }

  lines.push("## Potential Logical Links", "");
  if (report.potentialLogicalLinks.length === 0) {
    lines.push("None detected.", "");
  } else {
    for (const link of report.potentialLogicalLinks) {
      lines.push(
        `- \`${formatQualifiedTable(link.sourceTable)}.${link.column}\` <-> ` +
        `\`${formatQualifiedTable(link.targetTable)}.${link.column}\`: ${link.reason}`
      );
    }
    lines.push("");
  }

  lines.push("## Next Steps", "");
  for (const step of report.nextSteps) {
    lines.push(`- ${step}`);
  }
  lines.push("");

  return lines.join("\n");
}

/**
 * Renders report JSON with deterministic indentation for CI artifacts.
 *
 * @param report - Report model created by `buildIntrospectorReport`.
 * @returns Pretty-printed JSON report.
 */
export function renderIntrospectorJson(report: IntrospectorReport): string {
  return `${JSON.stringify(report, null, 2)}\n`;
}
