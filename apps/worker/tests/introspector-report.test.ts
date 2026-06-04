import { describe, expect, it } from "vitest";
import {
  type IntrospectorDraft,
  buildIntrospectorReport,
  renderIntrospectorJson,
  renderIntrospectorMarkdown,
} from "@modules/introspector";

const draft: IntrospectorDraft = {
  root: { schema: "public", table: "users" },
  maxDepth: 32,
  generatedAt: "2026-05-11T00:00:00.000Z",
  schemaHash: "a".repeat(64),
  potentialLogicalLinks: [
    {
      sourceTable: { schema: "public", table: "orders" },
      targetTable: { schema: "public", table: "support_events" },
      column: "user_id",
      reason: "Both tables expose user_id but no physical foreign key was found.",
    },
  ],
  targets: [
    {
      table: { schema: "public", table: "users" },
      parentTable: null,
      fkCondition: "ROOT",
      childColumns: [],
      parentColumns: [],
      depth: 0,
      piiColumns: [
        {
          table: { schema: "public", table: "users" },
          column: "email",
          dataType: "text",
          metadataScore: 0.92,
          contentMatchRatio: 1,
          confidence: 0.95,
          sampleSize: 100,
          matchedSignatures: ["email"],
        },
        {
          table: { schema: "public", table: "users" },
          column: "bank_account_number",
          dataType: "text",
          metadataScore: 0.82,
          contentMatchRatio: 0,
          confidence: 0.82,
          sampleSize: 0,
          matchedSignatures: [],
        },
      ],
    },
  ],
};

describe("Introspector report rendering", () => {
  it("builds actionable report summaries without leaking sampled values", () => {
    const report = buildIntrospectorReport(draft);

    expect(report.summary.rootTable).toBe("public.users");
    expect(report.summary.piiColumnCount).toBe(2);
    expect(report.summary.highConfidenceCount).toBe(1);
    expect(report.summary.reviewRequiredCount).toBe(1);
    expect(report.summary.potentialLogicalLinkCount).toBe(1);
    expect(report.findings.map((finding) => finding.column)).toEqual(["email", "bank_account_number"]);
    expect(JSON.stringify(report)).not.toContain("alpha@example.com");
  });

  it("renders deterministic Markdown and JSON artifacts for developer review", () => {
    const report = buildIntrospectorReport(draft);
    const markdown = renderIntrospectorMarkdown(report);
    const json = renderIntrospectorJson(report);

    expect(markdown).toContain("# Compliance Introspector Report");
    expect(markdown).toContain("`public.users`");
    expect(markdown).toContain("Potential Logical Links");
    expect(markdown).toContain("compliance-worker check-integrity");
    expect(JSON.parse(json)).toMatchObject({
      summary: {
        rootTable: "public.users",
        piiColumnCount: 2,
      },
    });
  });
});
