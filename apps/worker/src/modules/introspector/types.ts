import type { Sql } from "@/types";

export interface QualifiedTable {
  schema: string;
  table: string;
}

export interface DagTarget {
  table: QualifiedTable;
  parentTable: QualifiedTable | null;
  constraintName: string | null;
  childColumns: string[];
  parentColumns: string[];
  depth: number;
  fkCondition: string;
}

export interface PotentialLogicalLink {
  sourceTable: QualifiedTable;
  targetTable: QualifiedTable;
  column: string;
  reason: string;
}

export interface ColumnTaxonomy {
  table: QualifiedTable;
  column: string;
  dataType: string;
  metadataScore: number;
  contentMatchRatio: number;
  confidence: number;
  sampleSize: number;
  matchedSignatures: string[];
}

export interface RunIntrospectorOptions {
  sql: Sql;
  rootTable: string;
  defaultSchema?: string;
  maxDepth?: number;
  samplePercent?: number;
  sampleLimit?: number;
  threshold?: number;
  generatedAt?: Date
}

export interface IntrospectorTargetDraft {
  table: QualifiedTable;
  parentTable: QualifiedTable | null;
  fkCondition: string;
  childColumns: string[];
  parentColumns: string[];
  piiColumns: ColumnTaxonomy[];
  depth: number;
}

export interface IntrospectorDraft {
  root: QualifiedTable;
  maxDepth: number;
  generatedAt: string;
  schemaHash: string;
  targets: IntrospectorTargetDraft[];
  potentialLogicalLinks: PotentialLogicalLink[];
}

export interface CompileDagOptions {
  sql: Sql;
  rootTable: string;
  defaultSchema?: string;
  maxDepth?: number;
}

export interface ClassifierOptions {
  sql: Sql;
  targets: DagTarget[];
  samplePercent?: number;
  sampleLimit?: number;
  threshold?: number;
}

export interface IntrospectorReportFinding {
  table: string;
  column: string;
  dataType: string;
  confidence: number;
  metadataScore: number;
  contentMatchRatio: number;
  sampleSize: number;
  matchedSignatures: string[];
}

export interface IntrospectorReportSummary {
  rootTable: string;
  generatedAt: string;
  schemaHash: string;
  targetCount: number;
  tablesWithPii: number;
  piiColumnCount: number;
  highConfidenceCount: number;
  reviewRequiredCount: number;
  potentialLogicalLinkCount: number;
}

export interface IntrospectorReport {
  summary: IntrospectorReportSummary;
  findings: IntrospectorReportFinding[];
  potentialLogicalLinks: PotentialLogicalLink[];
  nextSteps: string[];
}

export interface VerifySchemaIntegrityOptions {
  sql: Sql;
  configPath: string;
  env?: Record<string, string | undefined>;
}

export interface IntrospectorCliOptions {
  url?: string;
  root?: string;
  schema?: string;
  output?: string;
  maxDepth?: string;
  samplePercent?: string;
  sampleLimit?: string;
  threshold?: string;
  config?: string;
  verifyOnly?: boolean;
  report?: string;
  jsonReport?: string;
  failOnReview?: boolean;
}
