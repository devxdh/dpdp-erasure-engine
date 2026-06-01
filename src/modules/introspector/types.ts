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

export interface VerifySchemaIntegrityOptions {
  sql: Sql;
  configPath: string;
  env?: Record<string, string | undefined>;
}