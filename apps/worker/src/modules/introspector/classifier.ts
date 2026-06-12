import { fail } from "@/errors";
import type { ClassifierOptions, ColumnTaxonomy, DagTarget, QualifiedTable } from "./types";

const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder();
const MAX_FLATTEN_DEPTH = 10;

const SUPPORTED_DATA_TYPES = new Set([
  "text",
  "character varying",
  "varchar",
  "character",
  "char",
  "json",
  "jsonb",
  "uuid",
  "inet",
  "cidr",
  "macaddr",
  "macaddr8",
]);

const STRONG_METADATA_SCORE = 0.92;
const MEDIUM_METADATA_SCORE = 0.82;
const WEAK_METADATA_SCORE = 0.62;
const DEFAULT_THRESHOLD = 0.75;
const DEFAULT_SAMPLE_PERCENT = 1;
const DEFAULT_SAMPLE_LIMIT = 100;

const VERHOEFF_D = [
  [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
  [1, 2, 3, 4, 0, 6, 7, 8, 9, 5],
  [2, 3, 4, 0, 1, 7, 8, 9, 5, 6],
  [3, 4, 0, 1, 2, 8, 9, 5, 6, 7],
  [4, 0, 1, 2, 3, 9, 5, 6, 7, 8],
  [5, 9, 8, 7, 6, 0, 4, 3, 2, 1],
  [6, 5, 9, 8, 7, 1, 0, 4, 3, 2],
  [7, 6, 5, 9, 8, 2, 1, 0, 4, 3],
  [8, 7, 6, 5, 9, 3, 2, 1, 0, 4],
  [9, 8, 7, 6, 5, 4, 3, 2, 1, 0],
] as const;

const VERHOEFF_P = [
  [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
  [1, 5, 7, 6, 2, 8, 3, 0, 9, 4],
  [5, 8, 0, 3, 7, 9, 6, 1, 4, 2],
  [8, 9, 1, 6, 0, 4, 3, 5, 2, 7],
  [9, 4, 5, 3, 1, 2, 6, 8, 7, 0],
  [4, 2, 8, 6, 5, 7, 3, 9, 0, 1],
  [2, 7, 9, 3, 8, 0, 6, 4, 1, 5],
  [7, 0, 4, 6, 9, 1, 3, 2, 5, 8],
] as const;

interface ColumnRow {
  table_schema: string;
  table_name: string;
  column_name: string;
  data_type: string;
}

interface SampleRow {
  sample_value: unknown;
}

interface JsonLeafEntry {
  path: string;
  value: string;
}

interface ContentSignature {
  name: string;
  pattern: RegExp;
  weight: number;
  validate?: (value: string) => boolean;
  requiresMetadata?: boolean;
  metadataHints?: RegExp[];
}

const CONTENT_SIGNATURES: ContentSignature[] = [
  { name: "aadhaar", pattern: /^[2-9][0-9]{3}[\s-]?[0-9]{4}[\s-]?[0-9]{4}$/, weight: 0.98, validate: validateAadhaar },
  { name: "pan", pattern: /^[A-Z]{5}[0-9]{4}[A-Z]$/, weight: 0.96, validate: validatePan },
  { name: "gstin", pattern: /^[0-9]{2}[A-Z]{5}[0-9]{4}[A-Z][1-9A-Z]Z[0-9A-Z]$/, weight: 0.94, validate: validateGstin },
  { name: "credit_card", pattern: /^(?:\d[ -]?){13,19}$/, weight: 0.97, validate: validateLuhn },
  { name: "email", pattern: /^[^\s@]+@[^\s@]+\.[^\s@]+$/, weight: 0.95 },
  { name: "upi", pattern: /^[a-zA-Z0-9.\-_]{2,256}@[a-zA-Z]{2,64}$/, weight: 0.93 },
  { name: "ifsc", pattern: /^[A-Z]{4}0[A-Z0-9]{6}$/, weight: 0.9 },
  { name: "indian_mobile", pattern: /^(?:(?:\+|0{0,2})91(\s*[-]\s*)?|[0]?)?[6789]\d{9}$/, weight: 0.9 },
  { name: "indian_passport", pattern: /^[A-Z][0-9]{7}$/, weight: 0.88 },
  { name: "voter_epic", pattern: /^[A-Z]{3}[0-9]{7}$/, weight: 0.88 },
  { name: "ipv4", pattern: /^(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)$/, weight: 0.82 },
  { name: "ipv6", pattern: /^[0-9A-Fa-f:.]+$/, weight: 0.82, validate: validateIpv6 },
  { name: "mac_address", pattern: /^(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}$/, weight: 0.82 },
  {
    name: "bank_account",
    pattern: /^\d{9,18}$/,
    weight: 0.78,
    requiresMetadata: true,
    metadataHints: [/bank/i, /account/i, /iban/i],
  },
  {
    name: "date_of_birth",
    pattern: /^(?:19|20)\d{2}[-/](?:0[1-9]|1[0-2])[-/](?:0[1-9]|[12]\d|3[01])$/,
    weight: 0.82,
    requiresMetadata: true,
    metadataHints: [/dob/i, /birth/i, /date_of_birth/i],
  },
  {
    name: "indian_driving_license",
    pattern: /^[A-Z]{2}[-\s]?[0-9]{2}[-\s]?[0-9]{11}$/,
    weight: 0.84,
    requiresMetadata: true,
    metadataHints: [/driving/i, /licen[cs]e/i, /(^|_)dl(_|$)/i],
  },
  {
    name: "indian_pin_code",
    pattern: /^[1-9][0-9]{5}$/,
    weight: 0.78,
    requiresMetadata: true,
    metadataHints: [/pincode/i, /pin_code/i, /postal/i, /zip/i],
  },
];

const METADATA_PATTERNS: Array<{ pattern: RegExp; score: number }> = [
  { pattern: /(^|_)(full_name|first_name|last_name|middle_name|surname|given_name|display_name)($|_)/i, score: STRONG_METADATA_SCORE },
  { pattern: /(^|_)name($|_)/i, score: MEDIUM_METADATA_SCORE },
  { pattern: /(^|_)(password|passwd|pwd|secret|token|api_key|access_token|refresh_token|auth_token|hash|salt)($|_)/i, score: STRONG_METADATA_SCORE },
  { pattern: /(^|_)(role|roles|permission|permissions|group|groups|acl|access_level)($|_)/i, score: WEAK_METADATA_SCORE },
  { pattern: /(^|_)(email|e_mail|email_address|mail_address|contact_email)($|_)/i, score: STRONG_METADATA_SCORE },
  { pattern: /(^|_)(phone|mobile|msisdn|telephone|contact_number|whatsapp)(_number|_no)?($|_)/i, score: STRONG_METADATA_SCORE },
  { pattern: /(^|_)(aadhaar|aadhar|uidai)(_number|_no|_id)?($|_)/i, score: STRONG_METADATA_SCORE },
  { pattern: /(^|_)(pan|pan_number|pan_no)($|_)/i, score: STRONG_METADATA_SCORE },
  { pattern: /(^|_)(gstin|gst_number|gst_no)($|_)/i, score: STRONG_METADATA_SCORE },
  { pattern: /(^|_)(credit_card|debit_card|card_number|card_no|cc_number|cc_no)($|_)/i, score: STRONG_METADATA_SCORE },
  { pattern: /(^|_)(upi|vpa|upi_id|upi_address)($|_)/i, score: STRONG_METADATA_SCORE },
  { pattern: /(^|_)(ifsc|ifsc_code)($|_)/i, score: STRONG_METADATA_SCORE },
  { pattern: /(^|_)(passport|passport_number|passport_no)($|_)/i, score: STRONG_METADATA_SCORE },
  { pattern: /(^|_)(voter|voter_id|epic|epic_number|epic_no)($|_)/i, score: STRONG_METADATA_SCORE },
  { pattern: /(^|_)(dob|date_of_birth|birth_date|birthday)($|_)/i, score: MEDIUM_METADATA_SCORE },
  { pattern: /(^|_)(ip|ip_address|ipv4|ipv6|mac|mac_address)($|_)/i, score: MEDIUM_METADATA_SCORE },
  { pattern: /(^|_)(bank_account|account_number|account_no|iban|swift)($|_)/i, score: MEDIUM_METADATA_SCORE },
  { pattern: /(^|_)(driving_license|driving_licence|license_number|licence_number|dl_number|dl_no)($|_)/i, score: MEDIUM_METADATA_SCORE },
  { pattern: /(^|_)(address|street|postal_code|zip_code|pin_code|pincode)($|_)/i, score: WEAK_METADATA_SCORE },
  { pattern: /(^|_)(device_fingerprint|device_id|advertising_id|gaid|idfa)($|_)/i, score: WEAK_METADATA_SCORE },
  { pattern: /(^|_)(document_number|identity_number|id_number)($|_)/i, score: WEAK_METADATA_SCORE },
];

function qualifiedKey(table: QualifiedTable): string {
  return `${table.schema}.${table.table}`;
}

export function metadataScore(columnName: string): number {
  const normalized = columnName.toLowerCase();
  return METADATA_PATTERNS.reduce(
    (score, candidate) => candidate.pattern.test(normalized) ? Math.max(score, candidate.score) : score,
    0
  );
}

function digitsOnly(value: string): string {
  return value.replace(/\D/g, "");
}

/**
 * Validates an Aadhaar candidate with the Verhoeff checksum.
 *
 * @param value - Aadhaar candidate, with or without spaces.
 * @returns `true` when the final digit satisfies Verhoeff validation.
 */
export function validateAadhaar(value: string): boolean {
  const digits = digitsOnly(value);
  if (!/^[2-9]\d{11}$/.test(digits) || /^(\d)\1+$/.test(digits)) {
    return false;
  }

  let checksum = 0;
  const reversed = digits.split("").reverse();
  for (let index = 0; index < reversed.length; index += 1) {
    const digit = Number(reversed[index]);
    checksum = VERHOEFF_D[checksum]![VERHOEFF_P[index % 8]![digit]!]!;
  }

  return checksum === 0;
}

/**
 * Validates a generic account number candidate with the Luhn checksum.
 *
 * @param value - Candidate number, optionally separated by spaces or hyphens.
 * @returns `true` when the candidate passes Luhn validation.
 */
export function validateLuhn(value: string): boolean {
  const digits = digitsOnly(value);
  if (!/^\d{13,19}$/.test(digits) || /^(\d)\1+$/.test(digits)) {
    return false;
  }

  let sum = 0;
  let doubleDigit = false;
  for (let index = digits.length - 1; index >= 0; index -= 1) {
    let digit = Number(digits[index]);
    if (doubleDigit) {
      digit *= 2;
      if (digit > 9) {
        digit -= 9;
      }
    }
    sum += digit;
    doubleDigit = !doubleDigit;
  }

  return sum % 10 === 0;
}

/**
 * Applies structural PAN validation beyond the regex.
 *
 * The Indian PAN format does not expose a public checksum algorithm. This validator therefore
 * enforces the high-signal holder-status character and terminal alphabetic check character so
 * junk alphanumeric IDs are not treated as PAN solely because they match length and shape.
 *
 * @param value - Uppercase PAN candidate.
 * @returns `true` when status and terminal check character are structurally valid.
 */
export function validatePan(value: string): boolean {
  const normalized = value.trim().toUpperCase();
  return /^[A-Z]{5}[0-9]{4}[A-Z]$/.test(normalized) && "PCHFATBLJG".includes(normalized[3]!);
}

/**
 * Applies high-signal GSTIN structural validation.
 *
 * GSTIN embeds a PAN in positions 3-12. The final GSTIN checksum is not
 * universally reliable in legacy test data, so the classifier uses shape plus
 * embedded PAN validation to avoid treating arbitrary 15-character IDs as GSTIN.
 *
 * @param value - GSTIN candidate.
 * @returns `true` when the candidate has valid GSTIN shape and embedded PAN structure.
 */
export function validateGstin(value: string): boolean {
  const normalized = value.trim().toUpperCase();
  return /^[0-9]{2}[A-Z]{5}[0-9]{4}[A-Z][1-9A-Z]Z[0-9A-Z]$/.test(normalized) &&
    validatePan(normalized.slice(2, 12));
}

function validateIpv6(value: string): boolean {
  if (!value.includes(":")) {
    return false;
  }

  try {
    return new URL(`http://[${value}]/`).hostname.length > 0;
  } catch {
    return false;
  }
}

function flattenJsonLeaves(value: unknown): string[] {
  return flattenJsonLeafEntries(value).map((entry) => entry.value);
}

function flattenJsonLeafEntries(value: unknown): JsonLeafEntry[] {
  const output: JsonLeafEntry[] = [];
  const stack: Array<{ path: string; value: unknown; depth: number }> = [{ path: "", value, depth: 0 }];

  while (stack.length > 0) {
    const current = stack.pop()!;
    if (current.value === null || current.value === undefined || current.depth > MAX_FLATTEN_DEPTH) {
      continue;
    }

    if (
      typeof current.value === "string" ||
      typeof current.value === "number" ||
      typeof current.value === "boolean"
    ) {
      output.push({ path: current.path, value: String(current.value) });
      continue;
    }

    if (Array.isArray(current.value)) {
      for (let index = current.value.length - 1; index >= 0; index -= 1) {
        stack.push({
          path: current.path ? `${current.path}[${index}]` : `[${index}]`,
          value: current.value[index],
          depth: current.depth + 1,
        });
      }
      continue;
    }

    if (typeof current.value === "object") {
      const entries = Object.entries(current.value as Record<string, unknown>);
      for (let index = entries.length - 1; index >= 0; index -= 1) {
        const [key, child] = entries[index]!;
        stack.push({
          path: current.path ? `${current.path}.${key}` : key,
          value: child,
          depth: current.depth + 1,
        });
      }
    }
  }

  return output;
}

function extractLeafEntries(value: unknown, dataType: string): JsonLeafEntry[] {
  if (value === null || value === undefined) {
    return [];
  }

  if (dataType === "json" || dataType === "jsonb") {
    if (typeof value === "string") {
      try {
        return flattenJsonLeafEntries(JSON.parse(value));
      } catch {
        return [{ path: "", value }];
      }
    }

    return flattenJsonLeafEntries(value);
  }

  return [{ path: "", value: String(value) }];
}

export function extractLeafValues(value: unknown, dataType: string): string[] {
  return extractLeafEntries(value, dataType).map((entry) => entry.value);
}

function signatureHasMetadataSupport(signature: ContentSignature, columnName: string): boolean {
  if (!signature.requiresMetadata) {
    return true;
  }

  const normalized = columnName.toLowerCase();
  return (signature.metadataHints ?? []).some((pattern) => pattern.test(normalized));
}

function classifyLeafDetailed(value: string, columnName: string = ""): ContentSignature[] {
  const bytes = textEncoder.encode(value.trim());
  try {
    const normalized = textDecoder.decode(bytes).trim();
    // Split into tokens and strip leading/trailing punctuation so regexes can match substrings
    const tokens = normalized.split(/\s+/).map((t) => t.replace(/^[^\w\+]+|[^\w]+$/g, ""));
    const candidates = Array.from(new Set([normalized, ...tokens])).filter((t) => t.length > 0);

    const matches = new Set<ContentSignature>();
    for (const candidate of candidates) {
      for (const signature of CONTENT_SIGNATURES) {
        if (
          signatureHasMetadataSupport(signature, columnName) &&
          signature.pattern.test(candidate) &&
          (!signature.validate || signature.validate(candidate))
        ) {
          matches.add(signature);
        }
      }
    }
    return Array.from(matches);
  } finally {
    bytes.fill(0);
  }
}

export function classifyLeaf(value: string, columnName: string = ""): string[] {
  return classifyLeafDetailed(value, columnName).map((signature) => signature.name);
}

async function getColumns(sql: ClassifierOptions["sql"], targets: DagTarget[]): Promise<ColumnRow[]> {
  const targetKeys = targets.map((target) => `${target.table.schema}.${target.table.table}`);

  if (targetKeys.length === 0) {
    return [];
  }

  return sql<ColumnRow[]>`
    SELECT table_schema, table_name, column_name, data_type
    FROM information_schema.columns
    WHERE table_schema || '.' || table_name = ANY(${targetKeys})
      AND data_type = ANY(${Array.from(SUPPORTED_DATA_TYPES)})
    ORDER BY table_schema, table_name, ordinal_position
  `;
}

async function sampleColumn(
  sql: ClassifierOptions["sql"],
  table: QualifiedTable,
  column: string,
  samplePercent: number,
  sampleLimit: number
): Promise<SampleRow[]> {
  const sampledRows = await sql<SampleRow[]>`
    SELECT ${sql(column)} AS sample_value
    FROM ${sql(table.schema)}.${sql(table.table)} TABLESAMPLE SYSTEM (${samplePercent})
    WHERE ${sql(column)} IS NOT NULL
    LIMIT ${sampleLimit}
  `;

  if (sampledRows.length > 0) {
    return sampledRows;
  }

  return sql<SampleRow[]>`
    SELECT ${sql(column)} AS sample_value
    FROM ${sql(table.schema)}.${sql(table.table)}
    WHERE ${sql(column)} IS NOT NULL
    LIMIT ${sampleLimit}
  `;
}

/**
 * Classifies likely PII columns using metadata taxonomy and bounded block sampling.
 *
 * @param options - SQL handle, DAG targets, sampling controls, and confidence threshold.
 * @returns PII columns grouped by qualified table.
 */
export async function classifyDagTargets(options: ClassifierOptions): Promise<Map<string, ColumnTaxonomy[]>> {
  const samplePercent = options.samplePercent ?? DEFAULT_SAMPLE_PERCENT;
  const sampleLimit = options.sampleLimit ?? DEFAULT_SAMPLE_LIMIT;
  const threshold = options.threshold ?? DEFAULT_THRESHOLD;

  if (samplePercent <= 0 || samplePercent > 100) {
    fail({
      code: "INTROSPECTOR_SAMPLE_INVALID",
      title: "Invalid sample percentage",
      detail: "Introspector samplePercent must be greater than 0 and less than or equal to 100.",
      category: "validation",
      retryable: false,
      context: { samplePercent },
    });
  }

  if (!Number.isInteger(sampleLimit) || sampleLimit < 1 || sampleLimit > 1000) {
    fail({
      code: "INTROSPECTOR_SAMPLE_INVALID",
      title: "Invalid sample limit",
      detail: "Introspector sampleLimit must be an integer between 1 and 1000.",
      category: "validation",
      retryable: false,
      context: { sampleLimit },
    });
  }

  const findings = new Map<string, ColumnTaxonomy[]>();
  const columns = await getColumns(options.sql, options.targets);

  for (const column of columns) {
    const table = { schema: column.table_schema, table: column.table_name };
    const rows = await sampleColumn(options.sql, table, column.column_name, samplePercent, sampleLimit);
    let matchedRows = 0;
    const matchedSignatures = new Set<string>();
    let jsonPathMetadataScore = 0;

    for (const row of rows) {
      const leaves = extractLeafEntries(row.sample_value, column.data_type);
      let rowMatched = false;
      try {
        for (const leaf of leaves) {
          const leafMetadataScore = leaf.path ? metadataScore(leaf.path.replace(/[.[\]]+/g, "_")) : 0;
          if (leafMetadataScore > 0) {
            jsonPathMetadataScore = Math.max(jsonPathMetadataScore, leafMetadataScore);
            if (leafMetadataScore >= threshold) {
              rowMatched = true;
              matchedSignatures.add(`json_path:${leaf.path}`);
            }
          }

          const matches = classifyLeafDetailed(leaf.value, `${column.column_name}_${leaf.path}`);
          if (matches.length > 0) {
            rowMatched = true;
            for (const match of matches) {
              matchedSignatures.add(match.name);
            }
          }
        }
      } finally {
        leaves.length = 0;
      }

      if (rowMatched) {
        matchedRows += 1;
      }
    }

    const sampleSize = rows.length;
    const contentMatchRatio = sampleSize === 0 ? 0 : matchedRows / sampleSize;
    const meta = Math.max(metadataScore(column.column_name), jsonPathMetadataScore);
    const signatureWeight = Array.from(matchedSignatures).reduce((weight, signatureName) => {
      const signature = CONTENT_SIGNATURES.find((candidate) => candidate.name === signatureName);
      return Math.max(weight, signature?.weight ?? 0);
    }, 0);
    const contentConfidence = contentMatchRatio * signatureWeight;
    const confidence = Math.max(
      meta >= threshold ? meta : 0,
      contentConfidence,
      0.3 * meta + 0.7 * contentConfidence
    );

    if (confidence >= threshold) {
      const key = qualifiedKey(table);
      const existing = findings.get(key) ?? [];
      existing.push({
        table,
        column: column.column_name,
        dataType: column.data_type,
        metadataScore: meta,
        contentMatchRatio,
        confidence,
        sampleSize,
        matchedSignatures: Array.from(matchedSignatures).sort(),
      });
      findings.set(key, existing);
    }
  }

  return findings;
}
