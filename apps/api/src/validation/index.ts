import { ZodError } from "zod";
import type { $ZodIssue } from "zod/v4/core";

/**
 * Structured validation issue returned to API clients for actionable remediation.
 */
export interface ApiValidationIssue {
  path: string;
  param: string;
  code: string;
  message: string;
}

function formatIssuePath(path: PropertyKey[]): string {
  if (path.length === 0) {
    return "<root>";
  }

  return path.reduce<string>((accumulator, segment) => {
    if (typeof segment === "number") {
      return `${accumulator}[${segment}]`;
    }

    return accumulator.length > 0 ? `${accumulator}.${String(segment)}` : String(segment);
  }, "");
}

function toValidationIssue(issue: $ZodIssue): ApiValidationIssue {
  const path = formatIssuePath(issue.path);
  return {
    path,
    param: path,
    code: issue.code,
    message: issue.message,
  };
}

/**
 * Converts a Zod validation error into a stable, client-facing issue list.
 *
 * @param error - Zod parse/validation error emitted by request boundary validation.
 * @returns Flat issue list with normalized parameter paths and messages.
 */
export function formatZodIssues(error: ZodError): ApiValidationIssue[] {
  return error.issues.map(toValidationIssue);
}

/**
 * Produces a concise summary for top-level validation failures while retaining the full issue list separately.
 *
 * @param error - Zod validation error to summarize.
 * @returns Human-readable summary suitable for `problem.detail`.
 */
export function summarizeZodError(error: ZodError): string {
  const issues = formatZodIssues(error);
  if (issues.length === 0) {
    return "Request validation failed.";
  }

  if (issues.length === 1) {
    const issue = issues[0];
    if (!issue) {
      return "Request validation failed.";
    }
    return `${issue.param}: ${issue.message}`;
  }

  return `Request validation failed with ${issues.length} issue(s).`;
}
