import type { ZodError } from "zod";
import type { $ZodIssue } from "zod/v4/core";

/**
 * Structured worker-side validation issue retained in problem details and log
 */
export interface WorkerValidationIssue {
  path: string;
  param: string;
  code: string;
  message: string;
};

function formatIssuePath(path: PropertyKey[]): string {
  if (path.length === 0) {
    return "<root>";
  };

  return path.reduce<string>((accumulator, segment) => {
    if (typeof segment === "number") {
      return `${accumulator}[${segment}]`;
    }

    return accumulator.length > 0 ? `${accumulator}.${String(segment)}` : String(segment);

  }, "");
}

function toValidateIssue(issue: $ZodIssue) {
  const path = formatIssuePath(issue.path);
  return {
    path,
    param: path,
    code: issue.code,
    message: issue.message
  };
}

/**
 * Converts a Zod validation error into a deterministic issue list for worker diagnostics.
 *
 * @param error - Validation error raised by worker configuration or protocol parsing.
 * @returns Flat issue list with normalized parameter paths and messages.
 */
export function formatZodIssues(error: ZodError) {
  return error.issues.map(toValidateIssue);
};

/**
 * Produces a compact summary for worker validation failures while preserving the full issue list.
 *
 * @param error - Validation error to summarize.
 * @returns Human-readable summary for `WorkerProblemDetails.detail`.
 */
export function summarizeZodError(error: ZodError): string {
  const issues = formatZodIssues(error);
  if (issues.length === 0) {
    return "Worker validation failed.";
  };

  if (issues.length === 1) {
    const issue = issues[0];
    if (!issue) {
      return "Worker validation failed.";
    };
    return `${issue.param}: ${issue.message}`;
  };

  return `Worker validation failed with ${issues.length} issue(s)`;
};