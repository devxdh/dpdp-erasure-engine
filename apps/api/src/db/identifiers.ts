import { fail } from "@/errors";

const IDENTIFIER_PATTERN = /^[a-zA-Z_][a-zA-Z0-9_]*$/;

/**
 * Validates SQL identifiers used in dynamic schema/table references.
 *
 * @param name - Candidate SQL identifier.
 * @param label - Human-readable label used in validation errors.
 * @returns Unchanged identifier when valid.
 * @throws {ApiError} When `name` contains disallowed characters.
 */
export function assertIdentifier(name: string, label: string): string {
  if (!IDENTIFIER_PATTERN.test(name)) {
    fail({
      code: "API_IDENTIFIER_INVALID",
      title: "Invalid SQL identifier",
      detail: `Invalid ${label}: "${name}". Only letters, numbers, and underscores are allowed.`,
      status: 400,
      category: "validation",
      retryable: false,
    });
  }

  return name;
}
