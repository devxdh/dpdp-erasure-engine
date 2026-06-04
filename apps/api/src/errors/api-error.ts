import { formatZodIssues, summarizeZodError, type ApiValidationIssue } from "@/validation";
import type { ApiErrorCategory, ApiErrorCode, ApiErrorContext, ApiErrorFallback, ApiErrorOptions, ApiProblemDetails } from "./types";
import { ZodError } from "zod";
import { HTTPException } from "hono/http-exception";

function normalizeType(code: ApiErrorCode): string {
  return `urn:dpdp:api:error:${code.toLowerCase().replace(/^api_/, "")}`;
}

function buildCause(cause: unknown): Error | undefined {
  if (cause instanceof Error) {
    return cause;
  }

  if (cause === undefined) {
    return undefined;
  }

  return new Error(typeof cause === "string" ? cause : JSON.stringify(cause));
}

function getCause(error: Error): unknown {
  return (error as Error & { cause?: unknown }).cause;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null;
}

function isProblem(value: unknown): value is ApiProblemDetails {
  return isRecord(value) && typeof value.code === "string" && typeof value.detail === "string";
}

/**
 * Canonical API error envelope mapped to RFC-7807-compatible problem details.
 */
export class ApiError extends Error {
  readonly type: string;
  readonly title: string;
  readonly detail: string;
  readonly status: number;
  readonly code: ApiErrorCode;
  readonly category: ApiErrorCategory;
  readonly retryable: boolean;
  readonly fatal: boolean;
  readonly context?: ApiErrorContext;
  readonly issues?: ApiValidationIssue[];

  constructor(options: ApiErrorOptions) {
    super(options.detail, { cause: buildCause(options.cause) });
    this.name = "ApiError";
    this.type = options.type ?? normalizeType(options.code);
    this.title = options.title;
    this.detail = options.detail;
    this.status = options.status;
    this.code = options.code;
    this.category = options.category;
    this.retryable = options.retryable ?? false;
    this.fatal = options.fatal ?? false;
    this.context = options.context;
    this.issues = options.issues;
  }

  toProblem(instance?: string, requestId?: string): ApiProblemDetails {
    const cause =
      this.issues && this.issues.length > 0
        ? undefined
        : this.cause
          ? asApiError(this.cause).toProblem()
          : undefined;

    return {
      type: this.type,
      title: this.title,
      detail: this.detail,
      status: this.status,
      code: this.code,
      category: this.category,
      retryable: this.retryable,
      fatal: this.fatal,
      ...(instance ? { instance } : {}),
      ...(requestId ? { request_id: requestId } : {}),
      ...(this.context ? { context: this.context } : {}),
      ...(this.issues ? { issues: this.issues } : {}),
      ...(cause ? { cause } : {}),
    };
  }
}

/**
 * Constructs an `ApiError` from explicit options.
 *
 * @param options - Error metadata and HTTP semantics.
 * @returns API error instance.
 */
export function apiError(options: ApiErrorOptions): ApiError {
  return new ApiError(options);
}

/**
 * Throws a normalized `ApiError`.
 *
 * @param options - Error metadata and HTTP semantics.
 * @throws {ApiError} Always.
 */
export function fail(options: ApiErrorOptions): never {
  throw apiError(options);
}

/**
 * Normalizes unknown thrown values into `ApiError`.
 *
 * @param error - Unknown thrown value.
 * @param fallback - Optional fallback defaults when type inference is insufficient.
 * @returns Normalized API error.
 */
export function asApiError(error: unknown, fallback: ApiErrorFallback = {}): ApiError {
  if (error instanceof ApiError) {
    return error;
  }

  if (error instanceof ZodError) {
    return apiError({
      code: fallback.code ?? "API_VALIDATION_FAILED",
      title: fallback.title ?? "Validation failed",
      detail: fallback.detail ?? summarizeZodError(error),
      status: fallback.status ?? 400,
      category: fallback.category ?? "validation",
      retryable: fallback.retryable ?? false,
      fatal: fallback.fatal ?? false,
      context: fallback.context,
      issues: fallback.issues ?? formatZodIssues(error),
      cause: getCause(error),
    });
  }

  if (error instanceof HTTPException) {
    return apiError({
      code: fallback.code ?? `API_HTTP_${error.status}`,
      title: fallback.title ?? "HTTP exception",
      detail: fallback.detail ?? error.message,
      status: fallback.status ?? error.status,
      category: fallback.category ?? (error.status === 401 ? "authentication" : "external"),
      retryable: fallback.retryable ?? false,
      fatal: fallback.fatal ?? false,
      context: fallback.context,
      cause: getCause(error),
    });
  }

  if (isProblem(error)) {
    return apiError({
      code: error.code,
      title: error.title,
      detail: error.detail,
      status: error.status,
      category: error.category,
      retryable: error.retryable,
      fatal: error.fatal,
      context: error.context,
      issues: error.issues,
      cause: error.cause,
      type: error.type,
    });
  }

  return apiError({
    code: fallback.code ?? "API_INTERNAL_UNEXPECTED",
    title: fallback.title ?? "Unexpected API error",
    detail: fallback.detail ?? (error instanceof Error ? error.message : "Unexpected API error."),
    status: fallback.status ?? 500,
    category: fallback.category ?? "internal",
    retryable: fallback.retryable ?? false,
    fatal: fallback.fatal ?? false,
    context: fallback.context,
    cause: error instanceof Error ? getCause(error) : undefined,
  });
}

/**
 * Serializes unknown errors into API problem-details payload.
 *
 * @param error - Unknown thrown value.
 * @param instance - Optional request path/context identifier.
 * @returns Structured API problem details.
 */
export function serializeApiError(error: unknown, instance?: string): ApiProblemDetails {
  return asApiError(error).toProblem(instance);
}