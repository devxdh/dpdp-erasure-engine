import type {
  WorkerErrorCategory,
  WorkerErrorCode,
  WorkerErrorContext,
  WorkerErrorOptions,
  WorkerProblemDetails,
  WorkerErrorFallback
} from "./types";
import { formatZodIssues, type WorkerValidationIssue } from "@/validation/zod";
import {
  inferCategory,
  inferCode,
  inferDetail,
  inferFatal,
  inferRetryability,
  inferTitle
} from "./inferer";
import { ZodError } from "zod";

function buildCause(cause: unknown): Error | undefined {
  if (cause == null) return undefined;
  if (cause instanceof Error) return cause;

  return new Error(typeof cause === "string" ? cause : JSON.stringify(cause));
}

export function normalizeErrorType(code: WorkerErrorCode): string {
  return `urn:dpdp:worker:error:${code.toLowerCase().replace(/^dpdp_/, "")}`;
}

/**
 * WorkerError envelope mapped to RFC-7807-compatible problem details.
 */
export class WorkerError extends Error {
  readonly type: string;
  readonly code: WorkerErrorCode;
  readonly title: string;
  readonly detail: string;
  readonly category: WorkerErrorCategory;
  readonly retryable: boolean;
  readonly fatal: boolean;
  readonly context?: WorkerErrorContext | null;
  readonly issues?: WorkerValidationIssue[] | null;

  constructor(options: WorkerErrorOptions) {
    const cause = buildCause(options.cause)
    super(options.detail, { cause })

    this.name = "WorkerError";
    this.type = options.type ?? normalizeErrorType(options.code);
    this.code = options.code;
    this.title = options.title;
    this.detail = options.detail;
    this.category = options.category;
    this.retryable = options.retryable ?? false;
    this.fatal = options.fatal ?? false;
    this.context = options.context ?? null;

    /**
    * Issue resolution:
    * 1. Use explicitly provided issues.
    * 2. If missing, check if the cause is a ZodError and format it.
    * 3. Otherwise, null.
    */
    if (options.issues) {
      this.issues = options.issues;
    } else if (cause instanceof ZodError) {
      this.issues = formatZodIssues(cause);
    } else {
      this.issues = null;
    }
  }

  toProblem(instance?: string): WorkerProblemDetails {
    const causeProblem = this.cause ? asWorkerError(this.cause).toProblem() : undefined;

    const problem: WorkerProblemDetails = {
      type: this.type,
      code: this.code,
      title: this.title,
      detail: this.detail,
      category: this.category,
      retryable: this.retryable,
      fatal: this.fatal,
    };

    if (instance) problem.instance = instance;
    if (this.context) problem.context = this.context;
    if (this.issues && this.issues.length > 0) problem.issues = this.issues;
    if (causeProblem) problem.cause = causeProblem;

    return problem;
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null;
}

function isWorkerProblem(value: unknown): value is WorkerProblemDetails {
  return isRecord(value) && typeof value.code === "string" && typeof value.detail === "string";
}

/**
 * Constructs a normalized `WorkerError`
 * 
 * @param options - Error metadata and classification.
 * @returns Worker error instance
 */
export function workerError(options: WorkerErrorOptions): WorkerError {
  return new WorkerError(options)
}

/**
 * Normalizes unknown error into `WorkerError`, applying fallback defaults when needed
 * 
 * @param error - Unknown thrown value.
 * @param fallback - Optional fallback fields used when inference is ambiguous
 * @returns Normalized Worker Error
 */
export function asWorkerError(error: unknown, fallback: WorkerErrorFallback = {}): WorkerError {
  if (error instanceof WorkerError) return error;

  if (isWorkerProblem(error)) {
    return workerError({
      code: error.code,
      title: error.title,
      detail: error.detail,
      category: error.category,
      retryable: error.retryable,
      fatal: error.fatal,
      context: error.context,
      issues: error.issues,
      cause: error.cause,
      type: error.type,
    });
  };

  return workerError({
    code: inferCode(error, fallback),
    title: inferTitle(error, fallback),
    detail: inferDetail(error, fallback),
    category: inferCategory(error, fallback),
    retryable: inferRetryability(error, fallback),
    fatal: inferFatal(error, fallback),
    context: fallback.context,
    issues: error instanceof ZodError ? (fallback.issues ?? formatZodIssues(error)) : fallback.issues,
    cause: error instanceof Error ? error.cause : undefined
  });
};

/**
 * Serializes unknown errors into worker problem-details payload.
 *
 * @param error - Unknown thrown value.
 * @param instance - Optional instance path/context identifier.
 * @returns Structured worker problem details.
 */
export function serializeWorkerError(error: unknown, instance?: string): WorkerProblemDetails {
  return asWorkerError(error).toProblem(instance);
}