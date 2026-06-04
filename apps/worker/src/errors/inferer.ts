import { ZodError } from "zod";
import type {
  WorkerErrorCode,
  WorkerErrorFallback,
  WorkerErrorCategory,
} from "./types";
import { WorkerError } from "./worker";
import { summarizeZodError } from "@/validation/zod";

const RETRYABLE_POSTGRES_CODES = new Set([
  "40001", // serialization_failure
  "40P01", // deadlock_detected
  "55P03", // lock_not_available
  "57014", // query_canceled
  "57P01", // admin_shutdown
  "57P02", // crash_shutdown
  "57P03", // cannot_connect_now
]);

function isAbortLikeError(value: unknown): value is Error {
  return value instanceof Error && (value.name === "AbortError" || value.name === "TimeoutError");
}

function isPostgresError(value: unknown): value is Error & { code: string } {
  return value instanceof Error && typeof (value as { code?: unknown }).code === "string";
}

export function inferRetryability(error: unknown, fallback?: WorkerErrorFallback): boolean {
  if (fallback?.retryable !== undefined) {
    return fallback.retryable;
  }

  if (isAbortLikeError(error)) {
    return true;
  }

  if (isPostgresError(error)) {
    if (error.code.startsWith("08")) {
      return true;
    }

    return RETRYABLE_POSTGRES_CODES.has(error.code);
  }

  return false;
}

export function inferCategory(error: unknown, fallback?: WorkerErrorFallback): WorkerErrorCategory {
  if (fallback?.category) {
    return fallback.category;
  }

  if (error instanceof ZodError) {
    return "validation";
  }

  if (isAbortLikeError(error)) {
    return "network";
  }

  if (isPostgresError(error)) {
    if (error.code === "40001" || error.code === "40P01" || error.code === "55P03") {
      return "concurrency";
    }

    if (error.code.startsWith("08") || error.code.startsWith("57")) {
      return "database";
    }

    return "database";
  }

  return "internal";
}

export function inferFatal(error: unknown, fallback?: WorkerErrorFallback): boolean {
  if (fallback?.fatal !== undefined) {
    return fallback.fatal;
  }

  if (error instanceof WorkerError) {
    return error.fatal;
  }

  return false;
}

export function inferTitle(error: unknown, fallback?: WorkerErrorFallback): string {
  if (fallback?.title) {
    return fallback.title;
  }

  if (error instanceof ZodError) {
    return "Validation failed";
  }

  if (isAbortLikeError(error)) {
    return "Network operation timed out";
  }

  if (isPostgresError(error) && error.code === "40001") {
    return "Serialization failure";
  }

  if (error instanceof Error && error.name) {
    return error.name;
  }

  return "Unexpected worker error";
}

export function inferDetail(error: unknown, fallback?: WorkerErrorFallback): string {
  if (fallback?.detail) {
    return fallback.detail;
  }

  if (error instanceof ZodError) {
    return summarizeZodError(error);
  }

  if (error instanceof Error && error.message.trim().length > 0) {
    return error.message;
  }

  return "An unexpected worker error occurred.";
}

export function inferCode(error: unknown, fallback?: WorkerErrorFallback): WorkerErrorCode {
  if (fallback?.code) {
    return fallback.code;
  }

  if (error instanceof WorkerError) {
    return error.code;
  }

  if (error instanceof ZodError) {
    return "VALIDATION_FAILED";
  }

  if (isAbortLikeError(error)) {
    return "NETWORK_TIMEOUT";
  }

  if (isPostgresError(error)) {
    if (error.code === "40001") {
      return "DB_SERIALIZATION_FAILURE";
    }

    if (error.code === "40P01") {
      return "DB_DEADLOCK_DETECTED";
    }

    if (error.code === "55P03") {
      return "DB_LOCK_NOT_AVAILABLE";
    }

    if (error.code.startsWith("08")) {
      return "DB_CONNECTION_ERROR";
    }

    return "DB_ERROR";
  }

  return "INTERNAL_UNEXPECTED";
}