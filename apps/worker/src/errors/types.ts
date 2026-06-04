import { type WorkerValidationIssue } from "@/validation/zod";

export type WorkerErrorCode = string;

export type WorkerErrorCategory =
  | "configuration"
  | "validation"
  | "integrity"
  | "concurrency"
  | "database"
  | "network"
  | "crypto"
  | "runtime"
  | "external"
  | "internal";

export interface WorkerErrorContext {
  [key: string]: unknown
};

export interface WorkerProblemDetails {
  type: string;
  title: string;
  detail: string;
  code: WorkerErrorCode;
  category: WorkerErrorCategory;
  retryable: boolean;
  fatal: boolean;
  instance?: string;
  context?: WorkerErrorContext;
  issues?: WorkerValidationIssue[];
  cause?: WorkerProblemDetails;
}

export interface WorkerErrorOptions {
  code: WorkerErrorCode;
  title: string;
  detail: string;
  category: WorkerErrorCategory;
  retryable?: boolean;
  fatal?: boolean;
  context?: WorkerErrorContext | null;
  issues?: WorkerValidationIssue[] | null;
  cause?: unknown;
  type?: string;
}

export interface WorkerErrorFallback {
  code?: WorkerErrorCode;
  title?: string;
  detail?: string;
  category?: WorkerErrorCategory;
  retryable?: boolean;
  fatal?: boolean;
  context?: WorkerErrorContext;
  issues?: WorkerValidationIssue[];
}

export interface RegistryEntry<T = any> {
  title: string;
  detail?: (data: T) => string;
  category: WorkerErrorCategory;
  retryable: boolean;
  fatal?: boolean;
};