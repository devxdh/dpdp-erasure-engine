import type { ApiValidationIssue } from "@/validation";

export type ApiErrorCode = `API_${string}`;

export type ApiErrorCategory =
  | "validation"
  | "authentication"
  | "authorization"
  | "configuration"
  | "database"
  | "concurrency"
  | "external"
  | "integrity"
  | "internal";

export interface ApiErrorContext {
  [key: string]: unknown;
}

export interface ApiProblemDetails {
  type: string;
  title: string;
  detail: string;
  status: number;
  code: ApiErrorCode;
  category: ApiErrorCategory;
  retryable: boolean;
  fatal: boolean;
  instance?: string;
  request_id?: string;
  context?: ApiErrorContext;
  issues?: ApiValidationIssue[];
  cause?: ApiProblemDetails;
}

export interface ApiErrorOptions {
  code: ApiErrorCode;
  title: string;
  detail: string;
  status: number;
  category: ApiErrorCategory;
  retryable?: boolean;
  fatal?: boolean;
  context?: ApiErrorContext;
  issues?: ApiValidationIssue[];
  cause?: unknown;
  type?: string;
}

export interface ApiErrorFallback {
  code?: ApiErrorCode;
  title?: string;
  detail?: string;
  status?: number;
  category?: ApiErrorCategory;
  retryable?: boolean;
  fatal?: boolean;
  context?: ApiErrorContext;
  issues?: ApiValidationIssue[];
}
