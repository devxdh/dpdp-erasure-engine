import type { RegistryEntry, WorkerErrorCategory } from "./types";

export type ErrorCodeType = keyof typeof ERROR_REGISTRY;

export interface ErrorRegistryTypes {
  title: string;
  detail: (data: unknown) => string;
  category: WorkerErrorCategory;
  retryable: boolean;
  fatal: boolean;
}

/**
 * Centralized Error Registry
 */
export const ERROR_REGISTRY = {
  UNREGISTERED_ERROR_CODE: {
    title: "Unknown Error",
    detail: (data: { code: string }) => `An unregistered error occurred: ${data.code}`,
    category: "internal",
    retryable: false,
    fatal: true,
  },
  CONFIG_SIGNATURE_MISSING: {
    title: "Missing worker config signature",
    detail: (data: { value: string }) =>
      `Detached config signature ${data.value} is required when config signing is enabled.`,
    category: "configuration",
    retryable: false,
    fatal: true,
  },
  CONFIG_SIGNATURE_INVALID: {
    title: "Invalid worker config signature",
    detail: (data: { value: string }) => `Detached config signature ${data.value} failed verification.`,
    category: "integrity",
    retryable: false,
    fatal: true,
  },
  SECRET_ENV_MISSING: {
    title: "Required secret is missing",
    detail: (data: { keyName: string }) => `${data.keyName} is required.`,
    category: "configuration",
    retryable: false,
    fatal: true,
  },
  SECRET_ENV_INVALID: {
    title: "Invalid secret format",
    detail: (data: { keyName: string, KEY_LENGTH: number }) =>
      `${data.keyName} must resolve to exactly ${data.KEY_LENGTH} bytes. Supported formats: 64-char hex or base64.`,
    category: "configuration",
    retryable: false,
    fatal: true,
  },
  KMS_SECRET_MISSING: {
    title: "Runtime secret is missing",
    category: "configuration",
    retryable: false,
    fatal: true,
  },
  KMS_RESPONSE_INVALID: {
    title: "Key provider response invalid",
    category: "external",
    retryable: false,
    fatal: true,
  },
  VAULT_NOT_FOUND: {
    title: "Vault record not found",
    detail: (
      data: {
        appSchema: string,
        rootTable: string,
        normalizedSubjectId: string
      }
    ) => `Vault record not found for ${data.appSchema}.${data.rootTable}#${data.normalizedSubjectId}.`,
    category: "validation",
    retryable: false,
    fatal: false
  },
  USER_ID_INVALID: {
    title: "Invalid root identifier",
    detail: () => "subjectId must be a non-empty string or number.",
    category: "validation",
    retryable: false,
  },
  OUTBOX_LEASE_LOST: {
    title: "Outbox lease lost",
    category: "concurrency",
    retryable: true,
  },
  BLOB_URL_INVALID: {
    title: "Invalid S3 URL",
    category: "validation",
    retryable: false,
  },
  BLOB_URL_UNSUPPORTED: {
    title: "Unsupported blob URL protocol",
    category: "validation",
    retryable: false,
  },
  AWS_CREDENTIALS_INVALID: {
    title: "AWS credentials invalid",
    category: "configuration",
    retryable: false,
    fatal: true,
  },
  AWS_CREDENTIALS_UNAVAILABLE: {
    title: "AWS IMDS unavailable",
    category: "configuration",
    retryable: true,
    fatal: false,
  }
} as const satisfies Record<string, RegistryEntry>;

/**
 * Type-safe map for error codes derived from @constant {ERROR_REGISTRY}
 * It standardizes the code without writing it manually every time
 * 
 * @example fail({ code: CODE.CONFIG_SIGNATURE_MISSING });
 */
export const CODE = Object.fromEntries(
  Object.keys(ERROR_REGISTRY).map(k => [k, k])
) as { [k in keyof typeof ERROR_REGISTRY]: k }