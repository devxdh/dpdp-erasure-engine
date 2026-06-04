import { ERROR_REGISTRY, type ErrorCodeType } from "./registry";
import { normalizeErrorType, WorkerError } from "./worker";
import type { WorkerErrorContext, WorkerErrorCategory, RegistryEntry } from "./types";
import { type WorkerValidationIssue } from "@/validation/zod";

type ExtractBaseCode<T extends string> = T extends ErrorCodeType
  ? T
  : T extends `${string}_${infer Base extends ErrorCodeType}`
  ? Base
  : never;

type DetailParams<Base extends ErrorCodeType> =
  typeof ERROR_REGISTRY[Base] extends { detail: (...args: infer P) => string }
  ? P
  : never;

type InferData<Base extends ErrorCodeType> =
  DetailParams<Base> extends [infer D, ...any[]]
  ? D
  : never;

type IsDataRequired<Base extends ErrorCodeType> = DetailParams<Base> extends []
  ? false
  : DetailParams<Base> extends [never]
  ? false
  : true;

type FailOptions<T extends string> = {
  code: T;
  title?: string;
  category?: WorkerErrorCategory;
  retryable?: boolean;
  fatal?: boolean;
  cause?: unknown;
  context?: WorkerErrorContext | null;
  issues?: WorkerValidationIssue[] | null;
} & (
    [ExtractBaseCode<T>] extends [infer Base extends ErrorCodeType]
    ? (
      | { detail: string; data?: InferData<Base> }
      | (IsDataRequired<Base> extends true
        ? { detail?: never; data: InferData<Base> }
        : { detail?: never; data?: InferData<Base> })
    )
    : {
      title: string;
      detail: string;
      category: WorkerErrorCategory;
    });

export function fail<T extends string>(options: FailOptions<T>): never {
  const { code, title, category, retryable, fatal, cause, context, issues } = options;

  let meta: RegistryEntry | undefined = ERROR_REGISTRY[code as ErrorCodeType];
  let baseCode = code as string;

  if (!meta) {
    // Isolate the longest valid registry suffix matching the prefixed string
    const baseMatch = (Object.keys(ERROR_REGISTRY) as ErrorCodeType[])
      .filter((k) => code.endsWith(`_${k}`))
      .sort((a, b) => b.length - a.length)[0];

    if (baseMatch) {
      meta = ERROR_REGISTRY[baseMatch];
      baseCode = baseMatch;
    }
  }

  if (meta) {
    let resolvedDetail: string;

    if ('detail' in options && typeof options.detail === 'string') {
      resolvedDetail = options.detail;
    } else {
      const targetDetail = 'detail' in meta ? meta.detail : undefined;
      const inputData = (options as any).data ?? {};

      resolvedDetail = typeof targetDetail === 'function'
        ? (targetDetail as Function)(inputData)
        : String(targetDetail);
    }

    throw new WorkerError({
      code,
      type: normalizeErrorType(baseCode),
      title: title ?? meta.title,
      category: category ?? meta.category,
      fatal: fatal ?? meta.fatal,
      retryable: retryable ?? meta.retryable,
      detail: resolvedDetail,
      cause: cause ?? null,
      context: context ?? null,
      issues: issues ?? null,
    });
  }

  // Pure ad-hoc custom string signature layout engine
  throw new WorkerError({
    code,
    type: normalizeErrorType(baseCode),
    title: title ?? "Unhandled Application Fault",
    category: category ?? "internal",
    detail: (options as any).detail ?? "An unexpected runtime failure was triggered.",
    retryable: retryable ?? false,
    fatal: fatal ?? true,
    cause: cause ?? null,
    context: context ?? null,
    issues: issues ?? null,
  });
}
