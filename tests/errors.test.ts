import { asWorkerError, serializeWorkerError, workerError } from "@/errors";
import { describe, expect, it } from "vitest";
import { ZodError, z } from "zod";

describe("WorkerError normalization", () => {
  it("preserves explicit worker error metadata in RFC-9457-style problem details", () => {
    const error = workerError({
      code: "TEST_EXPLICIT",
      title: "Explicit worker error",
      detail: "The worker emitted a classified error.",
      category: "internal",
      retryable: false,
      fatal: true,
      context: { component: "test" },
    });

    expect(serializeWorkerError(error, "worker:test")).toEqual({
      type: "urn:dpdp:worker:error:test_explicit",
      title: "Explicit worker error",
      detail: "The worker emitted a classified error.",
      code: "TEST_EXPLICIT",
      category: "internal",
      retryable: false,
      fatal: true,
      instance: "worker:test",
      context: { component: "test" },
    });
  });

  it("classifies transient postgres failures as retryable concurrency/database errors", () => {
    const postgresError = Object.assign(new Error("deadlock detected"), {
      code: "40P01",
    });

    const normalized = asWorkerError(postgresError);

    expect(normalized.code).toBe("DB_DEADLOCK_DETECTED");
    expect(normalized.category).toBe("concurrency");
    expect(normalized.retryable).toBe(true);
    expect(normalized.fatal).toBe(false);
  });

  it("converts zod validation failures into structured validation errors", () => {
    let validationError: ZodError | null = null;

    try {
      z.object({ default_retention_years: z.number().int().min(0) }).parse({
        default_retention_years: null,
      });
    } catch (error) {
      validationError = error as ZodError;
    }

    const normalized = asWorkerError(validationError);

    expect(normalized.code).toBe("VALIDATION_FAILED");
    expect(normalized.category).toBe("validation");
    expect(normalized.detail).toContain("default_retention_years");
    expect(normalized.toProblem("worker:test").issues).toEqual([
      {
        path: "default_retention_years",
        param: "default_retention_years",
        code: "invalid_type",
        message: "Invalid input: expected number, received null",
      },
    ]);
    expect(normalized.retryable).toBe(false);
  });
});
