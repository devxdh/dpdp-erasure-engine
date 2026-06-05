import { describe, expect, it } from "vitest";
import { z } from "zod";
import { asApiError } from "@/errors";

describe("API error normalization", () => {
  it("converts zod failures into standardized field-level issues", () => {
    const schema = z
      .object({
        actor_opaque_id: z.string().min(1),
        cooldown_days: z.number().int().min(0),
      })
      .strict();

    const result = schema.safeParse({
      actor_opaque_id: "",
      cooldown_days: -1,
      email: "alice@example.com",
    });

    expect(result.success).toBe(false);
    if (result.success) {
      return;
    }

    const normalized = asApiError(result.error);

    expect(normalized.code).toBe("API_VALIDATION_FAILED");
    expect(normalized.detail).toBe("Request validation failed with 3 issue(s).");
    expect(normalized.toProblem("/api/v1/erasure-requests", "req_test").issues).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          param: "actor_opaque_id",
          code: "too_small",
        }),
        expect.objectContaining({
          param: "cooldown_days",
          code: "too_small",
        }),
        expect.objectContaining({
          param: "<root>",
          code: "unrecognized_keys",
        }),
      ])
    );
  });
});
