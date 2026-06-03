import type { Sql } from "@/types";
import { beforeEach, describe, expect, it, vi } from "vitest";

const getDependencyGraphMock = vi.fn();

vi.mock("../src/db/graph", () => ({
  getDependencyGraph: getDependencyGraphMock,
}));

const { vaultUser } = await import("@modules/engine");

describe("Vault Engine Static Plan Routing", () => {
  beforeEach(() => {
    getDependencyGraphMock.mockReset();
    getDependencyGraphMock.mockResolvedValue([]);
  });

  it("does not run recursive graph traversal during dry-run when a static plan is provided", async () => {
    const primary = {
      unsafe: vi.fn().mockResolvedValue([]),
    } as unknown as Sql;
    const replica = {
      tag: "replica",
    } as unknown as Sql;

    const result = await vaultUser(
      primary,
      42,
      {
        kek: new Uint8Array(32).fill(0x42),
        hmacKey: new Uint8Array(32).fill(0x24),
      },
      {
        appSchema: "tenant_app",
        engineSchema: "tenant_engine",
        rootTable: "users",
        rootIdColumn: "id",
        rootPiiColumns: { email: "HMAC", full_name: "STATIC_MASK" },
        satelliteTargets: [],
        compiledTargets: [
          { table: "tenant_app.users", pii_columns: ["email", "full_name"] },
          {
            table: "tenant_app.orders",
            parent: "tenant_app.users",
            join: "tenant_app.users.id = tenant_app.orders.user_id",
            pii_columns: [],
          },
        ],
        dryRun: true,
        sqlReplica: replica,
        now: new Date("2026-01-10T00:00:00.000Z"),
      }
    );

    expect(result.action).toBe("dry_run");
    expect(result.dependencyCount).toBe(1);
    expect(getDependencyGraphMock).not.toHaveBeenCalled();
  });
});
