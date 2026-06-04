import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { getDependencyGraph } from "@modules/db";
import { createTestSql, dropSchemas, uniqueSchema } from "./helpers";
import type { Sql } from "@/types";

describe("Graph Engine (Database Crawler)", () => {
  let sql: Sql;
  const schema = uniqueSchema("graph");

  beforeAll(async () => {
    sql = createTestSql();

    await dropSchemas(sql, schema);
    await sql`CREATE SCHEMA ${sql(schema)}`;

    await sql`CREATE TABLE ${sql(schema)}.users (id SERIAL PRIMARY KEY, email TEXT, full_name TEXT)`;
    await sql`CREATE TABLE ${sql(schema)}.orders (id SERIAL PRIMARY KEY, user_id INTEGER REFERENCES ${sql(schema)}.users(id))`;
    await sql`CREATE TABLE ${sql(schema)}.profiles (id SERIAL PRIMARY KEY, user_id INTEGER REFERENCES ${sql(schema)}.users(id))`;
    await sql`CREATE TABLE ${sql(schema)}.shipping_addresses (id SERIAL PRIMARY KEY, order_id INTEGER REFERENCES ${sql(schema)}.orders(id))`;
    await sql`CREATE TABLE ${sql(schema)}.address_verification_logs (id SERIAL PRIMARY KEY, address_id INTEGER REFERENCES ${sql(schema)}.shipping_addresses(id))`;
    await sql`CREATE TABLE ${sql(schema)}.level_4 (id SERIAL PRIMARY KEY, log_id INTEGER REFERENCES ${sql(schema)}.address_verification_logs(id))`;
    await sql`CREATE TABLE ${sql(schema)}.level_5 (id SERIAL PRIMARY KEY, l4_id INTEGER REFERENCES ${sql(schema)}.level_4(id))`;
    await sql`CREATE TABLE ${sql(schema)}.orphan_table (id SERIAL PRIMARY KEY, data TEXT)`;
    await sql`CREATE TABLE ${sql(schema)}.circ_a (id SERIAL PRIMARY KEY)`;
    await sql`CREATE TABLE ${sql(schema)}.circ_b (id SERIAL PRIMARY KEY, a_id INTEGER REFERENCES ${sql(schema)}.circ_a(id))`;
    await sql`ALTER TABLE ${sql(schema)}.circ_a ADD COLUMN b_id INTEGER REFERENCES ${sql(schema)}.circ_b(id)`;
    await sql`CREATE TABLE ${sql(schema)}.cascade_root (id SERIAL PRIMARY KEY)`;
    await sql`CREATE TABLE ${sql(schema)}.cascade_child (id SERIAL PRIMARY KEY, root_id INTEGER REFERENCES ${sql(schema)}.cascade_root(id) ON DELETE CASCADE)`;
    await sql`CREATE TABLE ${sql(schema)}.set_null_root (id SERIAL PRIMARY KEY)`;
    await sql`CREATE TABLE ${sql(schema)}.set_null_child (id SERIAL PRIMARY KEY, root_id INTEGER REFERENCES ${sql(schema)}.set_null_root(id) ON DELETE SET NULL)`;
  });

  afterAll(async () => {
    await dropSchemas(sql, schema);
    await sql.end();
  });

  it("maps a multi-level dependency graph without duplicate loop inflation", async () => {
    const graph = await getDependencyGraph(sql, schema, "users");
    const tableNames = graph.map((node) => node.table_name);

    expect(tableNames).toContain(`${schema}.orders`);
    expect(tableNames).toContain(`${schema}.profiles`);
    expect(tableNames).toContain(`${schema}.shipping_addresses`);
    expect(tableNames).toContain(`${schema}.address_verification_logs`);
    expect(tableNames).toContain(`${schema}.level_5`);

    const orderNode = graph.find((node) => node.table_name === `${schema}.orders`);
    const shippingNode = graph.find((node) => node.table_name === `${schema}.shipping_addresses`);
    const logNode = graph.find((node) => node.table_name === `${schema}.address_verification_logs`);
    const level5Node = graph.find((node) => node.table_name === `${schema}.level_5`);

    expect(orderNode?.depth).toBe(1);
    expect(orderNode?.delete_action).toBe("NO_ACTION");
    expect(shippingNode?.depth).toBe(2);
    expect(logNode?.depth).toBe(3);
    expect(level5Node?.depth).toBe(5);
  });

  it("returns an empty array for a table with zero dependencies", async () => {
    await expect(getDependencyGraph(sql, schema, "orphan_table")).resolves.toEqual([]);
  });

  it("breaks cycles instead of looping until a depth guard happens to stop it", async () => {
    const graph = await getDependencyGraph(sql, schema, "circ_a");
    const nodesForCircB = graph.filter((node) => node.table_name === `${schema}.circ_b`);

    expect(nodesForCircB).toHaveLength(1);
    expect(nodesForCircB[0]?.depth).toBe(1);
  });

  it("fails closed when FK delete actions can silently mutate dependent data", async () => {
    await expect(getDependencyGraph(sql, schema, "cascade_root")).rejects.toThrow(/ON DELETE CASCADE/i);
    await expect(getDependencyGraph(sql, schema, "set_null_root")).rejects.toThrow(/ON DELETE SET_NULL/i);
  });

  it("fails closed when the recursion depth limit would truncate the graph", async () => {
    await expect(getDependencyGraph(sql, schema, "users", { maxDepth: 3 })).rejects.toThrow(/safety limit/i);
  });

  it("fails clearly when the root table does not exist", async () => {
    await expect(getDependencyGraph(sql, schema, "does_not_exist")).rejects.toThrow(/does not exist/i);
  });
});
