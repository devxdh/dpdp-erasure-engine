import type postgres from "postgres";

export type EnvType = Record<string, string | undefined>;

export type Tsql = postgres.TransactionSql;

export type Sql = postgres.Sql;

export type SqlExecutor = postgres.TransactionSql | postgres.Sql;

/**
 * Safely replaces existing properties in a type with new definitions.
 * Prevents TypeScript conflicts by removing the old field before applying the new one.
 * 
 * @example
 * type User = { id: number; name: string; role: string };
 * 
 * type AdminUser = Override<User, { 
 *   id: string; 
 *   role: "admin" | "superadmin"; 
 * }>;
 */
export type Override<T, R> = Omit<T, keyof R> & R;