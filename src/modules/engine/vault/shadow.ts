import type { VaultUserResult } from "../types";

/**
 * Internal control-flow error used to force rollback during `shadowMode`.
 *
 * The result payload survives the rollback and is returned to the caller so the full pipeline
 * can be validated without persisting any mutation.
 */
export class ShadowModeRollback extends Error {
  readonly result: VaultUserResult;

  constructor(result: VaultUserResult) {
    super("Shadow mode rollback.");
    this.name = "ShadowModeRollback";
    this.result = result;
  }
}

/**
 * Returns a vault result or throws a rollback sentinel when shadow mode is enabled.
 *
 * @param result - Completed vault result.
 * @param shadowMode - Shadow-mode flag from runtime options.
 * @returns Result when shadow mode is disabled.
 * @throws {ShadowModeRollback} When shadow mode is enabled.
 */
export function finalizeVaultResult(
  result: VaultUserResult,
  shadowMode: boolean
): VaultUserResult {
  if (shadowMode) {
    throw new ShadowModeRollback(result);
  }

  return result;
}