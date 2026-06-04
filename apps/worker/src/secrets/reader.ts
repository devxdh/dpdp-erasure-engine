import type { EnvType } from "@/types";
import { decodeKeyMaterial } from "./repository";
import type { ResolveKeyOptions } from "./resolvers";

/**
 * Resolves a runtime secret from an environment variable or it's moutned-file companion
 * 
 * If `FOO_FILE` is present, the worker reads the secret from that path. This supports
 * Kubernetes secret volumes, Vault agent injection, and CSI-mounted secret providers
 * without changing the YAML contract that names logical secret identifiers. 
 * 
 * @param env - Raw environment variable
 * @param envName - Logical environment variable name declared in yaml
 * @returns Resolved secret value or an empty string when no source is configured
 */
export async function readRuntimeSecret(
  env: EnvType,
  envName: string
): Promise<string> {
  const directValue = env[envName];
  if (directValue && directValue.trim().length > 0) {
    return directValue.trim()
  };

  const filePath = env[`${envName}_FILE`];
  if (!filePath || filePath.trim().length === 0) {
    return "";
  }

  return (await Bun.file(filePath).text()).trim();
}

export async function readLegacyEnvKey(options: ResolveKeyOptions): Promise<Uint8Array> {
  const value =
    await readRuntimeSecret(options.env, options.legacyEnvName)
    || (
      options.fallbackLegacyEnvName
        ? await readRuntimeSecret(options.env, options.fallbackLegacyEnvName)
        : ""
    );
  return decodeKeyMaterial(value, options.keyName);
}