import { asWorkerError } from "@/errors";
import {
  type WorkerConfig,
  type WorkerYamlConfig,
  workerYamlSchema,
  normalizeWorkerYaml,
} from "./validation";
import yaml from "js-yaml";
import type { EnvType } from "@/types";
import { resolveConfiguredKey, resolveConfiguredKeyAsync } from "@/secrets";

/**
* Reads a configuration file by detecting the current JavaScript runtime.
* 
* It prioritizes `Bun.file` for performance if available, otherwise it
* dynamically imports `node:fs/promises` to read the file in Node.js.
* 
* @param configPath - The path or URL to the configuration file.
* @returns A promise that resolves to the file's content as a UTF-8 string.
* @throws Error if the file cannot be found or read.
*/
async function readConfigText(configPath: string | URL): Promise<string> {
  /**
   * Augments @module `globalThis` with Bun to satisfy type definition.
   */
  const bunRuntime = (globalThis as typeof globalThis & {
    Bun?: { file: (path: string | URL) => { text: () => Promise<string> } };
  }).Bun

  if (bunRuntime) {
    return bunRuntime.file(configPath).text();
  }

  const { readFile } = await import("node:fs/promises");
  return readFile(configPath, "utf-8");
}

/**
 * 
 * @param configPath - Path to config.
 * @returns {WorkerYamlConfig}
 */
async function readAndValidateWorkerYaml(configPath: string | URL): Promise<WorkerYamlConfig> {
  const yamlText = await readConfigText(configPath);
  let parsedYaml: unknown;
  try {
    parsedYaml = yaml.load(yamlText);
  } catch (error) {
    throw asWorkerError(error, {
      code: "CONFIG_YAML_INVALID",
      title: "Invalid worker YAML",
      detail: `Failed to parse ${String(configPath)} as YAML.`,
      category: "configuration",
      retryable: false,
      fatal: true,
      context: { configPath: String(configPath) },
    })
  }

  let parsedConfig: WorkerYamlConfig;
  try {
    parsedConfig = normalizeWorkerYaml(workerYamlSchema.parse(parsedYaml))
  } catch (error) {
    throw asWorkerError(error, {
      code: "CONFIG_SCHEMA_INVALID",
      title: "Invalid worker configuration",
      category: "configuration",
      retryable: false,
      fatal: true,
      context: { configPath: String(configPath) },
    });
  }

  return parsedConfig;
}

/**
 * Reads `compliance.worker.yml`, validates it strictly, and resolves local cryptographic secrets.
 *
 * This synchronous path is intended for tests and local env/file sources. Production boot should
 * use `readWorkerConfigFromRuntime` so remote KMS/Vault providers can be resolved without blocking
 * or silently falling back to process env.
 *
 * @param env - Environment map used to resolve key material.
 * @param configPath - Worker YAML path.
 * @returns Fully validated worker configuration with decoded binary keys.
 * @throws {WorkerError} When YAML parsing, schema validation, or local secret decoding fails.
 */
export async function readWorkerConfig(
  env: Record<string, string | undefined> = process.env,
  configPath: string | URL = new URL("../../compliance.worker.yml", import.meta.url)
): Promise<WorkerConfig> {
  const parsedConfig = await readAndValidateWorkerYaml(configPath);
  const masterKey = await resolveConfiguredKeyAsync({
    env,
    keyName: parsedConfig.security.master_key_env,
    legacyEnvName: parsedConfig.security.master_key_env,
    source: parsedConfig.security.master_key_source,
  });
  const hmacKey = await resolveConfiguredKeyAsync({
    env,
    keyName: parsedConfig.security.hmac_key_env,
    legacyEnvName: parsedConfig.security.hmac_key_env,
    fallbackLegacyEnvName: parsedConfig.security.master_key_env,
    source: parsedConfig.security.hmac_key_source,
  });

  return {
    ...parsedConfig,
    masterKey,
    hmacKey,
  };
}

/**
 * Reads `compliance.worker.yml` and resolves env, file, AWS KMS, GCP Secret Manager, or Vault keys.
 * 
 * @param env - Environment map used for provider credentials and legacy env key fallback.
 * @param configPath - Worker YAML path.
 * @returns Fully validated worker configuration with runtime-resolved binary keys.
 * @throws {WorkerError} When YAML, schema validation, provider access, or key decoding fails.
 */
export const readWorkerConfigFromRuntime = async (
  env: EnvType = process.env,
  configPath: string | URL = new URL("../../compliance.worker.yml", import.meta.url)
): Promise<WorkerConfig> => {
  const parsedConfig = await readAndValidateWorkerYaml(configPath);
  const [masterKey, hmacKey] = await Promise.all([
    resolveConfiguredKey({
      env,
      keyName: parsedConfig.security.hmac_key_env,
      legacyEnvName: parsedConfig.security.master_key_env,
      source: parsedConfig.security.master_key_source
    }),
    resolveConfiguredKey({
      env,
      keyName: parsedConfig.security.hmac_key_env,
      legacyEnvName: parsedConfig.security.hmac_key_env,
      fallbackLegacyEnvName: parsedConfig.security.master_key_env,
      source: parsedConfig.security.hmac_key_source,
    }),
  ]);

  return {
    ...parsedConfig,
    masterKey,
    hmacKey,
  }
};