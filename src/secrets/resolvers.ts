import { CODE, fail } from "@/errors";
import type { EnvType } from "@/types";
import { base64ToBytes } from "@/lib";
import { type KeySourceConfig, signAwsKmsRequest } from "./kms";
import { readLegacyEnvKey, readRuntimeSecret } from "./reader";
import { decodeKeyMaterial, encodeVaultPathSegment, fetchJson, isRecord, normalizeBase64 } from "./repository";

export interface ResolveKeyOptions {
  env: EnvType
  keyName: string;
  legacyEnvName: string;
  fallbackLegacyEnvName?: string;
  source?: KeySourceConfig;
  fetchFn?: typeof fetch;
}

async function requiredRuntimeSecret(
  env: EnvType,
  envName: string,
  purpose: string
): Promise<string> {
  const value = await readRuntimeSecret(env, envName);
  if (!value) {
    fail({
      code: CODE.KMS_SECRET_MISSING,
      detail: `${envName} is required to resolve ${purpose}.`,
      context: { envName, purpose },
    });
  }

  return value;
}

/**
 * Resolves a configured key source using only synchronous local sources.
 *
 * @param options - Key lookup contract and runtime environment map.
 * @returns A 32-byte key resolved from env or file.
 * @throws {WorkerError} If a remote key provider is configured on the sync path.
 */
export async function resolveConfiguredKeyAsync(options: ResolveKeyOptions): Promise<Uint8Array> {
  const source = options.source;
  if (!source) {
    return readLegacyEnvKey(options);
  }

  if (source.provider === "env") {
    return decodeKeyMaterial(
      await requiredRuntimeSecret(
        options.env,
        source.env,
        options.keyName
      ), options.keyName
    );
  }

  if (source.provider === "file") {
    const rawKey = (await Bun.file(source.path).text()).trim();
    return decodeKeyMaterial(rawKey, options.keyName)
  }
  fail({
    code: "KMS_ASYNC_PROVIDER_ON_SYNC_PATH",
    title: "Remote key provider requires async boot",
    detail: `${source.provider} key sources require readWorkerConfigFromRuntime().`,
    category: "configuration",
    retryable: false,
    fatal: true,
    context: { provider: source.provider, keyName: options.keyName }
  })
}

async function resolveAwsKmsKey(
  source: Extract<KeySourceConfig, { provider: "aws_kms" }>,
  options: ResolveKeyOptions
): Promise<Uint8Array> {
  const fetchFn = options.fetchFn ?? globalThis.fetch;
  const endpoint = new URL(source.endpoint ?? `https://kms.${source.region}.amazonaws.com/`);
  const body = JSON.stringify({
    CiphertextBlob: source.ciphertext_blob_base64,
    ...(source.key_id ? { KeyId: source.key_id } : {}),
    ...(source.encryption_context ? { EncryptionContext: source.encryption_context } : {}),
  });
  const headers = await signAwsKmsRequest(endpoint, source.region, body, {
    accessKeyId: await requiredRuntimeSecret(options.env,
      source.access_key_id_env,
      options.keyName
    ),
    secretAccessKey: await requiredRuntimeSecret(
      options.env,
      source.secret_access_key_env,
      options.keyName
    ),
    sessionToken: await readRuntimeSecret(
      options.env,
      source.session_token_env
    ) || undefined,
  });

  const json = await fetchJson(fetchFn, endpoint, { method: "POST", headers, body }, "AWS KMS");
  if (!isRecord(json) || typeof json.Plaintext !== "string") {
    fail({
      code: CODE.KMS_RESPONSE_INVALID,
      detail: "AWS KMS response did not include a base64 Plaintext field.",
      context: { provider: "aws_kms" },
    });
  }

  return decodeKeyMaterial(base64ToBytes(normalizeBase64(json.Plaintext)), options.keyName);
}

async function resolveGcpToken(
  source: Extract<KeySourceConfig, { provider: "gcp_secret_manager" }>,
  options: ResolveKeyOptions
): Promise<string> {
  const envToken = await readRuntimeSecret(options.env, source.access_token_env)
  if (envToken) return envToken;

  const json = await fetchJson(
    options.fetchFn ?? globalThis.fetch,
    source.metadata_token_url,
    {
      method: "GET",
      headers: {
        "metadata-flavor": "Google",
      },
    },
    "GCP metadata server"
  );

  if (!isRecord(json) || typeof json.access_token !== "string") {
    fail({
      code: CODE.KMS_RESPONSE_INVALID,
      detail: "GCP metadata token response did not include access_token.",
      context: { provider: "gcp_metadata" },
    })
  }

  return json.access_token;
}

async function resolveGcpSecretManagerKey(
  source: Extract<KeySourceConfig, { provider: "gcp_secret_manager" }>,
  options: ResolveKeyOptions
): Promise<Uint8Array> {
  const fetchFn = options.fetchFn ?? globalThis.fetch;
  const endpoint = source.endpoint ?? `https://secretmanager.googleapis.com/v1/${source.secret_version}:access`
  const accessToken = await resolveGcpToken(source, options);
  const json = await fetchJson(
    fetchFn,
    endpoint,
    {
      method: "GET",
      headers: {
        authorization: `Bearer ${accessToken}`
      },
    },
    "GCP Secret Manager"
  );

  const payload = isRecord(json) && isRecord(json.payload) ? json.payload : null;
  if (!payload || typeof payload.data !== "string") {
    fail({
      code: CODE.KMS_RESPONSE_INVALID,
      detail: "GCP Secret Manager response did not include payload.data.",
      context: { provider: "gcp_secret_manager" },
    });
  }

  return decodeKeyMaterial(base64ToBytes(normalizeBase64(payload.data)), options.keyName);
}


async function resolveVaultKey(
  source: Extract<KeySourceConfig, { provider: "hashicorp_vault" }>,
  options: ResolveKeyOptions
): Promise<Uint8Array> {
  const fetchFn = options.fetchFn ?? globalThis.fetch;
  const address = source.address ?? await readRuntimeSecret(options.env, source.address_env);
  if (!address) {
    fail({
      code: CODE.KMS_SECRET_MISSING,
      detail: `${source.address_env} or security key source address is required to resolve ${options.keyName}.`,
      context: { provider: "hashicorp_vault", addressEnv: source.address_env },
    });
  }

  const url = new URL(
    `/v1/${encodeVaultPathSegment(source.mount)}/data/${encodeVaultPathSegment(source.path)}`,
    address.endsWith("/") ? address : `${address}/`
  );
  if (source.version !== undefined) {
    url.searchParams.set("version", String(source.version));
  }

  const headers = new Headers({
    "x-vault-token": await requiredRuntimeSecret(options.env, source.token_env, options.keyName),
  });
  const namespace = await readRuntimeSecret(options.env, source.namespace_env);
  if (namespace) {
    headers.set("x-vault-namespace", namespace);
  }

  const json = await fetchJson(
    fetchFn,
    url,
    { method: "GET", headers },
    "HashiCorp Vault");
  const data = isRecord(json) && isRecord(json.data) && isRecord(json.data.data) ? json.data.data : null;
  const rawValue = data?.[source.field];
  if (typeof rawValue !== "string") {
    fail({
      code: CODE.KMS_RESPONSE_INVALID,
      detail: `HashiCorp Vault response did not include data.data.${source.field}.`,
      context: { provider: "hashicorp_vault", field: source.field },
    });
  }

  return decodeKeyMaterial(rawValue, options.keyName);
};

/**
 * Resolves a configured key source from env, file, AWS KMS, GCP Secret Manager, or Vault KV v2.
 *
 * @param options - Key lookup contract and runtime environment map.
 * @returns A 32-byte key suitable for Web Crypto operations.
 * @throws {WorkerError} If retrieval fails or the provider returns invalid key material.
 */
export async function resolveConfiguredKey(options: ResolveKeyOptions): Promise<Uint8Array> {
  const source = options.source;
  if (!source) {
    return readLegacyEnvKey(options);
  }

  if (source.provider === "env" || source.provider === "file") {
    return resolveConfiguredKeyAsync(options);
  }

  if (source.provider === "aws_kms") {
    return resolveAwsKmsKey(source, options);
  }

  if (source.provider === "gcp_secret_manager") {
    return resolveGcpSecretManagerKey(source, options);
  }

  return resolveVaultKey(source, options);
}