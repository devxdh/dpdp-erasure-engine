import { CODE, fail } from "@/errors";
import z from "zod";
import type { S3AwsCredentials } from "./type";

const ECS_CREDENTIAL_ENDPOINT = "http://169.254.170.2";
const EC2_METADATA_ENDPOINT = "http://169.254.169.254";
const ALLOWED_HTTP_FULL_URI_HOSTS = new Set([
  "localhost",
  "127.0.0.1",
  "[::1]",
  "169.254.170.2",
  "169.254.170.23",
]);

const awsCredentialResponseSchema = z.object({
  AccessKeyId: z.string().min(1),
  SecretAccessKey: z.string().min(1),
  Token: z.string().min(1).optional(),
  Expiration: z.string().datetime().optional(),
});

interface AwsCredentialProviderOptions {
  env?: Record<string, string | undefined>;
  fetchFn?: typeof fetch;
  timeoutMs?: number;
}

function validateContainerCredentialsFullUri(value: string): string {
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    fail({
      code: "AWS_CREDENTIALS_URI_INVALID",
      title: "AWS credential URI invalid",
      detail: "AWS_CONTAINER_CREDENTIALS_FULL_URI must be a valid URL.",
      category: "configuration",
      retryable: false,
      fatal: true,
    });
  }

  if (url.protocol === "https:") {
    return url.toString();
  }

  if (url.protocol === "http:" && ALLOWED_HTTP_FULL_URI_HOSTS.has(url.hostname)) {
    return url.toString();
  }

  fail({
    code: "AWS_CREDENTIALS_URI_REJECTED",
    title: "AWS credential URI rejected",
    detail: "HTTP container credential endpoints must be loopback or AWS container metadata endpoints.",
    category: "configuration",
    retryable: false,
    fatal: true,
    context: { host: url.hostname, protocol: url.protocol },
  });
}

async function resolveContainerAuthorizationHeader(env: Record<string, string | undefined>): Promise<Record<string, string> | undefined> {
  if (env.AWS_CONTAINER_AUTHORIZATION_TOKEN) {
    return { authorization: env.AWS_CONTAINER_AUTHORIZATION_TOKEN };
  }

  if (!env.AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE) {
    return undefined;
  }

  let token: string;
  try {
    token = (await Bun.file(env.AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE).text()).trim();
  } catch (error) {
    fail({
      code: "AWS_CREDENTIALS_TOKEN_UNAVAILABLE",
      title: "AWS credential token unavailable",
      detail: error instanceof Error ? error.message : "AWS container authorization token file could not be read.",
      category: "configuration",
      retryable: false,
      fatal: true,
    });
  }

  if (!token) {
    fail({
      code: "AWS_CREDENTIALS_TOKEN_EMPTY",
      title: "AWS credential token empty",
      detail: "AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE did not contain a token.",
      category: "configuration",
      retryable: false,
      fatal: true,
    });
  }

  return { authorization: token };
}

async function fetchWithTimeout(fetchFn: typeof fetch, url: string, init: RequestInit, timeoutMs: number): Promise<Response> {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), timeoutMs);

  try {
    return await fetchFn(url, {
      ...init,
      signal: controller.signal,
      redirect: "error",
    });
  } catch (error) {
    fail({
      code: CODE.AWS_CREDENTIALS_UNAVAILABLE,
      detail: error instanceof Error ? error.message : "AWS credential endpoint could not be reached.",
      context: { url },
    });
  } finally {
    clearTimeout(timeout);
  }
}

async function readJsonCredentials(fetchFn: typeof fetch, url: string, init: RequestInit, timeoutMs: number): Promise<S3AwsCredentials> {
  const response = await fetchWithTimeout(fetchFn, url, init, timeoutMs);
  if (!response.ok) {
    fail({
      code: CODE.AWS_CREDENTIALS_UNAVAILABLE,
      detail: `AWS credential endpoint returned HTTP ${response.status}.`,
      retryable: response.status >= 500 || response.status === 429,
      fatal: response.status >= 400 && response.status < 500 && response.status !== 429,
      context: { url },
    });
  }

  let body: unknown;
  try {
    body = await response.json();
  } catch {
    fail({
      code: CODE.AWS_CREDENTIALS_INVALID,
      detail: "AWS credential endpoint returned non-JSON credentials.",
      context: { url },
    });
  }

  const parsed = awsCredentialResponseSchema.safeParse(body);
  if (!parsed.success) {
    fail({
      code: CODE.AWS_CREDENTIALS_INVALID,
      detail: "AWS credential endpoint returned an unexpected response shape.",
      context: {
        url,
        issues: parsed.error.issues.map((issue) => ({
          path: issue.path.join("."),
          message: issue.message,
        })),
      },
    });
  }

  return {
    accessKeyId: parsed.data.AccessKeyId,
    secretAccessKey: parsed.data.SecretAccessKey,
    sessionToken: parsed.data.Token,
    expiration: parsed.data.Expiration ? new Date(parsed.data.Expiration) : undefined,
  };
}

async function resolveEc2RoleName(fetchFn: typeof fetch, timeoutMs: number): Promise<string> {
  const tokenResponse = await fetchWithTimeout(
    fetchFn,
    `${EC2_METADATA_ENDPOINT}/latest/api/token`,
    {
      method: "PUT",
      headers: {
        "x-aws-ec2-metadata-token-ttl-seconds": "21600",
      },
    },
    timeoutMs
  );
  if (!tokenResponse.ok) {
    fail({
      code: CODE.AWS_CREDENTIALS_UNAVAILABLE,
      detail: `EC2 metadata token endpoint returned HTTP ${tokenResponse.status}.`,
    });
  }

  const token = await tokenResponse.text();
  const roleResponse = await fetchWithTimeout(
    fetchFn,
    `${EC2_METADATA_ENDPOINT}/latest/meta-data/iam/security-credentials/`,
    {
      headers: {
        "x-aws-ec2-metadata-token": token,
      },
    },
    timeoutMs
  );
  if (!roleResponse.ok) {
    fail({
      code: CODE.AWS_CREDENTIALS_UNAVAILABLE,
      detail: `EC2 metadata role endpoint returned HTTP ${roleResponse.status}.`,
    });
  }

  const roleName = (await roleResponse.text()).trim().split("\n")[0];
  if (!roleName) {
    fail({
      code: CODE.AWS_CREDENTIALS_UNAVAILABLE,
      detail: "EC2 metadata did not return an IAM role name.",
    });
  }

  return roleName;
}

/**
 * Resolves AWS credentials from env, ECS task metadata, or EC2 IMDSv2.
 *
 * @param options - Environment, fetch implementation, and metadata timeout overrides.
 * @returns Temporary or static AWS credentials used for SigV4 requests.
 * @throws {WorkerError} When no credential source can be resolved.
 */
export async function resolveAwsCredentials(options: AwsCredentialProviderOptions = {}): Promise<S3AwsCredentials> {
  const env = options.env ?? process.env;
  const fetchFn = options.fetchFn ?? fetch;
  const timeoutMs = options.timeoutMs ?? 2_000;

  if (env.AWS_ACCESS_KEY_ID && env.AWS_SECRET_ACCESS_KEY) {
    return {
      accessKeyId: env.AWS_ACCESS_KEY_ID,
      secretAccessKey: env.AWS_SECRET_ACCESS_KEY,
      sessionToken: env.AWS_SESSION_TOKEN,
    };
  }

  if (env.AWS_CONTAINER_CREDENTIALS_RELATIVE_URI) {
    return readJsonCredentials(
      fetchFn,
      `${ECS_CREDENTIAL_ENDPOINT}${env.AWS_CONTAINER_CREDENTIALS_RELATIVE_URI}`,
      {},
      timeoutMs
    );
  }

  if (env.AWS_CONTAINER_CREDENTIALS_FULL_URI) {
    return readJsonCredentials(
      fetchFn,
      validateContainerCredentialsFullUri(env.AWS_CONTAINER_CREDENTIALS_FULL_URI),
      { headers: await resolveContainerAuthorizationHeader(env) },
      timeoutMs
    );
  }

  if (env.AWS_EC2_METADATA_DISABLED !== "true") {
    const roleName = await resolveEc2RoleName(fetchFn, timeoutMs);
    return readJsonCredentials(
      fetchFn,
      `${EC2_METADATA_ENDPOINT}/latest/meta-data/iam/security-credentials/${encodeURIComponent(roleName)}`,
      {},
      timeoutMs
    );
  }

  fail({
    code: "AWS_CREDENTIALS_MISSING",
    title: "AWS credentials missing",
    detail: "Set AWS_ACCESS_KEY_ID/AWS_SECRET_ACCESS_KEY or run the worker with an ECS/EC2 IAM role.",
    category: "configuration",
    retryable: false,
    fatal: true,
  });
}

