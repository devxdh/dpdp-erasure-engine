import { fail } from "@/errors";

export const fetchJson = async (
  fetchFn: typeof fetch,
  url: string | URL,
  init: RequestInit,
  provider: string
): Promise<unknown> => {
  const response = await fetchFn(url, {
    ...init,
    redirect: "error"
  });
  if (!response.ok) {
    fail({
      code: "KMS_PROVIDER_FAILED",
      title: "Key provider request failed",
      detail: `${provider} responded with HTTP ${response.status}.`,
      category: "external",
      retryable: response.status >= 500 || response.status === 429,
      fatal: response.status >= 400 && response.status < 500 && response.status !== 429,
      context: { provider, status: response.status },
    });
  }
  return response.json();
};

export const isRecord = (value: unknown): value is Record<string, unknown> => {
  return typeof value === "object" && value !== null;
}

export function encodeVaultPathSegment(value: string): string {
  return value
    .split("/")
    .filter((part) => part.length > 0)
    .map((part) => encodeURIComponent(part))
    .join("/");
}