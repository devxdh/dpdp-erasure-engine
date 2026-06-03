import { describe, expect, it, vi } from "vitest";
import { keySourceSchema, resolveConfiguredKey } from "@/secrets";
import { bytesToBase64 } from "@/lib";

const keyBytes = new Uint8Array(32).fill(0x7a);
const keyBase64 = bytesToBase64(keyBytes);

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: {
      "content-type": "application/json",
    },
  });
}

describe("runtime KMS key sources", () => {
  it("resolves AWS KMS plaintext through a signed native fetch request", async () => {
    const fetchFn = vi.fn(async (_url: string | URL | Request, init?: RequestInit) => {
      const headers = new Headers(init?.headers);
      expect(headers.get("authorization")).toMatch(/^AWS4-HMAC-SHA256 /);
      expect(headers.get("x-amz-target")).toBe("TrentService.Decrypt");
      expect(headers.get("x-amz-content-sha256")).toMatch(/^[0-9a-f]{64}$/);
      return jsonResponse({ Plaintext: keyBase64 });
    }) as unknown as typeof fetch;

    const resolved = await resolveConfiguredKey({
      env: {
        AWS_ACCESS_KEY_ID: "AKIATEST",
        AWS_SECRET_ACCESS_KEY: "secret",
      },
      keyName: "DPDP_MASTER_KEY",
      legacyEnvName: "DPDP_MASTER_KEY",
      fetchFn,
      source: keySourceSchema.parse({
        provider: "aws_kms",
        region: "ap-south-1",
        endpoint: "https://kms.ap-south-1.amazonaws.com/",
        ciphertext_blob_base64: "ciphertext",
      }),
    });

    expect(resolved).toEqual(keyBytes);
  });

  it("resolves GCP Secret Manager payload.data as URL-safe base64", async () => {
    const fetchFn = vi.fn(async () =>
      jsonResponse({
        payload: {
          data: keyBase64.replace(/\+/g, "-").replace(/\//g, "_"),
        },
      })
    ) as unknown as typeof fetch;

    const resolved = await resolveConfiguredKey({
      env: {
        GCP_ACCESS_TOKEN: "token",
      },
      keyName: "DPDP_MASTER_KEY",
      legacyEnvName: "DPDP_MASTER_KEY",
      fetchFn,
      source: keySourceSchema.parse({
        provider: "gcp_secret_manager",
        secret_version: "projects/p/secrets/dpdp-master-key/versions/latest",
      }),
    });

    expect(resolved).toEqual(keyBytes);
  });

  it("resolves HashiCorp Vault KV v2 data.data field without exposing the token", async () => {
    const fetchFn = vi.fn(async (_url: string | URL | Request, init?: RequestInit) => {
      const headers = new Headers(init?.headers);
      expect(headers.get("x-vault-token")).toBe("vault-token");
      return jsonResponse({
        data: {
          data: {
            key: `base64:${keyBase64}`,
          },
        },
      });
    }) as unknown as typeof fetch;

    const resolved = await resolveConfiguredKey({
      env: {
        VAULT_ADDR: "https://vault.example.com",
        VAULT_TOKEN: "vault-token",
      },
      keyName: "DPDP_MASTER_KEY",
      legacyEnvName: "DPDP_MASTER_KEY",
      fetchFn,
      source: keySourceSchema.parse({
        provider: "hashicorp_vault",
        mount: "secret",
        path: "dpdp/master-key",
        field: "key",
      }),
    });

    expect(resolved).toEqual(keyBytes);
  });

  it("fails closed when a remote provider returns malformed key material", async () => {
    const fetchFn = vi.fn(async () => jsonResponse({ Plaintext: bytesToBase64(new Uint8Array(8)) })) as unknown as typeof fetch;

    await expect(
      resolveConfiguredKey({
        env: {
          AWS_ACCESS_KEY_ID: "AKIATEST",
          AWS_SECRET_ACCESS_KEY: "secret",
        },
        keyName: "DPDP_MASTER_KEY",
        legacyEnvName: "DPDP_MASTER_KEY",
        fetchFn,
        source: keySourceSchema.parse({
          provider: "aws_kms",
          region: "ap-south-1",
          endpoint: "https://kms.ap-south-1.amazonaws.com/",
          ciphertext_blob_base64: "ciphertext",
        }),
      })
    ).rejects.toThrow(/exactly 32 bytes/i);
  });
});
