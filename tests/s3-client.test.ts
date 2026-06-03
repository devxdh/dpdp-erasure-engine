import { describe, expect, it, vi } from "vitest";
import { createS3Client, parseS3ObjectUrl } from "@modules/network";

describe("S3 client", () => {
  it("parses S3 URLs without losing version ids", () => {
    expect(parseS3ObjectUrl("s3://kyc-bucket/kyc/john-doe-aadhar.pdf?versionId=v123")).toEqual({
      bucket: "kyc-bucket",
      key: "kyc/john-doe-aadhar.pdf",
      versionId: "v123",
    });

    expect(parseS3ObjectUrl("https://kyc-bucket.s3.ap-south-1.amazonaws.com/kyc/doc.pdf?versionId=v9")).toEqual({
      bucket: "kyc-bucket",
      key: "kyc/doc.pdf",
      versionId: "v9",
    });
  });

  it("signs native S3 requests and crawls object versions", async () => {
    const calls: Array<{ url: string; method: string; authorization: string | null }> = [];
    const fetchFn = vi.fn(async (input: string | URL | Request, init?: RequestInit) => {
      const url = String(input);
      const headers = new Headers(init?.headers);
      calls.push({
        url,
        method: init?.method ?? "GET",
        authorization: headers.get("authorization"),
      });

      if (url.includes("169.254.170.2")) {
        return new Response(JSON.stringify({
          AccessKeyId: "AKIATEST",
          SecretAccessKey: "secret",
          Token: "session",
        }), { status: 200 });
      }

      if (url.includes("versions")) {
        return new Response(`<?xml version="1.0" encoding="UTF-8"?>
          <ListVersionsResult>
            <IsTruncated>false</IsTruncated>
            <Version>
              <Key>kyc/doc.pdf</Key>
              <VersionId>v1</VersionId>
              <ETag>"etag-1"</ETag>
            </Version>
            <DeleteMarker>
              <Key>kyc/doc.pdf</Key>
              <VersionId>marker-1</VersionId>
            </DeleteMarker>
          </ListVersionsResult>`, { status: 200 });
      }

      return new Response(null, {
        status: 200,
        headers: {
          "x-amz-version-id": "v1",
          etag: "\"etag-1\"",
        },
      });
    });

    const client = createS3Client({
      env: {
        AWS_CONTAINER_CREDENTIALS_RELATIVE_URI: "/v2/credentials/task",
        AWS_EC2_METADATA_DISABLED: "true",
      },
      fetchFn: fetchFn as unknown as typeof fetch,
    });

    const head = await client.headObject({
      bucket: "kyc-bucket",
      key: "kyc/doc.pdf",
      region: "ap-south-1",
    });
    const versions = await client.listObjectVersions({
      bucket: "kyc-bucket",
      key: "kyc/doc.pdf",
      region: "ap-south-1",
    });

    expect(head).toMatchObject({ versionId: "v1", eTag: "etag-1" });
    expect(versions).toEqual([
      { key: "kyc/doc.pdf", versionId: "v1", eTag: "etag-1", isDeleteMarker: false },
      { key: "kyc/doc.pdf", versionId: "marker-1", eTag: null, isDeleteMarker: true },
    ]);
    expect(calls.some((call) => call.authorization?.startsWith("AWS4-HMAC-SHA256"))).toBe(true);
    expect(calls.some((call) => call.url.includes("169.254.170.2/v2/credentials/task"))).toBe(true);
  });

  it("rejects unsafe HTTP container credential endpoints before any S3 request is sent", async () => {
    const fetchFn = vi.fn(async () => new Response(null, { status: 500 }));
    const client = createS3Client({
      env: {
        AWS_CONTAINER_CREDENTIALS_FULL_URI: "http://metadata.evil.local/creds",
        AWS_EC2_METADATA_DISABLED: "true",
      },
      fetchFn: fetchFn as unknown as typeof fetch,
    });

    await expect(client.headObject({
      bucket: "kyc-bucket",
      key: "kyc/doc.pdf",
      region: "ap-south-1",
    })).rejects.toMatchObject({
      code: "AWS_CREDENTIALS_URI_REJECTED",
    });
    expect(fetchFn).not.toHaveBeenCalled();
  });
});
