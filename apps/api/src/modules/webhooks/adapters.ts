import type { HonoRequest } from "hono";
import { fail } from "@/errors";
import { verifyHmacSha256 } from "./security";
import { normalizeProviderSubjectLookup } from "./subject";
import type { NormalizedJob, WebhookAdapter, WebhookProvider, WebhookTriggerSource } from "./types";

function asRecord(value: unknown): Record<string, unknown> {
  return typeof value === "object" && value !== null ? value as Record<string, unknown> : {};
}

function nestedRecord(value: unknown, key: string): Record<string, unknown> {
  return asRecord(asRecord(value)[key]);
}

function stringField(record: Record<string, unknown>, keys: readonly string[]): string | null {
  for (const key of keys) {
    const value = record[key];
    if (typeof value === "string" && value.trim().length > 0) {
      return value.trim();
    }
    if (typeof value === "number" && Number.isFinite(value)) {
      return String(value);
    }
  }

  return null;
}

function dateField(record: Record<string, unknown>, keys: readonly string[]): Date {
  const raw = stringField(record, keys);
  const date = raw ? new Date(raw) : new Date();
  return Number.isNaN(date.getTime()) ? new Date() : date;
}

function requireField(value: string | null, field: string, provider: string): string {
  if (!value) {
    fail({
      code: "API_WEBHOOK_PAYLOAD_INVALID",
      title: "Invalid webhook payload",
      detail: `${provider} webhook payload is missing ${field}.`,
      status: 400,
      category: "validation",
      retryable: false,
      context: { provider, field },
    });
  }
  return value;
}

async function buildJob(
  provider: WebhookTriggerSource,
  providerSubjectId: string | null,
  externalReferenceId: string | null,
  timestamp: Date
): Promise<NormalizedJob> {
  const subject = await normalizeProviderSubjectLookup(
    requireField(providerSubjectId, "provider subject id", provider)
  );
  return {
    provider_subject_id: subject.lookupId,
    provider_subject_kind: subject.kind,
    trigger_source: provider,
    external_reference_id: requireField(externalReferenceId, "external reference id", provider),
    request_timestamp: timestamp,
  };
}

abstract class HmacWebhookAdapter implements WebhookAdapter {
  protected abstract readonly signatureHeader: string;

  verifySignature(req: HonoRequest, rawBody: string, secret: string): Promise<boolean> {
    return verifyHmacSha256(secret, rawBody, req.header(this.signatureHeader));
  }

  abstract normalize(payload: unknown): Promise<NormalizedJob>;
}

export class OneTrustAdapter extends HmacWebhookAdapter {
  protected readonly signatureHeader = "X-OneTrust-Signature";

  normalize(payload: unknown): Promise<NormalizedJob> {
    const root = asRecord(payload);
    const subject = nestedRecord(root, "subject");
    const request = nestedRecord(root, "request");
    return buildJob(
      "ONETRUST",
      stringField(root, ["provider_subject_id", "dataSubjectId", "subjectId", "userId", "identifier", "email"]) ??
      stringField(subject, ["id", "externalId", "identifier", "email"]),
      stringField(root, ["external_reference_id", "requestId", "eventId", "id"]) ??
      stringField(request, ["id", "requestId"]),
      dateField(root, ["request_timestamp", "timestamp", "createdAt", "created_at"])
    );
  }
}

export class JiraAdapter extends HmacWebhookAdapter {
  protected readonly signatureHeader = "X-Hub-Signature";

  normalize(payload: unknown): Promise<NormalizedJob> {
    const root = asRecord(payload);
    const issue = nestedRecord(root, "issue");
    const fields = nestedRecord(issue, "fields");
    const reporter = nestedRecord(fields, "reporter");
    const creator = nestedRecord(fields, "creator");
    return buildJob(
      "JIRA",
      stringField(root, ["provider_subject_id", "accountId", "account_id", "email"]) ??
      stringField(reporter, ["accountId", "account_id", "emailAddress", "name"]) ??
      stringField(creator, ["accountId", "account_id", "emailAddress", "name"]),
      stringField(root, ["external_reference_id", "webhookEvent", "id"]) ??
      stringField(issue, ["id", "key"]),
      dateField(root, ["request_timestamp", "timestamp", "created"])
    );
  }
}

export class ZendeskAdapter extends HmacWebhookAdapter {
  protected readonly signatureHeader = "X-Zendesk-Webhook-Signature";
  private readonly timestampHeader = "X-Zendesk-Webhook-Signature-Timestamp";
  private readonly maxTimestampSkewMs = 5 * 60 * 1000;

  override verifySignature(req: HonoRequest, rawBody: string, secret: string): Promise<boolean> {
    const timestamp = req.header(this.timestampHeader);
    if (!timestamp) {
      return Promise.resolve(false);
    }

    const timestampNumber = Number(timestamp);
    const timestampMs = timestampNumber < 1_000_000_000_000 ? timestampNumber * 1000 : timestampNumber;
    if (!Number.isFinite(timestampMs) || Math.abs(Date.now() - timestampMs) > this.maxTimestampSkewMs) {
      return Promise.resolve(false);
    }

    return verifyHmacSha256(secret, `${timestamp}${rawBody}`, req.header(this.signatureHeader));
  }

  normalize(payload: unknown): Promise<NormalizedJob> {
    const root = asRecord(payload);
    const ticket = nestedRecord(root, "ticket");
    const requester = nestedRecord(root, "requester");
    const user = nestedRecord(root, "user");
    return buildJob(
      "ZENDESK",
      stringField(root, ["provider_subject_id", "requester_id", "external_id", "email"]) ??
      stringField(requester, ["id", "external_id", "email"]) ??
      stringField(user, ["id", "external_id", "email"]),
      stringField(root, ["external_reference_id", "event_id", "id"]) ??
      stringField(ticket, ["id", "external_id"]),
      dateField(root, ["request_timestamp", "timestamp", "created_at"])
    );
  }
}

/**
 * Resolves the provider adapter for the unified webhook ingestion route.
 *
 * @param provider - Provider slug from the URL.
 * @returns Provider-specific adapter.
 * @throws {ApiError} When the provider is unsupported.
 */
export function getWebhookAdapter(provider: string): WebhookAdapter {
  switch (provider.toLowerCase()) {
    case "onetrust":
      return new OneTrustAdapter();
    case "jira":
      return new JiraAdapter();
    case "zendesk":
      return new ZendeskAdapter();
    default:
      fail({
        code: "API_WEBHOOK_PROVIDER_UNSUPPORTED",
        title: "Unsupported webhook provider",
        detail: `Webhook provider ${provider} is not supported.`,
        status: 404,
        category: "validation",
        retryable: false,
        context: { provider },
      });
  }
}

export function normalizeWebhookProvider(provider: string): WebhookProvider {
  const normalized = provider.toLowerCase();
  if (normalized === "onetrust" || normalized === "jira" || normalized === "zendesk") {
    return normalized;
  }

  fail({
    code: "API_WEBHOOK_PROVIDER_UNSUPPORTED",
    title: "Unsupported webhook provider",
    detail: `Webhook provider ${provider} is not supported.`,
    status: 404,
    category: "validation",
    retryable: false,
    context: { provider },
  });
}
