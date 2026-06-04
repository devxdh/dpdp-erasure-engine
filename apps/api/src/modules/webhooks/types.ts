import type { HonoRequest } from "hono";
import type { ProviderSubjectKind } from "./subject";

export type WebhookProvider = "onetrust" | "jira" | "zendesk";

export type WebhookTriggerSource = "ONETRUST" | "JIRA" | "ZENDESK";

export interface NormalizedJob {
  provider_subject_id: string;
  provider_subject_kind: ProviderSubjectKind;
  trigger_source: WebhookTriggerSource;
  external_reference_id: string;
  request_timestamp: Date;
}

export interface WebhookAdapter {
  verifySignature(req: HonoRequest, rawBody: string, secret: string): Promise<boolean>;
  normalize(payload: unknown): Promise<NormalizedJob>;
}

export interface WebhookClient {
  id: string;
  organization_id: string;
  is_active: boolean;
  webhook_signing_secret: string | null;
  webhook_previous_signing_secret: string | null;
  webhook_previous_secret_expires_at: Date | null;
}

export interface IngestWebhookInput {
  provider: WebhookProvider;
  client: WebhookClient;
  normalized: NormalizedJob;
  now: Date;
}

export interface IngestWebhookResult {
  accepted: true;
  duplicate: boolean;
  erasure_job_id: string | null;
  task_id: string | null;
  subject_opaque_id?: string;
}
