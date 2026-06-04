import type { CoeSigner } from "@/crypto";
import { fail } from "@/errors";
import { canonicalJsonStringify } from "../hash";
import type { ControlPlaneRepository, ErasureJobRow } from "../repository";
import type {
  TerminalCertificateEnvelope,
  TerminalCertificateMethod,
  TerminalEventType,
} from "./types";

/**
 * Returns the Certificate of Erasure method code bound into the signed payload.
 *
 * @param eventType - Terminal worker event that completed the subject lifecycle.
 * @returns Stable method code persisted in the signed certificate.
 */
export function resolveCertificateMethod(
  eventType: TerminalEventType
): TerminalCertificateMethod {
  return eventType === "SHRED_SUCCESS"
    ? "CRYPTO_SHREDDING_DEK_DELETE"
    : "DIRECT_DELETE_ROOT_ROW";
}

/**
 * Narrows arbitrary outbox event strings to the terminal lifecycle events.
 *
 * @param eventType - Worker event type.
 * @returns `true` when the event completes the lifecycle and requires certificate logic.
 */
export function isTerminalEventType(eventType: string): eventType is TerminalEventType {
  return eventType === "SHRED_SUCCESS" || eventType === "USER_HARD_DELETED";
}

function buildTerminalCertificatePayload(
  job: ErasureJobRow,
  eventType: TerminalEventType,
  shreddedAt: Date,
  finalWormHash: string,
  blobReceipts: unknown[] = [],
  postgresTransactionIds: unknown[] = []
): TerminalCertificateEnvelope["payload"] {
  return {
    request_id: job.id,
    subject_opaque_id: job.subject_opaque_id,
    event_type: eventType,
    method: resolveCertificateMethod(eventType),
    legal_framework: job.legal_framework,
    applied_rule_name: job.applied_rule_name,
    applied_rule_citation: job.applied_rule_citation,
    shredded_at: shreddedAt.toISOString(),
    final_worm_hash: finalWormHash,
    blob_receipts: blobReceipts,
    postgres_transaction_ids: postgresTransactionIds,
  };
}

async function enqueueTerminalWebhook(
  repository: ControlPlaneRepository,
  jobId: string,
  url: string,
  headers: Record<string, string>,
  payload: unknown,
  now: Date
): Promise<void> {
  await repository.enqueueWebhook({
    jobId,
    url,
    headers,
    payload,
    now,
  });
}

function providerCompletionHeaders(
  target: Awaited<ReturnType<ControlPlaneRepository["getProviderCompletionTargetsForJob"]>>[number]
): Record<string, string> {
  if (!target.auth_header_name || !target.auth_header_value) {
    return {};
  }

  return {
    [target.auth_header_name]: target.auth_header_value,
  };
}

/**
 * Ensures a terminal Certificate of Erasure exists and matches the terminal WORM event exactly.
 *
 * @param repository - Control-plane persistence gateway.
 * @param signer - Ed25519 signer used to mint new certificates.
 * @param job - Existing erasure job.
 * @param eventType - Terminal worker event being finalized.
 * @param shreddedAt - Terminal timestamp bound into the certificate.
 * @param finalWormHash - Final ledger hash committed for the request.
 * @returns Existing or newly created signed certificate envelope.
 * @throws {ApiError} When stored certificate contents conflict with the terminal event.
 */
export async function ensureTerminalCertificate(
  repository: ControlPlaneRepository,
  signer: CoeSigner,
  job: ErasureJobRow,
  eventType: TerminalEventType,
  shreddedAt: Date,
  finalWormHash: string,
  blobReceipts: unknown[] = [],
  postgresTransactionIds: unknown[] = []
): Promise<TerminalCertificateEnvelope> {
  const payload = buildTerminalCertificatePayload(
    job,
    eventType,
    shreddedAt,
    finalWormHash,
    blobReceipts,
    postgresTransactionIds
  );
  const existingCertificate = await repository.getCertificateByRequestId(job.id, job.organization_id);
  if (existingCertificate) {
    if (
      canonicalJsonStringify(existingCertificate.payload) !==
      canonicalJsonStringify(payload)
    ) {
      fail({
        code: "API_CERTIFICATE_INTEGRITY_CONFLICT",
        title: "Stored certificate payload mismatch",
        detail: `Certificate ${job.id} does not match the terminal WORM event being processed.`,
        status: 409,
        category: "integrity",
        retryable: false,
      });
    }

    return {
      payload,
      signature: {
        algorithm: existingCertificate.algorithm,
        keyId: existingCertificate.key_id,
        signatureBase64: existingCertificate.signature_base64,
        publicKeySpkiBase64: existingCertificate.public_key_spki_base64,
      },
    };
  }

  const signature = await signer.sign(payload);
  const inserted = await repository.insertCertificate({
    requestId: job.id,
    organizationId: job.organization_id,
    subjectOpaqueId: job.subject_opaque_id,
    method: payload.method,
    legalFramework: job.legal_framework,
    shreddedAt,
    payload,
    signatureBase64: signature.signatureBase64,
    publicKeySpkiBase64: signature.publicKeySpkiBase64,
    keyId: signature.keyId,
    algorithm: signature.algorithm,
  });

  if (!inserted) {
    const racedCertificate = await repository.getCertificateByRequestId(job.id, job.organization_id);
    if (!racedCertificate) {
      fail({
        code: "API_CERTIFICATE_INSERT_RACE",
        title: "Certificate insert race failed",
        detail: `Certificate ${job.id} conflicted during insert but no stored certificate could be reloaded.`,
        status: 409,
        category: "concurrency",
        retryable: true,
      });
    }

    if (
      canonicalJsonStringify(racedCertificate.payload) !==
      canonicalJsonStringify(payload)
    ) {
      fail({
        code: "API_CERTIFICATE_INTEGRITY_CONFLICT",
        title: "Stored certificate payload mismatch",
        detail: `Certificate ${job.id} does not match the terminal WORM event being processed.`,
        status: 409,
        category: "integrity",
        retryable: false,
      });
    }

    return {
      payload,
      signature: {
        algorithm: racedCertificate.algorithm,
        keyId: racedCertificate.key_id,
        signatureBase64: racedCertificate.signature_base64,
        publicKeySpkiBase64: racedCertificate.public_key_spki_base64,
      },
    };
  }

  return {
    payload,
    signature: {
      algorithm: signature.algorithm,
      keyId: signature.keyId,
      signatureBase64: signature.signatureBase64,
      publicKeySpkiBase64: signature.publicKeySpkiBase64,
    },
  };
}

/**
 * Completes terminal side effects for a committed terminal outbox event.
 *
 * The WORM append and job transition happen first. This helper then ensures the signed
 * certificate exists and retries webhook delivery idempotently until the worker receives
 * a successful response from the Control Plane.
 *
 * @param repository - Control-plane persistence gateway.
 * @param signer - Ed25519 signer used for certificate issuance.
 * @param webhookTimeoutMs - Hard timeout for outbound webhook calls.
 * @param job - Existing erasure job.
 * @param eventType - Terminal worker event type.
 * @param shreddedAt - Timestamp carried by the worker event.
 * @param currentHash - Final WORM hash for the request lifecycle.
 * @param blobReceipts - Optional S3 object deletion receipts.
 * @param postgresTransactionIds - PostgreSQL transaction ids observed by the worker.
 */
export async function finalizeTerminalOutboxEvent(
  repository: ControlPlaneRepository,
  signer: CoeSigner,
  webhookTimeoutMs: number,
  job: ErasureJobRow,
  eventType: TerminalEventType,
  shreddedAt: Date,
  currentHash: string,
  blobReceipts?: unknown[],
  postgresTransactionIds?: unknown[]
): Promise<void> {
  const certificate = await ensureTerminalCertificate(
    repository,
    signer,
    job,
    eventType,
    shreddedAt,
    currentHash,
    blobReceipts,
    postgresTransactionIds
  );
  if (job.webhook_url) {
    await enqueueTerminalWebhook(
      repository,
      job.id,
      job.webhook_url,
      {},
      {
        request_id: job.id,
        subject_opaque_id: job.subject_opaque_id,
        event_type: eventType,
        legal_framework: job.legal_framework,
        applied_rule_name: certificate.payload.applied_rule_name,
        applied_rule_citation: certificate.payload.applied_rule_citation,
        shredded_at: shreddedAt.toISOString(),
        certificate: {
          request_id: job.id,
          subject_opaque_id: job.subject_opaque_id,
          event_type: eventType,
          method: certificate.payload.method,
          legal_framework: job.legal_framework,
          applied_rule_name: certificate.payload.applied_rule_name,
          applied_rule_citation: certificate.payload.applied_rule_citation,
          shredded_at: shreddedAt.toISOString(),
          final_worm_hash: certificate.payload.final_worm_hash,
          postgres_transaction_ids: certificate.payload.postgres_transaction_ids,
          blob_receipts: certificate.payload.blob_receipts,
          signature: {
            algorithm: certificate.signature.algorithm,
            key_id: certificate.signature.keyId,
            signature_base64: certificate.signature.signatureBase64,
            public_key_spki_base64: certificate.signature.publicKeySpkiBase64,
          },
        },
      },
      new Date()
    );
  }

  const providerTargets = await repository.getProviderCompletionTargetsForJob(job.id);
  for (const target of providerTargets) {
    await enqueueTerminalWebhook(
      repository,
      job.id,
      target.completion_url,
      providerCompletionHeaders(target),
      {
        provider: target.provider,
        external_reference_id: target.external_reference_id,
        request_id: job.id,
        subject_opaque_id: job.subject_opaque_id,
        status: eventType,
        completed_at: shreddedAt.toISOString(),
        certificate: {
          request_id: job.id,
          method: certificate.payload.method,
          final_worm_hash: certificate.payload.final_worm_hash,
          signature: {
            algorithm: certificate.signature.algorithm,
            key_id: certificate.signature.keyId,
            signature_base64: certificate.signature.signatureBase64,
            public_key_spki_base64: certificate.signature.publicKeySpkiBase64,
          },
        },
      },
      new Date()
    );
  }
}
