import type { CoeSigner } from "@/crypto";
import type { ControlPlaneRepository, ErasureJobRow } from "../repository";

/**
 * Dependencies required to construct the zero-PII orchestration service.
 */
export interface ServiceOptions {
  repository: ControlPlaneRepository;
  signer: CoeSigner;
  workerSharedSecret: string;
  workerClientName: string;
  maxOutboxPayloadBytes: number;
  webhookTimeoutMs?: number;
  shadowBurnInRequired?: boolean;
  shadowRequiredSuccesses?: number;
  now?: () => Date;
}

/**
 * Terminal worker events that complete the legal lifecycle.
 */
export type TerminalEventType = "SHRED_SUCCESS" | "USER_HARD_DELETED";

/**
 * Certificate method codes bound into the signed Certificate of Erasure.
 */
export type TerminalCertificateMethod =
  | "CRYPTO_SHREDDING_DEK_DELETE"
  | "DIRECT_DELETE_ROOT_ROW";

/**
 * Signed certificate envelope returned by Control Plane terminal finalization.
 */
export interface TerminalCertificateEnvelope {
  payload: {
    request_id: string;
    subject_opaque_id: string;
    event_type: TerminalEventType;
    method: TerminalCertificateMethod;
    legal_framework: string;
    applied_rule_name: string | null;
    applied_rule_citation: string | null;
    shredded_at: string;
    final_worm_hash: string;
    blob_receipts: unknown[];
    postgres_transaction_ids: unknown[];
  };
  signature: {
    algorithm: string;
    keyId: string;
    signatureBase64: string;
    publicKeySpkiBase64: string;
  };
}

/**
 * Worker-computed lifecycle timestamps persisted by the Control Plane after vaulting.
 */
export interface VaultLifecycleSchedule {
  notificationDueAt: Date;
  shredDueAt: Date;
}

/**
 * Worker-computed legal rule metadata emitted with `USER_VAULTED`.
 */
export interface VaultLifecyclePolicy {
  appliedRuleName: string;
  appliedRuleCitation: string;
}

/**
 * Current persisted predecessor states allowed for newly inserted worker outbox events.
 */
export type AllowedOutboxPredecessorStatus = ErasureJobRow["status"];
