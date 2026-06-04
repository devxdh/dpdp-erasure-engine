import { sha256Hex } from "./security";

const EMAIL_PATTERN = /^[^\s@]+@[^\s@]+\.[^\s@]+$/i;
const DERIVED_SUBJECT_PATTERN = /^(email_sha256|phone_sha256):[0-9a-f]{64}$/i;

function canonicalPhone(value: string): string | null {
  const normalized = value.replace(/[\s().-]/g, "");
  if (/^(?:\+91|0091|91)?[6789]\d{9}$/.test(normalized)) {
    return normalized.replace(/^(?:\+91|0091|91)/, "+91");
  }

  return null;
}

export type ProviderSubjectKind = "opaque" | "email_sha256" | "phone_sha256";

export interface ProviderSubjectLookup {
  lookupId: string;
  kind: ProviderSubjectKind;
}

/**
 * Converts a provider-local subject reference into the zero-PII lookup key used by Avantii.
 *
 * Opaque provider ids pass through unchanged for backward compatibility. Email and phone
 * references are accepted only as transient webhook/mapping inputs and are immediately
 * converted to deterministic SHA-256 lookup tokens. The raw PII value must never be stored.
 *
 * @param rawSubject - Provider-local subject id, email, or phone value.
 * @returns Canonical lookup key plus the classification of the original value.
 */
export async function normalizeProviderSubjectLookup(rawSubject: string): Promise<ProviderSubjectLookup> {
  const trimmed = rawSubject.trim();
  if (DERIVED_SUBJECT_PATTERN.test(trimmed)) {
    const kind = trimmed.toLowerCase().startsWith("email_sha256:") ? "email_sha256" : "phone_sha256";
    return { lookupId: trimmed.toLowerCase(), kind };
  }

  if (EMAIL_PATTERN.test(trimmed)) {
    const canonicalEmail = trimmed.toLowerCase();
    return {
      lookupId: `email_sha256:${await sha256Hex(canonicalEmail)}`,
      kind: "email_sha256",
    };
  }

  const phone = canonicalPhone(trimmed);
  if (phone) {
    return {
      lookupId: `phone_sha256:${await sha256Hex(phone)}`,
      kind: "phone_sha256",
    };
  }

  return {
    lookupId: trimmed,
    kind: "opaque",
  };
}
