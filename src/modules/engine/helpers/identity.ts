import { bytesToBase64 } from "@/lib";
import { generateHMAC } from "@/modules/crypto/hmac";

/**
 * Produces a deterministic subject hash used as the worker's irreversible lookup key.
 *
 * @param rootId - Subject identifier in the source schema.
 * @param appSchema - Source schema name.
 * @param rootTable - Source root table name.
 * @param hmacKey - HMAC key bytes.
 * @param tenantId - Optional tenant discriminator.
 * @returns Stable HMAC-SHA256 hex digest.
 */
export async function createUserHash(
  rootId: string | number,
  appSchema: string,
  rootTable: string,
  hmacKey: Uint8Array,
  tenantId?: string
): Promise<string> {
  return generateHMAC(
    `${appSchema}:${rootTable}:${tenantId ?? ""}:${rootId}`,
    bytesToBase64(hmacKey)
  );
}

/**
 * Derives an irreversible synthetic email for downstream systems that still require an address.
 *
 * @param userId - Source subject identifier.
 * @param email - Original email value from the root payload.
 * @param salt - Per-row salt stored in vault metadata.
 * @param hmacKey - HMAC key bytes.
 * @returns Pseudonymous `dpdp_...@dpdp.invalid` address.
 */
export async function createPseudonym(
  userId: string | number,
  email: string,
  salt: string,
  hmacKey: Uint8Array
): Promise<string> {
  const digest = await generateHMAC(
    `${userId}:${email}`,
    `${salt}:${bytesToBase64(hmacKey)}`
  );
  return `dpdp_${digest.slice(0, 24)}@dpdp.invalid`;
}