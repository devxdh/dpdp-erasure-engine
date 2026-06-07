import { fail, CODE } from "@/errors";
import { readRuntimeSecret } from "@/secrets";
import type { EnvType } from "@/types";
import { base64ToBytes } from "@/lib";

function toArrayBuffer(bytes: Uint8Array): ArrayBuffer {
    const copy = new Uint8Array(bytes.length);
    copy.set(bytes);
    return copy.buffer as ArrayBuffer;
}
/**
 * Verifies an optional detached Ed25519 signature for `compliance.worker.yml`.
 *
 * When no public key is configured the check is skipped. When a public key is configured, the
 * worker fails closed unless the detached signature exists and verifies successfully.
 *
 * @param env - Runtime environment map.
 * @param configPath - Path to the worker YAML manifest.
 * @throws {WorkerError} When the signature is required but missing or invalid.
 */
export async function verifySignatureWorkerConfig(
    env: EnvType,
    configPath: string | URL
): Promise<void> {
    const publicKeySpkiBase64 = await readRuntimeSecret(
        env,
        "CONFIG_SIGNING_PUBLIC_KEY_SPKI_BASE64"
    );
    if (!publicKeySpkiBase64) return;

    const signaturePath = env.CONFIG_SIGNATURE_PATH ?? `${String(configPath)}.sig`;
    let signatureBase64: string;
    try {
        signatureBase64 = (await Bun.file(signaturePath).text()).trim();
    } catch (error) {
        fail({
            code: CODE.CONFIG_SIGNATURE_MISSING,
            data: { value: signaturePath },
            cause: error
        });
    }

    const publicKey = await globalThis.crypto.subtle.importKey(
        "spki",
        toArrayBuffer(base64ToBytes(await publicKeySpkiBase64)),
        { name: "Ed25519" },
        false,
        ["verify"]
    );
    const configBytes = new Uint8Array(await Bun.file(configPath).arrayBuffer());
    const verified = await globalThis.crypto.subtle.verify(
        "Ed25519",
        publicKey,
        toArrayBuffer(base64ToBytes(signatureBase64)),
        toArrayBuffer(configBytes)
    );

    if (!verified) {
        fail({
            code: CODE.CONFIG_SIGNATURE_MISSING,
            data: { value: String(configPath) },
            cause: null,
            context: {
                configPath: String(configPath),
                signaturePath,
            }
        });
    }
}