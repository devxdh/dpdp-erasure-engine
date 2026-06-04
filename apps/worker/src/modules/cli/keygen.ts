import pc from "picocolors";
import { bytesToBase64 } from "@/lib";
import { UI, exitWithError } from "./ui";

/**
 * Generates an Ed25519 keypair for manifest signing.
 */
export async function keygenAction() {
  UI.header("Key Generation");
  UI.info("Generating cryptographically secure Ed25519 keypair...");

  try {
    const keyPair = (await globalThis.crypto.subtle.generateKey(
      { name: "Ed25519" },
      true,
      ["sign", "verify"],
    )) as unknown as CryptoKeyPair;

    const privateKeyRaw = await globalThis.crypto.subtle.exportKey("pkcs8", keyPair.privateKey);
    const publicKeyRaw = await globalThis.crypto.subtle.exportKey("pkcs8", keyPair.publicKey);

    const privateKeyBase64 = bytesToBase64(new Uint8Array(privateKeyRaw));
    const publicKeyBase64 = bytesToBase64(new Uint8Array(publicKeyRaw));

    await Bun.write("worker.pkcs8.key", privateKeyBase64);
    await Bun.write("worker.spki.pub", publicKeyBase64);

    UI.success("Keypair provisioned successfully.");
    UI.info("FILES GENERATED:");
    UI.keyValue("Private Key", pc.red("worker.pkcs8.key") + " (SECRET)");
    UI.keyValue("Public Key ", pc.green("worker.spki.pub") + " (AUDIT)");

    UI.warn("Never share your private key or commit it to version control.");
    UI.hint("Configuration signing provides tamper-evidence for your legal mandates.");
  } catch (err) {
    exitWithError("Key generation failed", err instanceof Error ? err.message : String(err));
  }
}