import pc from "picocolors";
import path from "node:path";
import { UI, exitWithError } from "./ui";
import { base64ToBytes, bytesToBase64 } from "@/lib";

/**
 * Signs the compliance manifest with a private key.
 */
export async function signAction(options: { config: string; key?: string }) {
  UI.header("Manifest Signing");

  const configPath = path.resolve(options.config);
  const keyPath = options.key ? path.resolve(options.key) : "worker.pkcs8.key";

  UI.info(`Manifest : ${pc.bold(options.config)}`);
  UI.info(`Key      : ${pc.bold(keyPath)}`);

  const spinner = UI.spinner("Signing manifest data...");

  try {
    const keyData = (await Bun.file(keyPath).text()).trim();
    const manifestData = new Uint8Array(await Bun.file(configPath).arrayBuffer());

    const privateKey = await globalThis.crypto.subtle.importKey(
      "pkcs8",
      base64ToBytes(keyData).buffer as ArrayBuffer,
      { name: "Ed25519" },
      false,
      ["sign"]
    );

    const signature = await globalThis.crypto.subtle.sign(
      "Ed25519",
      privateKey,
      manifestData.buffer as ArrayBuffer
    );

    const signatureBase64 = bytesToBase64(new Uint8Array(signature));
    const sigPath = `${configPath}.sig`;

    await Bun.write(sigPath, signatureBase64);
    spinner.stop();

    UI.success(`Detached signature generated: ${pc.bold(sigPath)}`);
    UI.info("Ensure this file is present alongside your manifest in the worker environment.");
  } catch (err) {
    spinner.fail("Signing failed");
    exitWithError("Process failed", err instanceof Error ? err.message : String(err));
  }
}
