import { readFileSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";
import { bytesToBase64, base64ToBytes } from "@engine/worker/src/lib";

function toArrayBuffer(bytes: Uint8Array): ArrayBuffer {
  const copy = new Uint8Array(bytes.length);
  copy.set(bytes);
  return copy.buffer as ArrayBuffer;
}

async function main(): Promise<void> {
  const configPath = resolve(process.argv[2] ?? "compliance-engine/compliance.worker.yml");
  const privateKeyPath = resolve(process.argv[3] ?? "deploy/local/generated/keys/worker-config-private-key.base64");
  const signaturePath = resolve(process.argv[4] ?? `${configPath}.sig`);

  const privateKeyBase64 = readFileSync(privateKeyPath, "utf8").trim();
  const configBytes = new TextEncoder().encode(readFileSync(configPath, "utf8"));
  const privateKey = await crypto.subtle.importKey(
    "pkcs8",
    toArrayBuffer(base64ToBytes(privateKeyBase64)),
    { name: "Ed25519" },
    false,
    ["sign"]
  );

  const signature = new Uint8Array(await crypto.subtle.sign("Ed25519", privateKey, configBytes));
  writeFileSync(signaturePath, bytesToBase64(signature), "utf8");
  console.log(`Wrote detached signature to ${signaturePath}`);
}

await main();

