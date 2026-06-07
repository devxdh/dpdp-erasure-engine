import { mkdirSync, writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { bytesToBase64 } from "@engine/api/src/utils";

function toArrayBuffer(bytes: Uint8Array): ArrayBuffer {
  const copy = new Uint8Array(bytes.length);
  copy.set(bytes);
  return copy.buffer as ArrayBuffer;
}

async function main(): Promise<void> {
  const outputDir = resolve(process.argv[2] ?? "deploy/local/generated/keys");
  mkdirSync(outputDir, { recursive: true });

  const pair = (await crypto.subtle.generateKey(
    { name: "Ed25519" },
    true,
    ["sign", "verify"]
  )) as unknown as CryptoKeyPair;

  const pkcs8 = await crypto.subtle.exportKey("pkcs8", pair.privateKey);
  const spki = await crypto.subtle.exportKey("spki", pair.publicKey);

  const privateKeyPath = resolve(outputDir, "coe-private-key.base64");
  const publicKeyPath = resolve(outputDir, "coe-public-key.base64");

  writeFileSync(privateKeyPath, bytesToBase64(toArrayBuffer(new Uint8Array(pkcs8))), "utf8");
  writeFileSync(publicKeyPath, bytesToBase64(toArrayBuffer(new Uint8Array(spki))), "utf8");

  console.log(
    JSON.stringify(
      {
        privateKeyPath,
        publicKeyPath,
      },
      null,
      2
    )
  );
}

await main();

