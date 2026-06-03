import { decryptGCM, decryptGCMBytes, encryptGCM, encryptGCMBytes, generateDEK, generateHMAC, unwrapKey, wrapKey } from "@modules/crypto";
import { describe, it, expect } from "vitest";


describe("Cryptographic Core (AES-256-GCM + Envelope + HMAC)", () => {
  const KEK = new Uint8Array(32).fill(0x42); // Dummy Master Key
  const rawPII = "User Email: john.doe@example.com, Phone: +91 9876543210";

  describe("AES-256-GCM & Envelope Encryption", () => {
    it("should successfully encrypt and decrypt PII using a unique DEK", async () => {
      const userDEK = generateDEK();

      // 1. Encrypt
      const encryptedPII = await encryptGCM(rawPII, userDEK);
      expect(encryptedPII.length).toBeGreaterThan(12 + 16); // IV (12) + Tag (16) + min 1 byte data

      // 2. Decrypt
      const decryptedPII = await decryptGCM(encryptedPII, userDEK);
      expect(decryptedPII).toBe(rawPII);
    });

    it("should expose decrypted bytes for callers that need explicit memory wiping", async () => {
      const userDEK = generateDEK();
      const encryptedPII = await encryptGCM(rawPII, userDEK);

      const decryptedBytes = await decryptGCMBytes(encryptedPII, userDEK);
      expect(new TextDecoder().decode(decryptedBytes)).toBe(rawPII);

      decryptedBytes.fill(0);
      expect(Array.from(decryptedBytes).every((byte) => byte === 0)).toBe(true);
    });

    it("should successfully wrap and unwrap a DEK using a Master KEK", async () => {
      const originalDEK = generateDEK();

      // 1. Wrap
      const wrappedDEK = await wrapKey(originalDEK, KEK);

      // 2. Unwrap
      const recoveredDEK = await unwrapKey(wrappedDEK, KEK);

      expect(recoveredDEK).toEqual(originalDEK);
    });

    it("should fail decryption if the wrong KEK is used", async () => {
      const originalDEK = generateDEK();
      const wrappedDEK = await wrapKey(originalDEK, KEK);
      const wrongKEK = new Uint8Array(32).fill(0x99);

      await expect(unwrapKey(wrappedDEK, wrongKEK)).rejects.toThrow();
    });

    it("should fail decryption if the ciphertext is tampered with", async () => {
      const userDEK = generateDEK();
      const encryptedPII = await encryptGCM(rawPII, userDEK);

      // Tamper with one byte in the middle of the ciphertext
      if (encryptedPII[20] !== undefined) {
        encryptedPII[20] ^= 0xFF;
      }

      await expect(decryptGCM(encryptedPII, userDEK)).rejects.toThrow();
    });

    it("should throw an error if encryptGCM is given an invalid key length", async () => {
      const invalidKey = new Uint8Array(16); // 128-bit instead of 256-bit
      await expect(encryptGCM(rawPII, invalidKey)).rejects.toThrow(/Invalid key length/);
    });

    it("should throw an error if decryptGCM is given an invalid key length", async () => {
      const userDEK = generateDEK();
      const encryptedPII = await encryptGCM(rawPII, userDEK);
      const invalidKey = new Uint8Array(16);
      await expect(decryptGCM(encryptedPII, invalidKey)).rejects.toThrow(/Invalid key length/);
    });

    it("should throw an error if decryptGCM is given a payload too short to be valid", async () => {
      const userDEK = generateDEK();
      const shortCiphertext = new Uint8Array(10); // Less than IV + Tag length
      await expect(decryptGCM(shortCiphertext, userDEK)).rejects.toThrow(/Invalid ciphertext/);
    });
  });

  describe("HMAC Pseudonymization", () => {
    it("should generate a consistent hash for the same input and salt", async () => {
      const salt = "somesalt123";
      const hash1 = await generateHMAC(rawPII, salt);
      const hash2 = await generateHMAC(rawPII, salt);
      expect(hash1).toBe(hash2);
      expect(hash1).toHaveLength(64); // SHA-256 hex length
    });

    it("should generate a different hash for the same input but different salt", async () => {
      const hash1 = await generateHMAC(rawPII, "saltA");
      const hash2 = await generateHMAC(rawPII, "saltB");
      expect(hash1).not.toBe(hash2);
    });

    it("should generate a different hash for different inputs with the same salt", async () => {
      const salt = "somesalt123";
      const hash1 = await generateHMAC("user1@example.com", salt);
      const hash2 = await generateHMAC("user2@example.com", salt);
      expect(hash1).not.toBe(hash2);
    });
  });
});
