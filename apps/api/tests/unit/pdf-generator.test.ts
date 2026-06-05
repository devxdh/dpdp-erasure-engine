import { describe, expect, it } from "vitest";
import { PDFDocument } from "pdf-lib";
import { PdfCertificateGenerator } from "@modules/control-plane";

describe("PdfCertificateGenerator", () => {
  it("paginates the full PostgreSQL transaction trace instead of truncating it", async () => {
    const generator = new PdfCertificateGenerator();
    const pdfBytes = await generator.generate({
      requestId: crypto.randomUUID(),
      subjectOpaqueId: "usr_pdf_trace",
      method: "CRYPTO_SHREDDING_DEK_DELETE",
      legalFramework: "DPDP_2023",
      appliedRuleName: "PMLA_FINANCIAL",
      appliedRuleCitation: "Prevention of Money Laundering Act, 2002, Sec 12",
      shreddedAt: "2036-04-19T10:00:00.000Z",
      finalWormHash: "ab".repeat(32),
      postgresTransactionIds: Array.from({ length: 40 }, (_, index) => `txid-${index + 1}`),
      signature: {
        algorithm: "Ed25519",
        keyId: "integration-key",
        signatureBase64: "a".repeat(128),
        publicKeySpkiBase64: "b".repeat(64),
      },
    });

    const parsed = await PDFDocument.load(pdfBytes);
    expect(parsed.getPageCount()).toBeGreaterThan(1);
  });
});
