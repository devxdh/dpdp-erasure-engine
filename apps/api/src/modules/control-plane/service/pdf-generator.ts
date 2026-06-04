import { PDFDocument, StandardFonts, rgb } from "pdf-lib";

/**
 * Technical details included in the proof of erasure.
 */
export interface ProofOfErasureData {
  requestId: string;
  subjectOpaqueId: string;
  method: string;
  legalFramework: string;
  appliedRuleName: string | null;
  appliedRuleCitation: string | null;
  shreddedAt: string;
  finalWormHash: string | null;
  postgresTransactionIds?: string[];
  blobSummary?: {
    totalObjects: number;
    totalVersionsPurged: number;
    provider: string;
  };
  signature: {
    algorithm: string;
    keyId: string;
    signatureBase64: string;
    publicKeySpkiBase64: string;
  };
}

/**
 * Service for generating human-readable legal artifacts from raw ledger data.
 */
export class PdfCertificateGenerator {
  /**
   * Generates a digitally signed PDF "Certificate of Erasure".
   *
   * @param data - Normalized certificate and signature data.
   * @param clientDisplayName - Optional display name of the tenant authority.
   * @returns PDF buffer as Uint8Array.
   */
  async generate(data: ProofOfErasureData, clientDisplayName: string = "DPDP Authority"): Promise<Uint8Array> {
    const pdfDoc = await PDFDocument.create();
    let page = pdfDoc.addPage([600, 800]);
    const font = await pdfDoc.embedFont(StandardFonts.Helvetica);
    const boldFont = await pdfDoc.embedFont(StandardFonts.HelveticaBold);
    const courier = await pdfDoc.embedFont(StandardFonts.Courier);

    const { width, height } = page.getSize();
    const margin = 50;
    let cursorY = height - 160;

    const drawFooter = () => {
      page.drawText("This document is a machine-generated legal record of non-reversible cryptographic erasure.", {
        x: margin,
        y: 40,
        size: 8,
        font,
        color: rgb(0.5, 0.5, 0.5),
      });
    };

    const addContinuationPage = () => {
      drawFooter();
      page = pdfDoc.addPage([600, 800]);
      cursorY = height - margin;
      page.drawText("CERTIFICATE OF PERMANENT DATA ERASURE (CONTINUED)", {
        x: margin,
        y: cursorY,
        size: 14,
        font: boldFont,
        color: rgb(0, 0, 0),
      });
      cursorY -= 25;
      page.drawLine({
        start: { x: margin, y: cursorY },
        end: { x: width - margin, y: cursorY },
        thickness: 1,
        color: rgb(0.8, 0.8, 0.8),
      });
      cursorY -= 25;
    };

    const ensureSpace = (requiredHeight: number) => {
      if (cursorY - requiredHeight < 70) {
        addContinuationPage();
      }
    };

    // Header
    page.drawText("CERTIFICATE OF PERMANENT DATA ERASURE", {
      x: margin,
      y: height - 100,
      size: 20,
      font: boldFont,
      color: rgb(0, 0, 0),
    });

    page.drawLine({
      start: { x: margin, y: height - 110 },
      end: { x: width - margin, y: height - 110 },
      thickness: 2,
      color: rgb(0, 0, 0),
    });

    // Subject Details
    const drawField = (label: string, value: string | null) => {
      ensureSpace(25);
      page.drawText(`${label}:`, { x: margin, y: cursorY, size: 10, font: boldFont });
      page.drawText(value ?? "N/A", { x: margin + 150, y: cursorY, size: 10, font });
      cursorY -= 25;
    };

    const drawSection = (title: string) => {
      ensureSpace(50);
      page.drawText(title, { x: margin, y: cursorY, size: 12, font: boldFont });
      cursorY -= 15;
      page.drawLine({
        start: { x: margin, y: cursorY },
        end: { x: width - margin, y: cursorY },
        thickness: 1,
        color: rgb(0.8, 0.8, 0.8),
      });
      cursorY -= 20;
    };

    drawField("Authority", clientDisplayName);
    drawField("Request ID", data.requestId);
    drawField("Subject Identifier", data.subjectOpaqueId);
    drawField("Erasure Method", data.method);
    drawField("Completed At", data.shreddedAt);
    cursorY -= 10;

    // Legal Compliance Section
    drawSection("LEGAL COMPLIANCE");

    drawField("Legal Framework", data.legalFramework);
    drawField("Rule Applied", data.appliedRuleName);
    drawField("Statutory Citation", data.appliedRuleCitation);
    cursorY -= 10;

    if (data.postgresTransactionIds && data.postgresTransactionIds.length > 0) {
      drawSection("POSTGRES TRANSACTION TRACE");

      for (const [index, txid] of data.postgresTransactionIds.entries()) {
        drawField(`Transaction ID ${index + 1}`, txid);
      }
      cursorY -= 10;
    }

    // Object Storage Section
    if (data.blobSummary && data.blobSummary.totalObjects > 0) {
      drawSection("OBJECT STORAGE PURGE");

      drawField("Storage Provider", data.blobSummary.provider);
      drawField("Linked Objects Purged", String(data.blobSummary.totalObjects));
      drawField("Total Versions Deleted", String(data.blobSummary.totalVersionsPurged));
      cursorY -= 10;
    }

    // Cryptographic Proof Section
    drawSection("CRYPTOGRAPHIC PROOF (WORM)");

    ensureSpace(55);
    page.drawText("Final Ledger Hash (SHA-256):", { x: margin, y: cursorY, size: 10, font: boldFont });
    cursorY -= 15;
    page.drawText(data.finalWormHash ?? "GENESIS", {
      x: margin,
      y: cursorY,
      size: 9,
      font: courier,
      color: rgb(0.2, 0.2, 0.2),
    });
    cursorY -= 30;

    ensureSpace(55);
    page.drawText("Digital Signature (Ed25519):", { x: margin, y: cursorY, size: 10, font: boldFont });
    cursorY -= 15;
    const signatureChunk = data.signature.signatureBase64.match(/.{1,64}/g) ?? [];
    for (const chunk of signatureChunk) {
      ensureSpace(12);
      page.drawText(chunk, { x: margin, y: cursorY, size: 8, font: courier, color: rgb(0.3, 0.3, 0.3) });
      cursorY -= 12;
    }
    cursorY -= 10;

    ensureSpace(25);
    page.drawText("Signing Key ID:", { x: margin, y: cursorY, size: 10, font: boldFont });
    page.drawText(data.signature.keyId, { x: margin + 150, y: cursorY, size: 9, font: courier });

    // Footer
    drawFooter();

    return pdfDoc.save();
  }
}
