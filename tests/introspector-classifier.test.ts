import { describe, expect, it } from "vitest";
import {
  classifyLeaf,
  metadataScore,
  validateAadhaar,
  validateGstin,
  validateLuhn,
  validatePan,
} from "@modules/introspector";

describe("Introspector PII classifier", () => {
  it("detects high-confidence Indian identity and payment identifiers", () => {
    expect(validateAadhaar("2345-6789-1238")).toBe(true);
    expect(classifyLeaf("2345-6789-1238")).toContain("aadhaar");
    expect(classifyLeaf("2345-6789-1234")).not.toContain("aadhaar");

    expect(validatePan("ABCPE1234F")).toBe(true);
    expect(classifyLeaf("ABCPE1234F")).toContain("pan");
    expect(classifyLeaf("ABCDE1234F")).not.toContain("pan");

    expect(validateGstin("27ABCPE1234F1Z5")).toBe(true);
    expect(classifyLeaf("27ABCPE1234F1Z5")).toContain("gstin");
    expect(classifyLeaf("27ABCDE1234F1Z5")).not.toContain("gstin");

    expect(validateLuhn("4111 1111 1111 1111")).toBe(true);
    expect(classifyLeaf("4111 1111 1111 1111")).toContain("credit_card");
    expect(classifyLeaf("4111 1111 1111 1112")).not.toContain("credit_card");
  });

  it("detects communication, account, and infrastructure identifiers", () => {
    expect(classifyLeaf("person@example.com")).toContain("email");
    expect(classifyLeaf("+91-9876543210")).toContain("indian_mobile");
    expect(classifyLeaf("person.name@upi")).toContain("upi");
    expect(classifyLeaf("HDFC0001234")).toContain("ifsc");
    expect(classifyLeaf("P1234567")).toContain("indian_passport");
    expect(classifyLeaf("ABC1234567")).toContain("voter_epic");
    expect(classifyLeaf("203.0.113.10")).toContain("ipv4");
    expect(classifyLeaf("2001:db8:85a3::8a2e:370:7334")).toContain("ipv6");
    expect(classifyLeaf("00:1A:2B:3C:4D:5E")).toContain("mac_address");
  });

  it("requires metadata support for false-positive-prone numeric patterns", () => {
    expect(classifyLeaf("123456789012")).not.toContain("bank_account");
    expect(classifyLeaf("123456789012", "bank_account_number")).toContain("bank_account");

    expect(classifyLeaf("1990-01-31")).not.toContain("date_of_birth");
    expect(classifyLeaf("1990-01-31", "date_of_birth")).toContain("date_of_birth");

    expect(classifyLeaf("KA0120111234567")).not.toContain("indian_driving_license");
    expect(classifyLeaf("KA0120111234567", "driving_license_number")).toContain("indian_driving_license");

    expect(classifyLeaf("560001")).not.toContain("indian_pin_code");
    expect(classifyLeaf("560001", "postal_code")).toContain("indian_pin_code");
  });

  it("does not infer personal names without a dedicated NER model", () => {
    expect(metadataScore("full_name")).toBe(0);
    expect(metadataScore("first_name")).toBe(0);
    expect(metadataScore("customer_name")).toBe(0);
    expect(classifyLeaf("Priya Sharma")).toEqual([]);
  });
});
