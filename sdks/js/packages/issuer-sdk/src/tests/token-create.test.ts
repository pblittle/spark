import { describe, it, expect } from "@jest/globals";
import { validateTokenParameters } from "../utils/create-validation.js";

const MAX_SUPPLY_128 = (1n << 128n) - 1n;

describe("validateTokenParameters (V1)", () => {
  describe("valid inputs", () => {
    it("accepts minimum & maximum byte length for name", () => {
      expect(() => validateTokenParameters("abc", "AAA", 0, 1n)).not.toThrow();
      expect(() =>
        validateTokenParameters("12345678901234567890", "AAA", 0, 1n),
      ).not.toThrow();
    });

    it("accepts minimum & maximum byte length for symbol", () => {
      expect(() =>
        validateTokenParameters("Token", "ABC", 0, 1n),
      ).not.toThrow();
      expect(() =>
        validateTokenParameters("Token", "ABCDEF", 0, 1n),
      ).not.toThrow();
    });

    it("accepts combined length exactly at upper bound", () => {
      // name 17 bytes + symbol 3 bytes = 20 bytes
      expect(() =>
        validateTokenParameters("ABCDEFGHIJKLMNOPQ", "AAA", 0, 1n),
      ).not.toThrow();
    });

    it("accepts decimals within 0-255 and maxSupply within u128", () => {
      expect(() =>
        validateTokenParameters("Token", "TOK", 255, MAX_SUPPLY_128),
      ).not.toThrow();
    });

    it("handles multi-byte UTF-8 characters correctly", () => {
      // "🚀" is 4 bytes in UTF-8
      expect(() =>
        validateTokenParameters("Tok🚀n", "TOK", 8, 1000n),
      ).not.toThrow();
    });
  });

  describe("invalid inputs", () => {
    it("rejects name too short or too long", () => {
      expect(() => validateTokenParameters("ab", "AAA", 0, 1n)).toThrow();
      expect(() =>
        validateTokenParameters("123456789012345678901", "AAA", 0, 1n),
      ).toThrow();
    });

    it("rejects symbol too short or too long", () => {
      expect(() => validateTokenParameters("Token", "AB", 0, 1n)).toThrow();
      expect(() =>
        validateTokenParameters("Token", "ABCDEFG", 0, 1n),
      ).toThrow();
    });

    it("rejects decimals outside 0-255 or non-integer", () => {
      // >255
      expect(() => validateTokenParameters("Token", "TOK", 256, 1n)).toThrow();
      // negative
      expect(() => validateTokenParameters("Token", "TOK", -1, 1n)).toThrow();
      // non-integer (should be rejected by safe-integer check)
      // eslint-disable-next-line @typescript-eslint/ban-ts-comment
      // @ts-ignore intentional wrong type for test
      expect(() => validateTokenParameters("Token", "TOK", 1.5, 1n)).toThrow();
    });

    it("rejects decimals >= 2^53", () => {
      const hugeDecimal = 2 ** 53;
      expect(() =>
        validateTokenParameters("Token", "TOK", hugeDecimal, 1n),
      ).toThrow();
    });

    it("rejects maxSupply outside u128 range", () => {
      expect(() => validateTokenParameters("Token", "TOK", 0, -1n)).toThrow();
      expect(() =>
        validateTokenParameters("Token", "TOK", 0, MAX_SUPPLY_128 + 1n),
      ).toThrow();
    });
  });
});
