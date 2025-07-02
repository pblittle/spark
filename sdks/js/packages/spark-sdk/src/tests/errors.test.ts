import { SparkSDKError } from "../errors/base.js";

describe("SparkSDKError", () => {
  it("should not throw and should stringify BigInt values in context", () => {
    const bigNumber = 123n;

    const err = new SparkSDKError("Test BigInt", { big: bigNumber });

    expect(err.message).toContain("Context:");
    // BigInt should be converted to a string representation
    expect(err.message).toContain('big: "123"');
  });

  it("should stringify regular primitives correctly", () => {
    const err = new SparkSDKError("Test primitives", {
      num: 1,
      str: "abc",
      bool: true,
    });

    expect(err.message).toContain("num: 1");
    expect(err.message).toContain('str: "abc"');
    expect(err.message).toContain("bool: true");
  });

  it("should include original error message when provided", () => {
    const original = new Error("something broke");
    const err = new SparkSDKError("Wrapper error", {}, original);

    expect(err.message).toContain("Original Error: something broke");
  });

  it("should stringify Uint8Array values correctly", () => {
    const bytes = new Uint8Array([1, 2, 3]);
    const err = new SparkSDKError("Uint8Array test", { bytes });

    expect(err.message).toContain("bytes:");
    expect(err.message).toMatch(/Uint8Array\(0x010203\)/);
  });

  it("should generate the correct full error message", () => {
    const original = new Error("root cause");
    const context = {
      big: 123n,
      bytes: new Uint8Array([1, 2, 3]),
      num: 42,
    } as const;

    const err = new SparkSDKError("Something went wrong", context, original);

    const expectedMessage =
      "SparkSDKError: Something went wrong\n" +
      'Context: big: "123", bytes: "Uint8Array(0x010203)", num: 42\n' +
      "Original Error: root cause";

    expect(err.message).toBe(expectedMessage);
  });
});
