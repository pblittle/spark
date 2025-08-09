import "bare-encoding/global";
import "bare-buffer/global";
import process from "bare-process";
import bareUtil from "bare-utils";
import Module from "bare-module";
import btoa from "btoa";

globalThis.process = process as unknown as typeof globalThis.process;
globalThis.btoa = btoa;

/* Avoid a console.error that comes from an import of Node.js require-in-the-middle module, see LIG-8098 */
Object.defineProperty(Module, "_resolveFilename", {
  value: () => {
    throw new Error(
      "@buildonspark/bare: This method is not supported in bare.",
    );
  },
  writable: false,
  enumerable: false,
  configurable: false,
});

globalThis.Intl = {
  NumberFormat: () => {
    return {
      resolvedOptions: () => ({
        locale: "en-US",
        numberingSystem: "latn",
        style: "decimal",
        minimumIntegerDigits: 1,
        minimumFractionDigits: 0,
        maximumFractionDigits: 3,
        useGrouping: "auto",
        notation: "standard",
        signDisplay: "auto",
        roundingIncrement: 1,
        roundingMode: "halfExpand",
        roundingPriority: "auto",
        trailingZeroDisplay: "auto",
      }),
    };
  },
} as unknown as typeof Intl;

export * from "@buildonspark/spark-sdk/bare";
export { BareSparkSigner } from "./bare-signer.js";
