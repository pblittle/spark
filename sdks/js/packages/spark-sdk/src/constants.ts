import { isNode } from "@lightsparkdev/core";

export const isReactNative =
  typeof navigator !== "undefined" && navigator.product === "ReactNative";

export const isBun = globalThis.Bun !== undefined;

declare const __PACKAGE_VERSION__: string;

export const packageVersion =
  typeof __PACKAGE_VERSION__ !== "undefined" ? __PACKAGE_VERSION__ : "unknown";

let baseEnvStr = "unknown";
if (isBun) {
  const bunVersion =
    "version" in globalThis.Bun ? globalThis.Bun.version : "unknown-version";
  baseEnvStr = `bun/${bunVersion}`;
} else if (isNode) {
  baseEnvStr = `node/${process.version}`;
} else if (isReactNative) {
  baseEnvStr = "react-native";
} else {
  const userAgent =
    (typeof navigator !== "undefined" && navigator.userAgent) ||
    "unknown-user-agent";
  baseEnvStr = `browser/${userAgent}`;
}

export const clientEnv = `js-spark-sdk/${packageVersion} ${baseEnvStr}`;
