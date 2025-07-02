import { bytesToHex } from "@noble/hashes/utils";

export class SparkSDKError extends Error {
  public readonly context: Record<string, unknown>;
  public readonly originalError?: Error;

  constructor(
    message: string,
    context: Record<string, unknown> = {},
    originalError?: Error,
  ) {
    const msg = getMessage(message, context, originalError);
    super(msg);
    this.name = this.constructor.name;
    this.context = context;
    this.originalError = originalError;

    if (Error.captureStackTrace) {
      Error.captureStackTrace(this, this.constructor);
    }
  }

  public toString(): string {
    return this.message;
  }

  public toJSON(): Record<string, unknown> {
    return {
      name: this.name,
      message: this.message,
      context: this.context,
      originalError: this.originalError
        ? {
            name: this.originalError.name,
            message: this.originalError.message,
            stack: this.originalError.stack,
          }
        : undefined,
      stack: this.stack,
    };
  }
}

function getMessage(
  message: string,
  context: Record<string, unknown> = {},
  originalError?: Error,
) {
  const contextStr = Object.entries(context)
    .map(([key, value]) => `${key}: ${safeStringify(value)}`)
    .join(", ");

  const originalErrorStr = originalError
    ? `\nOriginal Error: ${originalError.message}`
    : "";

  return `SparkSDKError: ${message}${contextStr ? `\nContext: ${contextStr}` : ""}${originalErrorStr}`;
}

function safeStringify(value: unknown): string {
  const replacer = (_: string, v: unknown) => {
    /* Handle BigInt explicitly because JSON.stringify throws a TypeError when encountering it at any depth. */
    if (typeof v === "bigint") {
      return v.toString();
    }
    if (v instanceof Uint8Array) {
      return formatUint8Array(v);
    }
    return v;
  };

  /* If the value itself is a BigInt (top-level), stringify will still throw, so convert beforehand. */
  if (typeof value === "bigint") {
    return `"${value.toString()}"`;
  }

  /* Format Uint8Array as hex instead of record */
  if (value instanceof Uint8Array) {
    return `"${formatUint8Array(value)}"`;
  }

  try {
    const result = JSON.stringify(value, replacer);
    /* JSON.stringify returns undefined for unsupported types like undefined, function, or symbol.
       In those cases, fall back to String(value) for a more informative output. */
    return result === undefined ? String(value) : result;
  } catch {
    try {
      return String(value);
    } catch {
      return "[Unserializable]";
    }
  }
}

function formatUint8Array(arr: Uint8Array): string {
  return `Uint8Array(0x${bytesToHex(arr)})`;
}
