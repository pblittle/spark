import { bech32m } from "@scure/base";

import { NetworkType } from "../utils/network.js";
import { ValidationError } from "../errors/index.js";

const HumanReadableTokenIdentifierNetworkPrefix: Record<NetworkType, string> = {
  MAINNET: "btk",
  REGTEST: "btkrt",
  TESTNET: "btkt",
  SIGNET: "btks",
  LOCAL: "btkl",
} as const;

export type HumanReadableTokenIdentifier =
  | `btk1${string}`
  | `btkrt1${string}`
  | `btkt1${string}`
  | `btks1${string}`
  | `btkl1${string}`;

export interface HumanReadableTokenIdentifierData {
  tokenIdentifier: Uint8Array;
  network: NetworkType;
}

export function encodeHumanReadableTokenIdentifier(
  payload: HumanReadableTokenIdentifierData,
): HumanReadableTokenIdentifier {
  try {
    const words = bech32m.toWords(payload.tokenIdentifier);
    return bech32m.encode(
      HumanReadableTokenIdentifierNetworkPrefix[payload.network],
      words,
      500,
    ) as HumanReadableTokenIdentifier;
  } catch (error) {
    throw new ValidationError(
      "Failed to encode human readable token identifier",
      {
        field: "tokenIdentifier",
        value: payload.tokenIdentifier,
      },
      error as Error,
    );
  }
}

export function decodeHumanReadableTokenIdentifier(
  humanReadableTokenIdentifier: HumanReadableTokenIdentifier,
  network: NetworkType,
): HumanReadableTokenIdentifierData {
  try {
    const decoded = bech32m.decode(
      humanReadableTokenIdentifier as HumanReadableTokenIdentifier,
      500,
    );

    if (decoded.prefix !== HumanReadableTokenIdentifierNetworkPrefix[network]) {
      throw new ValidationError(
        "Invalid human readable token identifier prefix",
        {
          field: "humanReadableTokenIdentifier",
          value: humanReadableTokenIdentifier,
          expected: `prefix='${HumanReadableTokenIdentifierNetworkPrefix[network]}'`,
        },
      );
    }

    const tokenIdentifier = bech32m.fromWords(decoded.words);

    return {
      tokenIdentifier,
      network,
    };
  } catch (error) {
    if (error instanceof ValidationError) {
      throw error;
    }
    throw new ValidationError(
      "Failed to decode human readable token identifier",
      {
        field: "humanReadableTokenIdentifier",
        value: humanReadableTokenIdentifier,
      },
      error as Error,
    );
  }
}
