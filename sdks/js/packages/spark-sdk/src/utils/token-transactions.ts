import { bytesToHex, bytesToNumberBE } from "@noble/curves/abstract/utils";
import { OutputWithPreviousTransactionData } from "../proto/spark.js";
import {
  TokenBalanceMap,
  TokenOutputsMap,
  RawTokenIdentifierHex,
} from "../spark-wallet/types.js";
import { Bech32mTokenIdentifier } from "./token-identifier.js";

export function sumAvailableTokens(
  outputs: OutputWithPreviousTransactionData[],
): bigint {
  return outputs.reduce(
    (sum, output) => sum + BigInt(bytesToNumberBE(output.output!.tokenAmount!)),
    BigInt(0),
  );
}

export function checkIfSelectedOutputsAreAvailable(
  selectedOutputs: OutputWithPreviousTransactionData[],
  tokenOutputs: TokenOutputsMap,
  tokenIdentifier: Bech32mTokenIdentifier,
) {
  const tokenOutputsAvailable = tokenOutputs.get(tokenIdentifier);
  if (!tokenOutputsAvailable) {
    return false;
  }
  if (
    selectedOutputs.length === 0 ||
    tokenOutputsAvailable.length < selectedOutputs.length
  ) {
    return false;
  }

  // Create a Set of available token output IDs for O(n + m) lookup
  const availableOutputIds = new Set(
    tokenOutputsAvailable.map((output) => output.output!.id),
  );

  for (const selectedOutput of selectedOutputs) {
    if (
      !selectedOutput.output?.id ||
      !availableOutputIds.has(selectedOutput.output.id)
    ) {
      return false;
    }
  }

  return true;
}

export function filterTokenBalanceForTokenPublicKey(
  tokenBalances: TokenBalanceMap,
  publicKey: string,
): { balance: bigint } {
  if (!tokenBalances) {
    return { balance: 0n };
  }

  const tokenBalance = [...tokenBalances.entries()].find(
    ([, info]) => info.tokenMetadata.tokenPublicKey === publicKey,
  );

  if (!tokenBalance) {
    return {
      balance: 0n,
    };
  }
  return {
    balance: tokenBalance[1].balance,
  };
}
