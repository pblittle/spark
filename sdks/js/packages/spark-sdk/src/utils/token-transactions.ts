import { bytesToHex, bytesToNumberBE } from "@noble/curves/abstract/utils";
import { OutputWithPreviousTransactionData } from "../proto/spark.js";
import { TokenBalanceMap } from "../spark-wallet/types.js";

export function calculateAvailableTokenAmount(
  outputLeaves: OutputWithPreviousTransactionData[],
): bigint {
  return outputLeaves.reduce(
    (sum, output) => sum + BigInt(bytesToNumberBE(output.output!.tokenAmount!)),
    BigInt(0),
  );
}

export function checkIfSelectedOutputsAreAvailable(
  selectedOutputs: OutputWithPreviousTransactionData[],
  tokenOutputs: Map<string, OutputWithPreviousTransactionData[]>,
  tokenPublicKey: Uint8Array,
) {
  const tokenPubKeyHex = bytesToHex(tokenPublicKey);
  const tokenOutputsAvailable = tokenOutputs.get(tokenPubKeyHex);
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
