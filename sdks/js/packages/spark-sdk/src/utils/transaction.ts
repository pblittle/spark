import { Transaction } from "@scure/btc-signer";
import { TransactionInput, TransactionOutput } from "@scure/btc-signer/psbt";
import { ValidationError } from "../errors/types.js";
import { getP2TRScriptFromPublicKey } from "./bitcoin.js";
import { Network } from "./network.js";

const TIME_LOCK_INTERVAL = 100;

// Default fee constants matching Go implementation
const ESTIMATED_TX_SIZE = 191;
const DEFAULT_SATS_PER_VBYTE = 5;
export const DEFAULT_FEE_SATS = ESTIMATED_TX_SIZE * DEFAULT_SATS_PER_VBYTE;

/**
 * Subtracts the default fee from the amount if it's greater than the fee.
 * Returns the original amount if it's less than or equal to the fee.
 */
export function maybeApplyFee(amount: bigint): bigint {
  if (amount > BigInt(DEFAULT_FEE_SATS)) {
    return amount - BigInt(DEFAULT_FEE_SATS);
  }
  return amount;
}

export function createRefundTx(
  sequence: number,
  nodeOutPoint: TransactionInput,
  amountSats: bigint,
  receivingPubkey: Uint8Array,
  network: Network,
): Transaction {
  const newRefundTx = new Transaction({
    version: 3,
    allowUnknownOutputs: true,
  });
  newRefundTx.addInput({
    ...nodeOutPoint,
    sequence,
  });

  const refundPkScript = getP2TRScriptFromPublicKey(receivingPubkey, network);

  newRefundTx.addOutput({
    script: refundPkScript,
    amount: amountSats,
  });

  newRefundTx.addOutput(getEphemeralAnchorOutput());

  return newRefundTx;
}

export function getCurrentTimelock(currSequence?: number): number {
  return (currSequence || 0) & 0xffff;
}

export function getTransactionSequence(currSequence?: number): number {
  const timelock = getCurrentTimelock(currSequence);
  return (1 << 30) | timelock;
}

export function checkIfValidSequence(currSequence?: number) {
  // Check bit 31 is active. If not equal to 0, timelock is not active.
  const TIME_LOCK_ACTIVE = (currSequence || 0) & 0x80000000;
  if (TIME_LOCK_ACTIVE !== 0) {
    throw new ValidationError("Timelock not active", {
      field: "currSequence",
      value: currSequence,
    });
  }

  // Check bit 22 is active. If not equal to 0, block based time lock not active.
  const RELATIVE_TIME_LOCK_ACTIVE = (currSequence || 0) & 0x00400000;
  if (RELATIVE_TIME_LOCK_ACTIVE !== 0) {
    throw new ValidationError("Block based timelock not active", {
      field: "currSequence",
      value: currSequence,
    });
  }
}

// make sure that the leaves are ok before sending or else next user could lose funds
export function getNextTransactionSequence(
  currSequence?: number,
  forRefresh?: boolean,
): {
  nextSequence: number;
  needRefresh: boolean;
} {
  // Check if the previous sequence is valid. If not, the user could lose funds.
  checkIfValidSequence(currSequence);

  const currentTimelock = getCurrentTimelock(currSequence);
  const nextTimelock = currentTimelock - TIME_LOCK_INTERVAL;

  // Confirm that the next sequence is valid. This should never happen since bit 17-31 should all be 0.
  checkIfValidSequence(nextTimelock);

  if (forRefresh && nextTimelock <= 100 && currentTimelock > 0) {
    return {
      nextSequence: (1 << 30) | nextTimelock,
      needRefresh: true,
    };
  }

  if (nextTimelock < 100) {
    throw new ValidationError("timelock interval is less than 100", {
      field: "nextTimelock",
      value: nextTimelock,
    });
  }

  return {
    nextSequence: (1 << 30) | nextTimelock,
    needRefresh: nextTimelock <= 100,
  };
}

export function getEphemeralAnchorOutput(): TransactionOutput {
  return {
    script: new Uint8Array([0x51, 0x02, 0x4e, 0x73]), // Pay-to-anchor (P2A) ephemeral anchor output
    amount: 0n,
  };
}
