import type { HDKey } from "@scure/bip32";
import type { ISigningCommitment } from "../spark_bindings/types.js";

export { MultisigReceiptInput } from "@buildonspark/lrc20-sdk/lrc/types";

export type SigningNonce = {
  binding: Uint8Array;
  hiding: Uint8Array;
};

export type SigningCommitment = {
  binding: Uint8Array;
  hiding: Uint8Array;
};

export enum KeyDerivationType {
  LEAF = "leaf",
  DEPOSIT = "deposit",
  STATIC_DEPOSIT = "static_deposit",
  ECIES = "ecies",
  RANDOM = "random",
}

export type KeyDerivation =
  | { type: KeyDerivationType.LEAF; path: string }
  | { type: KeyDerivationType.DEPOSIT }
  | { type: KeyDerivationType.RANDOM }
  | { type: KeyDerivationType.STATIC_DEPOSIT; path: number }
  | { type: KeyDerivationType.ECIES; path: Uint8Array };

export type SignFrostParams = {
  message: Uint8Array;
  keyDerivation: KeyDerivation;
  publicKey: Uint8Array;
  verifyingKey: Uint8Array;
  selfCommitment: ISigningCommitment;
  statechainCommitments?: { [key: string]: ISigningCommitment } | undefined;
  adaptorPubKey?: Uint8Array | undefined;
};

export type AggregateFrostParams = Omit<SignFrostParams, "keyDerivation"> & {
  selfSignature: Uint8Array;
  statechainSignatures?: { [key: string]: Uint8Array } | undefined;
  statechainPublicKeys?: { [key: string]: Uint8Array } | undefined;
};

export type SplitSecretWithProofsParams = {
  secret: Uint8Array;
  curveOrder: bigint;
  threshold: number;
  numShares: number;
};

export type DerivedHDKey = {
  hdKey: HDKey;
  privateKey: Uint8Array;
  publicKey: Uint8Array;
};

export type KeyPair = {
  privateKey: Uint8Array;
  publicKey: Uint8Array;
};
