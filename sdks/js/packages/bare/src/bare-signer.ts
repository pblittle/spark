import { bytesToHex, hexToBytes } from "@noble/hashes/utils";
import {
  createDummyTx,
  signFrost,
  aggregateFrost,
} from "@buildonspark/spark-frost-bare-addon";
import {
  DefaultSparkSigner,
  ValidationError,
  type SignFrostParams,
  type AggregateFrostParams,
  type IKeyPackage,
} from "@buildonspark/spark-sdk/bare";

export class BareSparkSigner extends DefaultSparkSigner {
  async signFrost({
    message,
    publicKey,
    verifyingKey,
    selfCommitment,
    statechainCommitments,
    keyDerivation,
    adaptorPubKey,
  }: SignFrostParams): Promise<Uint8Array> {
    const signingPrivateKey =
      await this.getSigningPrivateKeyFromDerivation(keyDerivation);

    if (!signingPrivateKey) {
      throw new ValidationError("Private key not found for public key", {
        field: "privateKey",
      });
    }

    const commitment = selfCommitment.commitment;
    const nonce = this.commitmentToNonceMap.get(commitment);
    if (!nonce) {
      throw new ValidationError("Nonce not found for commitment", {
        field: "nonce",
      });
    }

    const keyPackage: IKeyPackage = {
      secretKey: signingPrivateKey,
      publicKey: publicKey,
      verifyingKey: verifyingKey,
    };

    const statechainCommitmentsArr = statechainCommitments
      ? Object.entries(statechainCommitments)
      : [];

    const result = signFrost(
      message,
      keyPackage,
      nonce,
      selfCommitment.commitment,
      statechainCommitmentsArr,
      adaptorPubKey || null,
    );

    return result;
  }

  async aggregateFrost({
    message,
    statechainCommitments,
    selfCommitment,
    statechainSignatures,
    selfSignature,
    statechainPublicKeys,
    publicKey,
    verifyingKey,
    adaptorPubKey,
  }: AggregateFrostParams): Promise<Uint8Array> {
    const statechainCommitmentsArr = statechainCommitments
      ? Object.entries(statechainCommitments)
      : [];
    const statechainSignaturesArr = statechainSignatures
      ? Object.entries(statechainSignatures)
      : [];
    const statechainPublicKeysArr = statechainPublicKeys
      ? Object.entries(statechainPublicKeys)
      : [];

    // msg, statechainCommitments, selfCommitment, statechainSignatures, selfSignature, statechainPublicKeys, selfPublicKey, verifyingKey, adaptorPublicKey
    const result = aggregateFrost(
      message,
      statechainCommitmentsArr,
      selfCommitment.commitment,
      statechainSignaturesArr,
      selfSignature,
      statechainPublicKeysArr,
      publicKey,
      verifyingKey,
      adaptorPubKey || null,
    );

    return result;
  }
}
