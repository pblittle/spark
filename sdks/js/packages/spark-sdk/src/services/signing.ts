import { hexToBytes } from "@noble/curves/abstract/utils";
import { TransactionInput } from "@scure/btc-signer/psbt";
import { ValidationError } from "../errors/types.js";
import {
  RequestedSigningCommitments,
  UserSignedTxSigningJob,
} from "../proto/spark.js";
import {
  getSigHashFromTx,
  getTxFromRawTxBytes,
  getTxId,
} from "../utils/bitcoin.js";
import {
  createRefundTx,
  getNextTransactionSequence,
} from "../utils/transaction.js";
import { WalletConfigService } from "./config.js";
import type { LeafKeyTweak } from "./transfer.js";

export class SigningService {
  private readonly config: WalletConfigService;

  constructor(config: WalletConfigService) {
    this.config = config;
  }

  async signRefunds(
    leaves: LeafKeyTweak[],
    signingCommitments: RequestedSigningCommitments[],
    receiverIdentityPubkey: Uint8Array,
  ): Promise<UserSignedTxSigningJob[]> {
    const leafSigningJobs: UserSignedTxSigningJob[] = [];
    for (let i = 0; i < leaves.length; i++) {
      const leaf = leaves[i];
      if (!leaf?.leaf) {
        throw new ValidationError("Leaf not found in signRefunds", {
          field: "leaf",
          value: leaf,
          expected: "Non-null leaf",
        });
      }

      const nodeTx = getTxFromRawTxBytes(leaf.leaf.nodeTx);
      const nodeOutPoint: TransactionInput = {
        txid: hexToBytes(getTxId(nodeTx)),
        index: 0,
      };

      const currRefundTx = getTxFromRawTxBytes(leaf.leaf.refundTx);

      const sequence = currRefundTx.getInput(0).sequence;
      if (!sequence) {
        throw new ValidationError("Invalid refund transaction", {
          field: "sequence",
          value: currRefundTx.getInput(0),
          expected: "Non-null sequence",
        });
      }
      const { nextSequence } = getNextTransactionSequence(sequence);

      const amountSats = currRefundTx.getOutput(0).amount;
      if (amountSats === undefined) {
        throw new ValidationError("Invalid refund transaction", {
          field: "amount",
          value: currRefundTx.getOutput(0),
          expected: "Non-null amount",
        });
      }

      const refundTx = createRefundTx(
        nextSequence,
        nodeOutPoint,
        amountSats,
        receiverIdentityPubkey,
        this.config.getNetwork(),
      );

      const sighash = getSigHashFromTx(refundTx, 0, nodeTx.getOutput(0));

      const signingCommitment =
        await this.config.signer.getRandomSigningCommitment();

      const signingNonceCommitments =
        signingCommitments[i]?.signingNonceCommitments;
      if (!signingNonceCommitments) {
        throw new ValidationError("Invalid signing commitments", {
          field: "signingNonceCommitments",
          value: signingCommitments[i],
          expected: "Non-null signing nonce commitments",
        });
      }
      const signingResult = await this.config.signer.signFrost({
        message: sighash,
        keyDerivation: leaf.keyDerivation,
        publicKey: await this.config.signer.getPublicKeyFromDerivation(
          leaf.keyDerivation,
        ),
        selfCommitment: signingCommitment,
        statechainCommitments: signingNonceCommitments,
        adaptorPubKey: new Uint8Array(),
        verifyingKey: leaf.leaf.verifyingPublicKey,
      });

      leafSigningJobs.push({
        leafId: leaf.leaf.id,
        signingPublicKey: await this.config.signer.getPublicKeyFromDerivation(
          leaf.keyDerivation,
        ),
        rawTx: refundTx.toBytes(),
        signingNonceCommitment: signingCommitment.commitment,
        userSignature: signingResult,
        signingCommitments: {
          signingCommitments: signingNonceCommitments,
        },
      });
    }

    return leafSigningJobs;
  }
}
