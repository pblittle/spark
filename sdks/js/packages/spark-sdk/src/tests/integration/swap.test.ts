import { describe, expect, it } from "@jest/globals";
import { equalBytes, hexToBytes } from "@noble/curves/abstract/utils";
import { secp256k1 } from "@noble/curves/secp256k1";
import { uuidv7 } from "uuidv7";
import { ValidationError } from "../../errors/types.js";
import { KeyDerivation, KeyDerivationType } from "../../index.js";
import { WalletConfigService } from "../../services/config.js";
import { ConnectionManager } from "../../services/connection.js";
import { SigningService } from "../../services/signing.js";
import type { LeafKeyTweak } from "../../services/transfer.js";
import { TransferService } from "../../services/transfer.js";
import {
  applyAdaptorToSignature,
  generateAdaptorFromSignature,
} from "../../utils/adaptor-signature.js";
import {
  computeTaprootKeyNoScript,
  getSigHashFromTx,
} from "../../utils/bitcoin.js";
import { createNewTree, signerTypes } from "../test-utils.js";
import { SparkWalletTesting } from "../utils/spark-testing-wallet.js";
import { BitcoinFaucet } from "../utils/test-faucet.js";

const testLocalOnly = process.env.GITHUB_ACTIONS ? it.skip : it;

describe.each(signerTypes)("swap", ({ name, Signer }) => {
  testLocalOnly(
    `${name} - test swap`,
    async () => {
      const faucet = BitcoinFaucet.getInstance();
      // Initiate sender
      const { wallet: senderWallet } = await SparkWalletTesting.initialize({
        options: {
          network: "LOCAL",
        },
        signer: new Signer(),
      });
      const senderPubkey = await senderWallet.getIdentityPublicKey();

      const senderConfig = new WalletConfigService(
        {
          network: "LOCAL",
        },
        senderWallet.getSigner(),
      );
      const senderConnectionManager = new ConnectionManager(senderConfig);
      const senderSigningService = new SigningService(senderConfig);
      const senderTransferService = new TransferService(
        senderConfig,
        senderConnectionManager,
        senderSigningService,
      );

      // Initiate receiver
      const { wallet: receiverWallet } = await SparkWalletTesting.initialize({
        options: {
          network: "LOCAL",
        },
        signer: new Signer(),
      });
      const receiverPubkey = await receiverWallet.getIdentityPublicKey();

      const receiverConfig = new WalletConfigService(
        {
          network: "LOCAL",
        },
        receiverWallet.getSigner(),
      );
      const receiverConnectionManager = new ConnectionManager(receiverConfig);
      const receiverSigningService = new SigningService(receiverConfig);
      const receiverTransferService = new TransferService(
        receiverConfig,
        receiverConnectionManager,
        receiverSigningService,
      );

      const senderLeafId = uuidv7();
      const senderRootNode = await createNewTree(
        senderWallet,
        senderLeafId,
        faucet,
      );

      const receiverLeafId = uuidv7();
      const receiverRootNode = await createNewTree(
        receiverWallet,
        receiverLeafId,
        faucet,
      );

      // Sender initiates transfer
      const senderNewLeafId = uuidv7();
      const senderTransferNode: LeafKeyTweak = {
        leaf: senderRootNode,
        keyDerivation: {
          type: KeyDerivationType.LEAF,
          path: senderLeafId,
        },
        newKeyDerivation: {
          type: KeyDerivationType.LEAF,
          path: senderNewLeafId,
        },
      };
      const senderLeavesToTransfer = [senderTransferNode];

      // Get signature for refunds (normal flow)
      const {
        transfer: senderTransfer,
        signatureMap: senderRefundSignatureMap,
        leafDataMap: senderLeafDataMap,
      } = await senderTransferService.startSwapSignRefund(
        senderLeavesToTransfer,
        hexToBytes(receiverPubkey),
        new Date(Date.now() + 10 * 60 * 1000),
      );

      expect(senderRefundSignatureMap.size).toBe(1);
      const senderSignature = senderRefundSignatureMap.get(senderRootNode.id);
      expect(senderSignature).toBeDefined();
      expect(senderLeafDataMap.size).toBe(1);

      const { adaptorPrivateKey, adaptorSignature } =
        generateAdaptorFromSignature(senderSignature!);
      const adaptorPubKey = secp256k1.getPublicKey(adaptorPrivateKey);

      const receiverNewLeafDerivation: KeyDerivation = {
        type: KeyDerivationType.LEAF,
        path: uuidv7(),
      };
      const receiverTransferNode: LeafKeyTweak = {
        leaf: receiverRootNode,
        keyDerivation: {
          type: KeyDerivationType.LEAF,
          path: receiverLeafId,
        },
        newKeyDerivation: receiverNewLeafDerivation,
      };
      const receiverLeavesToTransfer = [receiverTransferNode];

      const {
        transfer: receiverTransfer,
        signatureMap: receiverRefundSignatureMap,
        leafDataMap: receiverLeafDataMap,
        signingResults: operatorSigningResults,
      } = await receiverTransferService.counterSwapSignRefund(
        receiverLeavesToTransfer,
        hexToBytes(senderPubkey),
        new Date(Date.now() + 10 * 60 * 1000),
        adaptorPubKey,
      );

      const newReceiverRefundSignatureMap = new Map<string, Uint8Array>();
      for (const [nodeId, signature] of receiverRefundSignatureMap.entries()) {
        const leafData = receiverLeafDataMap.get(nodeId);
        if (!leafData?.refundTx) {
          throw new ValidationError("Refund transaction not found", {
            field: "refundTx",
            value: leafData,
          });
        }
        const sighash = getSigHashFromTx(
          leafData.refundTx,
          0,
          leafData.tx.getOutput(leafData.vout),
        );
        let verifyingPubkey: Uint8Array | undefined;
        for (const signingResult of operatorSigningResults) {
          if (signingResult.leafId === nodeId) {
            verifyingPubkey = signingResult.verifyingKey;
          }
        }
        expect(verifyingPubkey).toBeDefined();
        const taprootKey = computeTaprootKeyNoScript(
          verifyingPubkey!.slice(1, 33),
        );
        const adaptorSig = applyAdaptorToSignature(
          taprootKey.slice(1, 33),
          sighash,
          signature,
          adaptorPrivateKey,
        );
        newReceiverRefundSignatureMap.set(nodeId, adaptorSig);
      }
      const senderTransferTweakKey =
        await senderTransferService.sendTransferTweakKey(
          senderTransfer,
          senderLeavesToTransfer,
          senderRefundSignatureMap,
        );

      const pendingTransfer =
        await receiverTransferService.queryPendingTransfers();
      expect(pendingTransfer.transfers.length).toBe(1);
      const receiverPendingTransfer = pendingTransfer.transfers[0];
      expect(receiverPendingTransfer!.id).toBe(senderTransferTweakKey.id);

      const leafPrivKeyMap =
        await receiverTransferService.verifyPendingTransfer(
          receiverPendingTransfer!,
        );

      expect(leafPrivKeyMap.size).toBe(1);
      expect(leafPrivKeyMap.get(senderRootNode.id)).toBeDefined();
      const bytesEqual = equalBytes(
        leafPrivKeyMap.get(senderRootNode.id)!,
        await senderWallet
          .getSigner()
          .getPublicKeyFromDerivation(senderTransferNode.newKeyDerivation),
      );
      expect(bytesEqual).toBe(true);
      expect(receiverPendingTransfer!.leaves[0]!.leaf).toBeDefined();

      const claimingNodes: LeafKeyTweak[] = receiverPendingTransfer!.leaves.map(
        (leaf) => ({
          leaf: leaf.leaf!,
          keyDerivation: {
            type: KeyDerivationType.ECIES,
            path: leaf.secretCipher,
          },
          newKeyDerivation: {
            type: KeyDerivationType.LEAF,
            path: senderNewLeafId,
          },
        }),
      );
      await receiverTransferService.claimTransfer(
        receiverPendingTransfer!,
        claimingNodes,
      );
      await receiverTransferService.sendTransferTweakKey(
        receiverTransfer,
        receiverLeavesToTransfer,
        newReceiverRefundSignatureMap,
      );

      const sPendingTransfer =
        await senderTransferService.queryPendingTransfers();
      expect(sPendingTransfer.transfers.length).toBe(1);
      const senderPendingTransfer = sPendingTransfer.transfers[0];
      expect(senderPendingTransfer!.id).toBe(receiverTransfer.id);

      const senderLeafPrivKeyMap =
        await senderTransferService.verifyPendingTransfer(
          senderPendingTransfer!,
        );
      expect(senderLeafPrivKeyMap.size).toBe(1);
      expect(senderLeafPrivKeyMap.get(receiverRootNode.id)).toBeDefined();
      const bytesEqual_1 = equalBytes(
        senderLeafPrivKeyMap.get(receiverRootNode.id)!,
        await receiverWallet
          .getSigner()
          .getPublicKeyFromDerivation(receiverNewLeafDerivation),
      );
      expect(bytesEqual_1).toBe(true);
      expect(senderPendingTransfer!.leaves[0]!.leaf).toBeDefined();

      const claimingNodes_1: LeafKeyTweak[] = senderPendingTransfer!.leaves.map(
        (leaf) => ({
          leaf: leaf.leaf!,
          keyDerivation: {
            type: KeyDerivationType.ECIES,
            path: leaf.secretCipher,
          },
          newKeyDerivation: {
            type: KeyDerivationType.LEAF,
            path: leaf.leaf!.id,
          },
        }),
      );
      await senderTransferService.claimTransfer(
        senderPendingTransfer!,
        claimingNodes_1,
      );
    },
    30000,
  );

  testLocalOnly(
    `${name} - test swap v2`,
    async () => {
      const faucet = BitcoinFaucet.getInstance();
      // Initiate sender
      const { wallet: senderWallet } = await SparkWalletTesting.initialize({
        options: {
          network: "LOCAL",
        },
        signer: new Signer(),
      });
      const senderPubkey = await senderWallet.getIdentityPublicKey();

      const senderConfig = new WalletConfigService(
        {
          network: "LOCAL",
        },
        senderWallet.getSigner(),
      );
      const senderConnectionManager = new ConnectionManager(senderConfig);
      const senderSigningService = new SigningService(senderConfig);
      const senderTransferService = new TransferService(
        senderConfig,
        senderConnectionManager,
        senderSigningService,
      );

      // Initiate receiver
      const { wallet: receiverWallet } = await SparkWalletTesting.initialize({
        options: {
          network: "LOCAL",
        },
        signer: new Signer(),
      });
      const receiverPubkey = await receiverWallet.getIdentityPublicKey();

      const receiverConfig = new WalletConfigService(
        {
          network: "LOCAL",
        },
        receiverWallet.getSigner(),
      );
      const receiverConnectionManager = new ConnectionManager(receiverConfig);
      const receiverSigningService = new SigningService(receiverConfig);
      const receiverTransferService = new TransferService(
        receiverConfig,
        receiverConnectionManager,
        receiverSigningService,
      );

      const senderLeafId = uuidv7();
      const senderRootNode = await createNewTree(
        senderWallet,
        senderLeafId,
        faucet,
      );

      const receiverLeafId = uuidv7();
      const receiverRootNode = await createNewTree(
        receiverWallet,
        receiverLeafId,
        faucet,
      );

      // Sender initiates transfer
      const senderNewLeafDerivation: KeyDerivation = {
        type: KeyDerivationType.LEAF,
        path: uuidv7(),
      };
      const senderTransferNode: LeafKeyTweak = {
        leaf: senderRootNode,
        keyDerivation: {
          type: KeyDerivationType.LEAF,
          path: senderLeafId,
        },
        newKeyDerivation: senderNewLeafDerivation,
      };
      const senderLeavesToTransfer = [senderTransferNode];

      // Get signature for refunds (normal flow)
      const {
        transfer: senderTransfer,
        signatureMap: senderRefundSignatureMap,
        leafDataMap: senderLeafDataMap,
      } = await senderTransferService.startSwapSignRefund(
        senderLeavesToTransfer,
        hexToBytes(receiverPubkey),
        new Date(Date.now() + 10 * 60 * 1000),
      );

      expect(senderRefundSignatureMap.size).toBe(1);
      const senderSignature = senderRefundSignatureMap.get(senderRootNode.id);
      expect(senderSignature).toBeDefined();
      expect(senderLeafDataMap.size).toBe(1);

      const { adaptorPrivateKey } = generateAdaptorFromSignature(
        senderSignature!,
      );
      const adaptorPubKey = secp256k1.getPublicKey(adaptorPrivateKey);

      const receiverNewLeafDerivation: KeyDerivation = {
        type: KeyDerivationType.LEAF,
        path: uuidv7(),
      };
      const receiverTransferNode: LeafKeyTweak = {
        leaf: receiverRootNode,
        keyDerivation: {
          type: KeyDerivationType.LEAF,
          path: receiverLeafId,
        },
        newKeyDerivation: receiverNewLeafDerivation,
      };
      const receiverLeavesToTransfer = [receiverTransferNode];

      const {
        transfer: receiverTransfer,
        signatureMap: receiverRefundSignatureMap,
        leafDataMap: receiverLeafDataMap,
        signingResults: operatorSigningResults,
      } = await receiverTransferService.counterSwapSignRefund(
        receiverLeavesToTransfer,
        hexToBytes(senderPubkey),
        new Date(Date.now() + 10 * 60 * 1000),
        adaptorPubKey,
      );

      const newReceiverRefundSignatureMap = new Map<string, Uint8Array>();
      for (const [nodeId, signature] of receiverRefundSignatureMap.entries()) {
        const leafData = receiverLeafDataMap.get(nodeId);
        if (!leafData?.refundTx) {
          throw new ValidationError("Refund transaction not found", {
            field: "refundTx",
            value: leafData,
          });
        }
        const sighash = getSigHashFromTx(
          leafData.refundTx,
          0,
          leafData.tx.getOutput(leafData.vout),
        );
        let verifyingPubkey: Uint8Array | undefined;
        for (const signingResult of operatorSigningResults) {
          if (signingResult.leafId === nodeId) {
            verifyingPubkey = signingResult.verifyingKey;
          }
        }
        expect(verifyingPubkey).toBeDefined();
        const taprootKey = computeTaprootKeyNoScript(
          verifyingPubkey!.slice(1, 33),
        );
        const adaptorSig = applyAdaptorToSignature(
          taprootKey.slice(1, 33),
          sighash,
          signature,
          adaptorPrivateKey,
        );
        newReceiverRefundSignatureMap.set(nodeId, adaptorSig);
      }
      const senderTransferTweakKey =
        await senderTransferService.deliverTransferPackage(
          senderTransfer,
          senderLeavesToTransfer,
          senderRefundSignatureMap,
        );

      const pendingTransfer =
        await receiverTransferService.queryPendingTransfers();
      expect(pendingTransfer.transfers.length).toBe(1);
      const receiverPendingTransfer = pendingTransfer.transfers[0];
      expect(receiverPendingTransfer!.id).toBe(senderTransferTweakKey.id);

      const leafPrivKeyMap =
        await receiverTransferService.verifyPendingTransfer(
          receiverPendingTransfer!,
        );

      expect(leafPrivKeyMap.size).toBe(1);
      expect(leafPrivKeyMap.get(senderRootNode.id)).toBeDefined();
      const bytesEqual = equalBytes(
        leafPrivKeyMap.get(senderRootNode.id)!,
        await senderWallet
          .getSigner()
          .getPublicKeyFromDerivation(senderNewLeafDerivation),
      );
      expect(bytesEqual).toBe(true);
      expect(receiverPendingTransfer!.leaves[0]!.leaf).toBeDefined();
      const claimingNodes: LeafKeyTweak[] = receiverPendingTransfer!.leaves.map(
        (leaf) => ({
          leaf: leaf.leaf!,
          keyDerivation: {
            type: KeyDerivationType.ECIES,
            path: leaf.secretCipher,
          },
          newKeyDerivation: {
            type: KeyDerivationType.LEAF,
            path: leaf.leaf!.id,
          },
        }),
      );
      await receiverTransferService.claimTransfer(
        receiverPendingTransfer!,
        claimingNodes,
      );
      await receiverTransferService.deliverTransferPackage(
        receiverTransfer,
        receiverLeavesToTransfer,
        newReceiverRefundSignatureMap,
      );

      const sPendingTransfer =
        await senderTransferService.queryPendingTransfers();
      expect(sPendingTransfer.transfers.length).toBe(1);
      const senderPendingTransfer = sPendingTransfer.transfers[0];
      expect(senderPendingTransfer!.id).toBe(receiverTransfer.id);

      const senderLeafPrivKeyMap =
        await senderTransferService.verifyPendingTransfer(
          senderPendingTransfer!,
        );
      expect(senderLeafPrivKeyMap.size).toBe(1);
      expect(senderLeafPrivKeyMap.get(receiverRootNode.id)).toBeDefined();
      const bytesEqual_1 = equalBytes(
        senderLeafPrivKeyMap.get(receiverRootNode.id)!,
        await receiverWallet
          .getSigner()
          .getPublicKeyFromDerivation(receiverNewLeafDerivation),
      );
      expect(bytesEqual_1).toBe(true);
      expect(senderPendingTransfer!.leaves[0]!.leaf).toBeDefined();

      const claimingNodes_1: LeafKeyTweak[] = senderPendingTransfer!.leaves.map(
        (leaf) => ({
          leaf: leaf.leaf!,
          keyDerivation: {
            type: KeyDerivationType.ECIES,
            path: leaf.secretCipher,
          },
          newKeyDerivation: {
            type: KeyDerivationType.LEAF,
            path: leaf.leaf!.id,
          },
        }),
      );
      await senderTransferService.claimTransfer(
        senderPendingTransfer!,
        claimingNodes_1,
      );
    },
    30000,
  );
});
