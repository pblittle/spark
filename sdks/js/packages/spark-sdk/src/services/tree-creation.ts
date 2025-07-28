import { hexToBytes } from "@noble/curves/abstract/utils";
import { Address, OutScript, Transaction } from "@scure/btc-signer";
import { NetworkError, ValidationError } from "../errors/index.js";
import {
  AddressNode,
  AddressRequestNode,
  CreateTreeRequest,
  CreateTreeResponse,
  CreationNode,
  CreationResponseNode,
  FinalizeNodeSignaturesResponse,
  NodeSignatures,
  PrepareTreeAddressRequest,
  PrepareTreeAddressResponse,
  SigningJob,
  TreeNode,
} from "../proto/spark.js";
import {
  KeyDerivation,
  KeyDerivationType,
  SigningCommitmentWithOptionalNonce,
} from "../signer/types.js";
import {
  getSigHashFromTx,
  getTxFromRawTxBytes,
  getTxId,
} from "../utils/bitcoin.js";
import { getNetwork, Network } from "../utils/network.js";
import {
  createLeafNodeTx,
  createNodeTxs,
  createRefundTxs,
  createSplitTx,
  DEFAULT_FEE_SATS,
  INITIAL_DIRECT_SEQUENCE,
  INITIAL_SEQUENCE,
} from "../utils/transaction.js";
import { WalletConfigService } from "./config.js";
import { ConnectionManager } from "./connection.js";

export type DepositAddressTree = {
  address?: string | undefined;
  signingPublicKey: Uint8Array;
  verificationKey?: Uint8Array | undefined;
  children: DepositAddressTree[];
};

export type CreationNodeWithNonces = CreationNode & {
  directNodeTxSigningCommitment?:
    | SigningCommitmentWithOptionalNonce
    | undefined;
  nodeTxSigningCommitment?: SigningCommitmentWithOptionalNonce | undefined;
  refundTxSigningCommitment?: SigningCommitmentWithOptionalNonce | undefined;
  directRefundTxSigningCommitment?:
    | SigningCommitmentWithOptionalNonce
    | undefined;
  directFromCpfpRefundTxSigningCommitment?:
    | SigningCommitmentWithOptionalNonce
    | undefined;
  directNodeTxSigningJob?: SigningJob | undefined;
  directRefundTxSigningJob?: SigningJob | undefined;
  directFromCpfpRefundTxSigningJob?: SigningJob | undefined;
};

const INITIAL_TIME_LOCK = 2000;

/**
 * Subtracts the default fee from the amount if it's greater than the fee.
 * Returns the original amount if it's less than or equal to the fee.
 */
function maybeApplyFee(amount: bigint): bigint {
  if (amount > BigInt(DEFAULT_FEE_SATS)) {
    return amount - BigInt(DEFAULT_FEE_SATS);
  }
  return amount;
}

export class TreeCreationService {
  private readonly config: WalletConfigService;
  private readonly connectionManager: ConnectionManager;

  constructor(
    config: WalletConfigService,
    connectionManager: ConnectionManager,
  ) {
    this.config = config;
    this.connectionManager = connectionManager;
  }

  async generateDepositAddressForTree(
    vout: number,
    parentSigningPublicKey: Uint8Array,
    parentTx?: Transaction,
    parentNode?: TreeNode,
  ): Promise<DepositAddressTree> {
    if (!parentTx && !parentNode) {
      throw new Error("No parent tx or parent node provided");
    }

    const id = parentNode?.id ?? getTxId(parentTx!);

    const tree = await this.createDepositAddressTree(
      parentSigningPublicKey,
      id,
    );

    const addressRequestNodes =
      this.createAddressRequestNodeFromTreeNodes(tree);
    const sparkClient = await this.connectionManager.createSparkClient(
      this.config.getCoordinatorAddress(),
    );

    const request: PrepareTreeAddressRequest = {
      userIdentityPublicKey: await this.config.signer.getIdentityPublicKey(),
      node: undefined,
    };
    if (parentNode) {
      if (!parentNode.parentNodeId) {
        throw new Error("Parent node ID is undefined");
      }
      request.source = {
        $case: "parentNodeOutput",
        parentNodeOutput: {
          nodeId: parentNode.parentNodeId,
          vout: vout,
        },
      };
    } else if (parentTx) {
      request.source = {
        $case: "onChainUtxo",
        onChainUtxo: {
          txid: hexToBytes(getTxId(parentTx)),
          vout: vout,
          rawTx: parentTx.toBytes(),
          network: this.config.getNetworkProto(),
        },
      };
    } else {
      throw new Error("No parent node or parent tx provided");
    }

    request.node = {
      userPublicKey: parentSigningPublicKey,
      children: addressRequestNodes,
    };

    const root: DepositAddressTree = {
      address: undefined,
      signingPublicKey: parentSigningPublicKey,
      children: tree,
    };

    let response: PrepareTreeAddressResponse;
    try {
      response = await sparkClient.prepare_tree_address(request);
    } catch (error) {
      throw new Error(`Error preparing tree address: ${error}`);
    }

    if (!response.node) {
      throw new Error("No node found in response");
    }

    this.applyAddressNodesToTree([root], [response.node]);

    return root;
  }

  async createTree(
    vout: number,
    root: DepositAddressTree,
    createLeaves: boolean,
    parentTx?: Transaction,
    parentNode?: TreeNode,
  ): Promise<FinalizeNodeSignaturesResponse> {
    const request: CreateTreeRequest = {
      userIdentityPublicKey: await this.config.signer.getIdentityPublicKey(),
      node: undefined,
    };

    let tx: Transaction | undefined;
    if (parentTx) {
      tx = parentTx;
      request.source = {
        $case: "onChainUtxo",
        onChainUtxo: {
          txid: hexToBytes(getTxId(parentTx)),
          vout: vout,
          rawTx: parentTx.toBytes(),
          network: this.config.getNetworkProto(),
        },
      };
    } else if (parentNode) {
      tx = getTxFromRawTxBytes(parentNode.nodeTx);
      if (!parentNode.parentNodeId) {
        throw new Error("Parent node ID is undefined");
      }
      request.source = {
        $case: "parentNodeOutput",
        parentNodeOutput: {
          nodeId: parentNode.parentNodeId,
          vout: vout,
        },
      };
    } else {
      throw new Error("No parent node or parent tx provided");
    }

    const rootCreationNode = await this.buildCreationNodesFromTree(
      vout,
      createLeaves,
      this.config.getNetwork(),
      root,
      tx,
    );

    request.node = rootCreationNode;

    const sparkClient = await this.connectionManager.createSparkClient(
      this.config.getCoordinatorAddress(),
    );

    let response: CreateTreeResponse;
    try {
      response = await sparkClient.create_tree_v2(request);
    } catch (error) {
      throw new Error(`Error creating tree: ${error}`);
    }

    if (!response.node) {
      throw new Error("No node found in response");
    }

    const creationResultTreeRoot = response.node;

    const nodeSignatures = await this.signTreeCreation(
      tx,
      vout,
      root,
      rootCreationNode,
      creationResultTreeRoot,
    );

    let finalizeResp: FinalizeNodeSignaturesResponse;
    try {
      finalizeResp = await sparkClient.finalize_node_signatures_v2({
        nodeSignatures: nodeSignatures,
      });
    } catch (error) {
      throw new NetworkError(
        "Failed to finalize node signatures",
        {
          operation: "finalize_node_signatures",
          nodeSignaturesCount: nodeSignatures.length,
        },
        error as Error,
      );
    }

    return finalizeResp;
  }

  private async createDepositAddressTree(
    targetSigningPublicKey: Uint8Array,
    nodeId: string,
  ): Promise<DepositAddressTree[]> {
    // TODO: If we decide to reimplement tree-creation into the SDK
    // this needs to be updated to use the new derivation path based signing
    const leftNode: DepositAddressTree = {
      // signingPublicKey: leftKey,
      signingPublicKey: targetSigningPublicKey,
      children: [],
    };

    const rightKey =
      await this.config.signer.subtractPrivateKeysGivenDerivationPaths(
        // targetSigningPublicKey,
        nodeId,
        nodeId,
      );

    const rightNode: DepositAddressTree = {
      signingPublicKey: rightKey,
      children: [],
    };
    return [leftNode, rightNode];
  }

  private createAddressRequestNodeFromTreeNodes(
    treeNodes: DepositAddressTree[],
  ): AddressRequestNode[] {
    const results: AddressRequestNode[] = [];
    for (const node of treeNodes) {
      const result: AddressRequestNode = {
        userPublicKey: node.signingPublicKey,
        children: this.createAddressRequestNodeFromTreeNodes(node.children),
      };
      results.push(result);
    }
    return results;
  }

  private applyAddressNodesToTree(
    tree: DepositAddressTree[],
    addressNodes: AddressNode[],
  ) {
    for (let i = 0; i < tree.length; i++) {
      if (!tree[i]) {
        throw new ValidationError("Tree node is undefined", {
          index: i,
          treeLength: tree.length,
        });
      }
      if (!addressNodes[i]) {
        throw new ValidationError("Address node is undefined", {
          index: i,
          addressNodesLength: addressNodes.length,
        });
      }
      // @ts-ignore
      tree[i].address = addressNodes[i].address?.address;
      // @ts-ignore
      tree[i].verificationKey = addressNodes[i].address?.verifyingKey;
      // @ts-ignore
      this.applyAddressNodesToTree(tree[i].children, addressNodes[i].children);
    }
  }

  private async buildChildCreationNode(
    node: DepositAddressTree,
    parentTx: Transaction,
    vout: number,
    network: Network,
  ): Promise<CreationNodeWithNonces> {
    // internal node
    const internalCreationNode: CreationNodeWithNonces = {
      nodeTxSigningJob: undefined,
      directNodeTxSigningJob: undefined,
      refundTxSigningJob: undefined,
      directRefundTxSigningJob: undefined,
      directFromCpfpRefundTxSigningJob: undefined,
      children: [],
    };

    const parentTxOut = parentTx.getOutput(vout);
    if (!parentTxOut?.script || !parentTxOut?.amount) {
      throw new Error("parentTxOut is undefined");
    }

    const parentOutPoint = {
      txid: hexToBytes(getTxId(parentTx)),
      index: vout,
    };
    const parentTxOutObj = {
      script: parentTxOut.script,
      amount: parentTxOut.amount,
    };

    // Create both CPFP and direct node transactions
    const { cpfpNodeTx, directNodeTx } = createNodeTxs(
      parentTxOutObj,
      parentOutPoint,
    );

    // Create nonce commitments for node transactions
    const cpfpNodeSigningCommitment =
      await this.config.signer.getRandomSigningCommitment();
    const directNodeSigningCommitment =
      await this.config.signer.getRandomSigningCommitment();

    const cpfpNodeSigningJob: SigningJob = {
      signingPublicKey: node.signingPublicKey,
      rawTx: cpfpNodeTx.toBytes(),
      signingNonceCommitment: cpfpNodeSigningCommitment.commitment,
    };
    const directNodeSigningJob: SigningJob | undefined = directNodeTx
      ? {
          signingPublicKey: node.signingPublicKey,
          rawTx: directNodeTx.toBytes(),
          signingNonceCommitment: directNodeSigningCommitment.commitment,
        }
      : undefined;

    internalCreationNode.nodeTxSigningCommitment = cpfpNodeSigningCommitment;
    internalCreationNode.directNodeTxSigningCommitment =
      directNodeSigningCommitment;
    internalCreationNode.nodeTxSigningJob = cpfpNodeSigningJob;
    internalCreationNode.directNodeTxSigningJob = directNodeSigningJob;

    // leaf node
    const sequence = INITIAL_SEQUENCE;
    const directSequence = INITIAL_DIRECT_SEQUENCE;

    const childCreationNode: CreationNodeWithNonces = {
      nodeTxSigningJob: undefined,
      directNodeTxSigningJob: undefined,
      refundTxSigningJob: undefined,
      directRefundTxSigningJob: undefined,
      directFromCpfpRefundTxSigningJob: undefined,
      children: [],
    };

    // Create both CPFP and direct leaf node transactions
    const [cpfpLeafTx, directLeafTx] = createLeafNodeTx(
      sequence,
      directSequence,
      { txid: hexToBytes(getTxId(cpfpNodeTx)), index: 0 },
      parentTxOutObj,
      true, // shouldCalculateFee
    );

    // Create nonce commitments for leaf node transactions
    const cpfpLeafSigningCommitment =
      await this.config.signer.getRandomSigningCommitment();
    const directLeafSigningCommitment =
      await this.config.signer.getRandomSigningCommitment();

    const cpfpLeafSigningJob: SigningJob = {
      signingPublicKey: node.signingPublicKey,
      rawTx: cpfpLeafTx.toBytes(),
      signingNonceCommitment: cpfpLeafSigningCommitment.commitment,
    };
    const directLeafSigningJob: SigningJob = {
      signingPublicKey: node.signingPublicKey,
      rawTx: directLeafTx.toBytes(),
      signingNonceCommitment: directLeafSigningCommitment.commitment,
    };

    childCreationNode.nodeTxSigningCommitment = cpfpLeafSigningCommitment;
    childCreationNode.directNodeTxSigningCommitment =
      directLeafSigningCommitment;
    childCreationNode.nodeTxSigningJob = cpfpLeafSigningJob;
    childCreationNode.directNodeTxSigningJob = directLeafSigningJob;

    // Create both CPFP and direct refund transactions
    const { cpfpRefundTx, directRefundTx, directFromCpfpRefundTx } =
      createRefundTxs({
        sequence,
        directSequence,
        input: { txid: hexToBytes(getTxId(cpfpLeafTx)), index: 0 },
        directInput: { txid: hexToBytes(getTxId(directLeafTx)), index: 0 },
        amountSats: parentTxOut.amount,
        receivingPubkey: node.signingPublicKey,
        network,
      });

    // Create nonce commitments for refund transactions
    const cpfpRefundSigningCommitment =
      await this.config.signer.getRandomSigningCommitment();
    const directRefundSigningCommitment =
      await this.config.signer.getRandomSigningCommitment();
    const directFromCpfpRefundSigningCommitment =
      await this.config.signer.getRandomSigningCommitment();

    const cpfpRefundSigningJob: SigningJob = {
      signingPublicKey: node.signingPublicKey,
      rawTx: cpfpRefundTx.toBytes(),
      signingNonceCommitment: cpfpRefundSigningCommitment.commitment,
    };
    const directRefundSigningJob: SigningJob | undefined = directRefundTx
      ? {
          signingPublicKey: node.signingPublicKey,
          rawTx: directRefundTx.toBytes(),
          signingNonceCommitment: directRefundSigningCommitment.commitment,
        }
      : undefined;
    const directFromCpfpRefundSigningJob: SigningJob | undefined =
      directFromCpfpRefundTx
        ? {
            signingPublicKey: node.signingPublicKey,
            rawTx: directFromCpfpRefundTx.toBytes(),
            signingNonceCommitment:
              directFromCpfpRefundSigningCommitment.commitment,
          }
        : undefined;

    childCreationNode.refundTxSigningCommitment = cpfpRefundSigningCommitment;
    childCreationNode.directRefundTxSigningCommitment =
      directRefundSigningCommitment;
    childCreationNode.directFromCpfpRefundTxSigningCommitment =
      directFromCpfpRefundSigningCommitment;
    childCreationNode.refundTxSigningJob = cpfpRefundSigningJob;
    childCreationNode.directRefundTxSigningJob = directRefundSigningJob;
    childCreationNode.directFromCpfpRefundTxSigningJob =
      directFromCpfpRefundSigningJob;

    internalCreationNode.children.push(childCreationNode);

    return internalCreationNode;
  }

  private async buildCreationNodesFromTree(
    vout: number,
    createLeaves: boolean,
    network: Network,
    root: DepositAddressTree,
    parentTx: Transaction,
  ): Promise<CreationNodeWithNonces> {
    const parentTxOutput = parentTx.getOutput(vout);
    if (!parentTxOutput?.script || !parentTxOutput?.amount) {
      throw new Error("parentTxOutput is undefined");
    }

    // Create child transaction outputs
    const childTxOuts: { script: Uint8Array; amount: bigint }[] = [];
    for (let i = 0; i < root.children.length; i++) {
      const child = root.children[i];
      if (!child || !child.address) {
        throw new Error("child address is undefined");
      }
      const childAddress = Address(getNetwork(network)).decode(child.address);
      const childPkScript = OutScript.encode(childAddress);

      childTxOuts.push({
        script: childPkScript,
        amount: parentTxOutput.amount / 2n,
      });
    }

    const parentOutPoint = {
      txid: hexToBytes(getTxId(parentTx)),
      index: vout,
    };

    // Create both CPFP and direct split transactions
    const [cpfpSplitTx, directSplitTx] = createSplitTx(
      parentOutPoint,
      childTxOuts,
    );

    // Create nonce commitments for split transactions
    const cpfpSplitSigningCommitment =
      await this.config.signer.getRandomSigningCommitment();
    const directSplitSigningCommitment =
      await this.config.signer.getRandomSigningCommitment();

    const cpfpSplitSigningJob: SigningJob = {
      signingPublicKey: root.signingPublicKey,
      rawTx: cpfpSplitTx.toBytes(),
      signingNonceCommitment: cpfpSplitSigningCommitment.commitment,
    };
    const directSplitSigningJob: SigningJob = {
      signingPublicKey: root.signingPublicKey,
      rawTx: directSplitTx.toBytes(),
      signingNonceCommitment: directSplitSigningCommitment.commitment,
    };

    const rootCreationNode: CreationNodeWithNonces = {
      nodeTxSigningJob: cpfpSplitSigningJob,
      directNodeTxSigningJob: directSplitSigningJob,
      refundTxSigningJob: undefined,
      directRefundTxSigningJob: undefined,
      directFromCpfpRefundTxSigningJob: undefined,
      children: [],
    };
    rootCreationNode.nodeTxSigningCommitment = cpfpSplitSigningCommitment;
    rootCreationNode.directNodeTxSigningCommitment =
      directSplitSigningCommitment;

    const leftChild = root.children[0];
    const rightChild = root.children[1];
    if (!leftChild || !rightChild) {
      throw new Error("Root children are undefined");
    }

    const leftChildCreationNode = await this.buildChildCreationNode(
      leftChild,
      cpfpSplitTx, // Use CPFP version for children
      0,
      network,
    );
    const rightChildCreationNode = await this.buildChildCreationNode(
      rightChild,
      cpfpSplitTx, // Use CPFP version for children
      1,
      network,
    );

    rootCreationNode.children.push(leftChildCreationNode);
    rootCreationNode.children.push(rightChildCreationNode);

    return rootCreationNode;
  }

  private async signNodeCreation(
    parentTx: Transaction,
    vout: number,
    internalNode: DepositAddressTree,
    creationNode: CreationNodeWithNonces,
    creationResponseNode: CreationResponseNode,
  ): Promise<{ tx: Transaction; signature: NodeSignatures }> {
    if (
      !creationNode.nodeTxSigningJob?.signingPublicKey ||
      !creationNode.directNodeTxSigningJob?.signingPublicKey ||
      !internalNode.verificationKey
    ) {
      throw new Error("signingPublicKey or verificationKey is undefined");
    }

    const parentTxOutput = parentTx.getOutput(vout);
    if (!parentTxOutput) {
      throw new Error("parentTxOutput is undefined");
    }

    // Sign CPFP node transaction
    const cpfpNodeTx = getTxFromRawTxBytes(creationNode.nodeTxSigningJob.rawTx);
    const cpfpNodeTxSighash = getSigHashFromTx(cpfpNodeTx, 0, parentTxOutput);

    let cpfpNodeTxSignature: Uint8Array = new Uint8Array();
    if (creationNode.nodeTxSigningCommitment) {
      const cpfpUserSignature = await this.config.signer.signFrost({
        message: cpfpNodeTxSighash,
        publicKey: creationNode.nodeTxSigningJob.signingPublicKey,
        keyDerivation: {
          type: KeyDerivationType.LEAF,
          path: creationResponseNode.nodeId,
        },
        selfCommitment: creationNode.nodeTxSigningCommitment,
        statechainCommitments:
          creationResponseNode.nodeTxSigningResult?.signingNonceCommitments,
        verifyingKey: internalNode.verificationKey,
      });

      cpfpNodeTxSignature = await this.config.signer.aggregateFrost({
        message: cpfpNodeTxSighash,
        statechainSignatures:
          creationResponseNode.nodeTxSigningResult?.signatureShares,
        statechainPublicKeys:
          creationResponseNode.nodeTxSigningResult?.publicKeys,
        verifyingKey: internalNode.verificationKey,
        statechainCommitments:
          creationResponseNode.nodeTxSigningResult?.signingNonceCommitments,
        selfCommitment: creationNode.nodeTxSigningCommitment,
        selfSignature: cpfpUserSignature,
        publicKey: internalNode.signingPublicKey,
      });
    }

    // Sign direct node transaction
    const directNodeTx = getTxFromRawTxBytes(
      creationNode.directNodeTxSigningJob.rawTx,
    );
    const directNodeTxSighash = getSigHashFromTx(
      directNodeTx,
      0,
      parentTxOutput,
    );

    let directNodeTxSignature: Uint8Array = new Uint8Array();
    if (creationNode.directNodeTxSigningCommitment) {
      const directUserSignature = await this.config.signer.signFrost({
        message: directNodeTxSighash,
        publicKey: creationNode.directNodeTxSigningJob.signingPublicKey,
        keyDerivation: {
          type: KeyDerivationType.LEAF,
          path: creationResponseNode.nodeId,
        },
        selfCommitment: creationNode.directNodeTxSigningCommitment,
        statechainCommitments:
          creationResponseNode.directNodeTxSigningResult
            ?.signingNonceCommitments,
        verifyingKey: internalNode.verificationKey,
      });

      directNodeTxSignature = await this.config.signer.aggregateFrost({
        message: directNodeTxSighash,
        statechainSignatures:
          creationResponseNode.directNodeTxSigningResult?.signatureShares,
        statechainPublicKeys:
          creationResponseNode.directNodeTxSigningResult?.publicKeys,
        verifyingKey: internalNode.verificationKey,
        statechainCommitments:
          creationResponseNode.directNodeTxSigningResult
            ?.signingNonceCommitments,
        selfCommitment: creationNode.directNodeTxSigningCommitment,
        selfSignature: directUserSignature,
        publicKey: internalNode.signingPublicKey,
      });
    }

    // Sign refund transactions if they exist
    let cpfpRefundTxSignature: Uint8Array = new Uint8Array();
    let directRefundTxSignature: Uint8Array = new Uint8Array();
    let directFromCpfpRefundTxSignature: Uint8Array = new Uint8Array();
    if (
      creationNode.refundTxSigningCommitment &&
      creationNode.directRefundTxSigningCommitment &&
      creationNode.directFromCpfpRefundTxSigningCommitment
    ) {
      const rawCpfpRefundTx = creationNode.refundTxSigningJob?.rawTx;
      const rawDirectRefundTx = creationNode.directRefundTxSigningJob?.rawTx;
      const rawDirectFromCpfpRefundTx =
        creationNode.directFromCpfpRefundTxSigningJob?.rawTx;
      if (
        !rawCpfpRefundTx ||
        !rawDirectRefundTx ||
        !rawDirectFromCpfpRefundTx
      ) {
        throw new Error("refund transaction rawTx is undefined");
      }
      if (
        !creationNode.refundTxSigningJob?.signingPublicKey ||
        !creationNode.directRefundTxSigningJob?.signingPublicKey ||
        !creationNode.directFromCpfpRefundTxSigningJob?.signingPublicKey
      ) {
        throw new Error("refund transaction signingPublicKey is undefined");
      }

      const cpfpRefundTx = getTxFromRawTxBytes(rawCpfpRefundTx);
      const directRefundTx = getTxFromRawTxBytes(rawDirectRefundTx);
      const directFromCpfpRefundTx = getTxFromRawTxBytes(
        rawDirectFromCpfpRefundTx,
      );
      const cpfpRefundTxSighash = getSigHashFromTx(
        cpfpRefundTx,
        0,
        cpfpNodeTx.getOutput(0),
      );
      const directRefundTxSighash = getSigHashFromTx(
        directRefundTx,
        0,
        directNodeTx.getOutput(0),
      );
      const directFromCpfpRefundTxSighash = getSigHashFromTx(
        directFromCpfpRefundTx,
        0,
        cpfpNodeTx.getOutput(0),
      );

      // Sign CPFP refund transaction
      const cpfpRefundUserSignature = await this.config.signer.signFrost({
        message: cpfpRefundTxSighash,
        publicKey: creationNode.refundTxSigningJob.signingPublicKey,
        keyDerivation: {
          type: KeyDerivationType.LEAF,
          path: creationResponseNode.nodeId,
        },
        selfCommitment: creationNode.refundTxSigningCommitment,
        statechainCommitments:
          creationResponseNode.refundTxSigningResult?.signingNonceCommitments,
        verifyingKey: internalNode.verificationKey,
      });

      cpfpRefundTxSignature = await this.config.signer.aggregateFrost({
        message: cpfpRefundTxSighash,
        statechainSignatures:
          creationResponseNode.refundTxSigningResult?.signatureShares,
        statechainPublicKeys:
          creationResponseNode.refundTxSigningResult?.publicKeys,
        verifyingKey: internalNode.verificationKey,
        statechainCommitments:
          creationResponseNode.refundTxSigningResult?.signingNonceCommitments,
        selfCommitment: creationNode.refundTxSigningCommitment,
        selfSignature: cpfpRefundUserSignature,
        publicKey: internalNode.signingPublicKey,
      });

      const keyDerivation: KeyDerivation = {
        type: KeyDerivationType.LEAF,
        path: creationResponseNode.nodeId,
      };
      // Sign direct refund transaction
      const directRefundUserSignature = await this.config.signer.signFrost({
        message: directRefundTxSighash,
        publicKey: creationNode.directRefundTxSigningJob.signingPublicKey,
        keyDerivation,
        selfCommitment: creationNode.directRefundTxSigningCommitment,
        statechainCommitments:
          creationResponseNode.directRefundTxSigningResult
            ?.signingNonceCommitments,
        verifyingKey: internalNode.verificationKey,
      });

      directRefundTxSignature = await this.config.signer.aggregateFrost({
        message: directRefundTxSighash,
        statechainSignatures:
          creationResponseNode.directRefundTxSigningResult?.signatureShares,
        statechainPublicKeys:
          creationResponseNode.directRefundTxSigningResult?.publicKeys,
        verifyingKey: internalNode.verificationKey,
        statechainCommitments:
          creationResponseNode.directRefundTxSigningResult
            ?.signingNonceCommitments,
        selfCommitment: creationNode.directRefundTxSigningCommitment,
        selfSignature: directRefundUserSignature,
        publicKey: internalNode.signingPublicKey,
      });

      // Sign direct from CPFP refund transaction
      const directFromCpfpRefundUserSignature =
        await this.config.signer.signFrost({
          message: directFromCpfpRefundTxSighash,
          publicKey:
            creationNode.directFromCpfpRefundTxSigningJob.signingPublicKey,
          keyDerivation,
          selfCommitment: creationNode.directFromCpfpRefundTxSigningCommitment,
          statechainCommitments:
            creationResponseNode.directFromCpfpRefundTxSigningResult
              ?.signingNonceCommitments,
          verifyingKey: internalNode.verificationKey,
        });

      directFromCpfpRefundTxSignature = await this.config.signer.aggregateFrost(
        {
          message: directFromCpfpRefundTxSighash,
          statechainSignatures:
            creationResponseNode.directFromCpfpRefundTxSigningResult
              ?.signatureShares,
          statechainPublicKeys:
            creationResponseNode.directFromCpfpRefundTxSigningResult
              ?.publicKeys,
          verifyingKey: internalNode.verificationKey,
          statechainCommitments:
            creationResponseNode.directFromCpfpRefundTxSigningResult
              ?.signingNonceCommitments,
          selfCommitment: creationNode.directFromCpfpRefundTxSigningCommitment,
          selfSignature: directFromCpfpRefundUserSignature,
          publicKey: internalNode.signingPublicKey,
        },
      );
    }

    return {
      tx: cpfpNodeTx, // Return CPFP version for children
      signature: {
        nodeId: creationResponseNode.nodeId,
        nodeTxSignature: cpfpNodeTxSignature,
        directNodeTxSignature: directNodeTxSignature,
        refundTxSignature: cpfpRefundTxSignature,
        directRefundTxSignature: directRefundTxSignature,
        directFromCpfpRefundTxSignature: directFromCpfpRefundTxSignature,
      },
    };
  }

  private async signTreeCreation(
    tx: Transaction,
    vout: number,
    root: DepositAddressTree,
    rootCreationNode: CreationNodeWithNonces,
    creationResultTreeRoot: CreationResponseNode,
  ): Promise<NodeSignatures[]> {
    const rootSignature = await this.signNodeCreation(
      tx,
      vout,
      root,
      rootCreationNode,
      creationResultTreeRoot,
    );

    const firstRootChild = root.children[0];
    const secondRootChild = root.children[1];
    const firstRootChildCreationNode = rootCreationNode.children[0];
    const secondRootChildCreationNode = rootCreationNode.children[1];
    const firstRootChildCreationResult = creationResultTreeRoot.children[0];
    const secondRootChildCreationResult = creationResultTreeRoot.children[1];
    if (!firstRootChild || !secondRootChild) {
      throw new Error("Root children are undefined");
    }

    if (!firstRootChildCreationNode || !secondRootChildCreationNode) {
      throw new Error("Root child creation nodes are undefined");
    }

    if (!firstRootChildCreationResult || !secondRootChildCreationResult) {
      throw new Error("Root child creation results are undefined");
    }

    const leftChildSignature = await this.signNodeCreation(
      rootSignature.tx,
      0,
      firstRootChild,
      firstRootChildCreationNode,
      firstRootChildCreationResult,
    );

    const rightChildSignature = await this.signNodeCreation(
      rootSignature.tx,
      1,
      secondRootChild,
      secondRootChildCreationNode,
      secondRootChildCreationResult,
    );

    const signatures = [
      rootSignature.signature,
      leftChildSignature.signature,
      rightChildSignature.signature,
    ];

    return signatures;
  }
}
