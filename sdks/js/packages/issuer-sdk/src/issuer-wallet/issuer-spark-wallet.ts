import { TokenPubkey, TokenPubkeyAnnouncement } from "@buildonspark/lrc20-sdk";
import {
  NetworkError,
  SparkWallet,
  SparkWalletProps,
  UserTokenMetadata,
  ValidationError,
} from "@buildonspark/spark-sdk";
import { isNode } from "@lightsparkdev/core";
import {
  decodeSparkAddress,
  encodeSparkAddress,
} from "@buildonspark/spark-sdk";
import {
  OutputWithPreviousTransactionData,
  TokenTransaction as TokenTransactionV0,
} from "@buildonspark/spark-sdk/proto/spark";
import { TokenTransaction } from "@buildonspark/spark-sdk/proto/spark_token";
import { type ConfigOptions } from "@buildonspark/spark-sdk";
import {
  bytesToHex,
  bytesToNumberBE,
  hexToBytes,
} from "@noble/curves/abstract/utils";
import { TokenFreezeService } from "../services/freeze.js";
import { IssuerTokenTransactionService } from "../services/token-transactions.js";
import { TokenDistribution, IssuerTokenMetadata } from "./types.js";
import { NotImplementedError } from "@buildonspark/spark-sdk";
import { SparkSigner } from "@buildonspark/spark-sdk";
import {
  encodeBech32mTokenIdentifier,
  Bech32mTokenIdentifier,
} from "@buildonspark/spark-sdk";

const BURN_ADDRESS = "02".repeat(33);

/**
 * Represents a Spark wallet with minting capabilities.
 * This class extends the base SparkWallet with additional functionality for token minting,
 * burning, and freezing operations.
 */
export class IssuerSparkWallet extends SparkWallet {
  private issuerTokenTransactionService: IssuerTokenTransactionService;
  private tokenFreezeService: TokenFreezeService;
  protected tracerId = "issuer-sdk";

  /**
   * Initializes a new IssuerSparkWallet instance.
   * @param options - Configuration options for the wallet
   * @returns An object containing the initialized wallet and initialization response
   */
  public static async initialize({
    mnemonicOrSeed,
    accountNumber,
    signer,
    options,
  }: SparkWalletProps) {
    const wallet = new IssuerSparkWallet(options, signer);

    const initResponse = await wallet.initWallet(mnemonicOrSeed, accountNumber);

    if (isNode) {
      wallet.wrapIssuerSparkWalletWithTracing();
    }

    return {
      wallet,
      ...initResponse,
    };
  }

  private wrapIssuerSparkWalletWithTracing() {
    this.getIssuerTokenBalance = this.wrapWithOtelSpan(
      "SparkIssuerWallet.getIssuerTokenBalance",
      this.getIssuerTokenBalance.bind(this),
    );
    this.getIssuerTokenMetadata = this.wrapWithOtelSpan(
      "SparkIssuerWallet.getIssuerTokenMetadata",
      this.getIssuerTokenMetadata.bind(this),
    );
    this.getIssuerTokenIdentifier = this.wrapWithOtelSpan(
      "SparkIssuerWallet.getIssuerTokenIdentifier",
      this.getIssuerTokenIdentifier.bind(this),
    );
    this.mintTokens = this.wrapWithOtelSpan(
      "SparkIssuerWallet.mintTokens",
      this.mintTokens.bind(this),
    );
    this.burnTokens = this.wrapWithOtelSpan(
      "SparkIssuerWallet.burnTokens",
      this.burnTokens.bind(this),
    );
    this.freezeTokens = this.wrapWithOtelSpan(
      "SparkIssuerWallet.freezeTokens",
      this.freezeTokens.bind(this),
    );
    this.unfreezeTokens = this.wrapWithOtelSpan(
      "SparkIssuerWallet.unfreezeTokens",
      this.unfreezeTokens.bind(this),
    );
    this.getIssuerTokenDistribution = this.wrapWithOtelSpan(
      "SparkIssuerWallet.getIssuerTokenDistribution",
      this.getIssuerTokenDistribution.bind(this),
    );
    this.announceTokenL1 = this.wrapWithOtelSpan(
      "SparkIssuerWallet.announceTokenL1",
      this.announceTokenL1.bind(this),
    );
  }

  protected constructor(configOptions?: ConfigOptions, signer?: SparkSigner) {
    super(configOptions, signer);
    this.issuerTokenTransactionService = new IssuerTokenTransactionService(
      this.config,
      this.connectionManager,
    );
    this.tokenFreezeService = new TokenFreezeService(
      this.config,
      this.connectionManager,
    );
  }

  /**
   * Gets the token balance for the issuer's token.
   * @returns An object containing the token balance as a bigint
   */
  public async getIssuerTokenBalance(): Promise<{
    tokenIdentifier: Bech32mTokenIdentifier | undefined;
    balance: bigint;
  }> {
    const publicKey = await super.getIdentityPublicKey();
    const balanceObj = await this.getBalance();
    const issuerBalance = [...balanceObj.tokenBalances.entries()].find(
      ([, info]) => info.tokenMetadata.tokenPublicKey === publicKey,
    ); // [tokenIdentifier, { balance, tokenMetadata }]

    if (!balanceObj.tokenBalances || issuerBalance === undefined) {
      return {
        tokenIdentifier: undefined,
        balance: 0n,
      };
    }
    return {
      tokenIdentifier: issuerBalance[0] ?? undefined,
      balance: issuerBalance[1].balance,
    };
  }

  /**
   * Retrieves information about the issuer's token.
   * @returns An object containing token information including public key, name, symbol, decimals, max supply, and freeze status
   * @throws {NetworkError} If the token metadata cannot be retrieved
   */
  public async getIssuerTokenMetadata(): Promise<IssuerTokenMetadata> {
    const issuerPublicKey = await super.getIdentityPublicKey();
    const tokenMetadata = this.tokenMetadata;

    const cachedIssuerTokenMetadata = [...tokenMetadata.entries()].find(
      ([, metadata]) =>
        bytesToHex(metadata.issuerPublicKey) === issuerPublicKey,
    );
    if (cachedIssuerTokenMetadata !== undefined) {
      const metadata = cachedIssuerTokenMetadata[1];
      return {
        tokenPublicKey: bytesToHex(metadata.issuerPublicKey),
        rawTokenIdentifier: metadata.tokenIdentifier,
        tokenName: metadata.tokenName,
        tokenTicker: metadata.tokenTicker,
        decimals: metadata.decimals,
        maxSupply: bytesToNumberBE(metadata.maxSupply),
        isFreezable: metadata.isFreezable,
      };
    }

    const sparkTokenClient =
      await this.connectionManager.createSparkTokenClient(
        this.config.getCoordinatorAddress(),
      );
    try {
      const response = await sparkTokenClient.query_token_metadata({
        issuerPublicKeys: Array.of(hexToBytes(issuerPublicKey)),
      });
      if (response.tokenMetadata.length === 0) {
        throw new ValidationError(
          "Token metadata not found - If a token has not yet been announced, please announce. If a token was recently announced, it is being confirmed. Try again in a few seconds.",
          {
            field: "tokenMetadata",
            value: response.tokenMetadata,
            expected: "non-empty array",
            actualLength: response.tokenMetadata.length,
            expectedLength: 1,
          },
        );
      }
      const metadata = response.tokenMetadata[0];
      const tokenIdentifier = encodeBech32mTokenIdentifier({
        tokenIdentifier: metadata.tokenIdentifier,
        network: this.config.getNetworkType(),
      });
      this.tokenMetadata.set(tokenIdentifier, metadata);

      return {
        tokenPublicKey: bytesToHex(metadata.issuerPublicKey),
        rawTokenIdentifier: metadata.tokenIdentifier,
        tokenName: metadata.tokenName,
        tokenTicker: metadata.tokenTicker,
        decimals: metadata.decimals,
        maxSupply: bytesToNumberBE(metadata.maxSupply),
        isFreezable: metadata.isFreezable,
      };
    } catch (error) {
      throw new NetworkError("Failed to fetch token metadata", {
        errorCount: 1,
        errors: error instanceof Error ? error.message : String(error),
      });
    }
  }

  /**
   * Retrieves the bech32m encoded token identifier for the issuer's token.
   * @returns The bech32m encoded token identifier for the issuer's token
   * @throws {NetworkError} If the token identifier cannot be retrieved
   */
  public async getIssuerTokenIdentifier(): Promise<Bech32mTokenIdentifier | null> {
    const tokenMetadata = await this.getIssuerTokenMetadata();

    return encodeBech32mTokenIdentifier({
      tokenIdentifier: tokenMetadata.rawTokenIdentifier,
      network: this.config.getNetworkType(),
    });
  }

  /**
   * Mints new tokens
   * @param tokenAmount - The amount of tokens to mint
   * @returns The transaction ID of the mint operation
   */
  public async mintTokens(tokenAmount: bigint): Promise<string> {
    let tokenTransaction: TokenTransactionV0 | TokenTransaction;
    const issuerTokenPublicKey = await super.getIdentityPublicKey();
    const issuerTokenPublicKeyBytes = hexToBytes(issuerTokenPublicKey);

    const tokenMetadata = await this.getIssuerTokenMetadata();
    const rawTokenIdentifier: Uint8Array = tokenMetadata.rawTokenIdentifier;

    if (this.config.getTokenTransactionVersion() === "V0") {
      tokenTransaction =
        await this.issuerTokenTransactionService.constructMintTokenTransactionV0(
          issuerTokenPublicKeyBytes,
          tokenAmount,
        );
    } else {
      tokenTransaction =
        await this.issuerTokenTransactionService.constructMintTokenTransaction(
          rawTokenIdentifier,
          issuerTokenPublicKeyBytes,
          tokenAmount,
        );
    }

    return await this.issuerTokenTransactionService.broadcastTokenTransaction(
      tokenTransaction,
    );
  }

  /**
   * Burns issuer's tokens
   * @param tokenAmount - The amount of tokens to burn
   * @param selectedOutputs - Optional array of outputs to use for the burn operation
   * @returns The transaction ID of the burn operation
   */
  public async burnTokens(
    tokenAmount: bigint,
    selectedOutputs?: OutputWithPreviousTransactionData[],
  ): Promise<string> {
    const burnAddress = encodeSparkAddress({
      identityPublicKey: BURN_ADDRESS,
      network: this.config.getNetworkType(),
    });
    const issuerTokenIdentifier: Bech32mTokenIdentifier | null =
      await this.getIssuerTokenIdentifier();
    if (issuerTokenIdentifier === null) {
      throw new ValidationError("Issuer token identifier not found");
    }

    return await this.transferTokens({
      tokenIdentifier: issuerTokenIdentifier,
      tokenAmount,
      receiverSparkAddress: burnAddress,
      selectedOutputs,
    });
  }

  /**
   * Freezes tokens associated with a specific Spark address.
   * @param sparkAddress - The Spark address whose tokens should be frozen
   * @returns An object containing the IDs of impacted outputs and the total amount of frozen tokens
   */
  public async freezeTokens(
    sparkAddress: string,
  ): Promise<{ impactedOutputIds: string[]; impactedTokenAmount: bigint }> {
    await this.syncTokenOutputs();
    const tokenPublicKey = await super.getIdentityPublicKey();
    const decodedOwnerPubkey = decodeSparkAddress(
      sparkAddress,
      this.config.getNetworkType(),
    );
    const response = await this.tokenFreezeService!.freezeTokens(
      hexToBytes(decodedOwnerPubkey.identityPublicKey),
      hexToBytes(tokenPublicKey),
    );

    // Convert the Uint8Array to a bigint
    const tokenAmount = bytesToNumberBE(response.impactedTokenAmount);

    return {
      impactedOutputIds: response.impactedOutputIds,
      impactedTokenAmount: tokenAmount,
    };
  }

  /**
   * Unfreezes previously frozen tokens associated with a specific Spark address.
   * @param sparkAddress - The Spark address whose tokens should be unfrozen
   * @returns An object containing the IDs of impacted outputs and the total amount of unfrozen tokens
   */
  public async unfreezeTokens(
    sparkAddress: string,
  ): Promise<{ impactedOutputIds: string[]; impactedTokenAmount: bigint }> {
    await this.syncTokenOutputs();
    const tokenPublicKey = await super.getIdentityPublicKey();
    const decodedOwnerPubkey = decodeSparkAddress(
      sparkAddress,
      this.config.getNetworkType(),
    );
    const response = await this.tokenFreezeService!.unfreezeTokens(
      hexToBytes(decodedOwnerPubkey.identityPublicKey),
      hexToBytes(tokenPublicKey),
    );
    const tokenAmount = bytesToNumberBE(response.impactedTokenAmount);

    return {
      impactedOutputIds: response.impactedOutputIds,
      impactedTokenAmount: tokenAmount,
    };
  }

  /**
   * Retrieves the distribution information for the issuer's token.
   * @throws {NotImplementedError} This feature is not yet supported
   */
  public async getIssuerTokenDistribution(): Promise<TokenDistribution> {
    throw new NotImplementedError("Token distribution is not yet supported");
  }

  /**
   * Announces a new token on the L1 (Bitcoin) network.
   * @param tokenName - The name of the token
   * @param tokenTicker - The ticker symbol for the token
   * @param decimals - The number of decimal places for the token
   * @param maxSupply - The maximum supply of the token
   * @param isFreezable - Whether the token can be frozen
   * @param feeRateSatsPerVb - The fee rate in satoshis per virtual byte (default: 4.0)
   * @returns The transaction ID of the announcement
   * @throws {ValidationError} If decimals is not a safe integer
   * @throws {NetworkError} If the announcement transaction cannot be broadcast
   */
  public async announceTokenL1(
    tokenName: string,
    tokenTicker: string,
    decimals: number,
    maxSupply: bigint,
    isFreezable: boolean,
    feeRateSatsPerVb: number = 4.0,
  ): Promise<string> {
    if (!Number.isSafeInteger(decimals)) {
      throw new ValidationError("Decimals must be less than 2^53", {
        field: "decimals",
        value: decimals,
        expected: "smaller or equal to " + Number.MAX_SAFE_INTEGER,
      });
    }

    await this.lrc20Wallet!.syncWallet();

    const tokenPublicKey = new TokenPubkey(this.lrc20Wallet!.pubkey);

    const announcement = new TokenPubkeyAnnouncement(
      tokenPublicKey,
      tokenName,
      tokenTicker,
      decimals,
      maxSupply,
      isFreezable,
    );

    try {
      const tx = await this.lrc20Wallet!.prepareAnnouncement(
        announcement,
        feeRateSatsPerVb,
      );

      const txId = await this.lrc20Wallet!.broadcastRawBtcTransaction(
        tx.bitcoin_tx.toHex(),
      );

      return txId;
    } catch (error) {
      throw new NetworkError(
        "Failed to broadcast announcement transaction on L1",
        {
          operation: "broadcastRawBtcTransaction",
          errorCount: 1,
          errors: error instanceof Error ? error.message : String(error),
        },
      );
    }
  }
}
