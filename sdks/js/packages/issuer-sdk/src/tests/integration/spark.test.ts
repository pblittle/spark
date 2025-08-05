import {
  WalletConfig,
  ConfigOptions,
  filterTokenBalanceForTokenIdentifier,
} from "@buildonspark/spark-sdk";
import { jest } from "@jest/globals";
import { IssuerSparkWalletTesting } from "../utils/issuer-test-wallet.js";
import { SparkWalletTesting } from "../utils/spark-testing-wallet.js";
import { BitcoinFaucet } from "@buildonspark/spark-sdk/test-utils";
import { bytesToHex } from "@noble/curves/abstract/utils";
import { IssuerSparkWallet } from "../../issuer-wallet/issuer-spark-wallet.node.js";

export const TOKENS_V0_SCHNORR_CONFIG: Required<ConfigOptions> = {
  ...WalletConfig.LOCAL,
  tokenTransactionVersion: "V0",
  tokenSignatures: "SCHNORR",
};

export const TOKENS_V1_SCHNORR_CONFIG: Required<ConfigOptions> = {
  ...WalletConfig.LOCAL,
  tokenTransactionVersion: "V1",
  tokenSignatures: "SCHNORR",
};

export const TOKENS_V0_ECDSA_CONFIG: Required<ConfigOptions> = {
  ...WalletConfig.LOCAL,
  tokenSignatures: "ECDSA",
  tokenTransactionVersion: "V0",
};

export const TOKENS_V1_ECDSA_CONFIG: Required<ConfigOptions> = {
  ...WalletConfig.LOCAL,
  tokenSignatures: "ECDSA",
  tokenTransactionVersion: "V1",
};

const TEST_CONFIGS = [
  { name: "TV0E", config: TOKENS_V0_ECDSA_CONFIG },
  { name: "TV0S", config: TOKENS_V0_SCHNORR_CONFIG },
  { name: "TV1E", config: TOKENS_V1_ECDSA_CONFIG },
  { name: "TV1S", config: TOKENS_V1_SCHNORR_CONFIG },
];

const brokenTestFn = process.env.GITHUB_ACTIONS ? it.skip : it;

describe.each(TEST_CONFIGS)(
  "token integration tests - $name",
  ({ name, config }) => {
    jest.setTimeout(80000);

    it("should create a token", async () => {
      const { wallet: issuerWallet } =
        await IssuerSparkWalletTesting.initialize({
          options: config,
        });

      const tokenName = `${name}Creatable`;
      const tokenTicker = "CRT";
      const maxSupply = 5000n;
      const decimals = 0;
      const txId = await issuerWallet.createToken({
        tokenName,
        tokenTicker,
        decimals,
        isFreezable: false,
        maxSupply,
      });

      expect(typeof txId).toBe("string");
      expect(txId.length).toBeGreaterThan(0);

      const metadata = await issuerWallet.getIssuerTokenMetadata();
      expect(metadata.tokenName).toEqual(tokenName);
      expect(metadata.tokenTicker).toEqual(tokenTicker);
      expect(metadata.maxSupply).toEqual(maxSupply);
      expect(metadata.decimals).toEqual(decimals);
    });

    it("should announce a token", async () => {
      const { wallet: issuerWallet } =
        await IssuerSparkWalletTesting.initialize({
          options: config,
        });

      const tokenName = `${name}Announcable`;
      const tokenTicker = "ANN";
      const maxSupply = 5000n;
      const decimals = 0;

      await fundAndAnnounce(
        issuerWallet,
        5000n,
        0,
        tokenName,
        tokenTicker,
        false,
      );

      const metadata = await issuerWallet.getIssuerTokenMetadata();
      expect(metadata.tokenName).toEqual(tokenName);
      expect(metadata.tokenTicker).toEqual(tokenTicker);
      expect(metadata.maxSupply).toEqual(maxSupply);
      expect(metadata.decimals).toEqual(decimals);
    });

    it("should fail on duplicate token creation", async () => {
      const { wallet: issuerWallet } =
        await IssuerSparkWalletTesting.initialize({
          options: config,
        });

      const tokenName = `${name}Dup`;
      const tokenTicker = `DP${name}`;

      await issuerWallet.createToken({
        tokenName,
        tokenTicker,
        decimals: 0,
        isFreezable: false,
        maxSupply: 100n,
      });

      await expect(
        issuerWallet.createToken({
          tokenName,
          tokenTicker,
          decimals: 0,
          isFreezable: false,
          maxSupply: 100n,
        }),
      ).rejects.toThrow();
    });

    it("should fail when minting tokens without creation", async () => {
      const tokenAmount: bigint = 1000n;
      const { wallet } = await IssuerSparkWalletTesting.initialize({
        options: config,
      });

      await expect(wallet.mintTokens(tokenAmount)).rejects.toThrow();
    });

    it("should create, andfail when minting more than max supply", async () => {
      const tokenAmount: bigint = 1000n;
      const { wallet } = await IssuerSparkWalletTesting.initialize({
        options: config,
      });

      await wallet.createToken({
        tokenName: "MST",
        tokenTicker: "MST",
        decimals: 0,
        isFreezable: false,
        maxSupply: 2n,
      });
      await expect(wallet.mintTokens(tokenAmount)).rejects.toThrow();
    });

    it("should create, and mint tokens successfully", async () => {
      const tokenAmount: bigint = 1000n;

      const { wallet: issuerWallet } =
        await IssuerSparkWalletTesting.initialize({
          options: config,
        });
      await issuerWallet.createToken({
        tokenName: `${name}M`,
        tokenTicker: "MIN",
        decimals: 0,
        isFreezable: false,
        maxSupply: 1_000_000n,
      });

      const tokenMetadata = await issuerWallet.getIssuerTokenMetadata();

      const identityPublicKey = await issuerWallet.getIdentityPublicKey();
      expect(tokenMetadata?.tokenName).toEqual(`${name}M`);
      expect(tokenMetadata?.tokenTicker).toEqual("MIN");
      expect(tokenMetadata?.decimals).toEqual(0);
      expect(tokenMetadata?.maxSupply).toEqual(1000000n);
      expect(tokenMetadata?.isFreezable).toEqual(false);

      // Compare the public key using bytesToHex
      const metadataPubkey = tokenMetadata?.tokenPublicKey;
      expect(metadataPubkey).toEqual(identityPublicKey);

      await issuerWallet.mintTokens(tokenAmount);

      const tokenBalance = await issuerWallet.getIssuerTokenBalance();
      expect(tokenBalance.balance).toBeGreaterThanOrEqual(tokenAmount);
    });

    it("should create, mint, and transfer tokens", async () => {
      const tokenAmount: bigint = 1000n;

      const { wallet: issuerWallet } =
        await IssuerSparkWalletTesting.initialize({
          options: config,
        });
      const { wallet: userWallet } = await SparkWalletTesting.initialize({
        options: config,
      });
      await issuerWallet.createToken({
        tokenName: `${name}MTR`,
        tokenTicker: "MTR",
        decimals: 0,
        isFreezable: false,
        maxSupply: 1_000_000n,
      });

      await issuerWallet.mintTokens(tokenAmount);

      const tokenIdentifier = await issuerWallet.getIssuerTokenIdentifier();
      await issuerWallet.transferTokens({
        tokenAmount,
        tokenIdentifier: tokenIdentifier!,
        receiverSparkAddress: await userWallet.getSparkAddress(),
      });

      const balanceObj = await userWallet.getBalance();
      const userBalance = filterTokenBalanceForTokenIdentifier(
        balanceObj?.tokenBalances,
        tokenIdentifier!,
      );
      expect(userBalance.balance).toBeGreaterThanOrEqual(tokenAmount);
    });

    it("should create, mint, and batchtransfer tokens", async () => {
      const tokenAmount: bigint = 999n;

      const { wallet: issuerWallet } =
        await IssuerSparkWalletTesting.initialize({
          options: config,
        });
      await issuerWallet.createToken({
        tokenName: `${name}MBN`,
        tokenTicker: "MBN",
        decimals: 0,
        isFreezable: false,
        maxSupply: 1_000_000n,
      });

      const { wallet: destinationWallet } = await SparkWalletTesting.initialize(
        {
          options: config,
        },
      );

      const { wallet: destinationWallet2 } =
        await SparkWalletTesting.initialize({
          options: config,
        });

      const { wallet: destinationWallet3 } =
        await SparkWalletTesting.initialize({
          options: config,
        });

      await issuerWallet.mintTokens(tokenAmount);
      const sharedIssuerBalance = await issuerWallet.getIssuerTokenBalance();
      expect(sharedIssuerBalance).toBeDefined();
      expect(sharedIssuerBalance.tokenIdentifier).toBeDefined();

      const tokenIdentifier = sharedIssuerBalance.tokenIdentifier!;
      const sourceBalanceBefore = sharedIssuerBalance.balance;

      await issuerWallet.batchTransferTokens([
        {
          tokenAmount: tokenAmount / 3n,
          tokenIdentifier,
          receiverSparkAddress: await destinationWallet.getSparkAddress(),
        },
        {
          tokenAmount: tokenAmount / 3n,
          tokenIdentifier,
          receiverSparkAddress: await destinationWallet2.getSparkAddress(),
        },
        {
          tokenAmount: tokenAmount / 3n,
          tokenIdentifier,
          receiverSparkAddress: await destinationWallet3.getSparkAddress(),
        },
      ]);

      const sourceBalanceAfter = (await issuerWallet.getIssuerTokenBalance())
        .balance;
      expect(sourceBalanceAfter).toEqual(sourceBalanceBefore - tokenAmount);

      const balanceObj = await destinationWallet.getBalance();
      const destinationBalance = filterTokenBalanceForTokenIdentifier(
        balanceObj?.tokenBalances,
        tokenIdentifier!,
      );
      expect(destinationBalance.balance).toEqual(tokenAmount / 3n);
      const balanceObj2 = await destinationWallet2.getBalance();
      const destinationBalance2 = filterTokenBalanceForTokenIdentifier(
        balanceObj2?.tokenBalances,
        tokenIdentifier!,
      );
      expect(destinationBalance2.balance).toEqual(tokenAmount / 3n);
      const balanceObj3 = await destinationWallet3.getBalance();
      const destinationBalance3 = filterTokenBalanceForTokenIdentifier(
        balanceObj3?.tokenBalances,
        tokenIdentifier!,
      );
      expect(destinationBalance3.balance).toEqual(tokenAmount / 3n);
    });

    it("should track token operations in monitoring", async () => {
      const tokenAmount: bigint = 1000n;

      const { wallet: issuerWallet } =
        await IssuerSparkWalletTesting.initialize({
          options: config,
        });

      const { wallet: userWallet } = await SparkWalletTesting.initialize({
        options: config,
      });

      await issuerWallet.createToken({
        tokenName: `${name}FRZ`,
        tokenTicker: "FRZ",
        decimals: 0,
        isFreezable: true,
        maxSupply: 100000n,
      });
      await issuerWallet.mintTokens(tokenAmount);
      const tokenIdentifier = await issuerWallet.getIssuerTokenIdentifier();
      const issuerPublicKey = await issuerWallet.getIdentityPublicKey();

      await issuerWallet.transferTokens({
        tokenAmount,
        tokenIdentifier: tokenIdentifier!,
        receiverSparkAddress: await userWallet.getSparkAddress(),
      });

      const userBalanceObj = await userWallet.getBalance();
      const userBalance = filterTokenBalanceForTokenIdentifier(
        userBalanceObj?.tokenBalances,
        tokenIdentifier!,
      );
      expect(userBalance.balance).toBeGreaterThanOrEqual(tokenAmount);

      const transactions = await issuerWallet.queryTokenTransactions({
        tokenIdentifiers: [tokenIdentifier!],
        ownerPublicKeys: [issuerPublicKey],
      });
      expect(transactions.length).toBeGreaterThanOrEqual(2);

      let mint_operation = 0;
      let transfer_operation = 0;
      transactions.forEach((transaction) => {
        if (transaction.tokenTransaction?.tokenInputs?.$case === "mintInput") {
          mint_operation++;
        } else if (
          transaction.tokenTransaction?.tokenInputs?.$case === "transferInput"
        ) {
          transfer_operation++;
        }
      });
      expect(mint_operation).toBeGreaterThanOrEqual(1);
      expect(transfer_operation).toBeGreaterThanOrEqual(1);
    });

    it("should correctly assign operation types for complete token lifecycle operations", async () => {
      const tokenAmount = 1000n;

      const { wallet: issuerWallet } =
        await IssuerSparkWalletTesting.initialize({
          options: config,
        });

      const { wallet: userWallet } = await SparkWalletTesting.initialize({
        options: config,
      });

      await issuerWallet.createToken({
        tokenName: `${name}LFC`,
        tokenTicker: "LFC",
        decimals: 0,
        isFreezable: false,
        maxSupply: 1_000_000n,
      });

      await issuerWallet.mintTokens(tokenAmount);

      const tokenIdentifier = await issuerWallet.getIssuerTokenIdentifier();
      const issuerPublicKey = await issuerWallet.getIdentityPublicKey();

      await issuerWallet.transferTokens({
        tokenAmount: 500n,
        tokenIdentifier: tokenIdentifier!,
        receiverSparkAddress: await userWallet.getSparkAddress(),
      });

      await userWallet.transferTokens({
        tokenAmount: 250n,
        tokenIdentifier: tokenIdentifier!,
        receiverSparkAddress: await issuerWallet.getSparkAddress(),
      });

      const BURN_ADDRESS = "02".repeat(33);

      await issuerWallet.burnTokens(250n);

      const transactions = await issuerWallet.queryTokenTransactions({
        tokenIdentifiers: [tokenIdentifier!],
        ownerPublicKeys: [issuerPublicKey],
      });

      const mintTransaction = transactions.find(
        (tx) => tx.tokenTransaction?.tokenInputs?.$case === "mintInput",
      );

      const transferTransaction = transactions.find(
        (tx) => tx.tokenTransaction?.tokenInputs?.$case === "transferInput",
      );

      const burnTransaction = transactions.find(
        (tx) =>
          tx.tokenTransaction?.tokenInputs?.$case === "transferInput" &&
          bytesToHex(tx.tokenTransaction?.tokenOutputs?.[0]?.ownerPublicKey) ===
            BURN_ADDRESS,
      );

      expect(mintTransaction).toBeDefined();
      expect(transferTransaction).toBeDefined();
      expect(burnTransaction).toBeDefined();
    });

    it("should create, mint, get all transactions, transfer tokens multiple times, get all transactions again, and check difference", async () => {
      const tokenAmount: bigint = 100n;

      const { wallet: issuerWallet } =
        await IssuerSparkWalletTesting.initialize({
          options: config,
        });

      const { wallet: userWallet } = await SparkWalletTesting.initialize({
        options: config,
      });

      await issuerWallet.createToken({
        tokenName: `${name}Transfer`,
        tokenTicker: "TTO",
        decimals: 0,
        isFreezable: false,
        maxSupply: 100000n,
      });

      const tokenIdentifier = await issuerWallet.getIssuerTokenIdentifier();

      await issuerWallet.mintTokens(tokenAmount);

      {
        const transactions = await issuerWallet.queryTokenTransactions({
          tokenIdentifiers: [tokenIdentifier!],
        });
        const amount_of_transactions = transactions.length;
        expect(amount_of_transactions).toEqual(1);
      }

      await issuerWallet.transferTokens({
        tokenAmount,
        tokenIdentifier: tokenIdentifier!,
        receiverSparkAddress: await userWallet.getSparkAddress(),
      });

      {
        const transactions = await issuerWallet.queryTokenTransactions({
          tokenIdentifiers: [tokenIdentifier!],
        });
        const amount_of_transactions = transactions.length;
        expect(amount_of_transactions).toEqual(2);
      }

      for (let index = 0; index < 100; ++index) {
        await issuerWallet.mintTokens(tokenAmount);
        await issuerWallet.transferTokens({
          tokenAmount,
          tokenIdentifier: tokenIdentifier!,
          receiverSparkAddress: await userWallet.getSparkAddress(),
        });
      } // 202 in total

      {
        const transactions = await issuerWallet.queryTokenTransactions({
          tokenIdentifiers: [tokenIdentifier!],
          pageSize: 10,
        });
        const amount_of_transactions = transactions.length;
        expect(amount_of_transactions).toEqual(10);
      }

      {
        let hashset_of_all_transactions: Set<String> = new Set();

        let pageSize = 10;
        let offset = 0;
        let page_num = 0;

        while (true) {
          const transactionsPage = await issuerWallet.queryTokenTransactions({
            tokenIdentifiers: [tokenIdentifier!],
            pageSize,
            offset,
          });

          if (transactionsPage.length === 0) {
            break;
          }

          if (offset === 0) {
            expect(transactionsPage.length).toEqual(pageSize);
          }

          for (let index = 0; index < transactionsPage.length; ++index) {
            const element = transactionsPage[index];
            if (element.tokenTransaction !== undefined) {
              const hash: String = bytesToHex(element.tokenTransactionHash);
              if (hashset_of_all_transactions.has(hash)) {
                expect(
                  `Duplicate found. Pagination is broken? Index of transaction: ${index} ; page №: ${page_num} ; page size: ${pageSize} ; hash_duplicate: ${hash}`,
                ).toEqual("");
              } else {
                hashset_of_all_transactions.add(hash);
              }
            } else {
              expect(
                `Transaction is undefined. Something is really wrong. Index of transaction: ${index} ; page №: ${page_num} ; page size: ${pageSize}`,
              ).toEqual("");
            }
          }

          // Prepare for next iteration.
          offset += transactionsPage.length;
          page_num += 1;
        }

        expect(hashset_of_all_transactions.size).toEqual(202);
      }
    });

    it("should mint token with 1 max supply without issue", async () => {
      const tokenAmount: bigint = 1n;
      const { wallet: issuerWallet } =
        await IssuerSparkWalletTesting.initialize({
          options: config,
        });

      await issuerWallet.createToken({
        tokenName: "MST",
        tokenTicker: "MST",
        decimals: 0,
        isFreezable: false,
        maxSupply: 1n,
      });
      await issuerWallet.mintTokens(tokenAmount);

      const tokenBalance = await issuerWallet.getIssuerTokenBalance();
      expect(tokenBalance.balance).toEqual(tokenAmount);
    });

    it("should be able to create a token with name of size equal to MAX_SYMBOL_SIZE", async () => {
      const { wallet: issuerWallet } =
        await IssuerSparkWalletTesting.initialize({
          options: config,
        });

      await issuerWallet.createToken({
        tokenName: "MST",
        tokenTicker: "TESTAA",
        decimals: 0,
        isFreezable: false,
        maxSupply: 1n,
      });
    });

    it("should be able to anounce a token with name of size equal to MAX_SYMBOL_SIZE", async () => {
      const { wallet: issuerWallet } =
        await IssuerSparkWalletTesting.initialize({
          options: config,
        });

      await fundAndAnnounce(issuerWallet, 100000n, 0, "MST", "TESTAA", false);
    });

    it("should be able to create a token with symbol of size equal to MAX_NAME_SIZE", async () => {
      const { wallet: issuerWallet } =
        await IssuerSparkWalletTesting.initialize({
          options: config,
        });

      await issuerWallet.createToken({
        tokenName: "ABCDEFGHIJKLMNOPQ",
        tokenTicker: "MQS",
        decimals: 0,
        isFreezable: false,
        maxSupply: 1n,
      });
    });

    it("should be able to announce a token with symbol of size equal to MAX_NAME_SIZE", async () => {
      const { wallet: issuerWallet } =
        await IssuerSparkWalletTesting.initialize({
          options: config,
        });

      await fundAndAnnounce(
        issuerWallet,
        100000n,
        0,
        "ABCDEFGHIJKLMNOPQ",
        "MQS",
        false,
      );
    });

    it("should create, mint, freeze, and unfreeze tokens", async () => {
      const tokenAmount: bigint = 1000n;
      const { wallet: issuerWallet } =
        await IssuerSparkWalletTesting.initialize({
          options: config,
        });

      await issuerWallet.createToken({
        tokenName: `${name}FRZ`,
        tokenTicker: "FRZ",
        decimals: 0,
        isFreezable: true,
        maxSupply: 100000n,
      });
      await issuerWallet.mintTokens(tokenAmount);

      // Check issuer balance after minting
      const issuerBalanceObjAfterMint =
        await issuerWallet.getIssuerTokenBalance();
      expect(issuerBalanceObjAfterMint).toBeDefined();
      expect(issuerBalanceObjAfterMint.tokenIdentifier).toBeDefined();

      const issuerBalanceAfterMint = issuerBalanceObjAfterMint.balance;
      const tokenIdentifier = issuerBalanceObjAfterMint.tokenIdentifier!;

      expect(issuerBalanceAfterMint).toEqual(tokenAmount);

      const { wallet: userWallet } = await SparkWalletTesting.initialize({
        options: config,
      });
      const userSparkAddress = await userWallet.getSparkAddress();

      await issuerWallet.transferTokens({
        tokenAmount,
        tokenIdentifier,
        receiverSparkAddress: userSparkAddress,
      });
      const issuerBalanceAfterTransfer = (
        await issuerWallet.getIssuerTokenBalance()
      ).balance;
      expect(issuerBalanceAfterTransfer).toEqual(0n);

      const userBalanceObj = await userWallet.getBalance();
      const userBalanceAfterTransfer = filterTokenBalanceForTokenIdentifier(
        userBalanceObj?.tokenBalances,
        tokenIdentifier!,
      );
      expect(userBalanceAfterTransfer.balance).toEqual(tokenAmount);

      // Freeze tokens
      const freezeResponse = await issuerWallet.freezeTokens(userSparkAddress);
      expect(freezeResponse.impactedOutputIds.length).toBeGreaterThan(0);
      expect(freezeResponse.impactedTokenAmount).toEqual(tokenAmount);

      // Unfreeze tokens
      const unfreezeResponse =
        await issuerWallet.unfreezeTokens(userSparkAddress);
      expect(unfreezeResponse.impactedOutputIds.length).toBeGreaterThan(0);
      expect(unfreezeResponse.impactedTokenAmount).toEqual(tokenAmount);
    });

    it("should create, mint and burn tokens", async () => {
      const tokenAmount: bigint = 200n;

      const { wallet: issuerWallet } =
        await IssuerSparkWalletTesting.initialize({
          options: config,
        });
      await issuerWallet.createToken({
        tokenName: `${name}MBN`,
        tokenTicker: "MBN",
        decimals: 0,
        isFreezable: false,
        maxSupply: 1_000_000n,
      });

      await issuerWallet.mintTokens(tokenAmount);
      const issuerTokenBalance = (await issuerWallet.getIssuerTokenBalance())
        .balance;
      expect(issuerTokenBalance).toBeGreaterThanOrEqual(tokenAmount);

      await issuerWallet.burnTokens(tokenAmount);

      const issuerTokenBalanceAfterBurn = (
        await issuerWallet.getIssuerTokenBalance()
      ).balance;
      expect(issuerTokenBalanceAfterBurn).toEqual(
        issuerTokenBalance - tokenAmount,
      );
    });

    it("should complete a full token lifecycle - create, mint, transfer, return, burn", async () => {
      const tokenAmount: bigint = 1000n;

      const { wallet: issuerWallet } =
        await IssuerSparkWalletTesting.initialize({
          options: config,
        });
      await issuerWallet.createToken({
        tokenName: `${name}LFC`,
        tokenTicker: "LFC",
        decimals: 0,
        isFreezable: false,
        maxSupply: 1_000_000n,
      });

      const { wallet: userWallet } = await SparkWalletTesting.initialize({
        options: config,
      });

      const initialBalance = (await issuerWallet.getIssuerTokenBalance())
        .balance;

      await issuerWallet.mintTokens(tokenAmount);
      const issuerBalanceObjAfterMint =
        await issuerWallet.getIssuerTokenBalance();
      expect(issuerBalanceObjAfterMint).toBeDefined();
      const issuerBalanceAfterMint = issuerBalanceObjAfterMint.balance;
      expect(issuerBalanceAfterMint).toEqual(initialBalance + tokenAmount);
      expect(issuerBalanceObjAfterMint.tokenIdentifier).toBeDefined();
      const tokenIdentifier = issuerBalanceObjAfterMint.tokenIdentifier!;
      const userSparkAddress = await userWallet.getSparkAddress();

      await issuerWallet.transferTokens({
        tokenAmount,
        tokenIdentifier,
        receiverSparkAddress: userSparkAddress,
      });

      const issuerBalanceAfterTransfer = (
        await issuerWallet.getIssuerTokenBalance()
      ).balance;
      expect(issuerBalanceAfterTransfer).toEqual(initialBalance);

      const userBalanceObj = await userWallet.getBalance();
      const userBalanceAfterTransfer = filterTokenBalanceForTokenIdentifier(
        userBalanceObj?.tokenBalances,
        tokenIdentifier!,
      );
      expect(userBalanceAfterTransfer.balance).toEqual(tokenAmount);

      await userWallet.transferTokens({
        tokenIdentifier,
        tokenAmount,
        receiverSparkAddress: await issuerWallet.getSparkAddress(),
      });

      const userBalanceObjAfterTransferBack = await userWallet.getBalance();
      const userBalanceAfterTransferBack = filterTokenBalanceForTokenIdentifier(
        userBalanceObjAfterTransferBack?.tokenBalances,
        tokenIdentifier!,
      );

      expect(userBalanceAfterTransferBack.balance).toEqual(0n);

      const issuerTokenBalance = (await issuerWallet.getIssuerTokenBalance())
        .balance;
      expect(issuerTokenBalance).toEqual(initialBalance + tokenAmount);

      await issuerWallet.burnTokens(tokenAmount);

      const issuerTokenBalanceAfterBurn = (
        await issuerWallet.getIssuerTokenBalance()
      ).balance;
      expect(issuerTokenBalanceAfterBurn).toEqual(initialBalance);
    });
  },
);

async function fundAndAnnounce(
  wallet: IssuerSparkWallet,
  maxSupply: bigint = 100000n,
  decimals: number = 0,
  tokenName: string = "TestToken1",
  tokenSymbol: string = "TT1",
  isFreezable: boolean = false,
) {
  // Faucet funds to the Issuer wallet because announcing a token
  // requires ownership of an L1 UTXO.
  const faucet = BitcoinFaucet.getInstance();
  const l1WalletPubKey = await wallet.getTokenL1Address();
  await faucet.sendToAddress(l1WalletPubKey, 100_000n);
  await faucet.mineBlocks(6);

  await new Promise((resolve) => setTimeout(resolve, 3000));

  try {
    const response = await wallet.announceTokenL1(
      tokenName,
      tokenSymbol,
      decimals,
      maxSupply,
      isFreezable,
    );
    console.log("Announce token response:", response);
  } catch (error: any) {
    console.error("Error when announcing token on L1:", error);
    throw error;
  }
  await faucet.mineBlocks(2);

  const SECONDS = 1000;
  await new Promise((resolve) => setTimeout(resolve, 3 * SECONDS));
}
