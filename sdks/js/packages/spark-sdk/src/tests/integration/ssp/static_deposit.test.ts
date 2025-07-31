import {
  SparkWalletTesting,
  initWallet,
} from "../../utils/spark-testing-wallet.js";
import { ValidationError } from "../../../errors/types.js";
import { bytesToHex } from "@noble/hashes/utils";
import { BitcoinFaucet } from "../../utils/test-faucet.js";

export const DEPOSIT_AMOUNT = 10000n;
const SECOND_DEPOSIT_AMOUNT = 20000n;
const THIRD_DEPOSIT_AMOUNT = 30000n;

describe("SSP static deposit address integration", () => {
  // it("should claim deposits to a static deposit address", async () => {
  //   console.log("Initializing user wallet for static deposit claim test...");
  //   const faucet = BitcoinFaucet.getInstance();

  //   const { wallet: userWallet } = await SparkWalletTesting.initialize(
  //     {
  //       options: {
  //         network: "LOCAL",
  //       },
  //     },
  //     false,
  //   );

  //   const depositAddress = await userWallet.getStaticDepositAddress();
  //   expect(depositAddress).toBeDefined();

  //   const signedTx = await faucet.sendToAddress(depositAddress, DEPOSIT_AMOUNT);

  //   expect(signedTx).toBeDefined();
  //   const transactionId = signedTx.id;
  //   const outputs = Array.from({ length: signedTx.outputsLength }, (_, i) => ({
  //     output: signedTx.getOutput(i),
  //     index: i,
  //   }));
  //   const match = outputs.find(
  //     ({ output }) => output.amount === DEPOSIT_AMOUNT,
  //   );
  //   const vout = match ? match.index : undefined;

  //   // Wait for the transaction to be mined
  //   await faucet.mineBlocks(6);

  //   console.log("Fetching claim quote for static deposit...");
  //   const quote = await userWallet.getClaimStaticDepositQuote(
  //     transactionId,
  //     vout!,
  //   );

  //   console.log("Attempting to claim static deposit...");
  //   await userWallet.claimStaticDeposit({
  //     transactionId: transactionId,
  //     creditAmountSats: quote.creditAmountSats,
  //     sspSignature: quote.signature,
  //   });
  //   await new Promise((resolve) => setTimeout(resolve, 40000));

  //   console.log("Fetching wallet balance after claim...");
  //   const { balance } = await userWallet.getBalance();

  //   expect(balance).toBe(BigInt(quote.creditAmountSats));

  //   // Test depositing money to the same address and second time and claiming.
  //   const signedTx2 = await faucet.sendToAddress(
  //     depositAddress,
  //     SECOND_DEPOSIT_AMOUNT,
  //   );
  //   const transactionId2 = signedTx2.id;
  //   // Wait for the transaction to be mined
  //   await faucet.mineBlocks(6);

  //   // Test claiming and getting the quote without passing in the output index.
  //   const quote2 = await userWallet.getClaimStaticDepositQuote(transactionId2);

  //   const quoteAmount2 = quote2!.creditAmountSats;
  //   const sspSignature2 = quote2!.signature;

  //   await userWallet.claimStaticDeposit({
  //     transactionId: transactionId2,
  //     creditAmountSats: quoteAmount2,
  //     sspSignature: sspSignature2,
  //   });

  //   await new Promise((resolve) => setTimeout(resolve, 1000));

  //   const { balance: balance2 } = await userWallet.getBalance();
  //   expect(balance2).toBe(balance + BigInt(quoteAmount2));

  //   // Test depositing money to the same address and test claim with max fee flow.
  //   const signedTx3 = await faucet.sendToAddress(
  //     depositAddress,
  //     THIRD_DEPOSIT_AMOUNT,
  //   );
  //   const transactionId3 = signedTx3.id;
  //   // Wait for the transaction to be mined
  //   await faucet.mineBlocks(6);

  //   // Get quote so we can calculate the expected balance. Not needed for actual flow.
  //   const quote3 = await userWallet.getClaimStaticDepositQuote(transactionId3);

  //   const quoteAmount3 = quote3!.creditAmountSats;

  //   await userWallet.claimStaticDepositWithMaxFee({
  //     transactionId: transactionId3,
  //     maxFee: 1000,
  //   });

  //   await new Promise((resolve) => setTimeout(resolve, 1000));

  //   const { balance: balance3 } = await userWallet.getBalance();
  //   expect(balance3).toBe(
  //     BigInt(quote.creditAmountSats + quoteAmount2 + quoteAmount3),
  //   );

  //   // Get transfers should include static deposit transfers.
  //   const transfers = await userWallet.getTransfers();
  //   expect(transfers.transfers.length).toBe(3);
  // }, 60000);

  // it("should create a refund transaction", async () => {
  //   const faucet = BitcoinFaucet.getInstance();

  //   const { wallet: userWallet } = await SparkWalletTesting.initialize(
  //     {
  //       options: {
  //         network: "LOCAL",
  //       },
  //     },
  //     false,
  //   );

  //   const depositAddress = await userWallet.getStaticDepositAddress();
  //   expect(depositAddress).toBeDefined();

  //   const signedTx = await faucet.sendToAddress(depositAddress, DEPOSIT_AMOUNT);

  //   // Wait for the transaction to be mined
  //   await faucet.mineBlocks(6);

  //   expect(signedTx).toBeDefined();

  //   const transactionId = signedTx.id;

  //   let vout: number | undefined;

  //   for (let i = 0; i < signedTx.outputsLength; i++) {
  //     const output = signedTx.getOutput(i);
  //     if (output.amount === DEPOSIT_AMOUNT) {
  //       vout = i;
  //       break;
  //     }
  //   }

  //   const refundAddress = await faucet.getNewAddress();

  //   const refundTx = await userWallet.refundStaticDeposit({
  //     depositTransactionId: transactionId,
  //     destinationAddress: refundAddress,
  //     satsPerVbyteFee: 2,
  //   });

  //   expect(refundTx).toBeDefined();

  //   // Calling it again should create a new transaction.
  //   const refundTx2 = await userWallet.refundStaticDeposit({
  //     depositTransactionId: transactionId,
  //     destinationAddress: refundAddress,
  //     outputIndex: vout!,
  //     satsPerVbyteFee: 2,
  //   });

  //   expect(refundTx2).toBeDefined();

  //   expect(refundTx).not.toBe(refundTx2);
  // }, 60000);

  // it("Claim, then try to refund.", async () => {
  //   console.log("Initializing wallet for claim and refund test...");
  //   const {
  //     wallet: userWallet,
  //     depositAddress,
  //     signedTx,
  //     vout,
  //     faucet,
  //   } = await initWallet(DEPOSIT_AMOUNT, "LOCAL");

  //   // Wait for the transaction to be mined
  //   await faucet.mineBlocks(6);

  //   expect(signedTx).toBeDefined();

  //   const transactionId = signedTx.id;

  //   const quote = await userWallet.getClaimStaticDepositQuote(
  //     transactionId,
  //     vout!,
  //   );

  //   const quoteAmount = quote!.creditAmountSats;
  //   const sspSignature = quote!.signature;

  //   console.log("Attempting to claim static deposit...");
  //   await userWallet.claimStaticDeposit({
  //     transactionId,
  //     creditAmountSats: quoteAmount,
  //     sspSignature,
  //     outputIndex: vout!,
  //   });

  //   await new Promise((resolve) => setTimeout(resolve, 30000));

  //   console.log("Fetching wallet balance after claim...");
  //   const { balance } = await userWallet.getBalance();
  //   expect(balance).toBe(BigInt(quoteAmount));

  //   console.log(`Alice balance: ${balance}`);

  //   console.log("Initiating transfer to Spark address...");
  //   const sparkAddress = await userWallet.getSparkAddress();
  //   const transfer = await userWallet.transfer({
  //     amountSats: Number(balance),
  //     receiverSparkAddress: sparkAddress,
  //   });

  //   expect(transfer).toBeDefined();

  //   await new Promise((resolve) => setTimeout(resolve, 1000));

  //   // Try to refund the deposit after claiming and transfer
  //   console.log("Attempting refund of claimed deposit...");
  //   await expect(
  //     userWallet.refundStaticDeposit({
  //       depositTransactionId: transactionId,
  //       destinationAddress: depositAddress,
  //       fee: 301,
  //     }),
  //   ).rejects.toMatch(
  //     "Spark error: Failed to aggregate frost: InvalidSignatureShare",
  //   );
  // }, 600000);

  it("should reject claim quote from a different wallet", async () => {
    console.log("Initializing Alice's wallet for cross-wallet claim test...");
    const {
      wallet: alice,
      depositAddress,
      signedTx,
      vout,
      faucet,
    } = await initWallet(DEPOSIT_AMOUNT, "LOCAL");

    const { wallet: bob } = await SparkWalletTesting.initialize(
      {
        options: {
          network: "LOCAL",
        },
      },
      false,
    );

    // Wait for the transaction to be mined
    await faucet.mineBlocks(6);

    expect(signedTx).toBeDefined();

    const transactionId = signedTx.id;

    await new Promise((resolve) => setTimeout(resolve, 10000));

    const bobDepositAddress = await bob.getStaticDepositAddress();
    expect(bobDepositAddress).toBeDefined();

    console.log(`Bob's static depost address: ${bobDepositAddress}`);

    // Test without vout
    console.log(
      "Expecting error when Bob tries to get claim quote without vout...",
    );
    await expect(bob.getClaimStaticDepositQuote(transactionId)).rejects.toThrow(
      "No static deposit address found",
    );

    // Test with vout
    console.log("Fetching claim quote for Bob and Alice with vout...");
    const bobQuote = await bob.getClaimStaticDepositQuote(transactionId, vout!);

    const aliceQuote = await alice.getClaimStaticDepositQuote(
      transactionId,
      vout!,
    );

    expect(bobQuote.creditAmountSats).toEqual(aliceQuote.creditAmountSats);
    expect(bobQuote.transactionId).toEqual(aliceQuote.transactionId);
    expect(bobQuote.signature).toEqual(aliceQuote.signature);

    // Test claim with different wallet
    console.log("Expecting error when Bob tries to claim Alice's deposit...");
    await expect(
      bob.claimStaticDeposit({
        transactionId,
        creditAmountSats: bobQuote.creditAmountSats,
        sspSignature: bobQuote.signature,
        outputIndex: vout!,
      }),
    ).rejects.toThrow("InvalidInputException");
  }, 600000);

  it("should reject claim with fake SSP signature", async () => {
    console.log("Initializing wallet for fake SSP signature test...");
    const {
      wallet: userWallet,
      depositAddress,
      signedTx,
      vout,
      faucet,
    } = await initWallet(DEPOSIT_AMOUNT, "LOCAL");

    // Wait for the transaction to be mined
    await faucet.mineBlocks(6);

    const transactionId = signedTx.id;

    console.log("Fetching claim quote for static deposit...");
    const quote = await userWallet.getClaimStaticDepositQuote(
      transactionId,
      vout!,
    );

    await new Promise((resolve) => setTimeout(resolve, 10000));

    const quoteAmount = quote!.creditAmountSats;

    // Generate a fake signature (64 bytes of random data to simulate a signature)
    const fakeSignature = new Uint8Array(64);
    crypto.getRandomValues(fakeSignature);
    console.log("Expecting error when claiming with fake signature...");
    await expect(
      userWallet.claimStaticDeposit({
        transactionId,
        creditAmountSats: quoteAmount,
        sspSignature: bytesToHex(fakeSignature),
        outputIndex: vout!,
      }),
    ).rejects.toThrow(
      'Request ClaimStaticDeposit failed. [{"message":"Something went wrong."',
    );
  }, 600000);

  it("should reject claiming the same deposit twice", async () => {
    console.log("Initializing wallet for double-claim test...");
    const {
      wallet: userWallet,
      depositAddress,
      signedTx,
      vout,
      faucet,
    } = await initWallet(DEPOSIT_AMOUNT, "LOCAL");

    // Wait for the transaction to be mined
    await faucet.mineBlocks(6);

    const transactionId = signedTx.id;

    console.log("Fetching claim quote for static deposit...");
    const quote = await userWallet.getClaimStaticDepositQuote(
      transactionId,
      vout!,
    );

    await new Promise((resolve) => setTimeout(resolve, 10000));

    const quoteAmount = quote!.creditAmountSats;
    const sspSignature = quote!.signature;

    console.log("Attempting to claim static deposit for the first time...");
    const outputs = await userWallet.claimStaticDeposit({
      transactionId,
      creditAmountSats: quoteAmount,
      sspSignature,
      outputIndex: vout!,
    });

    await new Promise((resolve) => setTimeout(resolve, 30000));

    expect(outputs).toBeDefined();

    console.log(
      "Expecting error when attempting to claim the same deposit twice...",
    );
    await expect(
      userWallet.claimStaticDeposit({
        transactionId,
        creditAmountSats: quoteAmount,
        sspSignature,
        outputIndex: vout!,
      }),
    ).rejects.toThrow("UTXO is spent or not found.");
  }, 600000);

  // it("should reject second refund attempt on already refunded deposit", async () => {
  //   console.log("Initializing wallet for double-refund test...");
  //   const {
  //     wallet: userWallet,
  //     depositAddress,
  //     signedTx,
  //     vout,
  //     faucet,
  //   } = await initWallet(DEPOSIT_AMOUNT, "LOCAL");

  //   // Wait for the transaction to be mined
  //   await faucet.mineBlocks(6);

  //   const transactionId = signedTx.id;

  //   // First refund attempt should succeed
  //   console.log("Attempting first refund of static deposit...");
  //   const txHex = await userWallet.refundStaticDeposit({
  //     depositTransactionId: transactionId,
  //     outputIndex: vout!,
  //     destinationAddress: depositAddress,
  //     fee: 301,
  //   });

  //   await new Promise((resolve) => setTimeout(resolve, 10000));

  //   // Second refund attempt should fail
  //   console.log(
  //     "Expecting error when attempting a second refund on same deposit...",
  //   );
  //   await expect(
  //     userWallet.refundStaticDeposit({
  //       depositTransactionId: transactionId,
  //       outputIndex: vout!,
  //       destinationAddress: depositAddress,
  //       fee: 301,
  //     }),
  //   ).rejects.toMatch("InvalidSignatureShare"); // Returns a string, not an error
  // }, 600000);

  // it("should fail due to low fee", async () => {
  //   console.log("Initializing wallet for low-fee refund test...");
  //   const {
  //     wallet: userWallet,
  //     depositAddress,
  //     signedTx,
  //     vout,
  //     faucet,
  //   } = await initWallet(DEPOSIT_AMOUNT, "LOCAL");

  //   // Wait for the transaction to be mined
  //   await faucet.mineBlocks(6);

  //   const transactionId = signedTx.id;

  //   expect(transactionId).toBeDefined();

  //   // refund attempt should fail due to low fee
  //   console.log("Expecting error when attempting refund with too low fee...");
  //   await expect(
  //     userWallet.refundStaticDeposit({
  //       depositTransactionId: transactionId,
  //       outputIndex: vout!,
  //       destinationAddress: depositAddress,
  //       fee: 300,
  //     }),
  //   ).rejects.toMatchObject({
  //     name: ValidationError.name,
  //     message: expect.stringContaining("Fee must be greater than 300"),
  //     context: expect.objectContaining({
  //       field: "fee",
  //       value: 300,
  //     }),
  //   });

  //   console.log("Attempting refund with sufficient fee...");
  //   await userWallet.refundStaticDeposit({
  //     depositTransactionId: transactionId,
  //     outputIndex: vout!,
  //     destinationAddress: depositAddress,
  //     fee: 301,
  //   });
  // }, 600000);
});
