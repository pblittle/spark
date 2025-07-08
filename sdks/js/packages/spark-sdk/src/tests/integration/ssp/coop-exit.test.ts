import { describe, expect, it } from "@jest/globals";
import { ExitSpeed } from "../../../types/index.js";
import { SparkWalletTesting } from "../../utils/spark-testing-wallet.js";
import { BitcoinFaucet } from "../../utils/test-faucet.js";

const DEPOSIT_AMOUNT = 10_000n;

describe("SSP coop exit integration", () => {
  it("should estimate coop exit fee", async () => {
    const faucet = BitcoinFaucet.getInstance();

    const { wallet: userWallet } = await SparkWalletTesting.initialize(
      {
        options: {
          network: "LOCAL",
        },
      },
      false,
    );

    const depositAddress = await userWallet.getSingleUseDepositAddress();
    expect(depositAddress).toBeDefined();

    const signedTx = await faucet.sendToAddress(depositAddress, DEPOSIT_AMOUNT);
    expect(signedTx).toBeDefined();
    await faucet.mineBlocks(6);

    await userWallet.claimDeposit(signedTx.id);

    await new Promise((resolve) => setTimeout(resolve, 1000));

    const { balance } = await userWallet.getBalance();
    expect(balance).toBe(DEPOSIT_AMOUNT);

    const withdrawalAddress = await faucet.getNewAddress();

    const feeEstimate = await userWallet.getWithdrawalFeeQuote({
      amountSats: Number(DEPOSIT_AMOUNT),
      withdrawalAddress,
    });

    expect(feeEstimate).toBeDefined();
    expect(feeEstimate?.l1BroadcastFeeFast).toBeDefined();
    expect(feeEstimate?.l1BroadcastFeeFast).toBeGreaterThan(0);
    expect(feeEstimate?.userFeeFast).toBeDefined();
    expect(feeEstimate?.userFeeFast).toBeGreaterThan(0);

    expect(feeEstimate?.l1BroadcastFeeMedium).toBeDefined();
    expect(feeEstimate?.l1BroadcastFeeMedium).toBeGreaterThan(0);
    expect(feeEstimate?.userFeeMedium).toBeDefined();
    expect(feeEstimate?.userFeeMedium).toBeGreaterThan(0);

    expect(feeEstimate?.l1BroadcastFeeSlow).toBeDefined();
    expect(feeEstimate?.l1BroadcastFeeSlow).toBeGreaterThan(0);
    expect(feeEstimate?.userFeeSlow).toBeDefined();
    expect(feeEstimate?.userFeeSlow).toBeGreaterThan(0);
  }, 60000);

  it("should complete coop exit without deducting fees from withdrawal amount", async () => {
    const faucet = BitcoinFaucet.getInstance();

    const { wallet: userWallet } = await SparkWalletTesting.initialize(
      {
        options: {
          network: "LOCAL",
        },
      },
      false,
    );

    const depositAddress = await userWallet.getSingleUseDepositAddress();
    expect(depositAddress).toBeDefined();

    const signedTx = await faucet.sendToAddress(depositAddress, DEPOSIT_AMOUNT);
    expect(signedTx).toBeDefined();
    await faucet.mineBlocks(6);

    await userWallet.claimDeposit(signedTx.id);

    await new Promise((resolve) => setTimeout(resolve, 1000));

    const { balance } = await userWallet.getBalance();
    expect(balance).toBe(DEPOSIT_AMOUNT);

    const withdrawalAddress = await faucet.getNewAddress();

    const feeQuote = await userWallet.getWithdrawalFeeQuote({
      amountSats: 5000,
      withdrawalAddress,
    });

    expect(feeQuote).toBeDefined();

    const coopExit = await userWallet.withdraw({
      amountSats: 5000,
      onchainAddress: withdrawalAddress,
      feeQuote: feeQuote!,
      exitSpeed: ExitSpeed.FAST,
      deductFeeFromWithdrawalAmount: false,
    });

    const fee =
      (coopExit?.l1BroadcastFee?.originalValue ?? 0) +
      (coopExit?.fee?.originalValue ?? 0);

    expect(fee).toBeGreaterThan(0);

    const { balance: balanceAfter } = await userWallet.getBalance();

    expect(balanceAfter).toBe(DEPOSIT_AMOUNT - 5000n - BigInt(fee));
    expect(coopExit).toBeDefined();
    expect(coopExit?.coopExitTxid).toBeDefined();

    await faucet.mineBlocks(6);

    const deposit = await userWallet.claimDeposit(coopExit!.coopExitTxid);

    await new Promise((resolve) => setTimeout(resolve, 1000));

    expect(deposit).toBeDefined();
    expect(deposit?.reduce((acc, leaf) => acc + leaf.value, 0)).toBe(5000);

    const { balance: balance2 } = await userWallet.getBalance();

    expect(balance2).toBe(DEPOSIT_AMOUNT - BigInt(fee));
  }, 60000);
});
