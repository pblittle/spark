// @ts-nocheck
import { describe, expect, it } from "@jest/globals";
import { bytesToHex } from "@noble/curves/abstract/utils";
import { ValidationError } from "../../errors/types.js";
import { getTxFromRawTxBytes, getTxId } from "../../utils/bitcoin.js";
import { Network } from "../../utils/network.js";
import { DEFAULT_FEE_SATS } from "../../utils/transaction.js";
import { SparkWalletTesting } from "../utils/spark-testing-wallet.js";

describe("Tree Creation", () => {
  it.skip("test tree creation address generation", async () => {
    const wallet = new SparkWalletTesting({ network: Network.LOCAL });
    await wallet.initWallet();

    const pubKey = await wallet.getSigner().generatePublicKey();

    const depositResp = await wallet.generateDepositAddress();

    expect(depositResp.depositAddress).toBeDefined();

    const dummyTx = createDummyTx({
      address: depositResp.depositAddress!.address,
      amountSats: 65536n + DEFAULT_FEE_SATS,
    });

    const depositTxHex = bytesToHex(dummyTx.tx);
    const depositTx = getTxFromRawTxBytes(dummyTx.tx);

    const vout = 0;
    const txid = getTxId(depositTx);
    if (!txid) {
      throw new ValidationError("Transaction ID not found", {
        field: "txid",
        value: depositTx,
      });
    }

    const treeResp = await wallet.generateDepositAddressForTree(
      vout,
      pubKey,
      depositTx,
    );

    const treeNodes = await wallet.createTree(vout, treeResp, true, depositTx);
  }, 30000);
});
