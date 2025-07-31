import { IssuerSparkWallet as BaseIssuerSparkWallet } from "./issuer-spark-wallet.js";
import {
  initializeTracerEnv as initializeTracerEnvBrowser,
  type SparkWalletProps,
} from "@buildonspark/spark-sdk";

export class IssuerSparkWalletBrowser extends BaseIssuerSparkWallet {
  public static async initialize({
    mnemonicOrSeed,
    accountNumber,
    signer,
    options,
  }: SparkWalletProps) {
    const wallet = new IssuerSparkWalletBrowser(options, signer);
    wallet.initializeTracer(wallet);

    const initResponse = await wallet.initWallet(mnemonicOrSeed, accountNumber);

    return {
      wallet,
      ...initResponse,
    };
  }

  protected initializeTracerEnv({
    spanProcessors,
    traceUrls,
  }: Parameters<BaseIssuerSparkWallet["initializeTracerEnv"]>[0]) {
    initializeTracerEnvBrowser({ spanProcessors, traceUrls });
  }
}

export { IssuerSparkWalletBrowser as IssuerSparkWallet };
