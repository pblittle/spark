import { IssuerSparkWallet as BaseIssuerSparkWallet } from "./issuer-spark-wallet.js";
import {
  initializeTracerEnv as initializeTracerEnvNodeJS,
  type SparkWalletProps,
} from "@buildonspark/spark-sdk";

export class IssuerSparkWalletNodeJS extends BaseIssuerSparkWallet {
  public static async initialize({
    mnemonicOrSeed,
    accountNumber,
    signer,
    options,
  }: SparkWalletProps) {
    const wallet = new IssuerSparkWalletNodeJS(options, signer);
    wallet.initializeTracer(wallet);

    if (options && options.signerWithPreExistingKeys) {
      await wallet.initWalletWithoutSeed();

      return {
        wallet,
      };
    }

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
    initializeTracerEnvNodeJS({ spanProcessors, traceUrls });
  }
}

export { IssuerSparkWalletNodeJS as IssuerSparkWallet };
