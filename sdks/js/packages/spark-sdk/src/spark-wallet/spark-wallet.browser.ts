import { SparkWallet as BaseSparkWallet } from "./spark-wallet.js";
import {
  ConsoleSpanExporter,
  SimpleSpanProcessor,
  SpanProcessor,
  WebTracerProvider,
} from "@opentelemetry/sdk-trace-web";
import { registerInstrumentations } from "@opentelemetry/instrumentation";
import { FetchInstrumentation } from "@opentelemetry/instrumentation-fetch";
import { W3CTraceContextPropagator } from "@opentelemetry/core";
import { propagation } from "@opentelemetry/api";
import { SparkWalletProps } from "../spark-wallet/types.js";
import type { ConfigOptions } from "../services/wallet-config.js";
import type { SparkSigner } from "../signer/signer.js";

export class SparkWalletBrowser extends BaseSparkWallet {
  public static async initialize({
    mnemonicOrSeed,
    accountNumber,
    signer,
    options,
  }: SparkWalletProps) {
    const wallet = new SparkWalletBrowser(options, signer);
    wallet.initializeTracer(wallet);

    const initResponse = await wallet.initWallet(mnemonicOrSeed, accountNumber);

    return {
      wallet,
      ...initResponse,
    };
  }

  protected initializeTracerEnv({
    spanProcessors,
  }: Parameters<BaseSparkWallet["initializeTracerEnv"]>[0]) {
    const provider = new WebTracerProvider({ spanProcessors });
    provider.register();

    propagation.setGlobalPropagator(new W3CTraceContextPropagator());

    const otelTraceUrls = this.getOtelTraceUrls();
    registerInstrumentations({
      instrumentations: [
        new FetchInstrumentation({
          ignoreUrls: [
            /* Since we're wrapping global fetch we should be careful to avoid
               adding headers for unrelated requests */
            new RegExp(
              `^(?!(${otelTraceUrls
                .map((p) => p.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"))
                .join("|")}))`,
            ),
          ],
          propagateTraceHeaderCorsUrls: /.*/,
        }),
      ],
    });
  }
}

export { SparkWalletBrowser as SparkWallet };
