import { SparkWallet as BaseSparkWallet } from "./spark-wallet.js";
import { NodeTracerProvider } from "@opentelemetry/sdk-trace-node";
import { AsyncLocalStorageContextManager } from "@opentelemetry/context-async-hooks";
import { W3CTraceContextPropagator } from "@opentelemetry/core";
import { registerInstrumentations } from "@opentelemetry/instrumentation";
import { UndiciInstrumentation } from "@opentelemetry/instrumentation-undici";
import {
  ConsoleSpanExporter,
  SimpleSpanProcessor,
} from "@opentelemetry/sdk-trace-base";
import { SparkWalletProps } from "./types.js";

export class SparkWalletNodeJS extends BaseSparkWallet {
  public static async initialize({
    mnemonicOrSeed,
    accountNumber,
    signer,
    options,
  }: SparkWalletProps) {
    const wallet = new SparkWalletNodeJS(options, signer);
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
  }: Parameters<BaseSparkWallet["initializeTracerEnv"]>[0]) {
    initializeTracerEnvNodeJS({ spanProcessors, traceUrls });
  }
}

export function initializeTracerEnvNodeJS({
  spanProcessors,
  traceUrls,
}: Parameters<BaseSparkWallet["initializeTracerEnv"]>[0]) {
  const provider = new NodeTracerProvider({ spanProcessors });
  provider.register({
    contextManager: new AsyncLocalStorageContextManager(),
    propagator: new W3CTraceContextPropagator(),
  });

  registerInstrumentations({
    instrumentations: [
      new UndiciInstrumentation({
        requestHook: (span, request) => {
          console.log("tmp in Node requestHook", span, request);
        },
        ignoreRequestHook: (request) => {
          /* Since we're wrapping global fetch we should be careful to avoid
               adding headers or causing errors for unrelated requests */
          try {
            return !traceUrls.some((prefix) =>
              request.origin.startsWith(prefix),
            );
          } catch {
            return true;
          }
        },
      }),
    ],
  });
}

export {
  SparkWalletNodeJS as SparkWallet,
  initializeTracerEnvNodeJS as initializeTracerEnv,
};
