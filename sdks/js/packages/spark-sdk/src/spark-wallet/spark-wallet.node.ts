import { Tracer } from "@opentelemetry/api";
import { SparkWallet as BaseSparkWallet } from "./spark-wallet.js";
import type { InitWalletResponse } from "./types.js";
import { isObject } from "@lightsparkdev/core";

export class SparkWallet extends BaseSparkWallet {
  private tracer: Tracer | null = null;

  protected wrapWithOtelSpan<A extends unknown[], R>(
    name: string,
    fn: (...args: A) => Promise<R>,
  ) {
    return async (...args: A) => {
      if (!this.tracer) {
        throw new Error("Tracer not initialized");
      }

      return await this.tracer.startActiveSpan(name, async (span) => {
        const traceId = span.spanContext().traceId;
        try {
          const result = await fn(...args);
          return result;
        } catch (error) {
          if (error instanceof Error) {
            error.message += ` [traceId: ${traceId}]`;
          } else if (isObject(error)) {
            error["traceId"] = traceId;
          }
          throw error;
        } finally {
          span.end();
        }
      });
    };
  }

  protected async initializeTracer(tracerName: string) {
    const { trace, propagation, context } = await import("@opentelemetry/api");
    const { W3CTraceContextPropagator } = await import("@opentelemetry/core");
    const { AsyncLocalStorageContextManager } = await import(
      "@opentelemetry/context-async-hooks"
    );
    const { BasicTracerProvider } = await import(
      "@opentelemetry/sdk-trace-base"
    );

    trace.setGlobalTracerProvider(new BasicTracerProvider());
    propagation.setGlobalPropagator(new W3CTraceContextPropagator());
    context.setGlobalContextManager(new AsyncLocalStorageContextManager());

    this.tracer = trace.getTracer(tracerName);
  }

  private getTraceName(methodName: string) {
    return `SparkWallet.${methodName}`;
  }

  private wrapPublicMethodsWithOtelSpan<M extends keyof SparkWallet>(
    methodName: M,
  ) {
    const original = this[methodName];

    if (typeof original !== "function") {
      throw new Error(`Method ${methodName} is not a function on SparkWallet.`);
    }

    const wrapped = this.wrapWithOtelSpan(
      this.getTraceName(methodName),
      original.bind(this) as (...args: unknown[]) => Promise<unknown>,
    ) as SparkWallet[M];

    (this as SparkWallet)[methodName] = wrapped;
  }

  private wrapSparkWalletWithTracing() {
    const methods = [
      "getLeaves",
      "getIdentityPublicKey",
      "getSparkAddress",
      "createSparkPaymentIntent",
      "getSwapFeeEstimate",
      "getTransfers",
      "getBalance",
      "getSingleUseDepositAddress",
      "getStaticDepositAddress",
      "queryStaticDepositAddresses",
      "getClaimStaticDepositQuote",
      "claimStaticDeposit",
      "refundStaticDeposit",
      "getUnusedDepositAddresses",
      "claimDeposit",
      "advancedDeposit",
      "transfer",
      "createLightningInvoice",
      "payLightningInvoice",
      "getLightningSendFeeEstimate",
      "withdraw",
      "getWithdrawalFeeQuote",
      "getTransferFromSsp",
      "getTransfer",
      "transferTokens",
      "batchTransferTokens",
      "queryTokenTransactions",
      "getLightningReceiveRequest",
      "getLightningSendRequest",
      "getCoopExitRequest",
      "checkTimelock",
      "testOnly_expireTimelock",
    ] as const;

    methods.forEach((m) => this.wrapPublicMethodsWithOtelSpan(m));

    /* Private methods can't be indexed on `this` and need to be wrapped individually: */
    this.initWallet = this.wrapWithOtelSpan(
      this.getTraceName("initWallet"),
      this.initWallet.bind(this),
    );
  }

  protected async initWallet(
    mnemonicOrSeed?: Uint8Array | string,
    accountNumber?: number,
  ): Promise<InitWalletResponse | undefined> {
    const res = super.initWallet(mnemonicOrSeed, accountNumber);
    await this.initializeTracer(this.tracerId);
    this.wrapSparkWalletWithTracing();
    return res;
  }
}
