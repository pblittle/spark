import { Tracer } from "@opentelemetry/api";
import { SparkWallet as BaseSparkWallet } from "./spark-wallet.js";
import type { InitWalletResponse } from "./types.js";

export class SparkWallet extends BaseSparkWallet {
  private tracer: Tracer | null = null;

  protected wrapWithOtelSpan<T>(
    name: string,
    fn: (...args: any[]) => Promise<T>,
  ): (...args: any[]) => Promise<T> {
    return async (...args: any[]): Promise<T> => {
      if (!this.tracer) {
        throw new Error("Tracer not initialized");
      }

      return await this.tracer.startActiveSpan(name, async (span) => {
        const traceId = span.spanContext().traceId;
        try {
          return await fn(...args);
        } catch (error) {
          if (error instanceof Error) {
            error.message += ` [traceId: ${traceId}]`;
          } else if (typeof error === "object" && error !== null) {
            (error as any).traceId = traceId;
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

  private wrapSparkWalletWithTracing() {
    this.getLeaves = this.wrapWithOtelSpan(
      "SparkWallet.getLeaves",
      this.getLeaves.bind(this),
    );
    this.getIdentityPublicKey = this.wrapWithOtelSpan(
      "SparkWallet.getIdentityPublicKey",
      this.getIdentityPublicKey.bind(this),
    );
    this.getSparkAddress = this.wrapWithOtelSpan(
      "SparkWallet.getSparkAddress",
      this.getSparkAddress.bind(this),
    );
    this.createSparkPaymentIntent = this.wrapWithOtelSpan(
      "SparkWallet.createSparkPaymentIntent",
      this.createSparkPaymentIntent.bind(this),
    );
    this.initWallet = this.wrapWithOtelSpan(
      "SparkWallet.initWallet",
      this.initWallet.bind(this),
    );
    this.getSwapFeeEstimate = this.wrapWithOtelSpan(
      "SparkWallet.getSwapFeeEstimate",
      this.getSwapFeeEstimate.bind(this),
    );
    this.getTransfers = this.wrapWithOtelSpan(
      "SparkWallet.getTransfers",
      this.getTransfers.bind(this),
    );
    this.getBalance = this.wrapWithOtelSpan(
      "SparkWallet.getBalance",
      this.getBalance.bind(this),
    );
    this.getSingleUseDepositAddress = this.wrapWithOtelSpan(
      "SparkWallet.getSingleUseDepositAddress",
      this.getSingleUseDepositAddress.bind(this),
    );
    this.getStaticDepositAddress = this.wrapWithOtelSpan(
      "SparkWallet.getStaticDepositAddress",
      this.getStaticDepositAddress.bind(this),
    );
    this.queryStaticDepositAddresses = this.wrapWithOtelSpan(
      "SparkWallet.queryStaticDepositAddresses",
      this.queryStaticDepositAddresses.bind(this),
    );
    this.getClaimStaticDepositQuote = this.wrapWithOtelSpan(
      "SparkWallet.getClaimStaticDepositQuote",
      this.getClaimStaticDepositQuote.bind(this),
    );
    this.claimStaticDeposit = this.wrapWithOtelSpan(
      "SparkWallet.claimStaticDeposit",
      this.claimStaticDeposit.bind(this),
    );
    this.refundStaticDeposit = this.wrapWithOtelSpan(
      "SparkWallet.refundStaticDeposit",
      this.refundStaticDeposit.bind(this),
    );
    this.getUnusedDepositAddresses = this.wrapWithOtelSpan(
      "SparkWallet.getUnusedDepositAddresses",
      this.getUnusedDepositAddresses.bind(this),
    );
    this.claimDeposit = this.wrapWithOtelSpan(
      "SparkWallet.claimDeposit",
      this.claimDeposit.bind(this),
    );
    this.advancedDeposit = this.wrapWithOtelSpan(
      "SparkWallet.advancedDeposit",
      this.advancedDeposit.bind(this),
    );
    this.transfer = this.wrapWithOtelSpan(
      "SparkWallet.transfer",
      this.transfer.bind(this),
    );
    this.createLightningInvoice = this.wrapWithOtelSpan(
      "SparkWallet.createLightningInvoice",
      this.createLightningInvoice.bind(this),
    );
    this.payLightningInvoice = this.wrapWithOtelSpan(
      "SparkWallet.payLightningInvoice",
      this.payLightningInvoice.bind(this),
    );
    this.getLightningSendFeeEstimate = this.wrapWithOtelSpan(
      "SparkWallet.getLightningSendFeeEstimate",
      this.getLightningSendFeeEstimate.bind(this),
    );
    this.withdraw = this.wrapWithOtelSpan(
      "SparkWallet.withdraw",
      this.withdraw.bind(this),
    );
    this.getWithdrawalFeeQuote = this.wrapWithOtelSpan(
      "SparkWallet.getWithdrawalFeeQuote",
      this.getWithdrawalFeeQuote.bind(this),
    );
    this.getTransferFromSsp = this.wrapWithOtelSpan(
      "SparkWallet.getTransferFromSsp",
      this.getTransferFromSsp.bind(this),
    );
    this.getTransfer = this.wrapWithOtelSpan(
      "SparkWallet.getTransfer",
      this.getTransfer.bind(this),
    );
    this.transferTokens = this.wrapWithOtelSpan(
      "SparkWallet.transferTokens",
      this.transferTokens.bind(this),
    );
    this.batchTransferTokens = this.wrapWithOtelSpan(
      "SparkWallet.batchTransferTokens",
      this.batchTransferTokens.bind(this),
    );
    this.queryTokenTransactions = this.wrapWithOtelSpan(
      "SparkWallet.queryTokenTransactions",
      this.queryTokenTransactions.bind(this),
    );
    this.getLightningReceiveRequest = this.wrapWithOtelSpan(
      "SparkWallet.getLightningReceiveRequest",
      this.getLightningReceiveRequest.bind(this),
    );
    this.getLightningSendRequest = this.wrapWithOtelSpan(
      "SparkWallet.getLightningSendRequest",
      this.getLightningSendRequest.bind(this),
    );
    this.getCoopExitRequest = this.wrapWithOtelSpan(
      "SparkWallet.getCoopExitRequest",
      this.getCoopExitRequest.bind(this),
    );
    this.checkTimelock = this.wrapWithOtelSpan(
      "SparkWallet.checkTimelock",
      this.checkTimelock.bind(this),
    );
    this.testOnly_expireTimelock = this.wrapWithOtelSpan(
      "SparkWallet.testOnly_expireTimelock",
      this.testOnly_expireTimelock.bind(this),
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
