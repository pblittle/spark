/* Root Node.js entrypoint */

import nodeCrypto from "crypto";

import { setCrypto } from "./utils/crypto.js";

const cryptoImpl =
  typeof global !== "undefined" && global.crypto ? global.crypto : nodeCrypto;

setCrypto(cryptoImpl);

export * from "./errors/index.js";
export * from "./utils/index.js";

export {
  DefaultSparkSigner,
  TaprootOutputKeysGenerator,
  TaprootSparkSigner,
  UnsafeStatelessSparkSigner,
  type SparkSigner,
} from "./signer/signer.js";
export * from "./signer/types.js";

export {
  SparkWalletNodeJS as SparkWallet,
  initializeTracerEnvNodeJS as initializeTracerEnv,
} from "./spark-wallet/spark-wallet.node.js";
export * from "./spark-wallet/types.js";

export { type WalletConfigService } from "./services/config.js";
export { type ConnectionManager } from "./services/connection.js";
export { TokenTransactionService } from "./services/token-transactions.js";
export { WalletConfig, type ConfigOptions } from "./services/wallet-config.js";
