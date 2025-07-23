/* Root web/default entrypoint. For Node.js see index.node.ts */

import { setCrypto } from "./utils/crypto.js";

const cryptoImpl =
  typeof window !== "undefined" && window.crypto
    ? window.crypto
    : typeof global !== "undefined" && global.crypto
      ? global.crypto
      : null;

setCrypto(cryptoImpl);

export * from "./errors/index.js";
export * from "./utils/index.js";

export {
  DefaultSparkSigner,
  TaprootOutputKeysGenerator,
  TaprootSparkSigner,
  UnsafeStatelessSparkSigner,
  type SparkSigner,
  type TokenSigner,
} from "./signer/signer.js";
export * from "./signer/types.js";

export { SparkWallet } from "./spark-wallet/spark-wallet.js";
export * from "./spark-wallet/types.js";

export { type WalletConfigService } from "./services/config.js";
export { type ConnectionManager } from "./services/connection.js";
export { TokenTransactionService } from "./services/token-transactions.js";
export { WalletConfig, type ConfigOptions } from "./services/wallet-config.js";
