/* Root React Native entrypoint */

import { setCrypto, SparkCrypto } from "../utils/crypto.js";

setCrypto(globalThis.crypto);

export * from "../errors/index.js";
export * from "../utils/index.js";

export { ReactNativeSparkSigner } from "../signer/signer.react-native.js";
/* Enable some consumers to use named import DefaultSparkSigner regardless of module, see LIG-7662 */
export { ReactNativeSparkSigner as DefaultSparkSigner } from "../signer/signer.react-native.js";

export { SparkWallet } from "../spark-wallet/spark-wallet.js";
export * from "../spark-wallet/types.js";

export { WalletConfig } from "../services/wallet-config.js";
export { TokenTransactionService } from "../services/token-transactions.js";
export { type ConnectionManager } from "../services/connection.js";
export { type WalletConfigService } from "../services/config.js";
export { type ConfigOptions } from "../services/wallet-config.js";
