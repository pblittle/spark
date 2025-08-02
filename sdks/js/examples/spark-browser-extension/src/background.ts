import { SparkWallet } from "@buildonspark/spark-sdk";
// import { createDummyTx } from "@buildonspark/spark-sdk/spark-frost";

let wallet: SparkWallet | null = null;
SparkWallet.initialize({}).then(({ wallet: initializedWallet }) => {
  console.log(
    "[spark-extension] SparkWallet initialised in background",
    initializedWallet,
  );
  wallet = initializedWallet;
});

globalThis.s = {
  SparkWallet,
  // createDummyTx,
};

console.log("[spark-extension] SparkWallet initialized in background", wallet);

chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
  if (message?.type === "PING_FROM_CONTENT") {
    console.log(
      "[spark-extension] background received PING_FROM_CONTENT",
      message,
    );
    sendResponse({
      ok: true,
      from: "background",
      walletState: wallet ? "ready" : "uninitialized",
      randomNumber: Math.random(),
    });
    return true;
  }
  return false;
});
