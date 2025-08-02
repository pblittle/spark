import { SparkWallet } from "@buildonspark/spark-sdk";

const { wallet } = await SparkWallet.initialize({});

console.log(
  "[spark-extension] SparkWallet initialised in content script",
  wallet,
);

const container = document.createElement("div");
container.id = "spark-extension-demo";
container.style.position = "fixed";
container.style.bottom = "16px";
container.style.right = "16px";
container.style.background = "#fff";
container.style.color = "#000";
container.style.padding = "8px 12px";
container.style.border = "1px solid #ccc";
container.style.zIndex = "2147483647";
container.textContent = "Spark content script loaded. Sending ping...";

document.body.appendChild(container);

chrome.runtime.sendMessage({ type: "PING_FROM_CONTENT" }, (response) => {
  console.log("[spark-extension] content received response", response);
  container.textContent = `Spark content script loaded. Response from background: ${JSON.stringify(
    response,
  )}`;
});
