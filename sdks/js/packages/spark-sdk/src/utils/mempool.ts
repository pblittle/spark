import {
  ELECTRS_CREDENTIALS,
  getElectrsUrl,
} from "../services/wallet-config.js";
import { BitcoinNetwork } from "../types/index.js";
import { getFetch } from "./fetch.js";
import { Network, getNetworkFromAddress } from "./network.js";

export async function getLatestDepositTxId(
  address: string,
): Promise<string | null> {
  const { fetch, Headers } = getFetch();
  const network = getNetworkFromAddress(address);
  const baseUrl =
    network === BitcoinNetwork.REGTEST
      ? getElectrsUrl("REGTEST")
      : getElectrsUrl("MAINNET");
  const headers = new Headers();

  if (network === BitcoinNetwork.REGTEST) {
    const auth = btoa(
      `${ELECTRS_CREDENTIALS.username}:${ELECTRS_CREDENTIALS.password}`,
    );
    headers.set("Authorization", `Basic ${auth}`);
  }

  const response = await fetch(`${baseUrl}/address/${address}/txs`, {
    headers,
  });

  const addressTxs = await response.json();

  if (addressTxs && addressTxs.length > 0) {
    const latestTx = addressTxs[0];

    const outputIndex: number = latestTx.vout.findIndex(
      (output: any) => output.scriptpubkey_address === address,
    );

    if (outputIndex === -1) {
      return null;
    }

    return latestTx.txid;
  }
  return null;
}

export async function isTxBroadcast(
  txid: string,
  baseUrl: string,
  network?: any,
): Promise<boolean> {
  const { fetch, Headers } = getFetch();
  const headers = new Headers();

  if (network === Network.REGTEST) {
    const auth = btoa(
      `${ELECTRS_CREDENTIALS.username}:${ELECTRS_CREDENTIALS.password}`,
    );
    headers.set("Authorization", `Basic ${auth}`);
  }

  const response = await fetch(`${baseUrl}/tx/${txid}`, {
    headers,
  });

  const tx = await response.json();
  if (tx.error) {
    return false;
  }

  return true;
}
