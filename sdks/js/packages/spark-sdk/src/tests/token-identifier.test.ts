import { describe, expect, test } from "@jest/globals";
import { Network, NetworkType } from "../utils/network.js";
import {
  decodeHumanReadableTokenIdentifier,
  encodeHumanReadableTokenIdentifier,
} from "../utils/token-identifier.js";

const TEST_TOKEN_IDENTIFIER = new Uint8Array([
  63, 122, 103, 46, 122, 5, 97, 185, 253, 135, 91, 94, 115, 80, 198, 19, 246,
  106, 151, 26, 124, 57, 156, 44, 26, 105, 66, 164, 126, 75, 150, 248,
]);

const getExpectedTokenIdentifier = (network: NetworkType) => {
  switch (network) {
    case "MAINNET":
      return "btk18aaxwtn6q4smnlv8td08x5xxz0mx49c60suectq6d9p2gljtjmuquewrjx";
    case "TESTNET":
      return "btkt18aaxwtn6q4smnlv8td08x5xxz0mx49c60suectq6d9p2gljtjmuqclz9p3";
    case "SIGNET":
      return "btks18aaxwtn6q4smnlv8td08x5xxz0mx49c60suectq6d9p2gljtjmuqh8f7qe";
    case "REGTEST":
      return "btkrt18aaxwtn6q4smnlv8td08x5xxz0mx49c60suectq6d9p2gljtjmuqree9zq";
    case "LOCAL":
      return "btkl18aaxwtn6q4smnlv8td08x5xxz0mx49c60suectq6d9p2gljtjmuq2p4x2m";
  }
};

describe("token identifier", () => {
  test("encodeHumanReadableTokenIdentifier", () => {
    const netKeys = Object.values(Network).filter((v) => isNaN(Number(v)));
    for (const network of netKeys) {
      const tokenIdentifier = encodeHumanReadableTokenIdentifier({
        tokenIdentifier: TEST_TOKEN_IDENTIFIER,
        network: network as NetworkType,
      });
      expect(tokenIdentifier).toBe(
        getExpectedTokenIdentifier(network as NetworkType),
      );
    }
  });

  test("decodeHumanReadableTokenIdentifier", () => {
    const netKeys = Object.values(Network).filter((v) => isNaN(Number(v)));
    for (const network of netKeys) {
      const identifier = getExpectedTokenIdentifier(network as NetworkType);
      const decoded = decodeHumanReadableTokenIdentifier(
        identifier,
        network as NetworkType,
      );
      expect(decoded.tokenIdentifier).toEqual(TEST_TOKEN_IDENTIFIER);
      expect(decoded.network).toEqual(network as NetworkType);
    }
  });
});
