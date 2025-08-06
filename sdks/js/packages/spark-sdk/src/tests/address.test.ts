import { uuidv7obj } from "uuidv7";

import {
  Bech32mTokenIdentifier,
  decodeBech32mTokenIdentifier,
} from "../utils/token-identifier.js";
import {
  bytesToHex,
  bytesToNumberBE,
  hexToBytes,
  numberToVarBytesBE,
} from "@noble/curves/abstract/utils";
import { encodeSparkAddress, decodeSparkAddress } from "../utils/address.js";

describe("Spark Invoice Encode/Decode", () => {
  const testCases = [
    {
      name: "no empty fields",
      emptyAmount: false,
      overMaxSatsAmount: false,
      emptyMemo: false,
      emptyExpiryTime: false,
      emptySenderPublicKey: false,
      emptyIdentityPublicKey: false,
      invalidVersion: false,
      invalidId: false,
    },
    {
      name: "empty amount",
      emptyAmount: true,
    },
    {
      name: "empty amount",
      overMaxSatsAmount: true,
    },
    {
      name: "empty memo",
      emptyMemo: true,
    },
    {
      name: "empty expiry time",
      emptyExpiryTime: true,
    },
    {
      name: "empty sender public key",
      emptySenderPublicKey: true,
    },
    {
      name: "empty identity public key",
      emptyIdentityPublicKey: true,
    },
    {
      name: "invalid version",
      invalidVersion: true,
    },
    {
      name: "invalid id",
      invalidId: true,
    },
  ];

  testCases.forEach((tc) => {
    test(tc.name, async () => {
      let identityPublicKey: string | undefined =
        "02ccb26ba79c63aaf60c9192fd874be3087ae8d8703275df0e558704a6d3a4f132";
      let senderPublicKey: string | undefined = identityPublicKey;

      const testUUID: Uint8Array = uuidv7obj().bytes;
      let tokenIdentifier: Bech32mTokenIdentifier =
        "btknrt1kcsyuqlkqz48f7pg442xefz3u355ccnn8v55keaz6hav42m032gs5nly6r";
      let satsAmount: number | undefined = 1000;
      let tokenAmount: Uint8Array | undefined = numberToVarBytesBE(1000n);
      let expiryTime = new Date(Date.now() + 24 * 60 * 60 * 1000);
      let memo = "myMemo";

      const rawTokenIdentifier = decodeBech32mTokenIdentifier(
        tokenIdentifier,
        "REGTEST",
      ).tokenIdentifier;

      if (tc.emptyAmount) {
        tokenAmount = undefined;
        satsAmount = undefined;
      }
      if (tc.overMaxSatsAmount) {
        satsAmount = 2_100_000_000_000_001;
      }
      if (tc.emptyMemo) {
        memo = "";
      }
      if (tc.emptySenderPublicKey) {
        senderPublicKey = undefined;
      }
      if (tc.emptyIdentityPublicKey) {
        identityPublicKey = undefined;
      }

      const tokenInvoiceFields = {
        version: tc.invalidVersion ? 9999 : 1,
        id: tc.invalidId ? new Uint8Array([1, 2, 3]) : testUUID,
        paymentType: {
          $case: "tokensPayment" as const,
          tokensPayment: {
            tokenIdentifier: rawTokenIdentifier,
            amount: tc.emptyAmount ? undefined : tokenAmount,
          },
        },
        memo: tc.emptyMemo ? undefined : memo,
        senderPublicKey: tc.emptySenderPublicKey
          ? undefined
          : hexToBytes(senderPublicKey as string),
        expiryTime: tc.emptyExpiryTime ? undefined : expiryTime,
      };

      const satsInvoiceFields = {
        version: tc.invalidVersion ? 9999 : 1,
        id: tc.invalidId ? new Uint8Array([1, 2, 3]) : testUUID,
        paymentType: {
          $case: "satsPayment" as const,
          satsPayment: {
            amount: satsAmount,
          },
        },
        memo: tc.emptyMemo ? undefined : memo,
        senderPublicKey: tc.emptySenderPublicKey
          ? undefined
          : hexToBytes(senderPublicKey as string),
        expiryTime: tc.emptyExpiryTime ? undefined : expiryTime,
      } as const;

      const shouldFail =
        tc.invalidVersion ||
        tc.invalidId ||
        tc.emptyIdentityPublicKey ||
        tc.overMaxSatsAmount;

      const identityKey = tc.emptyIdentityPublicKey ? null : identityPublicKey;

      if (shouldFail) {
        if (!tc.overMaxSatsAmount) {
          // tokens should not fail on over max sats amount
          expect(() =>
            encodeSparkAddress({
              identityPublicKey: identityKey as string,
              network: "REGTEST",
              sparkInvoiceFields: tokenInvoiceFields,
            }),
          ).toThrow();
        }
        expect(() =>
          encodeSparkAddress({
            identityPublicKey: identityKey as string,
            network: "REGTEST",
            sparkInvoiceFields: satsInvoiceFields,
          }),
        ).toThrow();

        return;
      }

      // Encode addresses
      const tokensAddress = await encodeSparkAddress({
        identityPublicKey: identityKey as string,
        network: "REGTEST",
        sparkInvoiceFields: tokenInvoiceFields,
      });

      const satsAddress = await encodeSparkAddress({
        identityPublicKey: identityKey as string,
        network: "REGTEST",
        sparkInvoiceFields: satsInvoiceFields,
      });

      const decodedTokensAddress = decodeSparkAddress(tokensAddress, "REGTEST");
      const decodedSatsAddress = decodeSparkAddress(satsAddress, "REGTEST");

      expect(decodedTokensAddress.network).toBe("REGTEST");
      expect(decodedTokensAddress.identityPublicKey).toBe(identityPublicKey);
      expect(decodedTokensAddress.sparkInvoiceFields?.version).toBe(1);
      expect(decodedTokensAddress.sparkInvoiceFields?.memo).toBe(
        tc.emptyMemo ? undefined : memo,
      );

      if (
        decodedTokensAddress.sparkInvoiceFields?.paymentType?.type === "tokens"
      ) {
        expect(
          decodedTokensAddress.sparkInvoiceFields.paymentType.tokenIdentifier,
        ).toBe(bytesToHex(rawTokenIdentifier));
        if (!tc.emptyAmount) {
          expect(
            decodedTokensAddress.sparkInvoiceFields.paymentType.amount,
          ).toBe(bytesToNumberBE(tokenAmount as Uint8Array));
        } else {
          expect(
            decodedTokensAddress.sparkInvoiceFields.paymentType.amount,
          ).toBeUndefined();
        }
      }

      expect(decodedSatsAddress.network).toBe("REGTEST");
      expect(decodedSatsAddress.identityPublicKey).toBe(identityPublicKey);
      expect(decodedSatsAddress.sparkInvoiceFields?.version).toBe(1);
      expect(decodedSatsAddress.sparkInvoiceFields?.memo).toBe(
        tc.emptyMemo ? undefined : memo,
      );

      if (decodedSatsAddress.sparkInvoiceFields?.paymentType?.type === "sats") {
        expect(decodedSatsAddress.sparkInvoiceFields.paymentType.amount).toBe(
          satsAmount,
        );
      }
    });
  });
});
