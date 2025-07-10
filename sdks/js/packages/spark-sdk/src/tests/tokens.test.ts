import { numberToBytesBE } from "@noble/curves/abstract/utils";
import {
  hashTokenTransactionV0,
  hashTokenTransactionV1,
} from "../utils/token-hashing.js";
import { Network, OutputWithPreviousTransactionData } from "../proto/spark.js";
import { TokenTransactionService } from "../services/token-transactions.js";
import { WalletConfigService } from "../services/config.js";
import { ConnectionManager } from "../services/connection.js";
import { sha256 } from "@noble/hashes/sha2";

// Test constants for consistent test data across all hash tests
const TEST_TOKEN_PUBLIC_KEY = new Uint8Array([
  242, 155, 208, 90, 72, 211, 120, 244, 69, 99, 28, 101, 149, 222, 123, 50, 252,
  63, 99, 54, 137, 226, 7, 224, 163, 122, 93, 248, 42, 159, 173, 45,
]);

const TEST_IDENTITY_PUB_KEY = new Uint8Array([
  25, 155, 208, 90, 72, 211, 120, 244, 69, 99, 28, 101, 149, 222, 123, 50, 252,
  63, 99, 54, 137, 226, 7, 224, 163, 122, 93, 248, 42, 159, 173, 46,
]);

const TEST_REVOCATION_PUB_KEY = new Uint8Array([
  100, 155, 208, 90, 72, 211, 120, 244, 69, 99, 28, 101, 149, 222, 123, 50, 252,
  63, 99, 54, 137, 226, 7, 224, 163, 122, 93, 248, 42, 159, 173, 46,
]);

const TEST_OPERATOR_PUB_KEY = new Uint8Array([
  200, 155, 208, 90, 72, 211, 120, 244, 69, 99, 28, 101, 149, 222, 123, 50, 252,
  63, 99, 54, 137, 226, 7, 224, 163, 122, 93, 248, 42, 159, 173, 46,
]);

const TEST_LEAF_ID = "db1a4e48-0fc5-4f6c-8a80-d9d6c561a436";
const TEST_BOND_SATS = 10000;
const TEST_LOCKTIME = 100;
const TEST_TOKEN_AMOUNT: bigint = 1000n;
const TEST_MAX_SUPPLY = new Uint8Array([
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3, 232,
]); // 1000 in BE format
const TEST_TOKEN_NAME = "TestToken";
const TEST_TOKEN_TICKER = "TEST";
const TEST_DECIMALS = 8;
const TEST_ISSUER_TIMESTAMP = 100;
const TEST_CLIENT_TIMESTAMP = 100;
const TEST_EXPIRY_TIME = 0;
const TEST_WITHDRAW_BOND_SATS = 10000;
const TEST_WITHDRAW_RELATIVE_BLOCK_LOCKTIME = 100;
const TEST_TOKEN_IDENTIFIER = new Uint8Array(32).fill(0x07);

// Precompute previous transaction hash to match Go test data
const PREV_TX_HASH = Uint8Array.from(
  sha256(new TextEncoder().encode("previous transaction")),
);

describe("hash token transaction", () => {
  it("should produce the exact same hash for mint v0 (legacy vector)", () => {
    const tokenAmount: bigint = 1000n;

    const tokenPublicKey = new Uint8Array([
      242, 155, 208, 90, 72, 211, 120, 244, 69, 99, 28, 101, 149, 222, 123, 50,
      252, 63, 99, 54, 137, 226, 7, 224, 163, 122, 93, 248, 42, 159, 173, 45,
    ]);

    const identityPubKey = new Uint8Array([
      25, 155, 208, 90, 72, 211, 120, 244, 69, 99, 28, 101, 149, 222, 123, 50,
      252, 63, 99, 54, 137, 226, 7, 224, 163, 122, 93, 248, 42, 159, 173, 46,
    ]);

    const tokenTransaction = {
      tokenInputs: {
        $case: "mintInput" as const,
        mintInput: {
          issuerPublicKey: tokenPublicKey,
          issuerProvidedTimestamp: 100,
        },
      },
      tokenOutputs: [
        {
          id: "db1a4e48-0fc5-4f6c-8a80-d9d6c561a436",
          ownerPublicKey: identityPubKey,
          withdrawBondSats: 10000,
          withdrawRelativeBlockLocktime: 100,
          tokenPublicKey: tokenPublicKey,
          tokenAmount: numberToBytesBE(tokenAmount, 16),
          revocationCommitment: identityPubKey,
        },
      ],
      sparkOperatorIdentityPublicKeys: [],
      network: Network.REGTEST,
    };

    const hash = hashTokenTransactionV0(tokenTransaction, false);

    expect(Array.from(hash)).toEqual([
      66, 235, 134, 101, 172, 110, 147, 77, 122, 48, 86, 240, 239, 9, 163, 82,
      120, 234, 246, 206, 245, 242, 186, 180, 154, 41, 207, 179, 194, 31, 211,
      36,
    ]);
  });

  it("should produce the exact same hash for mint v0", () => {
    const tokenTransaction = {
      tokenInputs: {
        $case: "mintInput" as const,
        mintInput: {
          issuerPublicKey: TEST_TOKEN_PUBLIC_KEY,
          issuerProvidedTimestamp: TEST_ISSUER_TIMESTAMP,
        },
      },
      tokenOutputs: [
        {
          id: TEST_LEAF_ID,
          ownerPublicKey: TEST_IDENTITY_PUB_KEY,
          tokenPublicKey: TEST_TOKEN_PUBLIC_KEY,
          tokenAmount: numberToBytesBE(TEST_TOKEN_AMOUNT, 16),
          revocationCommitment: TEST_REVOCATION_PUB_KEY,
          withdrawBondSats: TEST_WITHDRAW_BOND_SATS,
          withdrawRelativeBlockLocktime: TEST_WITHDRAW_RELATIVE_BLOCK_LOCKTIME,
        },
      ],
      sparkOperatorIdentityPublicKeys: [TEST_OPERATOR_PUB_KEY],
      network: Network.REGTEST,
    };

    const hash = hashTokenTransactionV0(tokenTransaction, false);

    expect(Array.from(hash)).toEqual([
      56, 47, 132, 171, 2, 236, 10, 72, 214, 89, 28, 46, 171, 39, 221, 113, 162,
      74, 170, 64, 160, 91, 11, 201, 45, 35, 67, 179, 199, 130, 116, 69,
    ]);
  });

  it("should produce the exact same hash for create v0", () => {
    const tokenTransaction = {
      tokenInputs: {
        $case: "createInput" as const,
        createInput: {
          issuerPublicKey: TEST_TOKEN_PUBLIC_KEY,
          tokenName: TEST_TOKEN_NAME,
          tokenTicker: TEST_TOKEN_TICKER,
          decimals: TEST_DECIMALS,
          maxSupply: TEST_MAX_SUPPLY,
          isFreezable: false,
        },
      },
      tokenOutputs: [],
      sparkOperatorIdentityPublicKeys: [TEST_OPERATOR_PUB_KEY],
      network: Network.REGTEST,
    };

    const hash = hashTokenTransactionV0(tokenTransaction, false);

    expect(Array.from(hash)).toEqual([
      35, 118, 177, 53, 49, 47, 174, 59, 123, 2, 212, 38, 217, 133, 124, 232,
      93, 185, 248, 87, 146, 123, 157, 10, 6, 111, 79, 183, 185, 175, 45, 224,
    ]);
  });

  it("should produce the exact same hash for transfer v0", () => {
    const tokenTransaction = {
      tokenInputs: {
        $case: "transferInput" as const,
        transferInput: {
          outputsToSpend: [
            {
              prevTokenTransactionHash: PREV_TX_HASH,
              prevTokenTransactionVout: 0,
            },
          ],
        },
      },
      tokenOutputs: [
        {
          id: TEST_LEAF_ID,
          ownerPublicKey: TEST_IDENTITY_PUB_KEY,
          tokenPublicKey: TEST_TOKEN_PUBLIC_KEY,
          tokenAmount: numberToBytesBE(1000n, 16),
          revocationCommitment: TEST_REVOCATION_PUB_KEY,
          withdrawBondSats: TEST_BOND_SATS,
          withdrawRelativeBlockLocktime: TEST_LOCKTIME,
        },
      ],
      sparkOperatorIdentityPublicKeys: [TEST_OPERATOR_PUB_KEY],
      network: Network.REGTEST,
    };

    const hash = hashTokenTransactionV0(tokenTransaction, false);

    expect(Array.from(hash)).toEqual([
      68, 88, 168, 87, 42, 251, 11, 182, 69, 202, 46, 202, 39, 234, 196, 201,
      24, 52, 213, 56, 151, 103, 99, 110, 211, 237, 148, 78, 216, 146, 143, 131,
    ]);
  });

  it("should produce the exact same hash for mint v1", () => {
    const tokenTransaction = {
      version: 1,
      tokenInputs: {
        $case: "mintInput" as const,
        mintInput: {
          issuerPublicKey: TEST_TOKEN_PUBLIC_KEY,
          issuerProvidedTimestamp: TEST_ISSUER_TIMESTAMP,
          tokenIdentifier: TEST_TOKEN_IDENTIFIER,
        },
      },
      tokenOutputs: [
        {
          id: TEST_LEAF_ID,
          ownerPublicKey: TEST_IDENTITY_PUB_KEY,
          withdrawBondSats: TEST_WITHDRAW_BOND_SATS,
          withdrawRelativeBlockLocktime: TEST_WITHDRAW_RELATIVE_BLOCK_LOCKTIME,
          tokenPublicKey: TEST_TOKEN_PUBLIC_KEY,
          tokenAmount: numberToBytesBE(TEST_TOKEN_AMOUNT, 16),
          revocationCommitment: TEST_REVOCATION_PUB_KEY,
        },
      ],
      sparkOperatorIdentityPublicKeys: [TEST_OPERATOR_PUB_KEY],
      network: Network.REGTEST,
      expiryTime: new Date(TEST_EXPIRY_TIME),
      clientCreatedTimestamp: new Date(TEST_CLIENT_TIMESTAMP),
    };

    const hash = hashTokenTransactionV1(tokenTransaction, false);

    expect(Array.from(hash)).toEqual([
      9, 162, 16, 177, 20, 91, 93, 148, 158, 249, 6, 42, 59, 136, 145, 184, 202,
      35, 243, 228, 14, 231, 132, 201, 66, 137, 201, 76, 97, 186, 149, 172,
    ]);
  });

  it("should produce the exact same hash for create v1", () => {
    const tokenTransaction = {
      version: 1,
      tokenInputs: {
        $case: "createInput" as const,
        createInput: {
          issuerPublicKey: TEST_TOKEN_PUBLIC_KEY,
          tokenName: TEST_TOKEN_NAME,
          tokenTicker: TEST_TOKEN_TICKER,
          decimals: TEST_DECIMALS,
          maxSupply: TEST_MAX_SUPPLY,
          isFreezable: false,
        },
      },
      tokenOutputs: [],
      sparkOperatorIdentityPublicKeys: [TEST_OPERATOR_PUB_KEY],
      network: Network.REGTEST,
      expiryTime: new Date(TEST_EXPIRY_TIME),
      clientCreatedTimestamp: new Date(TEST_CLIENT_TIMESTAMP),
    };

    const hash = hashTokenTransactionV1(tokenTransaction, false);

    expect(Array.from(hash)).toEqual([
      201, 249, 88, 215, 6, 7, 221, 209, 103, 153, 36, 41, 19, 60, 80, 144, 153,
      159, 185, 61, 20, 117, 87, 196, 102, 151, 76, 4, 191, 121, 221, 182,
    ]);
  });

  it("should produce the exact same hash for transfer v1", () => {
    const tokenTransaction = {
      version: 1,
      tokenInputs: {
        $case: "transferInput" as const,
        transferInput: {
          outputsToSpend: [
            {
              prevTokenTransactionHash: PREV_TX_HASH,
              prevTokenTransactionVout: 0,
            },
          ],
        },
      },
      tokenOutputs: [
        {
          id: TEST_LEAF_ID,
          ownerPublicKey: TEST_IDENTITY_PUB_KEY,
          tokenPublicKey: TEST_TOKEN_PUBLIC_KEY,
          tokenAmount: numberToBytesBE(TEST_TOKEN_AMOUNT, 16),
          revocationCommitment: TEST_REVOCATION_PUB_KEY,
          withdrawBondSats: TEST_BOND_SATS,
          withdrawRelativeBlockLocktime: TEST_LOCKTIME,
        },
      ],
      sparkOperatorIdentityPublicKeys: [TEST_OPERATOR_PUB_KEY],
      network: Network.REGTEST,
      expiryTime: new Date(TEST_EXPIRY_TIME),
      clientCreatedTimestamp: new Date(TEST_CLIENT_TIMESTAMP),
    };

    const hash = hashTokenTransactionV1(tokenTransaction, false);

    expect(Array.from(hash)).toEqual([
      86, 89, 220, 198, 197, 223, 236, 142, 73, 125, 112, 186, 29, 1, 26, 203,
      126, 154, 255, 176, 237, 210, 171, 98, 211, 130, 138, 113, 128, 129, 227,
      35,
    ]);
  });
});

describe("select token outputs", () => {
  let tokenTransactionService: TokenTransactionService;

  beforeEach(() => {
    const mockConfig = {} as WalletConfigService;
    const mockConnectionManager = {} as ConnectionManager;
    tokenTransactionService = new TokenTransactionService(
      mockConfig,
      mockConnectionManager,
    );
  });

  const createMockTokenOutput = (
    id: string,
    tokenAmount: bigint,
    tokenPublicKey: Uint8Array = new Uint8Array(32).fill(1),
    ownerPublicKey: Uint8Array = new Uint8Array(32).fill(2),
  ): OutputWithPreviousTransactionData => ({
    output: {
      id,
      ownerPublicKey,
      tokenPublicKey,
      tokenAmount: numberToBytesBE(tokenAmount, 16),
      revocationCommitment: new Uint8Array(32).fill(3),
    },
    previousTransactionHash: new Uint8Array(32).fill(4),
    previousTransactionVout: 0,
  });

  describe("exact match scenarios", () => {
    it("should return exact match when available", () => {
      const tokenOutputs = [
        createMockTokenOutput("output1", 100n),
        createMockTokenOutput("output2", 500n),
        createMockTokenOutput("output3", 1000n),
      ];

      const result = tokenTransactionService.selectTokenOutputs(
        tokenOutputs,
        500n,
        "SMALL_FIRST",
      );

      expect(result).toHaveLength(1);
      expect(result[0]!.output!.id).toBe("output2");
    });
  });

  describe("SMALL_FIRST strategy", () => {
    it("should select smallest outputs first when no exact match", () => {
      const tokenOutputs = [
        createMockTokenOutput("output1", 1000n),
        createMockTokenOutput("output2", 100n),
        createMockTokenOutput("output3", 300n),
      ];

      const result = tokenTransactionService.selectTokenOutputs(
        tokenOutputs,
        350n,
        "SMALL_FIRST",
      );

      expect(result).toHaveLength(2);
      expect(result[0]!.output!.id).toBe("output2"); // 100n
      expect(result[1]!.output!.id).toBe("output3"); // 300n
      // Total: 400n >= 350n
    });

    it("should select minimum number of outputs needed", () => {
      const tokenOutputs = [
        createMockTokenOutput("output1", 50n),
        createMockTokenOutput("output2", 100n),
        createMockTokenOutput("output3", 200n),
        createMockTokenOutput("output4", 1000n),
      ];

      const result = tokenTransactionService.selectTokenOutputs(
        tokenOutputs,
        300n,
        "SMALL_FIRST",
      );

      expect(result).toHaveLength(3);
      expect(result[0]!.output!.id).toBe("output1"); // 50n
      expect(result[1]!.output!.id).toBe("output2"); // 100n
      expect(result[2]!.output!.id).toBe("output3"); // 200n
      // Total: 350n >= 300n
    });
  });

  describe("LARGE_FIRST strategy", () => {
    it("should select largest outputs first when no exact match", () => {
      const tokenOutputs = [
        createMockTokenOutput("output1", 100n),
        createMockTokenOutput("output2", 1000n),
        createMockTokenOutput("output3", 300n),
      ];

      const result = tokenTransactionService.selectTokenOutputs(
        tokenOutputs,
        350n,
        "LARGE_FIRST",
      );

      expect(result).toHaveLength(1);
      expect(result[0]!.output!.id).toBe("output2"); // 1000n >= 350n
    });

    it("should select multiple outputs if largest is insufficient", () => {
      const tokenOutputs = [
        createMockTokenOutput("output1", 100n),
        createMockTokenOutput("output2", 200n),
        createMockTokenOutput("output3", 150n),
      ];

      const result = tokenTransactionService.selectTokenOutputs(
        tokenOutputs,
        350n,
        "LARGE_FIRST",
      );

      expect(result).toHaveLength(2);
      expect(result[0]!.output!.id).toBe("output2"); // 200n
      expect(result[1]!.output!.id).toBe("output3"); // 150n
      // Total: 350n >= 350n
    });
  });

  describe("edge cases", () => {
    it("should handle single output that exactly matches", () => {
      const tokenOutputs = [createMockTokenOutput("output1", 500n)];

      const result = tokenTransactionService.selectTokenOutputs(
        tokenOutputs,
        500n,
        "SMALL_FIRST",
      );

      expect(result).toHaveLength(1);
      expect(result[0]!.output!.id).toBe("output1");
    });

    it("should handle zero amount request", () => {
      const tokenOutputs = [createMockTokenOutput("output1", 100n)];

      const result = tokenTransactionService.selectTokenOutputs(
        tokenOutputs,
        0n,
        "SMALL_FIRST",
      );

      expect(result).toHaveLength(0);
    });

    it("should select all outputs if needed", () => {
      const tokenOutputs = [
        createMockTokenOutput("output1", 100n),
        createMockTokenOutput("output2", 200n),
        createMockTokenOutput("output3", 300n),
      ];

      const result = tokenTransactionService.selectTokenOutputs(
        tokenOutputs,
        600n,
        "SMALL_FIRST",
      );

      expect(result).toHaveLength(3);
      // Total: 600n >= 600n
    });
  });
});
