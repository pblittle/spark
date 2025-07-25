# Spark Vanity Token Identifier Generator

This tool helps generate vanity Spark token identifiers by searching for specific patterns in the bech32m-encoded identifier. It works by generating random mnemonics, deriving the corresponding issuer public key, and checking if the resulting token identifier matches the desired pattern.

## Features

- Generate vanity token identifiers for Spark's `mainnet` and `regtest` networks.
- Search for custom patterns at the `beginning`, `end`, or `anywhere` in the encoded identifier.
- Customize token parameters like `name`, `ticker`, `decimals`, `max-supply`, and `freezable` status.
- Multi-threaded search to accelerate the discovery process.
- Derives issuer keys using the same `m/8797555'/${accountNumber}'/0'` path as the official Spark wallets.

## How it Works

The tool performs the following steps in a loop:

1.  **Generate Mnemonic**: A new random BIP39 mnemonic is created.
2.  **Derive Public Key**: The issuer public key is derived from the mnemonic following the standard Spark derivation path.
3.  **Construct Token Metadata**: Token metadata is assembled using the derived public key and user-provided token parameters.
4.  **Compute Identifier**: The raw token identifier is computed using a SHA-256 hash of the token metadata.
5.  **Encode to Bech32m**: The raw identifier is encoded into a bech32m string (e.g., `btkn1...` or `btknrt1...`).
6.  **Pattern Match**: The tool checks if the specified pattern exists in the encoded data part of the bech32m string.
7.  **Success or Retry**: If a match is found, the process stops and prints the result. Otherwise, it repeats.

## Usage

You can run the generator from the command line.

```sh
go run ./tools/vanity-token-generator [flags]
```

### Flags

| Flag            | Description                                               |
| --------------- | --------------------------------------------------------- |
| `-name`         | Token name (3-20 bytes)                                   |
| `-ticker`       | Token ticker/symbol (3-6 bytes)                           |
| `-decimals`     | Number of decimal places (0-18)                           |
| `-freezable`    | Whether the token can be frozen                           |
| `-max-supply`   | Maximum token supply                                      |
| `-pattern`      | Bech32m pattern to search for (e.g., "spark")             |
| `-position`     | Where to look for pattern: `beginning`, `end`, `anywhere` |
| `-max-attempts` | Maximum number of attempts before giving up               |
| `-network`      | Network to use: `mainnet` or `regtest`                    |
| `-threads`      | Number of worker threads (0 = auto-detect CPU cores)      |
| `-help`         | Show the help message                                     |

### Examples

**Find a token starting with "ace":**

```sh
go run ./tools/vanity-token-generator/main.go -name=TestToken -ticker=TEST -decimals=0 -max-supply=21000000 -pattern=ace -position=beginning -network=mainnet -max-attempts=1000000
```

**Find a token for regtest ending with "cool" using 8 threads:**

```sh
go run ./tools/vanity-token-generator/main.go -name=CoolToken -ticker=COOL -decimals=2 -freezable=true -max-supply=1000000 -pattern=cool -position=end -network=regtest -threads=8 -max-attempts=1000000
```

**Find a token with "spark" anywhere in the identifier:**

```sh
go run ./tools/vanity-token-generator/main.go -name=SparkToken -ticker=SPARK -decimals=8 -max-supply=100000000 -pattern=spark -position=anywhere -network=mainnet
```

## Understanding the Odds

The difficulty of finding a pattern depends on its length and the size of the character set. Spark token identifiers use **bech32m**, which has an alphabet of **32 characters** (`acdefghjklmnpqrstuvwxyz023456789`).

The probability of finding a specific pattern of length `N` at a fixed position (like the beginning or end) is `1 in 32^N`.

Here are the average number of attempts you can expect for patterns of different lengths:

| Pattern Length | Average Attempts (1 in 32^N) | Example   | Difficulty |
| :------------: | :--------------------------: | :-------- | :--------- |
|       1        |              32              | `q`       | Trivial    |
|       2        |            1,024             | `qp`      | Easy       |
|       3        |            32,768            | `qpz`     | Moderate   |
|       4        |          1,048,576           | `qpzr`    | Hard       |
|       5        |          33,554,432          | `qpzry`   | Very Hard  |
|       6        |        1,073,741,824         | `qpzry9`  | Extreme    |
|       7        |        34,359,738,368        | `qpzry9x` | Lottery    |

**Notes:**

- **Position "Anywhere"**: Searching for a pattern "anywhere" is slightly easier than at a fixed position, but the table above provides a good estimate for the order of magnitude.
- **Performance**: The search speed depends on your CPU. A modern multi-core processor can perform hundreds of thousands of attempts per second. Use the `-threads` flag to maximize performance.
- **Patience is Key**: Finding patterns longer than 4-5 characters can take a significant amount of time, even on powerful hardware.
