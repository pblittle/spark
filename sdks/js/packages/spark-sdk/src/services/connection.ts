import { isError, isNode } from "@lightsparkdev/core";
import { sha256 } from "@noble/hashes/sha2";
import type { Channel, ClientFactory } from "nice-grpc";
import { retryMiddleware } from "nice-grpc-client-middleware-retry";
import { ClientMiddlewareCall, Metadata } from "nice-grpc-common";
import type {
  Channel as ChannelWeb,
  ClientFactory as ClientFactoryWeb,
} from "nice-grpc-web";
import { isBun, isReactNative, clientEnv } from "../constants.js";
import { AuthenticationError, NetworkError } from "../errors/types.js";
import { MockServiceClient, MockServiceDefinition } from "../proto/mock.js";
import { SparkServiceClient, SparkServiceDefinition } from "../proto/spark.js";
import {
  Challenge,
  SparkAuthnServiceClient,
  SparkAuthnServiceDefinition,
} from "../proto/spark_authn.js";
import { RetryOptions, SparkCallOptions } from "../types/grpc.js";
import { WalletConfigService } from "./config.js";
import {
  SparkTokenServiceClient,
  SparkTokenServiceDefinition,
} from "../proto/spark_token.js";

type SparkAuthnServiceClientWithClose = SparkAuthnServiceClient & {
  close?: () => void;
};

export class ConnectionManager {
  private config: WalletConfigService;
  private clients: Map<
    string,
    {
      client: SparkServiceClient & { close?: () => void };
      authToken: string;
    }
  > = new Map();
  private tokenClients: Map<
    string,
    {
      client: SparkTokenServiceClient & { close?: () => void };
      authToken: string;
    }
  > = new Map();

  // We are going to .unref() the underlying channels for stream clients
  // to prevent the stream from keeping the process alive
  // Using a different map to avoid unforeseen problems with unary calls
  private streamClients: Map<
    string,
    {
      client: SparkServiceClient & { close?: () => void };
      authToken: string;
      channel: Channel | ChannelWeb;
    }
  > = new Map();

  // Tracks in-flight authenticate() promises so concurrent callers share one
  private authPromises: Map<string, Promise<string>> = new Map();

  constructor(config: WalletConfigService) {
    this.config = config;
  }

  // When initializing wallet, go ahead and instantiate all clients
  public async createClients() {
    await Promise.all(
      Object.values(this.config.getSigningOperators()).map((operator) => {
        this.createSparkClient(operator.address);
      }),
    );
  }

  public async closeConnections() {
    await Promise.all(
      Array.from(this.clients.values()).map((client) =>
        client.client.close?.(),
      ),
    );
    this.clients.clear();
  }

  async createMockClient(address: string): Promise<
    MockServiceClient & {
      close: () => void;
    }
  > {
    const channel = await this.createChannelWithTLS(address);
    const isNodeChannel = "close" in channel;

    if (isNode && isNodeChannel && !isBun) {
      const grpcModule = await import("nice-grpc");
      const { createClient } =
        "default" in grpcModule ? grpcModule.default : grpcModule;

      const client = createClient(MockServiceDefinition, channel);
      return { ...client, close: () => channel.close() };
    } else if (!isNodeChannel) {
      const grpcModule = await import("nice-grpc-web");
      const { createClient } =
        "default" in grpcModule ? grpcModule.default : grpcModule;

      const client = createClient(MockServiceDefinition, channel);
      return { ...client, close: () => {} };
    } else {
      throw new Error("Channel does not have close in NodeJS environment");
    }
  }

  private async createChannelWithTLS(address: string, certPath?: string) {
    try {
      if (isNode && !isBun) {
        const grpcModule = await import("nice-grpc");
        const { ChannelCredentials, createChannel } =
          "default" in grpcModule ? grpcModule.default : grpcModule;

        if (certPath) {
          try {
            // Dynamic import for Node.js only
            const fs = await import("fs");
            const cert = fs.readFileSync(certPath);
            return createChannel(address, ChannelCredentials.createSsl(cert));
          } catch (error) {
            console.error("Error reading certificate:", error);
            // Fallback to insecure for development
            return createChannel(
              address,
              ChannelCredentials.createSsl(null, null, null, {
                rejectUnauthorized: false,
              }),
            );
          }
        } else {
          // No cert provided, use insecure SSL for development
          return createChannel(
            address,
            ChannelCredentials.createSsl(null, null, null, {
              rejectUnauthorized: false,
            }),
          );
        }
      } else {
        // Browser environment - nice-grpc-web handles TLS automatically
        const grpcModule = await import("nice-grpc-web");
        const { createChannel, FetchTransport } =
          "default" in grpcModule ? grpcModule.default : grpcModule;
        const { XHRTransport } = await import("./xhr-transport.js");

        return createChannel(
          address,
          isReactNative ? XHRTransport() : FetchTransport(),
        );
      }
    } catch (error) {
      console.error("Channel creation error:", error);
      throw new NetworkError(
        "Failed to create channel",
        {
          url: address,
          operation: "createChannel",
          errorCount: 1,
          errors: error instanceof Error ? error.message : String(error),
        },
        error as Error,
      );
    }
  }

  async createSparkStreamClient(
    address: string,
    certPath?: string,
  ): Promise<SparkServiceClient & { close?: () => void }> {
    if (this.streamClients.has(address)) {
      return this.streamClients.get(address)!.client;
    }
    const authToken = await this.authenticate(address);
    const channel = await this.createChannelWithTLS(address, certPath);

    const middleware = this.createMiddleware(address, authToken);
    const client = await this.createGrpcClient<SparkServiceClient>(
      SparkServiceDefinition,
      channel,
      true,
      middleware,
    );

    this.streamClients.set(address, { client, authToken, channel });
    return client;
  }

  async createSparkClient(
    address: string,
    certPath?: string,
  ): Promise<SparkServiceClient & { close?: () => void }> {
    if (this.clients.has(address)) {
      return this.clients.get(address)!.client;
    }
    const authToken = await this.authenticate(address);
    const channel = await this.createChannelWithTLS(address, certPath);

    const middleware = this.createMiddleware(address, authToken);
    const client = await this.createGrpcClient<SparkServiceClient>(
      SparkServiceDefinition,
      channel,
      true,
      middleware,
    );

    this.clients.set(address, { client, authToken });
    return client;
  }

  async createSparkTokenClient(
    address: string,
    certPath?: string,
  ): Promise<SparkTokenServiceClient & { close?: () => void }> {
    if (this.tokenClients.has(address)) {
      return this.tokenClients.get(address)!.client;
    }
    const authToken = await this.authenticate(address);
    const channel = await this.createChannelWithTLS(address, certPath);

    const middleware = this.createMiddleware(address, authToken);
    const tokenClient = await this.createGrpcClient<SparkTokenServiceClient>(
      SparkTokenServiceDefinition,
      channel,
      true,
      middleware,
    );

    this.tokenClients.set(address, { client: tokenClient, authToken });
    return tokenClient;
  }

  async getStreamChannel(address: string) {
    return this.streamClients.get(address)?.channel;
  }

  private async authenticate(address: string, certPath?: string) {
    const existing = this.authPromises.get(address);
    if (existing) {
      return existing;
    }

    const authPromise = (async () => {
      const MAX_ATTEMPTS = 3;
      let lastError: Error | undefined;

      /* React Native can cause some outgoing requests to be paused which can result
         in challenges expiring, so we'll retry any authentication failures: */
      for (let attempt = 0; attempt < MAX_ATTEMPTS; attempt++) {
        let sparkAuthnClient: SparkAuthnServiceClientWithClose | undefined;
        try {
          const identityPublicKey =
            await this.config.signer.getIdentityPublicKey();
          sparkAuthnClient = await this.createSparkAuthnGrpcConnection(
            address,
            certPath,
          );

          const challengeResp = await sparkAuthnClient.get_challenge({
            publicKey: identityPublicKey,
          });

          if (!challengeResp.protectedChallenge?.challenge) {
            throw new AuthenticationError("Invalid challenge response", {
              endpoint: "get_challenge",
              reason: "Missing challenge in response",
            });
          }

          const challengeBytes = Challenge.encode(
            challengeResp.protectedChallenge.challenge,
          ).finish();
          const hash = sha256(challengeBytes);

          const derSignatureBytes =
            await this.config.signer.signMessageWithIdentityKey(hash);

          const verifyResp = await sparkAuthnClient.verify_challenge({
            protectedChallenge: challengeResp.protectedChallenge,
            signature: derSignatureBytes,
            publicKey: identityPublicKey,
          });

          sparkAuthnClient.close?.();
          return verifyResp.sessionToken;
        } catch (error: unknown) {
          if (isError(error)) {
            sparkAuthnClient?.close?.();

            if (error.message.includes("challenge expired")) {
              console.warn(
                `Authentication attempt ${attempt + 1} failed due to expired challenge, retrying...`,
              );
              lastError = error;
              continue;
            }

            throw new AuthenticationError(
              "Authentication failed",
              {
                endpoint: "authenticate",
                reason: error.message,
              },
              error,
            );
          } else {
            lastError = new Error(
              `Unknown error during authentication: ${String(error)}`,
            );
          }
        }
      }

      throw new AuthenticationError(
        "Authentication failed after retrying expired challenges",
        {
          endpoint: "authenticate",
          reason: lastError?.message ?? "Unknown error",
        },
        lastError,
      );
    })();

    this.authPromises.set(address, authPromise);

    try {
      return await authPromise;
    } finally {
      this.authPromises.delete(address);
    }
  }

  private async createSparkAuthnGrpcConnection(
    address: string,
    certPath?: string,
  ): Promise<SparkAuthnServiceClientWithClose> {
    const channel = await this.createChannelWithTLS(address, certPath);
    const authnMiddleware = this.createAuthnMiddleware();
    return this.createGrpcClient<SparkAuthnServiceClient>(
      SparkAuthnServiceDefinition,
      channel,
      false,
      authnMiddleware,
    );
  }

  private createAuthnMiddleware() {
    if (isNode) {
      return async function* (
        this: ConnectionManager,
        call: ClientMiddlewareCall<any, any>,
        options: SparkCallOptions,
      ) {
        const metadata = Metadata(options.metadata).set(
          "X-Client-Env",
          clientEnv,
        );
        return yield* call.next(call.request, {
          ...options,
          metadata,
        });
      }.bind(this);
    } else {
      return async function* (
        this: ConnectionManager,
        call: ClientMiddlewareCall<any, any>,
        options: SparkCallOptions,
      ) {
        const metadata = Metadata(options.metadata)
          .set("X-Requested-With", "XMLHttpRequest")
          .set("X-Grpc-Web", "1")
          .set("X-Client-Env", clientEnv)
          .set("Content-Type", "application/grpc-web+proto");
        return yield* call.next(call.request, {
          ...options,
          metadata,
        });
      }.bind(this);
    }
  }

  private createMiddleware(address: string, authToken: string) {
    if (isNode) {
      return this.createNodeMiddleware(address, authToken);
    } else {
      return this.createBrowserMiddleware(address, authToken);
    }
  }

  private async *handleMiddlewareError(
    error: unknown,
    address: string,
    call: ClientMiddlewareCall<any, any>,
    metadata: Metadata,
    options: SparkCallOptions,
  ) {
    if (isError(error)) {
      if (error.message.includes("token has expired")) {
        const newAuthToken = await this.authenticate(address);
        const clientData = this.clients.get(address);
        if (!clientData) {
          throw new Error(`No client found for address: ${address}`);
        }
        clientData.authToken = newAuthToken;

        return yield* call.next(call.request, {
          ...options,
          metadata: metadata.set("Authorization", `Bearer ${newAuthToken}`),
        });
      }
    }

    throw error;
  }

  private createNodeMiddleware(address: string, initialAuthToken: string) {
    return async function* (
      this: ConnectionManager,
      call: ClientMiddlewareCall<any, any>,
      options: SparkCallOptions,
    ) {
      const metadata = Metadata(options.metadata).set(
        "X-Client-Env",
        clientEnv,
      );
      try {
        return yield* call.next(call.request, {
          ...options,
          metadata: metadata.set(
            "Authorization",
            `Bearer ${this.clients.get(address)?.authToken || initialAuthToken}`,
          ),
        });
      } catch (error: unknown) {
        return yield* this.handleMiddlewareError(
          error,
          address,
          call,
          metadata,
          options,
        );
      }
    }.bind(this);
  }

  private createBrowserMiddleware(address: string, initialAuthToken: string) {
    return async function* (
      this: ConnectionManager,
      call: ClientMiddlewareCall<any, any>,
      options: SparkCallOptions,
    ) {
      const metadata = Metadata(options.metadata)
        .set("X-Requested-With", "XMLHttpRequest")
        .set("X-Grpc-Web", "1")
        .set("X-Client-Env", clientEnv)
        .set("Content-Type", "application/grpc-web+proto");

      try {
        // throw new Error("token has expired");
        return yield* call.next(call.request, {
          ...options,
          metadata: metadata.set(
            "Authorization",
            `Bearer ${this.clients.get(address)?.authToken || initialAuthToken}`,
          ),
        });
      } catch (error: any) {
        return yield* this.handleMiddlewareError(
          error,
          address,
          call,
          metadata,
          options,
        );
      }
    }.bind(this);
  }

  private async createGrpcClient<T>(
    defintion:
      | SparkAuthnServiceDefinition
      | SparkServiceDefinition
      | SparkTokenServiceDefinition,
    channel: Channel | ChannelWeb,
    withRetries: boolean,
    middleware?: any,
  ): Promise<T & { close?: () => void }> {
    let clientFactory: ClientFactory | ClientFactoryWeb;

    const retryOptions = {
      retry: true,
      retryMaxAttempts: 3,
    };
    let options: RetryOptions = {};
    const isNodeChannel = "close" in channel;

    if (isNode && isNodeChannel && !isBun) {
      const grpcModule = await import("nice-grpc");
      const { openTelemetryClientMiddleware } = await import(
        "nice-grpc-opentelemetry"
      );
      const { createClientFactory } =
        "default" in grpcModule ? grpcModule.default : grpcModule;

      clientFactory = createClientFactory();
      if (withRetries) {
        options = retryOptions;
        clientFactory = clientFactory
          .use(openTelemetryClientMiddleware())
          .use(retryMiddleware);
      }
      if (middleware) {
        clientFactory = clientFactory.use(middleware);
      }
      const client = clientFactory.create(defintion, channel, {
        "*": options,
      }) as T;
      return {
        ...client,
        close: channel.close.bind(channel),
      };
    } else if (!isNodeChannel) {
      const grpcModule = await import("nice-grpc-web");
      const { createClientFactory } =
        "default" in grpcModule ? grpcModule.default : grpcModule;

      clientFactory = createClientFactory();
      if (withRetries) {
        options = retryOptions;
        clientFactory = clientFactory.use(retryMiddleware);
      }
      if (middleware) {
        clientFactory = clientFactory.use(middleware);
      }
      const client = clientFactory.create(defintion, channel, {
        "*": options,
      }) as T;
      return {
        ...client,
        close: undefined,
      };
    } else {
      throw new Error("Channel does not have close in NodeJS environment");
    }
  }
}
