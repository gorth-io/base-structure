import {
  createLocalJWKSet,
  type JSONWebKeySet,
  type JWTVerifyGetKey,
} from "jose";
import { z } from "zod";
import { AuthError } from "../interface";
import { waitForAuthOperation } from "../client/retry";
import { validateAuthEndpoint } from "./endpoint";
import type { AuthTransport } from "./interface";

const metadataSchema = z.object({
  issuer: z.string().max(2048),
  jwks_uri: z.string().max(2048),
  authorization_endpoint: z.string().max(2048).optional(),
  token_endpoint: z.string().max(2048).optional(),
  userinfo_endpoint: z.string().max(2048).optional(),
  revocation_endpoint: z.string().max(2048).optional(),
  end_session_endpoint: z.string().max(2048).optional(),
});
const jwksSchema = z.object({
  keys: z
    .array(
      z
        .object({ kty: z.enum(["RSA", "EC", "OKP"]) })
        .passthrough()
        .refine(
          (key) =>
            !["d", "p", "q", "dp", "dq", "qi", "oth", "k"].some(
              (name) => name in key,
            ),
        ),
    )
    .min(1)
    .max(100),
});
export type OidcMetadata = z.infer<typeof metadataSchema>;
export interface OidcDiscoveryOptions {
  issuer: string;
  endpointOrigins: readonly string[];
  allowedPath?(url: URL): boolean;
  allowLoopbackHttp?: boolean;
  transport: AuthTransport;
  cacheMaxAgeMs?: number;
  now?: () => number;
}

/** Fetch and validate a local key snapshot BEFORE exchanging/rotating credentials. */
export function createOidcDiscovery(options: OidcDiscoveryOptions) {
  const now = options.now ?? Date.now;
  const age = options.cacheMaxAgeMs ?? 300_000;
  const basePolicy = { allowLoopbackHttp: options.allowLoopbackHttp };
  const issuer = validateAuthEndpoint(options.issuer, basePolicy);
  for (const origin of options.endpointOrigins)
    if (validateAuthEndpoint(origin, basePolicy).origin !== origin)
      throw new AuthError("invalid_configuration");
  if (!Number.isFinite(age) || age < 0 || age > 3_600_000)
    throw new AuthError("invalid_configuration");
  const endpointPolicy = { ...options, origins: options.endpointOrigins };
  const discoveryUrl =
    issuer.href.replace(/\/$/, "") + "/.well-known/openid-configuration";
  let cached:
    | {
        metadata: Readonly<OidcMetadata>;
        key: JWTVerifyGetKey;
        expiresAt: number;
      }
    | undefined;
  let flight: Promise<NonNullable<typeof cached>> | undefined;
  let generation = 0;

  async function request(url: string) {
    try {
      const response = await options.transport.request(url, {
        method: "GET",
        headers: { Accept: "application/json", "Cache-Control": "no-store" },
      });
      if (response.status !== 200) throw new AuthError("unavailable");
      return response.data;
    } catch (error) {
      if (error instanceof AuthError) throw error;
      throw new AuthError("unavailable");
    }
  }

  function load(input: { force?: boolean; signal?: AbortSignal } = {}) {
    input.signal?.throwIfAborted();
    if (!input.force && cached && cached.expiresAt > now())
      return Promise.resolve(cached);
    if (!flight) {
      const version = generation;
      const operation = (async () => {
        const parsed = metadataSchema.safeParse(await request(discoveryUrl));
        if (!parsed.success || parsed.data.issuer !== options.issuer)
          throw new AuthError("rejected");
        for (const [name, value] of Object.entries(parsed.data))
          if (name !== "issuer" && value)
            validateAuthEndpoint(value, endpointPolicy, true);
        const keys = jwksSchema.safeParse(await request(parsed.data.jwks_uri));
        if (!keys.success) throw new AuthError("rejected");
        const snapshot = {
          metadata: Object.freeze(parsed.data),
          key: createLocalJWKSet(keys.data as JSONWebKeySet),
          expiresAt: now() + age,
        };
        if (generation !== version) throw new AuthError("cancelled");
        cached = snapshot;
        return snapshot;
      })();
      flight = operation;
      void operation.then(
        () => {
          if (flight === operation) flight = undefined;
        },
        () => {
          if (flight === operation) flight = undefined;
        },
      );
    }
    return waitForAuthOperation(flight, input.signal);
  }

  return {
    async metadata(input?: { force?: boolean; signal?: AbortSignal }) {
      return (await load(input)).metadata;
    },
    async getVerificationKey(input?: {
      force?: boolean;
      signal?: AbortSignal;
    }) {
      return (await load(input)).key;
    },
    /** Used by session-bound transports immediately after getVerificationKey. */
    currentVerificationKey() {
      return cached?.key;
    },
    invalidate() {
      generation++;
      cached = undefined;
      flight = undefined;
    },
  };
}
