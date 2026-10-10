import { waitForAuthOperation } from "@/modules/auth/client/retry";
import { AuthError } from "@/modules/auth/interface";
import { validateAuthEndpoint } from "@/modules/auth/server/endpoint";
import type {
  OidcDiscoveryOptions,
  OidcLoadInput,
  OidcSnapshot,
} from "@/utils/interface";
import { createLocalJWKSet, type JSONWebKeySet } from "jose";
import { z } from "zod";

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

/** Fetch and validate a local key snapshot BEFORE exchanging/rotating credentials. */
export function createOidcDiscovery(options: OidcDiscoveryOptions) {
  const now = options.now ?? Date.now;
  const age = options.cacheMaxAgeMs ?? 300_000;
  const cooldown = options.rotationCooldownMs ?? 30_000;
  const basePolicy = { allowLoopbackHttp: options.allowLoopbackHttp };
  const issuer = validateAuthEndpoint(options.issuer, basePolicy);
  for (const origin of options.endpointOrigins)
    if (validateAuthEndpoint(origin, basePolicy).origin !== origin)
      throw new AuthError("invalid_configuration");
  if (
    !Number.isSafeInteger(age) ||
    age < 0 ||
    age > 3_600_000 ||
    !Number.isSafeInteger(cooldown) ||
    cooldown < 0 ||
    cooldown > 3_600_000
  )
    throw new AuthError("invalid_configuration");
  const endpointPolicy = { ...options, origins: options.endpointOrigins };
  const discoveryUrl =
    issuer.href.replace(/\/$/, "") + "/.well-known/openid-configuration";
  let cached: OidcSnapshot | undefined;
  let flight: Promise<OidcSnapshot> | undefined;
  let generation = 0;
  let lastRotationAttempt = -Infinity;

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

  async function load(input: OidcLoadInput = {}): Promise<OidcSnapshot> {
    input.signal?.throwIfAborted();
    if (!input.force && cached && cached.expiresAt > now()) return cached;
    if (!flight) {
      const version = generation;
      let operation!: Promise<OidcSnapshot>;
      operation = (async () => {
        await Promise.resolve();
        try {
          const parsed = metadataSchema.safeParse(await request(discoveryUrl));
          if (!parsed.success || parsed.data.issuer !== options.issuer)
            throw new AuthError("rejected");
          for (const [name, value] of Object.entries(parsed.data))
            if (name !== "issuer" && value)
              validateAuthEndpoint(value, endpointPolicy, true);
          const keys = jwksSchema.safeParse(
            await request(parsed.data.jwks_uri),
          );
          if (!keys.success) throw new AuthError("rejected");
          const snapshot = {
            metadata: Object.freeze(parsed.data),
            key: createLocalJWKSet(keys.data as JSONWebKeySet),
            keyIds: new Set(
              keys.data.keys.flatMap((key) =>
                typeof key.kid === "string" ? [key.kid] : [],
              ),
            ),
            expiresAt: now() + age,
          };
          if (generation !== version) throw new AuthError("cancelled");
          cached = snapshot;
          return snapshot;
        } catch (error) {
          if (error instanceof AuthError) throw error;
          throw new AuthError("unavailable");
        } finally {
          if (flight === operation) flight = undefined;
        }
      })();
      flight = operation;
    }
    return await waitForAuthOperation(flight, input.signal);
  }

  return {
    async metadata(input?: OidcLoadInput) {
      return (await load(input)).metadata;
    },
    async getVerificationKey(input?: OidcLoadInput) {
      return (await load(input)).key;
    },
    /** Recovery after ERR_JWKS_NO_MATCHING_KEY. Never replay a code or refresh grant. */
    async refreshForUnknownKey(
      kid: string,
      input: Omit<OidcLoadInput, "force"> = {},
    ) {
      if (!kid || kid.length > 255 || /[\u0000-\u001f\u007f]/.test(kid))
        throw new AuthError("rejected");
      // Join an already running reload before checking the cooldown.
      const current = await load(input);
      if (current.keyIds.has(kid)) return current.key;
      if (flight) {
        const next = await waitForAuthOperation(flight, input.signal);
        if (!next.keyIds.has(kid)) throw new AuthError("rejected");
        return next.key;
      }
      if (now() - lastRotationAttempt < cooldown)
        throw new AuthError("rejected");
      lastRotationAttempt = now();
      const next = await load({ ...input, force: true });
      if (!next.keyIds.has(kid)) throw new AuthError("rejected");
      return next.key;
    },
    /** Used by session-bound transports immediately after getVerificationKey. */
    currentVerificationKey() {
      return cached?.key;
    },
    invalidate() {
      generation++;
      cached = undefined;
      flight = undefined;
      lastRotationAttempt = -Infinity;
    },
  };
}

export type {
  OidcDiscoveryOptions,
  OidcLoadInput,
  OidcMetadata,
} from "@/utils/interface";
