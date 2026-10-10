import { AuthError } from "@/modules/auth/interface";
import { createAuthPolicy } from "@/modules/auth/policy";
import { createProofReplayStore } from "@/modules/auth/server/proof";
import type { ResourceAuthOptions } from "@/utils/interface";
import {
  isInsufficientScopeError,
  verifyAccessTokenRequest,
  type ResourceRequestInput,
} from "better-auth/oauth2";
import type { JWTPayload } from "jose";

export function createResourceAuth(options: ResourceAuthOptions) {
  const now = options.now ?? Date.now;
  const policy = createAuthPolicy(options.policy);
  const { verification } = options;
  if (
    !verification.verifyOptions.issuer ||
    !verification.verifyOptions.audience ||
    (!verification.jwksUrl && !verification.remoteVerify) ||
    !["always", "sensitive"].includes(options.onlineVerification) ||
    (options.requireSid === false && options.onlineVerification !== "always")
  )
    throw new AuthError("invalid_configuration");
  const algorithms = verification.verifyOptions.algorithms ?? [
    "RS256",
    "ES256",
    "EdDSA",
  ];
  if (
    !algorithms.length ||
    algorithms.some(
      (algorithm) => !["RS256", "ES256", "EdDSA"].includes(algorithm),
    )
  ) {
    throw new AuthError("invalid_configuration");
  }
  const exact = (value: unknown): boolean =>
    typeof value === "string" && value.length > 0;
  if (
    ![
      verification.verifyOptions.issuer,
      verification.verifyOptions.audience,
    ].every((value) =>
      Array.isArray(value)
        ? value.length > 0 && value.every(exact)
        : exact(value),
    )
  )
    throw new AuthError("invalid_configuration");
  for (const endpoint of [
    verification.jwksUrl,
    verification.remoteVerify?.introspectUrl,
  ]) {
    if (!endpoint) continue;
    let url: URL;
    try {
      url = new URL(endpoint);
    } catch {
      throw new AuthError("invalid_configuration");
    }
    if (
      url.username ||
      url.password ||
      url.hash ||
      url.search ||
      (url.protocol !== "https:" &&
        !(
          options.allowLoopbackHttp &&
          url.protocol === "http:" &&
          ["localhost", "127.0.0.1", "[::1]"].includes(url.hostname)
        ))
    )
      throw new AuthError("invalid_configuration");
  }
  const replayStore = createProofReplayStore(options.proof, now);
  return {
    async verify(
      request: ResourceRequestInput,
      input: { sensitive?: boolean } = {},
    ) {
      let claims: JWTPayload;
      try {
        claims = await verifyAccessTokenRequest(request, {
          ...verification,
          verifyOptions: {
            ...verification.verifyOptions,
            algorithms: [...algorithms],
            clockTolerance: policy.clockToleranceSeconds,
            requiredClaims: [
              ...new Set([
                ...(verification.verifyOptions.requiredClaims ?? []),
                "iss",
                "aud",
                "sub",
                "exp",
                "iat",
              ]),
            ],
            currentDate: new Date(now()),
          },
          dpop: { replayStore },
        });
        if (
          typeof claims.sub !== "string" ||
          !claims.sub ||
          claims.sub.length > 255 ||
          (options.requireSid !== false && typeof claims.sid !== "string") ||
          claims.iat! > now() / 1000 + policy.clockToleranceSeconds ||
          claims.exp! * 1000 - now() >
            policy.revocationRetentionMs -
              policy.clockToleranceSeconds * 1000 ||
          (claims.sid !== undefined &&
            (typeof claims.sid !== "string" ||
              !claims.sid ||
              claims.sid.length > 255))
        )
          throw new AuthError("rejected");
      } catch (error) {
        if (isInsufficientScopeError(error)) throw new AuthError("forbidden");
        if (error instanceof AuthError) throw error;
        const status =
          error && typeof error === "object" && "statusCode" in error
            ? error.statusCode
            : undefined;
        if (typeof status === "number" && status >= 400 && status < 500)
          throw new AuthError("rejected");
        // Unknown/JWKS/network failures are not a reason to log users out.
        throw new AuthError("unavailable");
      }
      try {
        if (
          await options.revocation.isRevoked({
            subject: claims.sub!,
            sid: claims.sid as string | undefined,
            issuedAt: claims.iat! * 1000,
            now: now(),
          })
        )
          throw new AuthError("rejected");
      } catch (error) {
        if (error instanceof AuthError) throw error;
        throw new AuthError("unavailable");
      }
      if (options.onlineVerification === "always" || input.sensitive) {
        try {
          await options.verifyActive(claims, request);
        } catch (error) {
          if (error instanceof AuthError) throw error;
          throw new AuthError("unavailable");
        }
      }
      return claims; // App still owns local status, permissions, and domain authorization.
    },
  };
}

export type { ResourceAuthOptions } from "@/utils/interface";
