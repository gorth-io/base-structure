import { jwtVerify, type JWTVerifyGetKey } from "jose";
import { AuthError } from "../interface";
import { validateAuthEndpoint } from "./endpoint";
import type { AuthTransport } from "./interface";

export interface SessionBoundTransportOptions {
  issuer: string;
  clientId: string;
  tokenUrl: string;
  revocationUrl: string;
  endpointOrigins: readonly string[];
  allowLoopbackHttp?: boolean;
  /** Must be a prepared local resolver, obtained BEFORE token rotation. */
  key(): JWTVerifyGetKey | undefined;
  algorithms?: readonly ("RS256" | "ES256" | "EdDSA")[];
  clockToleranceSeconds?: number;
  now?: () => number;
  /** Confidential clients can supply their own authenticated revocation adapter. */
  revokeRejectedGrant?(
    refreshToken: string,
    signal?: AbortSignal,
  ): Promise<void>;
}

/** Interactive-session policy wrapper; the OAuth engine still validates nonce/hashes/subject. */
export function createSessionBoundTransport(
  transport: AuthTransport,
  options: SessionBoundTransportOptions,
): AuthTransport {
  validateAuthEndpoint(options.issuer, options);
  for (const origin of options.endpointOrigins)
    if (validateAuthEndpoint(origin, options).origin !== origin)
      throw new AuthError("invalid_configuration");
  const endpointPolicy = { ...options, origins: options.endpointOrigins };
  validateAuthEndpoint(options.tokenUrl, endpointPolicy);
  validateAuthEndpoint(options.revocationUrl, endpointPolicy);
  const algorithms = [...(options.algorithms ?? ["RS256", "ES256", "EdDSA"])];
  const tolerance = options.clockToleranceSeconds ?? 5;
  if (
    !options.clientId ||
    options.clientId.length > 255 ||
    !algorithms.length ||
    algorithms.some((alg) => !["RS256", "ES256", "EdDSA"].includes(alg)) ||
    !Number.isFinite(tolerance) ||
    tolerance < 0 ||
    tolerance > 30
  )
    throw new AuthError("invalid_configuration");
  return {
    async request(url, input) {
      // Pin this operation's prepared snapshot. Concurrent discovery/cache
      // invalidation must not replace its resolver after token consumption.
      let key: JWTVerifyGetKey | undefined;
      try {
        if (url === options.tokenUrl) key = options.key();
      } catch {
        throw new AuthError("unavailable");
      }
      const result = await transport.request(url, input);
      if (url !== options.tokenUrl || result.status !== 200) return result;
      const data =
        result.data &&
        typeof result.data === "object" &&
        !Array.isArray(result.data)
          ? (result.data as Record<string, unknown>)
          : undefined;
      try {
        if (
          !key ||
          typeof data?.id_token !== "string" ||
          data.id_token.length > 32_768
        )
          throw new AuthError("rejected");
        const { payload } = await jwtVerify(data.id_token, key, {
          issuer: options.issuer,
          audience: options.clientId,
          algorithms,
          requiredClaims: ["iss", "aud", "sub", "iat", "exp", "sid"],
          clockTolerance: tolerance,
          currentDate: new Date((options.now ?? Date.now)()),
          maxTokenAge: 300,
        });
        if (
          typeof payload.sid !== "string" ||
          !payload.sid ||
          payload.sid.length > 255
        )
          throw new AuthError("rejected");
      } catch {
        // A detached grant must not retain its newly issued refresh token.
        if (
          typeof data?.refresh_token === "string" &&
          data.refresh_token.length > 0 &&
          data.refresh_token.length <= 32_768
        ) {
          try {
            if (options.revokeRejectedGrant)
              await options.revokeRejectedGrant(
                data.refresh_token,
                input.signal,
              );
            else
              await transport.request(options.revocationUrl, {
                method: "POST",
                headers: {
                  "Content-Type": "application/x-www-form-urlencoded",
                },
                body: new URLSearchParams({
                  client_id: options.clientId,
                  token: data.refresh_token,
                  token_type_hint: "refresh_token",
                }),
                signal: input.signal,
              });
          } catch {
            /* Local rejection never depends on remote revocation availability. */
          }
        }
        throw new AuthError("rejected");
      }
      return result;
    },
  };
}
