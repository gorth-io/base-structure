import { jwtVerify, type JWTVerifyGetKey } from "jose";
import { AuthError, type AuthPolicy } from "../interface";
import { createAuthPolicy } from "../policy";
import type { LogoutStorage, VerifiedLogout } from "./interface";

export interface LogoutVerifierOptions {
  issuer: string;
  clientId: string;
  getVerificationKey(): Promise<JWTVerifyGetKey>;
  storage: LogoutStorage;
  algorithms?: readonly ("RS256" | "ES256" | "EdDSA")[];
  requireSid?: boolean;
  policy?: Partial<AuthPolicy>;
  now?: () => number;
}

export function createLogoutVerifier(options: LogoutVerifierOptions) {
  const policy = createAuthPolicy(options.policy);
  const now = options.now ?? Date.now;
  const algorithms = options.algorithms ?? ["RS256", "ES256", "EdDSA"];
  if (
    !options.issuer ||
    !options.clientId ||
    !algorithms.length ||
    algorithms.some(
      (algorithm) => !["RS256", "ES256", "EdDSA"].includes(algorithm),
    )
  )
    throw new AuthError("invalid_configuration");

  async function verify(token: string): Promise<VerifiedLogout> {
    if (!token || token.length > 32_768) throw new AuthError("rejected");
    let key: JWTVerifyGetKey;
    try {
      key = await options.getVerificationKey();
    } catch {
      throw new AuthError("unavailable");
    }
    try {
      const { payload } = await jwtVerify(token, key, {
        issuer: options.issuer,
        audience: options.clientId,
        algorithms: [...algorithms],
        typ: "logout+jwt",
        requiredClaims: ["iss", "aud", "iat", "exp", "jti", "events"],
        maxTokenAge: policy.logoutMaxAgeSeconds,
        clockTolerance: policy.clockToleranceSeconds,
        currentDate: new Date(now()),
      });
      const events = payload.events;
      const event =
        events && typeof events === "object" && !Array.isArray(events)
          ? (events as Record<string, unknown>)[
              "http://schemas.openid.net/event/backchannel-logout"
            ]
          : undefined;
      const identifier = (value: unknown) =>
        typeof value === "string" && value.length > 0 && value.length <= 255;
      if (
        payload.nonce !== undefined ||
        !identifier(payload.jti) ||
        (!identifier(payload.sub) && !identifier(payload.sid)) ||
        (payload.sub !== undefined && !identifier(payload.sub)) ||
        (payload.sid !== undefined && !identifier(payload.sid)) ||
        (options.requireSid && !identifier(payload.sid)) ||
        !event ||
        typeof event !== "object" ||
        Array.isArray(event) ||
        Object.keys(event).length !== 0 ||
        payload.exp! <= payload.iat! ||
        payload.exp! - payload.iat! > policy.logoutMaxAgeSeconds
      )
        throw new AuthError("rejected");
      return {
        jti: payload.jti!,
        subject: payload.sub,
        sid: payload.sid as string | undefined,
        issuedAt: payload.iat! * 1000,
        receiptExpiresAt: (payload.exp! + policy.clockToleranceSeconds) * 1000,
        revokeUntil: now() + policy.revocationRetentionMs,
      };
    } catch {
      throw new AuthError("rejected");
    }
  }

  async function handle(token: string) {
    const logout = await verify(token);
    // Verification never consumes the receipt on its own. The adapter commits the
    // receipt + revocation + session invalidation together, or rolls them all back.
    try {
      return { applied: await options.storage.apply(logout) };
    } catch {
      throw new AuthError("unavailable");
    }
  }
  return { verify, handle };
}
