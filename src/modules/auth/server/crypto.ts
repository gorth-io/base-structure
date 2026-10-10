import { AuthError } from "@/modules/auth/interface";
import type { AuthCipherOptions } from "@/utils/interface";
import { base64url, EncryptJWT, jwtDecrypt, type JWTPayload } from "jose";

export function randomAuthValue(): string {
  return base64url.encode(crypto.getRandomValues(new Uint8Array(32)));
}

export async function fingerprintAuthValue(value: string): Promise<string> {
  try {
    return base64url.encode(
      new Uint8Array(
        await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value)),
      ),
    );
  } catch {
    throw new AuthError("unavailable");
  }
}

export function equalAuthValue(left: string, right: string): boolean {
  if (left.length !== right.length) return false;
  let difference = 0;
  for (let index = 0; index < left.length; index++)
    difference |= left.charCodeAt(index) ^ right.charCodeAt(index);
  return difference === 0;
}

/** Framework-free authenticated encryption. Key management/rotation belongs to the app. */
export function createAuthCipher(options: AuthCipherOptions) {
  if (options.key.length !== 32 || !options.audience)
    throw new AuthError("invalid_configuration");
  const key = options.key.slice();
  const now = options.now ?? Date.now;
  return {
    async seal(
      data: JWTPayload,
      purpose: "credentials" | "transaction",
      expiresAt: number,
    ) {
      try {
        if (!Number.isFinite(expiresAt) || expiresAt <= now())
          throw new AuthError("rejected");
        return await new EncryptJWT({ data })
          .setProtectedHeader({
            alg: "dir",
            enc: "A256GCM",
            typ: "gorth-auth+jwe",
          })
          .setIssuer("gorth:" + purpose)
          .setAudience(options.audience)
          .setIssuedAt(Math.floor(now() / 1000))
          .setExpirationTime(Math.ceil(expiresAt / 1000))
          .encrypt(key);
      } catch (error) {
        if (error instanceof AuthError) throw error;
        throw new AuthError("unavailable");
      }
    },
    async open(
      value: string,
      purpose: "credentials" | "transaction",
    ): Promise<unknown> {
      try {
        if (value.length > 65_536) throw new AuthError("rejected");
        const { payload } = await jwtDecrypt(value, key, {
          issuer: "gorth:" + purpose,
          audience: options.audience,
          currentDate: new Date(now()),
          requiredClaims: ["exp", "iat"],
          keyManagementAlgorithms: ["dir"],
          contentEncryptionAlgorithms: ["A256GCM"],
        });
        return payload.data;
      } catch {
        throw new AuthError("rejected");
      }
    },
  };
}
