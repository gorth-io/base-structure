import { AuthError } from "@/modules/auth/interface";
import type { OAuthIdentityValidatorOptions } from "@/utils/interface";
import type { BetterAuthOptions } from "better-auth";

/** Fits native user.validateUserInfo; the SDK verifies the OAuth response first. */
export function createOAuthIdentityValidator(
  options: OAuthIdentityValidatorOptions,
): NonNullable<NonNullable<BetterAuthOptions["user"]>["validateUserInfo"]> {
  if (!options.providerId) throw new AuthError("invalid_configuration");
  return async ({ user, source }) => {
    try {
      const profile = source.oauth?.profile;
      if (
        source.method !== "oauth" ||
        source.oauth?.providerId !== options.providerId ||
        typeof profile?.sub !== "string" ||
        !profile.sub ||
        profile.sub.length > 255 ||
        profile.sub !== options.subject(user)
      )
        return { error: "invalid_identity_source" };
      if (options.allowed && !(await options.allowed(profile)))
        return { error: "account_unavailable" };
    } catch {
      return { error: "account_unavailable" };
    }
  };
}
