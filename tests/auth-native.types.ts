import { betterAuth } from "better-auth";
import { genericOAuth } from "better-auth/plugins/generic-oauth";
import { createAuthClient } from "better-auth/client";
import {
  createOAuthIdentityValidator,
  createIdentityCache,
  createSessionGrantGuard,
} from "../src/modules/auth/server";

// Type-check the installed official SDK contract; this fixture does not initialize auth or DB.
function nativeAuthFixture() {
  return betterAuth({
    plugins: [genericOAuth({ config: [] })],
    user: {
      validateUserInfo: createOAuthIdentityValidator({
        providerId: "example",
        subject: (user) => user.id,
      }),
    },
  });
}
const client = createAuthClient();
void client.signIn.social;
const cache = createIdentityCache({ load: async () => ({ sub: "subject" }) });
const profile: Promise<{ sub: string }> = cache.get("credential");
void profile;
const guard = createSessionGrantGuard({
  read: async () => null,
  assertAllowed: async () => {},
});
const result: Promise<number> = guard.run(
  async (binding) => binding.userId.length,
);
void result;
void nativeAuthFixture;
