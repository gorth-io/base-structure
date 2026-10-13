import assert from "node:assert/strict";
import { test } from "node:test";
import { memoryAdapter } from "better-auth/adapters/memory";
import { betterAuth } from "better-auth";
import { genericOAuth } from "better-auth/plugins/generic-oauth";

test("native Generic OAuth still owns state/PKCE/account selection through the app-owned SDK peer", async () => {
  const previousFetch = globalThis.fetch;
  globalThis.fetch = async () =>
    Response.json({
      issuer: "https://identity.example/auth",
      authorization_endpoint: "https://identity.example/auth/oauth2/authorize",
      token_endpoint: "https://identity.example/auth/oauth2/token",
      userinfo_endpoint: "https://identity.example/auth/oauth2/userinfo",
      jwks_uri: "https://identity.example/auth/jwks",
      response_types_supported: ["code"],
      subject_types_supported: ["public"],
      id_token_signing_alg_values_supported: ["RS256"],
    });
  try {
    const auth = betterAuth({
      baseURL: "https://application.example",
      basePath: "/auth",
      secret: "TEST-ONLY-NOT-A-DEPLOYMENT-SECRET-000000000000",
      database: memoryAdapter({}),
      plugins: [
        genericOAuth({
          config: [
            {
              providerId: "example",
              clientId: "fixture",
              discoveryUrl:
                "https://identity.example/auth/.well-known/openid-configuration",
              tokenEndpointAuth: { method: "none" },
              requireIdTokenVerification: true,
              scopes: ["openid", "profile", "email"],
              pkce: true,
              prompt: "select_account",
              disableProviderLogout: true,
            },
          ],
        }),
      ],
    });
    const response = await auth.handler(
      new Request("https://application.example/auth/sign-in/social", {
        method: "POST",
        headers: {
          "content-type": "application/json",
          origin: "https://application.example",
        },
        body: JSON.stringify({
          provider: "example",
          callbackURL: "https://application.example/",
        }),
      }),
    );
    assert.equal(response.status, 200);
    const result = (await response.json()) as { url: string };
    const url = new URL(result.url);
    assert.equal(url.origin, "https://identity.example");
    assert.equal(url.searchParams.get("prompt"), "select_account");
    assert.equal(url.searchParams.get("code_challenge_method"), "S256");
    assert.equal(
      url.searchParams.get("redirect_uri"),
      "https://application.example/auth/callback/example",
    );
    assert.ok(url.searchParams.get("state"));
    assert.ok(url.searchParams.get("code_challenge"));
    assert.ok(response.headers.get("set-cookie"));
  } finally {
    globalThis.fetch = previousFetch;
  }
});
