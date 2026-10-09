import { test } from "node:test";
import assert from "node:assert/strict";
import {
  calculateJwkThumbprint,
  exportJWK,
  generateKeyPair,
  SignJWT,
  base64url,
} from "jose";
import { createResourceAuth } from "../src/modules/auth/server/resource";
import { AuthError } from "../src/modules/auth/interface";
import type { ResourceAuthOptions } from "../src/modules/auth/server/resource";
import { sessionFixture } from "./auth.fixture";

test("resource verifier enforces audience/scopes, DPoP binding and shared replay storage", async () => {
  const signing = await generateKeyPair("ES256");
  const jwk = {
    ...(await exportJWK(signing.publicKey)),
    kid: "resource-test",
    alg: "ES256",
  };
  const previousFetch = globalThis.fetch;
  globalThis.fetch = async () =>
    new Response(JSON.stringify({ keys: [jwk] }), {
      headers: { "Content-Type": "application/json" },
    });
  try {
    const fixture = sessionFixture();
    const proofs = new Set<string>();
    let online = 0;
    const options: ResourceAuthOptions = {
      verification: {
        jwksUrl: "https://sso.example/auth/jwks-resource",
        requiredScopes: ["read:profile"],
        verifyOptions: {
          issuer: "https://sso.example/auth",
          audience: "https://resource.example",
        },
      },
      revocation: fixture.revocation,
      proof: {
        async consume(key) {
          if (proofs.has(key)) return false;
          proofs.add(key);
          return true;
        },
      },
      async verifyActive() {
        online++;
      },
      onlineVerification: "sensitive",
    };
    const left = createResourceAuth(options),
      right = createResourceAuth(options);
    const sign = (
      claims: Record<string, unknown>,
      audience = "https://resource.example",
    ) =>
      new SignJWT({
        sub: "subject-a",
        sid: "sid-a",
        scope: "read:profile",
        ...claims,
      })
        .setProtectedHeader({ alg: "ES256", kid: jwk.kid })
        .setIssuer("https://sso.example/auth")
        .setAudience(audience)
        .setIssuedAt()
        .setExpirationTime("5m")
        .sign(signing.privateKey);
    const token = await sign({});
    const request = {
      authorizationHeader: "Bearer " + token,
      method: "GET",
      url: "https://resource.example/profile",
    };
    assert.equal((await left.verify(request)).sub, "subject-a");
    assert.equal(online, 0);
    await left.verify(request, { sensitive: true });
    assert.equal(online, 1);
    await assert.rejects(
      left.verify({
        ...request,
        authorizationHeader:
          "Bearer " + (await sign({}, "https://wrong.example")),
      }),
    );
    await assert.rejects(
      left.verify({
        ...request,
        authorizationHeader: "Bearer " + (await sign({ scope: "other-scope" })),
      }),
    );

    const proofKeys = await generateKeyPair("ES256");
    const proofJwk = await exportJWK(proofKeys.publicKey);
    const jkt = await calculateJwkThumbprint(proofJwk);
    const boundToken = await sign({ cnf: { jkt } });
    const ath = base64url.encode(
      new Uint8Array(
        await crypto.subtle.digest(
          "SHA-256",
          new TextEncoder().encode(boundToken),
        ),
      ),
    );
    const proof = await new SignJWT({
      jti: "proof-once",
      htm: "GET",
      htu: request.url,
      ath,
    })
      .setProtectedHeader({ alg: "ES256", typ: "dpop+jwt", jwk: proofJwk })
      .setIssuedAt()
      .sign(proofKeys.privateKey);
    const bound = {
      ...request,
      authorizationHeader: "DPoP " + boundToken,
      dpopProofJwt: proof,
    };
    assert.equal((await left.verify(bound)).sub, "subject-a");
    await assert.rejects(right.verify(bound), { code: "rejected" });
    await assert.rejects(
      left.verify({ ...bound, authorizationHeader: "Bearer " + boundToken }),
    );

    await fixture.revocation.apply({
      jti: "logout",
      sid: "sid-a",
      subject: "subject-a",
      issuedAt: Date.now(),
      receiptExpiresAt: Date.now() + 120_000,
      revokeUntil: Date.now() + 86_400_000,
    });
    await assert.rejects(left.verify(request), { code: "rejected" });
  } finally {
    globalThis.fetch = previousFetch;
  }
});

test("resource config disallows regex identities, insecure endpoints and symmetric algorithms", () => {
  const fixture = sessionFixture();
  const options: ResourceAuthOptions = {
    verification: {
      jwksUrl: "https://sso.example/jwks",
      verifyOptions: {
        issuer: "https://sso.example/auth",
        audience: "https://resource.example",
      },
    },
    revocation: fixture.revocation,
    proof: {
      async consume() {
        return true;
      },
    },
    async verifyActive() {},
    onlineVerification: "always",
  };
  assert.throws(
    () =>
      createResourceAuth({
        ...options,
        verification: {
          ...options.verification,
          jwksUrl: "http://evil.example/jwks",
        },
      }),
    AuthError,
  );
  assert.throws(
    () =>
      createResourceAuth({
        ...options,
        verification: {
          ...options.verification,
          verifyOptions: {
            ...options.verification.verifyOptions,
            audience: /.*/ as never,
          },
        },
      }),
    AuthError,
  );
  assert.throws(
    () =>
      createResourceAuth({
        ...options,
        verification: {
          ...options.verification,
          verifyOptions: {
            ...options.verification.verifyOptions,
            algorithms: ["HS256"],
          },
        },
      }),
    AuthError,
  );
});
