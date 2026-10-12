import assert from "node:assert/strict";
import { test } from "node:test";
import { createLocalJWKSet, exportJWK, generateKeyPair, SignJWT } from "jose";
import { createLogoutVerifier } from "../src/modules/auth/server";
import { revocationFixture } from "./auth.fixture";

test("backchannel verification is signed/typed/audience-bound and atomic/idempotent", async () => {
  const pair = await generateKeyPair("ES256");
  const resolver = createLocalJWKSet({
    keys: [{ ...(await exportJWK(pair.publicKey)), kid: "test" }],
  });
  const fixture = revocationFixture();
  const verifier = createLogoutVerifier({
    issuer: "https://identity.example/auth",
    clientId: "app",
    getVerificationKey: async () => resolver,
    storage: fixture.revocation,
  });
  const sign = async (
    claims: Record<string, unknown>,
    typ = "logout+jwt",
    audience = "app",
  ) =>
    await new SignJWT(claims)
      .setProtectedHeader({ alg: "ES256", kid: "test", typ })
      .setIssuer("https://identity.example/auth")
      .setAudience(audience)
      .setIssuedAt()
      .setExpirationTime("2m")
      .sign(pair.privateKey);
  const base = {
    jti: "event",
    sub: "sub",
    sid: "sid",
    events: { "http://schemas.openid.net/event/backchannel-logout": {} },
  };
  const token = await sign(base);
  await verifier.verify(token);
  assert.equal(fixture.receipts.size, 0);
  assert.deepEqual(
    (await Promise.all([verifier.handle(token), verifier.handle(token)]))
      .map((r) => r.applied)
      .sort(),
    [false, true],
  );
  assert.equal(
    await fixture.revocation.isRevoked({
      subject: "sub",
      sid: "sid",
      issuedAt: Date.now(),
      now: Date.now(),
    }),
    true,
  );
  for (const claims of [
    { ...base, nonce: "invalid" },
    { ...base, events: {} },
    { ...base, sid: undefined, sub: undefined },
    { ...base, jti: "" },
  ])
    await assert.rejects(verifier.handle(await sign(claims)), {
      code: "rejected",
    });
  await assert.rejects(verifier.verify(await sign(base, "JWT")), {
    code: "rejected",
  });
  await assert.rejects(
    verifier.verify(await sign(base, "logout+jwt", "other")),
    { code: "rejected" },
  );
  assert.equal(fixture.receipts.size, 1);
});
