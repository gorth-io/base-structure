import assert from "node:assert/strict";
import { test } from "node:test";
import {
  assertMutationOrigin,
  authCookieOptions,
  createAuthPolicy,
  resolveReturnPath,
  createProofReplayStore,
} from "../src/modules/auth/server";
test("policy bounds, mutation origins, internal redirects and host-only cookies", () => {
  assert.equal(createAuthPolicy().transactionMaxAgeMs, 120_000);
  assert.equal(createAuthPolicy().identityMaxAgeMs, 120_000);
  assert.throws(() => createAuthPolicy({ revocationRetentionMs: 120_000 }));
  assert.throws(() => createAuthPolicy({ clockToleranceSeconds: 120 }));
  assert.throws(() => createAuthPolicy({ transactionMaxAgeMs: NaN }));
  assertMutationOrigin(new Headers({ origin: "https://app.example" }), [
    "https://app.example",
  ]);
  for (const headers of [
    new Headers(),
    new Headers({ origin: "https://evil.example" }),
    new Headers({
      origin: "https://app.example",
      "sec-fetch-site": "cross-site",
    }),
  ]) {
    assert.throws(() => assertMutationOrigin(headers, ["https://app.example"]));
  }
  for (const path of [
    "//evil.example",
    "/\\evil.example",
    "https://evil.example",
    "/\n/evil",
  ])
    assert.throws(() => resolveReturnPath(path));
  assert.equal(resolveReturnPath("/settings?mode=dark"), "/settings?mode=dark");
  assert.deepEqual(authCookieOptions({ secure: true, maxAgeSeconds: 0 }), {
    httpOnly: true,
    secure: true,
    sameSite: "lax",
    path: "/",
    maxAge: 0,
  });
});

test("DPoP adapter matches Better Auth reserve contract and shares atomic storage", async () => {
  const consumed = new Set<string>();
  const adapter = {
    async consume(key: string) {
      if (consumed.has(key)) return false;
      consumed.add(key);
      return true;
    },
  };
  const a = createProofReplayStore(adapter),
    b = createProofReplayStore(adapter);
  const request = {
    key: "key:thumbprint:jti",
    now: new Date(),
    expiresAt: new Date(Date.now() + 60_000),
  };
  assert.deepEqual(
    await Promise.all([a.reserve(request), b.reserve(request)]),
    [true, false],
  );
  await assert.rejects(
    Promise.resolve(a.reserve({ ...request, expiresAt: new Date(0) })),
  );
});
