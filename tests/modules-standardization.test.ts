import assert from "node:assert/strict";
import { readFile, readdir } from "node:fs/promises";
import { getEventListeners } from "node:events";
import { test } from "node:test";
import {
  createAuthClient,
  createAuthFreshnessPolicy,
} from "../src/modules/auth/client";
import { waitForAuthOperation } from "../src/modules/auth/client/retry";
import {
  createOidcDiscovery,
  createAuthCipher,
} from "../src/modules/auth/server";
import { exportJWK, generateKeyPair, jwtVerify, SignJWT } from "jose";
import ts from "typescript";
import {
  formatEpochMilliseconds,
  formatHexBytes,
  formatPublicSession,
  formatSessionCredentials,
} from "../src/utils/formatter";
import { deferred, sessionFixture } from "./auth.fixture";

test("redirect login does not read the old session; completed/legacy login reads once", async () => {
  for (const status of ["redirecting", "completed", undefined] as const) {
    let reads = 0;
    const state = createAuthClient({
      async read() {
        reads++;
        return { user: "account", expiresAt: 999_999 };
      },
      async login() {
        return status ? { status } : undefined;
      },
      async logout() {},
    });
    await state.login();
    assert.equal(reads, status === "redirecting" ? 0 : 1);
    assert.equal(
      state.getSnapshot().status,
      status === "redirecting" ? "loading" : "authenticated",
    );
    assert.equal(state.getSnapshot().busy, status === "redirecting");
    state.dispose();
  }
});

test("SDK adapter preserves the redirect completion signal", async () => {
  const { createSessionAuthAdapter } =
    await import("../src/modules/auth/client");
  let reads = 0;
  const state = createAuthClient(
    createSessionAuthAdapter({
      async getSession() {
        reads++;
        return { data: null };
      },
      async signOut() {
        return { data: null };
      },
      async login() {
        return { status: "redirecting" };
      },
      mapUser: (user: string) => user,
    }),
  );
  await state.login();
  assert.equal(reads, 0);
  state.dispose();
});

test("synchronous adapter errors release flights and cannot leak credentials", async () => {
  let reads = 0;
  const state = createAuthClient({
    read() {
      if (++reads === 1) throw new Error("SECRET");
      return Promise.resolve(null);
    },
    async login() {
      throw new Error("SECRET");
    },
    async logout() {},
  });
  await assert.rejects(state.load(), { message: "Authentication unavailable" });
  assert.equal(await state.load(), null);
  await assert.rejects(state.login(), {
    message: "Authentication unavailable",
  });
  await state.logout();
  assert.equal(state.getSnapshot().status, "anonymous");
  assert(!JSON.stringify(state.getSnapshot()).includes("SECRET"));
});

test("cancelled shared-operation wait still observes a late rejection", async () => {
  const controller = new AbortController();
  controller.abort();
  const wait = deferred<void>();
  const result = waitForAuthOperation(wait.promise, controller.signal);
  await assert.rejects(result, { name: "AbortError" });
  assert.equal(getEventListeners(controller.signal, "abort").length, 0);
  wait.reject(new Error("late failure"));
  await new Promise<void>((resolve) => setImmediate(resolve));
});

test("freshness policy has exact configurable boundaries and rejects invalid timestamps", () => {
  let now = 200_000;
  const freshness = createAuthFreshnessPolicy({}, () => now);
  const input = { verifiedAt: 100_000, accessExpiresAt: 1_000_000 };
  assert.deepEqual(freshness(input), {
    expired: false,
    refresh: false,
    verifyIdentity: false,
  });
  now = 220_000;
  assert.equal(freshness(input).verifyIdentity, true);
  assert.equal(
    freshness({ ...input, verifiedAt: now, fresh: true }).verifyIdentity,
    true,
  );
  assert.equal(
    freshness({ ...input, verifiedAt: now + 1 }).verifyIdentity,
    true,
  );
  assert.equal(
    freshness({ ...input, accessExpiresAt: now + 30_000 }).refresh,
    true,
  );
  assert.equal(freshness({ ...input, accessExpiresAt: now }).expired, true);
  for (const value of [NaN, Infinity, -1])
    assert.throws(() => freshness({ ...input, verifiedAt: value }), {
      code: "rejected",
    });
  const custom = createAuthFreshnessPolicy(
    { identityMaxAgeMs: 10, refreshLeewayMs: 0 },
    () => 100,
  );
  assert.equal(
    custom({ verifiedAt: 90, accessExpiresAt: 101 }).verifyIdentity,
    true,
  );
  assert.equal(custom({ verifiedAt: 91, accessExpiresAt: 101 }).refresh, false);
  assert.equal(
    custom({ verifiedAt: 99.5, accessExpiresAt: 100.5 }).expired,
    false,
  );
});

test("unknown key reload is coalesced, cooled down, and does not change a prepared resolver", async () => {
  const issuer = "https://sso.example/auth";
  const oldPair = await generateKeyPair("ES256"),
    newPair = await generateKeyPair("ES256");
  const oldKey = {
    ...(await exportJWK(oldPair.publicKey)),
    kid: "old",
    alg: "ES256",
  };
  const newKey = {
    ...(await exportJWK(newPair.publicKey)),
    kid: "new",
    alg: "ES256",
  };
  let published = [oldKey],
    now = Date.now(),
    calls = 0;
  const discovery = createOidcDiscovery({
    issuer,
    endpointOrigins: ["https://sso.example"],
    now: () => now,
    transport: {
      async request(url) {
        calls++;
        return {
          status: 200,
          data: url.endsWith("openid-configuration")
            ? { issuer, jwks_uri: issuer + "/jwks" }
            : { keys: published },
        };
      },
    },
  });
  const prepared = await discovery.getVerificationKey();
  assert.equal(await discovery.refreshForUnknownKey("old"), prepared);
  assert.equal(calls, 2);
  published = [oldKey, newKey];
  const [one, two] = await Promise.all([
    discovery.refreshForUnknownKey("new"),
    discovery.refreshForUnknownKey("new"),
  ]);
  assert.equal(one, two);
  assert.equal(calls, 4);
  const token = await new SignJWT({})
    .setProtectedHeader({ alg: "ES256", kid: "new" })
    .sign(newPair.privateKey);
  await jwtVerify(token, one);
  await assert.rejects(jwtVerify(token, prepared), {
    code: "ERR_JWKS_NO_MATCHING_KEY",
  });
  await assert.rejects(discovery.refreshForUnknownKey("random"), {
    code: "rejected",
  });
  assert.equal(calls, 4);
  now += 30_000;
  await assert.rejects(discovery.refreshForUnknownKey("random"), {
    code: "rejected",
  });
  assert.equal(calls, 6);
  await assert.rejects(discovery.refreshForUnknownKey("another"), {
    code: "rejected",
  });
  assert.equal(calls, 6);
});

test("unknown key input/configuration is bounded before making a request", async () => {
  let calls = 0;
  const options = {
    issuer: "https://sso.example/auth",
    endpointOrigins: ["https://sso.example"],
    transport: {
      async request() {
        calls++;
        throw new Error("offline");
      },
    },
  };
  for (const rotationCooldownMs of [-1, NaN, 3_600_001])
    assert.throws(
      () => createOidcDiscovery({ ...options, rotationCooldownMs }),
      { code: "invalid_configuration" },
    );
  const discovery = createOidcDiscovery(options);
  for (const kid of ["", "x".repeat(256), "bad\nkey"])
    await assert.rejects(discovery.refreshForUnknownKey(kid), {
      code: "rejected",
    });
  assert.equal(calls, 0);
});

test("shared formatters preserve projections and never mutate stored credentials", async () => {
  const fixture = sessionFixture();
  await fixture.service().create(fixture.login);
  const stored = [...fixture.records.values()][0];
  const publicValue = formatPublicSession(stored);
  assert.deepEqual(Object.keys(publicValue).sort(), ["expiresAt", "user"]);
  assert(!JSON.stringify(publicValue).includes("refreshToken"));
  const trusted = formatSessionCredentials(stored);
  trusted.credentials.accessToken = "changed";
  assert.notEqual(stored.credentials.accessToken, "changed");
  assert.equal(formatEpochMilliseconds(new Date(123_000)), 123_000);
  assert.equal(
    formatEpochMilliseconds(new Date(123_000).toISOString()),
    123_000,
  );
  assert.equal(formatHexBytes(new Uint8Array([0, 1, 255]).buffer), "0001ff");
});

test("encryption failures are sanitized without exposing the input payload", async () => {
  const cipher = createAuthCipher({
    key: new Uint8Array(32),
    audience: "fixture",
    now: () => 100,
  });
  await assert.rejects(
    cipher.seal({ private: "SECRET", invalid: 1n }, "credentials", 1_000),
    {
      code: "unavailable",
      message: "Authentication unavailable",
    },
  );
});

test("all module contracts live in utils and imports use aliases without Promise chains", async () => {
  async function inspect(directory: URL) {
    for (const entry of await readdir(directory, { withFileTypes: true })) {
      const path = new URL(entry.name, directory);
      if (entry.isDirectory()) {
        await inspect(new URL(entry.name + "/", directory));
        continue;
      }
      if (!entry.name.endsWith(".ts")) continue;
      const source = await readFile(path, "utf8");
      const ast = ts.createSourceFile(
        path.pathname,
        source,
        ts.ScriptTarget.Latest,
        true,
      );
      function check(node: ts.Node) {
        assert(
          !ts.isInterfaceDeclaration(node) && !ts.isTypeAliasDeclaration(node),
          path.pathname,
        );
        if (
          (ts.isImportDeclaration(node) || ts.isExportDeclaration(node)) &&
          node.moduleSpecifier &&
          ts.isStringLiteral(node.moduleSpecifier)
        )
          assert(!node.moduleSpecifier.text.startsWith("."), path.pathname);
        if (
          ts.isCallExpression(node) &&
          ts.isPropertyAccessExpression(node.expression)
        )
          assert(
            !["then", "catch", "finally"].includes(node.expression.name.text),
            path.pathname,
          );
        ts.forEachChild(node, check);
      }
      check(ast);
      assert.doesNotMatch(source, /process\.env|import\.meta\.env/);
    }
  }
  await inspect(new URL("../src/modules/", import.meta.url));
});
