import { test } from "node:test";
import assert from "node:assert/strict";
import { createRequire } from "node:module";
import { readFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const require = createRequire(import.meta.url);

test("native auth helpers expose ESM/CommonJS without legacy engines", async () => {
  for (const entry of ["client", "server"]) {
    const path = "@gorth/structure/modules/auth/" + entry;
    for (const module of [await import(path), require(path)]) {
      for (const name of entry === "client"
        ? ["createAuthRetry"]
        : [
          "AuthError",
          "createIdentityCache",
          "createOAuthIdentityValidator",
          "createSessionGrantGuard",
          "matchesAuthRevocation",
          "createResourceAuth",
          "createLogoutVerifier",
          "fingerprintAuthValue",
          "assertMutationOrigin",
        ])
        assert.equal(typeof module[name], "function");
      for (const retired of [
        "createOAuthProvider",
        "createSessionService",
        "createAuthClient",
        "createSessionAuthAdapter",
        "createBffSigner",
        "createBffVerifier",
        "createAuthCipher",
        "createOidcDiscovery",
        "createSessionBoundTransport",
      ])
        assert.equal(module[retired], undefined);
    }
  }
  assert.throws(() => require("@gorth/structure/modules/auth/desktop"));
});

test("Better Auth is an app-owned required peer, not a Structure SDK export", async () => {
  const manifest = JSON.parse(await readFile(new URL("../package.json", import.meta.url), "utf8"));
  assert.equal(manifest.peerDependencies["better-auth"], "^1.7");
  assert.notEqual(manifest.peerDependenciesMeta?.["better-auth"]?.optional, true);
  assert.equal(manifest.dependencies["better-auth"], undefined);
  assert.equal(manifest.devDependencies["better-auth"], "1.7");
  for (const name of Object.keys(manifest.dependencies))
    assert.ok(!name.startsWith("@better-auth/"), name);
  const retiredPaths = [
    "cores/auth", "cores/auth/index", "cores/auth/client", "cores/auth/client/vanilla",
    "cores/auth/server", "cores/auth/server/generic-oauth", "cores/auth/server/oap",
    "cores/auth/client/oap", "cores/auth/adapters", "cores/auth/cookies",
    "cores/auth/oauth2", "cores/auth/plugins", "cores/auth/integrations/next",
  ];
  for (const entry of retiredPaths) {
    const path = "@gorth/structure/" + entry;
    assert.throws(() => require(path), { code: "ERR_PACKAGE_PATH_NOT_EXPORTED" });
    await assert.rejects(import(path), { code: "ERR_PACKAGE_PATH_NOT_EXPORTED" });
  }
  const peer = await import("better-auth/oauth2");
  assert.equal(typeof peer.verifyAccessTokenRequest, "function");
});

test("public HTTP and desktop graphs contain no configured auth, env, Electron, Node or UI", async () => {
  const visited = new Set();
  async function inspect(path) {
    if (visited.has(path)) return;
    visited.add(path);
    const source = await readFile(path, "utf8");
    assert.doesNotMatch(
      source,
      /\bprocess\.env\b|import\.meta\.env|node:|better-auth|next\/|electron|@gorth\/primitive|\bfrom\s*["'](?:jose|pg|postgres|react)["']/,
    );
    for (const match of source.matchAll(
      /\b(?:from|import)\s*["']([^"']+)["']/g,
    )) {
      if (!match[1].startsWith(".")) {
        assert.ok(
          ["axios", "zod"].includes(match[1]),
          "unexpected browser dependency: " + match[1],
        );
        continue;
      }
      const dependency = resolve(dirname(path), match[1]);
      assert.ok(!dependency.includes("/server/"));
      await inspect(dependency);
    }
  }
  for (const path of [
    "@gorth/structure/modules/http",
    "@gorth/structure/modules/desktop",
  ])
    await inspect(fileURLToPath(import.meta.resolve(path)));
});

test("built package consumer uses HTTP and desktop exports without modifying applications", async () => {
  const { createCaller } = await import("@gorth/structure/modules/http");
  const { createDesktopRpcHandler, createDesktopRpcTransport } =
    await import("@gorth/structure/modules/desktop");
  const { default: axios, AxiosHeaders } = await import("axios");
  const { http } = createCaller({
    client: axios.create({
      adapter: async (config) => ({
        config,
        status: 200,
        statusText: "OK",
        headers: new AxiosHeaders(),
        data: { data: { name: "fixture" } },
      }),
    }),
  });
  assert.deepEqual(await http.get("/user"), { name: "fixture" });
  const handle = createDesktopRpcHandler({
    handle: async () => Response.json({ ok: true }),
  });
  const fetch = createDesktopRpcTransport({ request: handle });
  assert.deepEqual(
    await (await fetch("https://desktop.invalid/trpc/item.get")).json(),
    { ok: true },
  );
});

test("built client import graph is browser-safe and has no Next/Electron/server dependency", async () => {
  const visited = new Set();
  async function inspect(path) {
    if (visited.has(path)) return;
    visited.add(path);
    const source = await readFile(path, "utf8");
    assert.doesNotMatch(
      source,
      /\bprocess\.env\b|import\.meta\.env|node:|better-auth|next\/|electron|\b(?:jose|pg|postgres)\b/,
    );
    for (const match of source.matchAll(
      /\b(?:from|import)\s*["']([^"']+)["']/g,
    )) {
      assert.ok(
        match[1].startsWith("."),
        "external dependency leaked into client: " + match[1],
      );
      const dependency = resolve(dirname(path), match[1]);
      assert.ok(!dependency.includes("/server/"));
      await inspect(dependency);
    }
  }
  await inspect(
    fileURLToPath(import.meta.resolve("@gorth/structure/modules/auth/client")),
  );
  assert.ok(visited.size > 0);
});

test("new utils exports resolve in ESM/CJS and type contracts have no runtime dependencies", async () => {
  for (const module of [
    await import("@gorth/structure/utils/formatter"),
    require("@gorth/structure/utils/formatter"),
  ]) {
    assert.equal(module.formatEpochMilliseconds(new Date(100)), 100);
    assert.equal(module.normalizeAccelerator("Ctrl + a"), "Ctrl+A");
  }
  const types = await import("@gorth/structure/utils/interface");
  assert.deepEqual(Object.keys(types), []);
  assert.deepEqual(
    Object.keys(require("@gorth/structure/utils/interface")),
    [],
  );
  for (const module of [
    await import("@gorth/structure/modules/auth/client"),
    require("@gorth/structure/modules/auth/client"),
    await import("@gorth/structure/modules/auth/server"),
    require("@gorth/structure/modules/auth/server"),
  ]) {
    const freshness = module.createAuthFreshnessPolicy({}, () => 100);
    assert.equal(
      freshness({ verifiedAt: 99, accessExpiresAt: 101 }).expired,
      false,
    );
  }
});
