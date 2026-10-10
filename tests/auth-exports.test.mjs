import { test } from "node:test";
import assert from "node:assert/strict";
import { createRequire } from "node:module";
import { readFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const require = createRequire(import.meta.url);

test("published auth entrypoints expose both ESM and CommonJS APIs", async () => {
  for (const [entry, factory] of [
    ["client", "createAuthClient"],
    ["server", "createSessionService"],
    ["desktop", "createDesktopLogin"],
  ]) {
    const path = "@gorth/structure/modules/auth/" + entry;
    assert.equal(typeof (await import(path))[factory], "function");
    assert.equal(typeof require(path)[factory], "function");
    assert.equal(
      typeof (await import(path)).createOAuthProvider,
      entry === "server" ? "function" : "undefined",
    );
  }
});

test("all extracted infrastructure factories are available through public ESM/CJS entries", async () => {
  for (const [path, factories] of [
    [
      "@gorth/structure/modules/http",
      [
        "createFetcher",
        "toWebResponse",
        "createCaller",
        "normalizeCallerError",
      ],
    ],
    [
      "@gorth/structure/modules/desktop",
      [
        "createDesktopRpcHandler",
        "createDesktopRpcTransport",
        "createShortcutValidator",
      ],
    ],
    [
      "@gorth/structure/modules/auth/client",
      ["createAuthRetry", "createSessionAuthAdapter"],
    ],
    [
      "@gorth/structure/modules/auth/server",
      [
        "createSessionBoundTransport",
        "createOidcDiscovery",
        "createBffSigner",
        "createBffVerifier",
      ],
    ],
  ]) {
    const esm = await import(path),
      cjs = require(path);
    for (const factory of factories) {
      assert.equal(typeof esm[factory], "function", path + ":" + factory);
      assert.equal(typeof cjs[factory], "function", path + ":" + factory);
    }
  }
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

test("built SDK session adapter works through ESM and CJS without an SDK dependency", async () => {
  for (const module of [
    await import("@gorth/structure/modules/auth/client"),
    require("@gorth/structure/modules/auth/client"),
  ]) {
    const adapter = module.createSessionAuthAdapter({
      getSession: async () => ({
        data: {
          user: { id: "fixture", private: "SECRET" },
          session: {
            token: "SECRET",
            expiresAt: new Date(120_000),
          },
        },
      }),
      signOut: async () => ({ data: { success: true } }),
      mapUser: (user) => ({ id: user.id }),
      login: async () => {},
      now: () => 1_000,
    });
    const state = module.createAuthClient(adapter);
    assert.deepEqual(await state.load(), {
      user: { id: "fixture" },
      expiresAt: 120_000,
    });
    assert(!JSON.stringify(state.getSnapshot()).includes("SECRET"));
    await state.logout();
    assert.equal(state.getSnapshot().session, null);
    state.dispose();
  }
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
