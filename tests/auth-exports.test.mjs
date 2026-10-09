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
