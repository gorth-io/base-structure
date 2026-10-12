import assert from "node:assert/strict";
import { readFile, readdir } from "node:fs/promises";
import { test } from "node:test";
import ts from "typescript";
import { createAuthFreshnessPolicy } from "../src/modules/auth/client";
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
