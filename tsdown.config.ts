/// <reference types="node" />

import { defineConfig } from "tsdown";

export default defineConfig({
  clean: true,
  dts: true,
  fixedExtension: false,
  // Keep shared modules (e.g. React contexts) in common chunks
  // so different entrypoints consume the same runtime instance.
  // splitting: true,
  entry: [
    "src/index.ts",
    "src/lib/*.ts",
    "src/utils/*.ts",
    "src/modules/**/*.ts",
    "src/cores/**/*.ts",
  ],
  format: ["esm", "cjs"],
  sourcemap: false,
  minify: false,
  target: "es2024",
  outDir: "dist",
  treeshake: true,
});
