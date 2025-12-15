/**
 * Build script for generating CommonJS bundle from ESM source
 */

import { build } from "esbuild";
import { mkdir, readFile, writeFile } from "fs/promises";

async function main() {
  // Ensure dist directory exists
  await mkdir("./dist", { recursive: true });

  // Build CommonJS version with import.meta.url shimmed
  await build({
    entryPoints: ["./src/index.js"],
    bundle: true,
    platform: "node",
    target: "node18",
    format: "cjs",
    outfile: "./dist/index.cjs",
    external: ["@tensorflow/tfjs"],
    banner: {
      js: `/* @postalsys/bounce-classifier - CommonJS build */
// Shim import.meta.url for CommonJS
var import_meta_url = require('url').pathToFileURL(__filename).href;
// Pre-load Node.js modules for pkg compatibility
var _fs_module = require('fs');
var _path_module = require('path');
var _url_module = require('url');
`,
    },
    define: {
      "import.meta.url": "import_meta_url",
    },
  });

  // Post-process: replace dynamic imports with static requires for pkg compatibility
  let content = await readFile("./dist/index.cjs", "utf8");
  content = content
    .replace(/await import\("fs"\)/g, "_fs_module")
    .replace(/await import\("path"\)/g, "_path_module")
    .replace(/await import\("url"\)/g, "_url_module");
  await writeFile("./dist/index.cjs", content);

  console.log("Built dist/index.cjs");
}

main().catch((err) => {
  console.error("Build failed:", err);
  process.exit(1);
});
