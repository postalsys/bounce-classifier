/**
 * Build script for generating CommonJS bundle from ESM source
 */

import { build } from "esbuild";
import { mkdir, writeFile } from "fs/promises";

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
    external: ["@tensorflow/tfjs", "fs", "path", "url"],
    banner: {
      js: `/* @postalsys/bounce-classifier - CommonJS build */
// Shim import.meta.url for CommonJS
var import_meta_url = require('url').pathToFileURL(__filename).href;
`,
    },
    define: {
      "import.meta.url": "import_meta_url",
    },
  });

  console.log("Built dist/index.cjs");
}

main().catch((err) => {
  console.error("Build failed:", err);
  process.exit(1);
});
