#!/usr/bin/env node

/**
 * Download the latest trained model from the Bounce Trainer service
 * and update the local model files.
 *
 * Usage:
 *   node scripts/update-model.js
 *   npm run update-model
 *
 * Set BOUNCE_TRAINER_URL to use a different server:
 *   BOUNCE_TRAINER_URL=http://localhost:3000 npm run update-model
 */

import {
  createWriteStream,
  mkdtempSync,
  mkdirSync,
  readFileSync,
  rmSync,
  readdirSync,
  copyFileSync,
  existsSync,
} from "fs";
import { join, resolve, dirname } from "path";
import { tmpdir } from "os";
import { fileURLToPath } from "url";
import { pipeline } from "stream/promises";
import { execSync } from "child_process";

const __dirname = dirname(fileURLToPath(import.meta.url));
const MODEL_DIR = resolve(__dirname, "..", "model");
if (!existsSync(MODEL_DIR)) {
  mkdirSync(MODEL_DIR, { recursive: true });
}
const BASE_URL =
  process.env.BOUNCE_TRAINER_URL || "https://bounces.postalsys.com";

async function main() {
  // Fetch current model info
  process.stdout.write("Checking remote model... ");
  const infoRes = await fetch(`${BASE_URL}/api/model/info`);
  if (!infoRes.ok) {
    throw new Error(`Failed to fetch model info: ${infoRes.status}`);
  }
  const info = await infoRes.json();
  const remoteHash = info.active?.modelHash;
  console.log(
    remoteHash ? `hash ${remoteHash.slice(0, 8)}` : "no hash available",
  );

  // Check local model hash
  let localHash = null;
  try {
    const config = JSON.parse(
      readFileSync(join(MODEL_DIR, "config.json"), "utf8"),
    );
    localHash = config.model_hash || null;
  } catch {
    // No local config
  }

  if (localHash) {
    console.log(`Local model:  ${localHash.slice(0, 8)}`);
  }

  if (remoteHash && remoteHash === localHash) {
    console.log("Model is already up to date.");
    return;
  }

  // Download model archive
  process.stdout.write("Downloading model... ");
  const modelRes = await fetch(`${BASE_URL}/api/model`);
  if (!modelRes.ok) {
    throw new Error(`Failed to download model: ${modelRes.status}`);
  }

  const tmpDir = mkdtempSync(join(tmpdir(), "bounce-model-"));
  const tarPath = join(tmpDir, "model.tar.gz");

  const fileStream = createWriteStream(tarPath);
  await pipeline(modelRes.body, fileStream);
  console.log("done");

  // Extract archive
  process.stdout.write("Extracting... ");
  const extractDir = join(tmpDir, "extracted");
  execSync(
    `mkdir -p "${extractDir}" && tar xzf "${tarPath}" -C "${extractDir}"`,
  );
  console.log("done");

  // Copy model files (skip README.txt and keras_model.h5)
  const SKIP = new Set(["README.txt", "keras_model.h5"]);
  const files = readdirSync(extractDir).filter(
    (f) => !SKIP.has(f) && !f.startsWith("."),
  );

  process.stdout.write("Updating model files... ");
  for (const file of files) {
    copyFileSync(join(extractDir, file), join(MODEL_DIR, file));
  }
  console.log(`${files.length} files updated`);

  // Show result
  try {
    const newConfig = JSON.parse(
      readFileSync(join(MODEL_DIR, "config.json"), "utf8"),
    );
    console.log(`\nUpdated model:`);
    console.log(`  Hash:       ${newConfig.model_hash || "n/a"}`);
    console.log(`  Trained:    ${newConfig.trained_at || "n/a"}`);
    console.log(`  Samples:    ${newConfig.training_samples || "n/a"}`);
    console.log(
      `  Accuracy:   ${newConfig.validation_accuracy ? (newConfig.validation_accuracy * 100).toFixed(1) + "%" : "n/a"}`,
    );
  } catch {
    // Config may not have all fields
  }

  // Cleanup
  rmSync(tmpDir, { recursive: true, force: true });

  console.log(
    "\nRun 'npm run build' to rebuild the CJS bundle with the new model.",
  );
}

main().catch((err) => {
  console.error(`\nError: ${err.message}`);
  process.exit(1);
});
