// Builds the package.
//
// 1. Compiles src/ twice with tsc: once as ES modules into dist/esm and once as CommonJS into
//    dist/cjs. Each output directory gets its own package.json that pins the module format.
// 2. Replaces model-location.js in both outputs. The model directory sits at the package root,
//    two levels above dist/<format>/, and the CommonJS output can not use import.meta.url, so
//    each format gets a version of that file written for where it runs.
//
// Every module keeps the exports tsc gives it: src/index.ts has named exports plus a default
// export object, so `require('@postalsys/bounce-classifier')` returns the same object it always
// did (the named members plus `default`). No package-info module is generated: nothing in the
// library reports its own name or version.

import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import { createRequire } from 'node:module';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const require = createRequire(import.meta.url);
const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const tsc = require.resolve('typescript/bin/tsc');

const MODEL_LOCATION = {
    esm: [
        '// Written by scripts/build.js: the model directory at the package root',
        "export const defaultModelUrl = new URL('../../model', import.meta.url).href;"
    ],
    cjs: [
        '"use strict";',
        '// Written by scripts/build.js: the model directory at the package root',
        'Object.defineProperty(exports, "__esModule", { value: true });',
        'exports.defaultModelUrl = require("url").pathToFileURL(require("path").join(__dirname, "..", "..", "model")).href;'
    ]
};

function runTsc(project, ...args) {
    const result = spawnSync(process.execPath, [tsc, '-p', project, ...args], { cwd: root, stdio: 'inherit' });
    if (result.status !== 0) {
        process.exit(result.status || 1);
    }
}

function writeModelLocation(format) {
    const target = path.join(root, 'dist', format, 'model-location.js');
    // Fail loudly if src/model-location.ts stops exporting what this file replaces
    if (!fs.readFileSync(target, 'utf8').includes('defaultModelUrl')) {
        throw new Error(`${target} does not export defaultModelUrl`);
    }
    fs.writeFileSync(target, MODEL_LOCATION[format].join('\n') + '\n');
}

function build() {
    fs.rmSync(path.join(root, 'dist'), { recursive: true, force: true });

    runTsc('tsconfig.esm.json');
    // The ES module compile has already type-checked the same sources
    runTsc('tsconfig.cjs.json', '--noCheck');

    for (const [format, type] of [
        ['esm', 'module'],
        ['cjs', 'commonjs']
    ]) {
        fs.writeFileSync(path.join(root, 'dist', format, 'package.json'), JSON.stringify({ type }, null, 4) + '\n');
        writeModelLocation(format);
    }
}

build();
