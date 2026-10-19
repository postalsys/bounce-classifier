'use strict';

// Loads the CommonJS bundle the way EmailEngine does: require() of the package name, which the
// exports map resolves to dist/index.cjs. Run through `npm run test:cjs`, which builds first and
// sets NODE_OPTIONS=--no-experimental-require-module so an ES module anywhere in the graph fails
// here instead of inside EmailEngine's pkg binary. Needs the model (`npm run update-model`).

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { isBuiltin } = require('node:module');

const bundlePath = path.join(__dirname, '..', 'dist', 'index.cjs');
const source = fs.readFileSync(bundlePath, 'utf8');

// esbuild must inline everything: the only modules the bundle may load at runtime are Node
// built-ins, and no dynamic import() may survive (pkg cannot trace or load one).
const required = [...source.matchAll(/\brequire\(\s*["']([^"']+)["']\s*\)/g)].map(m => m[1]);
for (const name of required) {
    assert.ok(isBuiltin(name), `dist/index.cjs requires a non-builtin module: ${name}`);
}
assert.ok(!/\bimport\s*\(/.test(source), 'dist/index.cjs still contains a dynamic import()');

const classifier = require('@postalsys/bounce-classifier');
assert.equal(require.resolve('@postalsys/bounce-classifier'), bundlePath);

classifier
    .initialize()
    .then(() => classifier.classify('550 5.1.1 <nobody@example.com>: Recipient address rejected: User unknown in virtual mailbox table'))
    .then(result => {
        assert.equal(result.label, 'user_unknown');
        assert.equal(result.action, classifier.ACTION_MAP.user_unknown);
        console.log(`CommonJS bundle OK: ${required.length} built-in requires, sample bounce classified as ${result.label}`);
    })
    .catch(err => {
        console.error(err);
        process.exit(1);
    });
