'use strict';

// Loads the CommonJS build the way EmailEngine does: require() of the package name, which the
// exports map resolves to dist/cjs/index.js. Run through `npm run test:cjs`, which builds first and
// sets NODE_OPTIONS=--no-experimental-require-module so an ES module anywhere in the graph fails
// here instead of inside EmailEngine's pkg binary. Needs the model (`npm run update-model`).
// Kept as plain JavaScript on purpose: running it through tsx would let its loader transpile an
// ES module to CommonJS and mask exactly the failure this guards against.

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { isBuiltin } = require('node:module');

const root = path.resolve(__dirname, '..', '..');
const distDir = path.join(root, 'dist', 'cjs');

// The build must contain the real code: the only modules it may load at runtime are Node
// built-ins and its own files, and no dynamic import() may survive (pkg cannot trace or load one).
let requireCount = 0;
for (const file of fs.readdirSync(distDir).filter(name => name.endsWith('.js'))) {
    const source = fs.readFileSync(path.join(distDir, file), 'utf8');
    for (const [, name] of source.matchAll(/\brequire\(\s*["']([^"']+)["']\s*\)/g)) {
        requireCount++;
        assert.ok(isBuiltin(name) || name.startsWith('./'), `dist/cjs/${file} requires a non-builtin module: ${name}`);
    }
    assert.ok(!/\bimport\s*\(/.test(source), `dist/cjs/${file} still contains a dynamic import()`);
}

const classifier = require('@postalsys/bounce-classifier');
assert.equal(require.resolve('@postalsys/bounce-classifier'), path.join(distDir, 'index.js'));
assert.equal(classifier.default.classify, classifier.classify);

// EmailEngine's server.js: `Promise.resolve().then(bounceClassifier.initialize)` loads the model
// from its default location next to dist/, then `await bounceClassifier.classify(text)` per bounce
Promise.resolve()
    .then(classifier.initialize)
    .then(() => classifier.classify('550 5.1.1 <nobody@example.com>: Recipient address rejected: User unknown in virtual mailbox table'))
    .then(result => {
        assert.equal(result.label, 'user_unknown');
        assert.equal(result.action, classifier.ACTION_MAP.user_unknown);
        console.log(
            `CommonJS build OK (${process.version}, ${process.env.NODE_OPTIONS || 'no NODE_OPTIONS'}): ${requireCount} requires, sample bounce classified as ${result.label}`
        );
    })
    .catch(err => {
        console.error(err);
        process.exit(1);
    });
