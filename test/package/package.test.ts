import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { execFile, spawnSync } from 'node:child_process';
import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';

// These tests exercise the compiled output in dist/ (built by the pretest script) through the
// package.json exports map, the same way an installed copy of the package is loaded. Node
// resolves the package name to the package itself when the specifier is used from inside it.
const require = createRequire(import.meta.url);
const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
const tsc = require.resolve('typescript/bin/tsc');
const pkg = JSON.parse(fs.readFileSync(path.join(root, 'package.json'), 'utf8'));

// A non-literal specifier keeps TypeScript from resolving the built types at type-check time,
// when dist/ may not exist yet
const packageName: string = '@postalsys/bounce-classifier';

const hasDist = fs.existsSync(path.join(root, 'dist', 'cjs', 'index.js')) && fs.existsSync(path.join(root, 'dist', 'esm', 'index.js'));

// The public surface of the pre-TypeScript module, named exports and the default export object alike
const FUNCTIONS = [
    'classify',
    'classifyBatch',
    'clearTextFallbacks',
    'extractRetryTiming',
    'extractSmtpCodes',
    'getAction',
    'getCodeBasedFallback',
    'getLabels',
    'getModelInfo',
    'getTextBasedFallback',
    'identifyBlocklist',
    'initialize',
    'isReady',
    'registerTextFallback',
    'reload',
    'reset'
];
const CONSTANTS = ['ACTION_MAP', 'BLOCKLIST_PATTERNS', 'CODE_FALLBACK_THRESHOLD', 'SMTP_CODE_MAP', 'SMTP_MAIN_CODE_MAP'];

function assertShape(classifier: Record<string, any>): void {
    assert.deepEqual(Object.keys(classifier).sort(), [...CONSTANTS, ...FUNCTIONS, 'default'].sort());
    assert.deepEqual(Object.keys(classifier.default).sort(), [...CONSTANTS, ...FUNCTIONS].sort());
    for (const name of FUNCTIONS) {
        assert.equal(typeof classifier[name], 'function', name);
        assert.equal(classifier.default[name], classifier[name], `default.${name}`);
    }
    for (const name of CONSTANTS) {
        assert.equal(classifier.default[name], classifier[name], `default.${name}`);
    }
}

const SAMPLE = '550 5.1.1 <nobody@example.com>: Recipient address rejected: User unknown in virtual mailbox table';

describe('Built package', { timeout: 120 * 1000, skip: hasDist ? false : 'dist/ is not built, run npm run build first' }, () => {
    it('ships both module formats with type declarations', () => {
        for (const format of ['esm', 'cjs']) {
            for (const file of ['index.js', 'index.d.ts', 'model-location.js']) {
                assert.ok(fs.existsSync(path.join(root, 'dist', format, file)), `${format}/${file}`);
            }
        }
        assert.deepEqual(JSON.parse(fs.readFileSync(path.join(root, 'dist', 'esm', 'package.json'), 'utf8')), { type: 'module' });
        assert.deepEqual(JSON.parse(fs.readFileSync(path.join(root, 'dist', 'cjs', 'package.json'), 'utf8')), { type: 'commonjs' });
    });

    it('points every package.json entry at an existing file', () => {
        assert.equal(pkg.exports['.'].import, './dist/esm/index.js');
        assert.equal(pkg.exports['.'].require, './dist/cjs/index.js');
        assert.equal(pkg.main, './dist/cjs/index.js');
        assert.equal(pkg.module, './dist/esm/index.js');
        assert.equal(pkg.exports['./model/*'], './model/*');
        for (const target of [pkg.main, pkg.module, pkg.types, pkg.exports['.'].import, pkg.exports['.'].require, pkg.exports['./package.json']]) {
            assert.ok(fs.existsSync(path.join(root, target)), target);
        }
    });

    it('packs the build and the model and leaves the sources and tests out', () => {
        // --ignore-scripts: prepare would rebuild dist/ under the running suite
        const result = spawnSync('npm', ['pack', '--dry-run', '--json', '--ignore-scripts'], { cwd: root, encoding: 'utf8' });
        assert.equal(result.status, 0, result.stderr);
        const files: string[] = JSON.parse(result.stdout)[0].files.map((file: { path: string }) => file.path);
        const required = [
            'package.json',
            'dist/cjs/index.js',
            'dist/cjs/index.d.ts',
            'dist/cjs/model-location.js',
            'dist/cjs/package.json',
            'dist/esm/index.js',
            'dist/esm/model-location.js',
            'dist/esm/package.json'
        ];
        // model/ is downloaded, not tracked; the publish job fetches it before packing
        for (const file of ['vocab.json', 'labels.json', 'group1-shard1of1.bin', 'config.json']) {
            if (fs.existsSync(path.join(root, 'model', file))) {
                required.push(`model/${file}`);
            }
        }
        for (const file of required) {
            assert.ok(files.includes(file), `${file} is packed`);
        }
        for (const file of files) {
            assert.ok(!/^(src|test|scripts|example|docs|coverage)\//.test(file), `${file} must not be packed`);
            assert.ok(file !== 'model/keras_model.h5', 'the Keras model is left out');
        }
    });

    describe('CommonJS build', () => {
        it('resolves require() to the CommonJS entry point', () => {
            assert.equal(require.resolve(packageName), path.join(root, 'dist', 'cjs', 'index.js'));
        });

        it('keeps the shape of the pre-TypeScript module', () => {
            assertShape(require(packageName));
        });

        it('loads the model from the package root by default', async () => {
            const classifier = require(packageName);
            classifier.reset();
            // EmailEngine passes initialize to .then(), so it runs detached from the module object
            await Promise.resolve().then(classifier.initialize);
            assert.equal((await classifier.classify(SAMPLE)).label, 'user_unknown');
            classifier.reset();
        });
    });

    describe('ES module build', () => {
        it('resolves import to the ES module entry point', async () => {
            const direct = await import(new URL('../../dist/esm/index.js', import.meta.url).href);
            const byName = await import(packageName);
            assert.equal(byName.classify, direct.classify);
        });

        it('exposes named and default exports', async () => {
            assertShape(await import(packageName));
        });

        it('loads the model from the package root by default', async () => {
            const classifier = await import(packageName);
            classifier.reset();
            await classifier.initialize();
            assert.equal((await classifier.classify(SAMPLE)).label, 'user_unknown');
            classifier.reset();
        });

        it('keeps Node built-ins out of the static import graph, for the browser', () => {
            for (const file of ['index.js', 'model-location.js']) {
                const source = fs.readFileSync(path.join(root, 'dist', 'esm', file), 'utf8');
                const staticImports = [...source.matchAll(/^import\s.*?from\s+['"]([^'"]+)['"]/gm)].map(match => match[1]);
                assert.deepEqual(
                    staticImports.filter(specifier => !specifier!.startsWith('./')),
                    [],
                    `dist/esm/${file}`
                );
            }
        });
    });

    // each tsc run has its own temporary project, so they run side by side
    describe('type declarations', { concurrency: true }, () => {
        // Holds the declarations to the precision of the hand-written index.d.ts they replaced
        const esmConsumer = `
import { classify, classifyBatch, initialize, reload, getAction, identifyBlocklist, extractSmtpCodes, getModelInfo, getLabels, ACTION_MAP } from '@postalsys/bounce-classifier';
import classifier from '@postalsys/bounce-classifier';
import type { BounceAction, BounceLabel, ClassificationResult, InitProgress, BlocklistInfo, MultipleBlocklistInfo, TextFallbackEntry } from '@postalsys/bounce-classifier';

export async function run(text: string, path: string | undefined): Promise<string[]> {
    await initialize({ modelPath: path, onProgress: (progress: InitProgress) => void progress.phase });
    await reload();
    const result: ClassificationResult = await classify(text);
    const label: BounceLabel = result.label;
    const action: BounceAction = result.action;
    const fromMap: BounceAction = ACTION_MAP[label];
    const score: number = result.scores.user_unknown;
    const model: BounceLabel | undefined = result.modelLabel;
    const retry: number | undefined = result.retryAfter;
    const blocklist: BlocklistInfo | MultipleBlocklistInfo | undefined = result.blocklist;
    const found: BlocklistInfo | MultipleBlocklistInfo | null = identifyBlocklist(text);
    const main: string | null = extractSmtpCodes(text).mainCode;
    const hash: string | null = getModelInfo().modelHash;
    const labels: BounceLabel[] = await getLabels();
    const batch: ClassificationResult[] = await classifyBatch([text]);
    const custom: BounceAction = getAction('anything');
    const entry: TextFallbackEntry = { pattern: /x/, label: 'custom' };
    classifier.registerTextFallback(entry);
    void [action, fromMap, score, model, retry, blocklist, found, main, hash, batch, custom];
    return labels;
}
`;

        const cjsConsumer = `
import classifier = require('@postalsys/bounce-classifier');

export async function run(): Promise<string> {
    await classifier.initialize();
    return (await classifier.classify('550 5.1.1 User unknown')).label;
}
`;

        // Each of these was a type error against the hand-written declarations too
        const rejectedConsumers: [string, string][] = [
            ['an unknown label', `import type { BounceLabel } from '@postalsys/bounce-classifier'; export const label: BounceLabel = 'nope';`],
            ['an unknown action', `import { getAction } from '@postalsys/bounce-classifier'; export const action: 'nope' = getAction('x');`],
            [
                'an unknown progress phase',
                `import type { InitProgress } from '@postalsys/bounce-classifier'; export const phase: InitProgress['phase'] = 'nope';`
            ],
            ['a non-string message', `import { classify } from '@postalsys/bounce-classifier'; export const result = classify(42);`],
            ['a string pattern', `import { registerTextFallback } from '@postalsys/bounce-classifier'; registerTextFallback({ pattern: 'x', label: 'y' });`],
            ['a module internal', `import { tokenize } from '@postalsys/bounce-classifier'; void tokenize;`]
        ];

        // Type-checks a consumer against the built declarations the way an installed copy is
        // resolved: the package is linked into a temporary project, so the specifier goes
        // through the package.json exports map
        const typeCheck = async (source: string, compilerOptions: Record<string, unknown>, type?: string): Promise<{ status: number; output: string }> => {
            const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'bounce-classifier-types-'));
            try {
                fs.mkdirSync(path.join(dir, 'node_modules', '@types'), { recursive: true });
                fs.mkdirSync(path.join(dir, 'node_modules', '@postalsys'), { recursive: true });
                fs.symlinkSync(root, path.join(dir, 'node_modules', '@postalsys', 'bounce-classifier'), 'dir');
                fs.symlinkSync(path.join(root, 'node_modules', '@types', 'node'), path.join(dir, 'node_modules', '@types', 'node'), 'dir');
                fs.writeFileSync(path.join(dir, 'package.json'), JSON.stringify({ name: 'consumer', private: true, ...(type ? { type } : {}) }));
                fs.writeFileSync(path.join(dir, 'consumer.ts'), source);
                fs.writeFileSync(
                    path.join(dir, 'tsconfig.json'),
                    JSON.stringify({
                        compilerOptions: {
                            target: 'ES2022',
                            lib: ['ES2023'],
                            types: ['node'],
                            strict: true,
                            exactOptionalPropertyTypes: true,
                            noEmit: true,
                            ...compilerOptions
                        },
                        include: ['consumer.ts']
                    })
                );
                return await new Promise(resolve => {
                    execFile(process.execPath, [tsc, '-p', path.join(dir, 'tsconfig.json')], (err, stdout, stderr) =>
                        resolve({ status: err ? Number(err.code) || 1 : 0, output: stdout + stderr })
                    );
                });
            } finally {
                fs.rmSync(dir, { recursive: true, force: true });
            }
        };

        const node16 = { module: 'node16', moduleResolution: 'node16' };

        for (const [label, options, type] of [
            ['a node16 ES module project', node16, 'module'],
            ['a node16 CommonJS project', node16, undefined],
            ['bundler resolution', { module: 'esnext', moduleResolution: 'bundler' }, 'module']
        ] as const) {
            it(`type-check an ES module style consumer in ${label}`, async () => {
                const { status, output } = await typeCheck(esmConsumer, { ...options, esModuleInterop: true }, type);
                assert.equal(status, 0, output);
            });
        }

        it('type-check a CommonJS consumer', async () => {
            const { status, output } = await typeCheck(cjsConsumer, node16);
            assert.equal(status, 0, output);
        });

        for (const [label, source] of rejectedConsumers) {
            it(`reject ${label}`, async () => {
                const { status, output } = await typeCheck(source, node16, 'module');
                assert.notEqual(status, 0, `${label} type-checked`);
                assert.match(output, /error TS\d+/);
            });
        }
    });
});
