# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

```bash
npm test                  # node --test test/test.js (needs the model, see below)
npm run test:coverage     # c8 npm test
npm run lint              # eslint .
npm run lint:fix          # eslint . --fix
npm run format            # prettier --write .
npm run format:check      # prettier --check .
npm run build             # esbuild: src/index.js -> dist/index.cjs (CommonJS bundle)
npm run update-model      # download the latest model from bounces.postalsys.com into model/
npm run update            # rm -rf node_modules package-lock.json && ncu -u && npm install
```

Run a single test by name (Node's built-in test runner, `node:assert/strict` style assertions):

```bash
node --test --test-name-pattern="classifyBatch" test/test.js
```

The `model/` directory is not tracked in git (`.gitignore`). Run `npm run update-model` once before `npm test`; CI, the Pages deploy and `prepublishOnly` all download it fresh. Set `BOUNCE_TRAINER_URL` to fetch from a different trainer instance.

## Architecture

A single ESM module, `src/index.js`, that classifies SMTP bounce text into 16 labels and maps each label to an action (`ACTION_MAP`). It has no runtime dependencies and runs in both Node.js and the browser. `src/index.d.ts` holds the hand-written types; keep it in step with the exports.

- **Model loading.** `initialize()` loads `vocab.json`, `labels.json`, `group1-shard1of1.bin` (raw Float32 weights) and the optional `config.json` from `model/` (resolved relative to the module via `import.meta.url`, or `./model` in the browser, or `options.modelPath`). Initialization is memoised through `initPromise` and cleared on failure so a later call can retry. `reload()` waits for in-flight `classify()` calls to drain before swapping the model.
- **Inference.** Pure JavaScript forward pass (`tokenize()` -> embedding with average pooling -> dense layer with ReLU -> dense layer -> softmax) in `forward()`. Input is capped (`MAX_MESSAGE_LENGTH`, `MAX_LENGTH` tokens). No TensorFlow at runtime; `docs/inference.md` documents the weight layout.
- **Rule layer on top of the model.** Text patterns (`getTextBasedFallback()`, extendable with `registerTextFallback()`) override the model label; when the model is unsure (`CODE_FALLBACK_THRESHOLD`) or says `unknown`, the SMTP code maps (`SMTP_CODE_MAP`, `SMTP_MAIN_CODE_MAP`) decide. `confidence` is always the model's probability for the label actually returned (0 for labels the model does not know). `extractRetryTiming()` and `identifyBlocklist()` (`BLOCKLIST_PATTERNS`) enrich the result.
- **Dual package.** `exports` maps `import` to `src/index.js` and `require` to `dist/index.cjs`. `build.js` bundles with esbuild, shims `import.meta.url`, and rewrites the lazy `await import("fs"|"path"|"url")` calls into static requires so `pkg` can trace them. `dist/` is build output, not tracked, and is produced on publish.
- `example/index.html` is the browser demo deployed to GitHub Pages by `.github/workflows/pages.yml`. `Classifier.md` is the end-to-end technical overview (training and inference); the trainer itself lives elsewhere (bounces.postalsys.com).

## Critical constraints

- **EmailEngine consumes the CommonJS build.** `../emailengine/server.js` does `require('@postalsys/bounce-classifier')` (so it gets `dist/index.cjs`), calls `initialize()` at startup and `classify()` per bounce, and its `pkg` config ships `node_modules/@postalsys/bounce-classifier/model/**/*` as assets. Keep the `require` export working, keep the model in `model/` next to `dist/`, keep the Node built-ins loadable without dynamic `import()` in the bundle, and do not add runtime dependencies (especially ESM-only or native ones). CI smoke-tests the bundle after `npm run build`.
- **Browser compatibility.** `src/index.js` must keep running in the browser: Node modules are loaded lazily and only when `isBrowser` is false.
- **Releases are automated via release-please.** Version in `package.json` and `CHANGELOG.md` are owned by the bot; do not bump them by hand. The publish job downloads the latest model and builds before `npm publish`, so each release ships whatever model the trainer serves at that moment.

## Conventions

These mirror the conventions used across Postal Systems projects (see `../emailengine`).

**Git commits**

- Use Conventional Commits: `fix:` (patch release), `feat:` (minor release), and `chore:`/`docs:`/`ci:`/`build:`/`refactor:`/`style:`/`test:` for changes that should not trigger a release. release-please derives the version and changelog from these prefixes.
- Do **not** list Claude or any AI assistant as a co-author / co-contributor in commit messages or PR descriptions (no `Co-Authored-By` trailer).
- Append `[skip ci]` to commits that do not change runtime behavior (docs, comments, formatting) to avoid spending CI minutes. Exception: never add `[skip ci]` to a `fix:` or `feat:` commit, those must run so the release workflow triggers. GitHub reads the marker off the HEAD commit of a push, so when a push mixes the two, the release-triggering commit has to be last.

**Code and docs style**

- No emojis anywhere in code or documentation, printable ASCII only.
- Use a single hyphen-minus (`-`) as a dash in user-facing strings and docs. Never use double hyphens (`--`), em dashes, or en dashes.
- Formatting is Prettier (`.prettierrc`: 4 spaces, single quotes, print width 160); lint is the shared ESLint flat config in `eslint.config.js`.

**Before committing code changes**

1. `npm run format` and `npm run lint`
2. `npm test` (and `npm run build` if `src/` or `build.js` changed, then load `dist/index.cjs` with `require()`)
3. For non-trivial changes, consider `/simplify` and `/security-review`.

**After pushing**

- Check the workflow runs for the push (`gh run list --branch <branch>`) and report their status. If a run fails for an unrelated/infrastructure reason (checkout reporting "account suspended", HTTP 403, other auth errors), check <https://www.githubstatus.com/> for an active GitHub incident before assuming the change caused it.
