# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

```bash
npm run build    # Build CommonJS version (dist/index.cjs) from ESM source
npm test         # Run test suite
```

## Architecture

This is a dual-mode npm package (ESM + CommonJS) for classifying SMTP bounce messages into 16 categories using TensorFlow.js.

### Key Components

- **src/index.js** - Main ESM source. Exports `classify()`, `classifyBatch()`, `initialize()`, and helper functions. Contains environment detection (browser vs Node.js) and a custom `NodeFileSystem` IO handler for loading TensorFlow models from local files in Node.js.

- **build.js** - Uses esbuild to bundle ESM source into CommonJS (`dist/index.cjs`). Shims `import.meta.url` for CJS compatibility.

- **model/** - TensorFlow.js model files (model.json, weights, vocab.json, labels.json). The keras_model.h5 is excluded from npm/git as it's only needed for Python retraining.

- **example/** - Standalone browser demo with local TensorFlow.js and Tailwind CSS (works offline).

### Classification Flow

1. Text is tokenized using vocab.json (5000 tokens, max 100 length)
2. TensorFlow.js model predicts scores for 16 labels
3. If confidence < 50%, text-based pattern fallbacks are tried first (e.g., "doesn't have account" → user_unknown)
4. Then SMTP code fallbacks are used (e.g., 5.1.1 → user_unknown)
5. Result includes label, confidence, recommended action, and optional blocklist/retry timing info

### Training Data

Model training is done separately in `../raw_data/train_model.py`. Training data is in `../training_data/bounces_labeled.jsonl`. After retraining, the model is exported directly to the `model/` folder.
