# Pure JavaScript Neural Network Inference

## Abstract

This document describes the pure JavaScript implementation of neural network inference for the SMTP bounce message classifier. The implementation performs inference without external machine learning frameworks.

## Table of Contents

1. [Model Architecture](#1-model-architecture)
2. [Weight File Format](#2-weight-file-format)
3. [Inference Implementation](#3-inference-implementation)
4. [Text Preprocessing](#4-text-preprocessing)
5. [Environment Compatibility](#5-environment-compatibility)

## 1. Model Architecture

### 1.1. Layer Structure

The model is a Keras Sequential network exported to TensorFlow.js format:

```
Input (int32, shape: [batch, 100])
    |
    v
Embedding (5000 -> 64)
    |
    v
GlobalAveragePooling1D
    |
    v
Dense (64 -> 64, ReLU)
    |
    v
Dense (64 -> 16, Softmax)
    |
    v
Output (float32, shape: [batch, 16])
```

### 1.2. Layer Parameters

| Layer                  | Input Shape | Output Shape | Parameters  |
| ---------------------- | ----------- | ------------ | ----------- |
| Embedding              | [100]       | [100, 64]    | 320,000     |
| GlobalAveragePooling1D | [100, 64]   | [64]         | 0           |
| Dense 1                | [64]        | [64]         | 4,160       |
| Dense 2                | [64]        | [16]         | 1,040       |
| **Total**              |             |              | **325,200** |

### 1.3. Hyperparameters

```javascript
const MAX_LENGTH = 100; // Maximum sequence length (tokens)
const EMBEDDING_DIM = 64; // Embedding vector dimensionality
const VOCAB_SIZE = 5000; // Vocabulary size (including special tokens)
const NUM_LABELS = 16; // Number of output classes
const HIDDEN_DIM = 64; // Hidden layer dimensionality
```

## 2. Weight File Format

### 2.1. File Structure

The model weights are stored in TensorFlow.js LayersModel format:

```
model/
  model.json           # Model topology and weight manifest
  vocab.json           # Vocabulary array (5000 tokens)
  labels.json          # Label mapping (id_to_label, label_to_id)
  group1-shard1of1.bin # Binary weight data (1,300,800 bytes)
```

### 2.2. Binary Weight Layout

Weights are stored as contiguous Float32 arrays in the order specified by `weightsManifest`:

| Offset (floats) | Size (floats) | Weight Name          | Shape      |
| --------------- | ------------- | -------------------- | ---------- |
| 0               | 4,096         | dense/kernel         | [64, 64]   |
| 4,096           | 64            | dense/bias           | [64]       |
| 4,160           | 1,024         | dense_1/kernel       | [64, 16]   |
| 5,184           | 16            | dense_1/bias         | [16]       |
| 5,200           | 320,000       | embedding/embeddings | [5000, 64] |

Total: 325,200 floats x 4 bytes = 1,300,800 bytes

### 2.3. Weight Parsing

```javascript
function parseWeights(data) {
  let offset = 0;

  // Dense layer 1: kernel [64, 64] and bias [64]
  const dense1Kernel = data.slice(offset, offset + 64 * 64);
  offset += 64 * 64;
  const dense1Bias = data.slice(offset, offset + 64);
  offset += 64;

  // Dense layer 2: kernel [64, 16] and bias [16]
  const dense2Kernel = data.slice(offset, offset + 64 * 16);
  offset += 64 * 16;
  const dense2Bias = data.slice(offset, offset + 16);
  offset += 16;

  // Embedding: [5000, 64]
  const embedding = data.slice(offset);

  return { embedding, dense1Kernel, dense1Bias, dense2Kernel, dense2Bias };
}
```

## 3. Inference Implementation

### 3.1. Forward Pass Overview

```
tokens[100] -> Embedding Lookup -> pooled[64] -> Dense1 -> hidden[64] -> Dense2 -> logits[16] -> Softmax -> probs[16]
```

### 3.2. Embedding Lookup and Pooling

The embedding layer maps each token ID to a 64-dimensional vector. GlobalAveragePooling1D computes the mean across all 100 timesteps:

```javascript
function embeddingAndPool(tokens, embeddingWeights) {
  const pooled = new Float32Array(EMBEDDING_DIM).fill(0);

  // Sum embeddings for all tokens
  for (let i = 0; i < MAX_LENGTH; i++) {
    const tokenId = tokens[i];
    const embOffset = tokenId * EMBEDDING_DIM;
    for (let j = 0; j < EMBEDDING_DIM; j++) {
      pooled[j] += embeddingWeights[embOffset + j];
    }
  }

  // Divide by sequence length (average over ALL timesteps)
  for (let j = 0; j < EMBEDDING_DIM; j++) {
    pooled[j] /= MAX_LENGTH;
  }

  return pooled;
}
```

**Important:** The pooling averages over all 100 timesteps including padding tokens (token ID 0). This matches TensorFlow's `GlobalAveragePooling1D` behavior when `mask_zero=False` in the embedding layer.

### 3.3. Dense Layer Computation

Dense layers perform: `output = activation(input @ kernel + bias)`

```javascript
function denseLayer(input, kernel, bias, inputDim, outputDim, activation) {
  const output = new Float32Array(outputDim);

  for (let i = 0; i < outputDim; i++) {
    let sum = bias[i];
    for (let j = 0; j < inputDim; j++) {
      // Kernel layout: [inputDim, outputDim] in row-major order
      sum += input[j] * kernel[j * outputDim + i];
    }
    output[i] = activation(sum);
  }

  return output;
}
```

### 3.4. Activation Functions

**ReLU (Rectified Linear Unit):**

```javascript
function relu(x) {
  return Math.max(0, x);
}
```

**Softmax:**

```javascript
function softmax(arr) {
  // Subtract max for numerical stability
  const max = Math.max(...arr);
  const exps = arr.map((x) => Math.exp(x - max));
  const sum = exps.reduce((a, b) => a + b, 0);
  return exps.map((e) => e / sum);
}
```

### 3.5. Complete Forward Pass

```javascript
function forward(tokens) {
  // 1. Embedding lookup + global average pooling
  const pooled = new Float32Array(EMBEDDING_DIM).fill(0);
  for (let i = 0; i < tokens.length; i++) {
    const tokenId = tokens[i];
    const embOffset = tokenId * EMBEDDING_DIM;
    for (let j = 0; j < EMBEDDING_DIM; j++) {
      pooled[j] += weights.embedding[embOffset + j];
    }
  }
  for (let j = 0; j < EMBEDDING_DIM; j++) {
    pooled[j] /= MAX_LENGTH;
  }

  // 2. Dense layer 1: [64] -> [64] with ReLU
  const hidden = new Float32Array(64);
  for (let i = 0; i < 64; i++) {
    let sum = weights.dense1Bias[i];
    for (let j = 0; j < 64; j++) {
      sum += pooled[j] * weights.dense1Kernel[j * 64 + i];
    }
    hidden[i] = relu(sum);
  }

  // 3. Dense layer 2: [64] -> [16]
  const output = new Float32Array(NUM_LABELS);
  for (let i = 0; i < NUM_LABELS; i++) {
    let sum = weights.dense2Bias[i];
    for (let j = 0; j < 64; j++) {
      sum += hidden[j] * weights.dense2Kernel[j * NUM_LABELS + i];
    }
    output[i] = sum;
  }

  // 4. Softmax activation
  return softmax(Array.from(output));
}
```

## 4. Text Preprocessing

### 4.1. Tokenization Pipeline

```
Raw Text -> Lowercase -> Remove Punctuation -> Whitespace Normalize -> Split -> Vocabulary Lookup -> Pad/Truncate
```

### 4.2. Text Normalization

```javascript
function preprocessText(text) {
  return text
    .toLowerCase() // Case folding
    .replace(/[^\w\s]/g, " ") // Remove punctuation
    .replace(/\s+/g, " ") // Collapse whitespace
    .trim();
}
```

### 4.3. Vocabulary Mapping

The vocabulary is loaded from `vocab.json` as an ordered array. Token IDs are array indices:

| Token ID | Meaning                       |
| -------- | ----------------------------- |
| 0        | Padding token                 |
| 1        | Out-of-vocabulary (OOV) token |
| 2+       | Vocabulary words              |

```javascript
function tokenize(text) {
  const processed = preprocessText(text);
  const words = processed.split(" ");
  const tokens = new Array(MAX_LENGTH).fill(0); // Pad with zeros

  for (let i = 0; i < Math.min(words.length, MAX_LENGTH); i++) {
    const word = words[i];
    if (vocabMap.has(word)) {
      tokens[i] = vocabMap.get(word);
    } else {
      tokens[i] = 1; // OOV token
    }
  }

  return tokens;
}
```

## 5. Environment Compatibility

### 5.1. Dual Environment Support

The implementation supports both Node.js and browser environments:

| Feature        | Node.js                    | Browser                         |
| -------------- | -------------------------- | ------------------------------- |
| File loading   | `fs.promises.readFile`     | `fetch()`                       |
| Path handling  | `path.join()`              | URL concatenation               |
| Binary parsing | `Buffer` -> `Float32Array` | `ArrayBuffer` -> `Float32Array` |

### 5.2. Module Loading Strategy

Node.js modules are loaded lazily to avoid browser errors:

```javascript
let _fs = null,
  _path = null,
  _url = null;
let _nodeModulesLoaded = false;

async function loadNodeModules() {
  if (_nodeModulesLoaded || isBrowser) return;
  _nodeModulesLoaded = true;

  _fs = await import("fs");
  _path = await import("path");
  _url = await import("url");
}
```

---

## Appendix A: Classification Labels

| ID  | Label              | Recommended Action |
| --- | ------------------ | ------------------ |
| 0   | user_unknown       | remove             |
| 1   | mailbox_full       | retry              |
| 2   | mailbox_disabled   | remove             |
| 3   | ip_blacklisted     | retry_different_ip |
| 4   | domain_blacklisted | fix_configuration  |
| 5   | spam_blocked       | review             |
| 6   | auth_failure       | fix_configuration  |
| 7   | greylisting        | retry              |
| 8   | rate_limited       | retry              |
| 9   | relay_denied       | fix_configuration  |
| 10  | server_error       | retry              |
| 11  | invalid_address    | remove             |
| 12  | policy_blocked     | review             |
| 13  | geo_blocked        | retry_different_ip |
| 14  | virus_detected     | remove_content     |
| 15  | unknown            | review             |

## Appendix B: References

1. TensorFlow.js LayersModel Format: https://www.tensorflow.org/js/guide/save_load
2. Keras Sequential Model: https://keras.io/guides/sequential_model/
3. RFC 3463 - Enhanced Mail System Status Codes
4. Global Average Pooling: https://keras.io/api/layers/pooling_layers/global_average_pooling1d/
