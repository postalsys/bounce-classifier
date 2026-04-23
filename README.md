# @postalsys/bounce-classifier

SMTP bounce message classifier using machine learning. Classifies email bounce/error messages into 16 actionable categories — and maps each to a concrete next step (`remove`, `retry`, `retry_different_ip`, `fix_configuration`, `review`, `remove_content`).

Runs entirely **client-side** in Node.js or the browser. No API calls, no PII leaves your infrastructure, no runtime dependencies, ~1.3 MB model, ~95% in-distribution accuracy.

**[Live Demo](https://postalsys.github.io/bounce-classifier/example/)** · **[Contribute labels →](https://bounces.postalsys.com)** (submitting mislabeled bounces improves the next model)

> [!NOTE]
> Built for [EmailEngine](https://emailengine.app), a self-hosted email gateway that speaks REST to IMAP/SMTP accounts. See the [messageBounce webhook docs](https://learn.emailengine.app/docs/webhooks/messagebounce#bounce-categories) for the integration.

## When to use

- High-volume bounce pipelines where per-classification API cost or latency matters.
- Privacy-sensitive workloads where bounce bodies must not leave the process.
- Offline / edge / browser contexts where a server call isn't an option.
- Any time you want *action* (`remove` vs. `retry` vs. `fix_configuration`) rather than just a label.

## When not to use

- Bouncing < 100 messages a day, all from a handful of providers — a regex is simpler.
- Non-English bounces outside the trainer's distribution — accuracy will be noticeably lower. Contribute samples at [bounces.postalsys.com](https://bounces.postalsys.com) if this matters.
- You need a single-call "parse this whole MIME bounce" pipeline — this library takes the human-readable diagnostic text; pair it with your DSN/ARF parser of choice.

## Labels

| Label                | Description                        | Action             |
| -------------------- | ---------------------------------- | ------------------ |
| `user_unknown`       | Recipient doesn't exist            | remove             |
| `invalid_address`    | Bad syntax, domain not found       | remove             |
| `mailbox_disabled`   | Account suspended/disabled         | remove             |
| `mailbox_full`       | Over quota, storage exceeded       | retry              |
| `greylisting`        | Temporary rejection, retry later   | retry              |
| `rate_limited`       | Too many connections/messages      | retry              |
| `server_error`       | Timeout, connection failed         | retry              |
| `ip_blacklisted`     | Sender IP on RBL                   | retry_different_ip |
| `domain_blacklisted` | Sender domain on blocklist         | fix_configuration  |
| `auth_failure`       | DMARC/SPF/DKIM failure             | fix_configuration  |
| `relay_denied`       | Relaying not permitted             | fix_configuration  |
| `spam_blocked`       | Message detected as spam           | review             |
| `policy_blocked`     | Local policy rejection             | review             |
| `virus_detected`     | Infected content detected          | remove_content     |
| `geo_blocked`        | Geographic/country-based rejection | retry_different_ip |
| `unknown`            | Unclassified — queue for review and [submit to the trainer](https://bounces.postalsys.com) | review             |

## Installation

```bash
npm install @postalsys/bounce-classifier
```

## Usage

### ES Modules (Browser & Node.js)

```javascript
import { classify, initialize } from "@postalsys/bounce-classifier";

// Optional: pre-load the model
await initialize();

const result = await classify("550 5.1.1 User Unknown");
console.log(result.label); // 'user_unknown'
console.log(result.confidence); // 0.95
console.log(result.action); // 'remove'
```

### CommonJS (Node.js)

```javascript
const { classify } = require("@postalsys/bounce-classifier");

async function main() {
  const result = await classify("550 5.1.1 User Unknown");
  console.log(result);
}

main();
```

### Browser Usage

```html
<script type="module">
  import { classify, initialize } from "./src/index.js";

  // Specify model path for browser
  await initialize({ modelPath: "./model" });

  const result = await classify("550 5.1.1 User Unknown");
  console.log(result);
</script>
```

See the `example/` folder for a complete standalone browser demo that works offline.

## API

### `initialize(options?): Promise<void>`

Pre-load the model and vocabulary. Called automatically on first classification, but calling it up front lets you report load progress to the user.

```javascript
// Node.js - uses bundled model automatically
await initialize();

// Browser - specify model path
await initialize({ modelPath: "./path/to/model" });

// With progress reporting (browser streams the weights file)
await initialize({
  modelPath: "./model",
  onProgress: ({ phase, loaded, total }) => {
    console.log(`${phase}: ${loaded}/${total}`);
  },
});
```

`phase` is one of `"vocab"`, `"labels"`, `"weights"`, or `"config"`. In the browser the `"weights"` phase streams and fires multiple events with monotonically increasing `loaded`; other phases fire once at completion.

### `classify(message: string): Promise<ClassificationResult>`

Classify a single bounce message.

```javascript
const result = await classify("450 Greylisted, try again in 5 minutes");
// {
//   label: 'greylisting',
//   confidence: 0.947,
//   action: 'retry',
//   retryAfter: 300,  // seconds (only if timing found in message)
//   scores: { ... }
// }

const result2 = await classify("550 blocked using zen.spamhaus.org");
// {
//   label: 'ip_blacklisted',
//   confidence: 0.958,
//   action: 'retry_different_ip',
//   blocklist: { name: 'Spamhaus ZEN', type: 'ip' },
//   scores: { ... }
// }
```

### `classifyBatch(messages: string[]): Promise<ClassificationResult[]>`

Classify an array of bounce messages. Sequential today; the API is reserved for future vectorization. Errors on any item include `.index` identifying the failing message.

```javascript
const results = await classifyBatch([
  "550 5.1.1 User unknown",
  "552 5.2.2 Over quota",
  "421 4.7.0 Try again later",
]);
```

### `registerTextFallback({ pattern, label })` / `clearTextFallbacks()`

Add project-specific text patterns that override the built-in fallback classification. User patterns are scanned before the built-ins. Survives `reset()` / `reload()`; clear explicitly with `clearTextFallbacks()`.

```javascript
import {
  registerTextFallback,
  clearTextFallbacks,
} from "@postalsys/bounce-classifier";

registerTextFallback({
  pattern: /XYZZY-PROVIDER-\d+/,
  label: "spam_blocked",
});
```

### `getLabels(): Promise<string[]>`

Get list of all possible classification labels.

```javascript
const labels = await getLabels();
// ['auth_failure', 'domain_blacklisted', 'geo_blocked', ...]
```

### `reload(options?): Promise<void>`

Reload the model, optionally from a new path. Waits for any in-flight `classify()` calls to drain before swapping state — safe to call concurrently.

```javascript
// Reload from the same path (e.g., after retraining)
await reload();

// Switch to a different model directory
await reload({ modelPath: "/path/to/new-model" });
```

### `getModelInfo(): ModelInfo`

Get metadata about the loaded model. Always returns an object; the `initialized` flag distinguishes "classifier not yet loaded" from "config.json missing a field."

```javascript
const info = getModelInfo();
// {
//   modelHash: '6b6a2c75307d59bf',    // truncated SHA-256 of weights
//   trainedAt: '2026-03-16T14:30:00Z', // ISO 8601 UTC
//   trainingSamples: 22630,
//   validationAccuracy: 0.9523,
//   initialized: true
// }
```

### `isReady(): boolean`

Check if the classifier is initialized.

### `reset(): void`

Reset classifier state for re-initialization. Does **not** clear user-registered text fallbacks — use `clearTextFallbacks()` for that.

### Low-level helpers

```javascript
import {
  extractRetryTiming,
  identifyBlocklist,
  getAction,
  extractSmtpCodes,
} from "@postalsys/bounce-classifier";

// Extract retry timing from message
const seconds = extractRetryTiming("try again in 5 minutes");
// 300

// Identify blocklists mentioned
const blocklist = identifyBlocklist("blocked by zen.spamhaus.org");
// { name: 'Spamhaus ZEN', type: 'ip' }

// Get recommended action for a label
const action = getAction("mailbox_full");
// 'retry'

// Extract SMTP codes
const codes = extractSmtpCodes("550 5.1.1 User unknown");
// { mainCode: '550', extendedCode: '5.1.1' }
```

## Custom Model Path

You can point the classifier to a different model directory, for example to use a retrained model:

```javascript
import {
  initialize,
  classify,
  reload,
  getModelInfo,
} from "@postalsys/bounce-classifier";

// Use a custom model at startup
await initialize({ modelPath: "/path/to/retrained-model" });

// Later, after retraining, reload the model without restarting
await reload();

// Check which model version is loaded
const info = getModelInfo();
console.log(info.modelHash); // '6b6a2c75307d59bf'
```

The model directory must contain `vocab.json`, `labels.json`, and `group1-shard1of1.bin`. The optional `config.json` provides metadata exposed through `getModelInfo()`. (`model.json`, kept for TensorFlow.js compatibility, is shipped alongside the model but is not loaded by this pure-JS implementation.)

## SMTP Code Fallback

When the ML model has low confidence (< 50%), the classifier falls back to SMTP status code–based classification using RFC 3463 enhanced status codes. This ensures reliable classification even for messages the model hasn't seen.

```javascript
const result = await classify("550 5.2.2 Over quota");
// If ML confidence is low, uses 5.2.2 -> mailbox_full fallback
// result.usedFallback will be true
```

## Running the Demo

The `example/` folder contains a browser demo. To run it:

```bash
cd example
npx serve ..
# Open http://localhost:3000/example/ in your browser
```

## Model Details

- **Architecture**: Embedding + GlobalAveragePooling + Dense layers
- **Vocabulary size**: 5,000 tokens
- **Max sequence length**: 100 tokens
- **Validation accuracy**: ~95% (held-out slice of the trainer corpus — this is in-distribution; real-world accuracy on your sender mix will depend on how well it's represented in the training data)
- **Model size**: ~1.3 MB
- **Runtime**: Pure JavaScript (no native dependencies)

Help improve accuracy by contributing labeled bounces at [bounces.postalsys.com](https://bounces.postalsys.com).

## License

MIT License - Copyright (c) Postal Systems OU
