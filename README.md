# @postalsys/bounce-classifier

SMTP bounce message classifier using TensorFlow.js machine learning. Classifies email bounce/error messages into 16 categories.

Works in both **Node.js** and **browsers** - runs entirely client-side with no server required.

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
  import {
    classify,
    initialize,
  } from "https://cdn.example.com/@postalsys/bounce-classifier/src/index.js";

  // Specify model path for browser
  await initialize({ modelPath: "./model" });

  const result = await classify("550 5.1.1 User Unknown");
  console.log(result);
</script>
```

See the `example/` folder for a complete browser demo.

## API

### `initialize(options?): Promise<void>`

Pre-load the model and vocabulary. Called automatically on first classification.

```javascript
// Node.js - uses bundled model automatically
await initialize();

// Browser - specify model path
await initialize({ modelPath: "./path/to/model" });
```

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

Classify multiple messages efficiently in a single batch.

```javascript
const results = await classifyBatch([
  "550 User Unknown",
  "452 Mailbox full",
  "421 Try again later",
]);
```

### `getLabels(): Promise<string[]>`

Get list of all possible classification labels.

```javascript
const labels = await getLabels();
// ['auth_failure', 'domain_blacklisted', 'geo_blocked', ...]
```

### `isReady(): boolean`

Check if the classifier is initialized.

### `reset(): void`

Reset classifier state for re-initialization.

### Helper Functions

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
| `unknown`            | Unclassified bounce type           | review             |

## SMTP Code Fallback

When the ML model has low confidence (< 50%), the classifier falls back to SMTP status code-based classification using RFC 3463 enhanced status codes. This ensures reliable classification even for messages the model hasn't seen.

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
- **Validation accuracy**: ~85%
- **Model size**: ~1.3 MB

## License

MIT License - Copyright (c) Postal Systems OU
