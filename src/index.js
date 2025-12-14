/**
 * @postalsys/bounce-classifier
 * SMTP bounce message classifier using pure JavaScript inference
 *
 * Copyright (c) Postal Systems OU
 * Licensed under MIT
 */

// Configuration
const MAX_LENGTH = 100;
const MAX_MESSAGE_LENGTH = 10000; // Max characters per message
const EMBEDDING_DIM = 64;
const NUM_LABELS = 16;

// Detect environment
const isBrowser =
  typeof window !== "undefined" && typeof window.document !== "undefined";

// Action mapping based on bounce category
export const ACTION_MAP = {
  // Permanent failures - remove from list
  user_unknown: "remove",
  invalid_address: "remove",
  mailbox_disabled: "remove",

  // Temporary failures - retry later
  greylisting: "retry",
  rate_limited: "retry",
  server_error: "retry",
  mailbox_full: "retry",

  // IP/domain issues - retry with different IP or fix configuration
  ip_blacklisted: "retry_different_ip",
  domain_blacklisted: "fix_configuration",

  // Authentication issues - fix sender configuration
  auth_failure: "fix_configuration",

  // Content/policy issues - modify message or manual review
  spam_blocked: "review",
  policy_blocked: "review",
  virus_detected: "remove_content",
  geo_blocked: "retry_different_ip",
  relay_denied: "fix_configuration",

  // Unknown - manual review
  unknown: "review",
};

// Known blocklists and their patterns
export const BLOCKLIST_PATTERNS = [
  // Spamhaus
  { pattern: /spamhaus\.org/i, name: "Spamhaus", type: "ip" },
  { pattern: /\bsbl\b/i, name: "Spamhaus SBL", type: "ip" },
  { pattern: /\bxbl\b/i, name: "Spamhaus XBL", type: "ip" },
  { pattern: /\bpbl\b/i, name: "Spamhaus PBL", type: "ip" },
  { pattern: /\bdbl\.spamhaus/i, name: "Spamhaus DBL", type: "domain" },
  { pattern: /\bzen\.spamhaus/i, name: "Spamhaus ZEN", type: "ip" },

  // Barracuda
  { pattern: /barracuda/i, name: "Barracuda", type: "ip" },
  { pattern: /b\.barracudacentral/i, name: "Barracuda", type: "ip" },

  // SORBS
  { pattern: /sorbs\.net/i, name: "SORBS", type: "ip" },
  { pattern: /dnsbl\.sorbs/i, name: "SORBS", type: "ip" },

  // SpamCop
  { pattern: /spamcop\.net/i, name: "SpamCop", type: "ip" },

  // URIBL
  { pattern: /uribl\.com/i, name: "URIBL", type: "uri" },
  { pattern: /multi\.uribl/i, name: "URIBL", type: "uri" },

  // Cloudmark
  { pattern: /cloudmark/i, name: "Cloudmark", type: "ip" },

  // Proofpoint
  { pattern: /proofpoint/i, name: "Proofpoint", type: "ip" },

  // Mimecast
  { pattern: /mimecast/i, name: "Mimecast", type: "ip" },

  // Microsoft
  { pattern: /\bS3150\b/i, name: "Microsoft Blocklist", type: "ip" },

  // Invaluement
  { pattern: /invaluement/i, name: "Invaluement", type: "ip" },

  // Hostkarma
  { pattern: /hostkarma/i, name: "Hostkarma", type: "ip" },

  // Trend Micro
  { pattern: /trend\s*micro/i, name: "Trend Micro", type: "ip" },

  // Generic RBL detection
  { pattern: /\brbl\b/i, name: "RBL", type: "ip" },
  { pattern: /\bdnsbl\b/i, name: "DNSBL", type: "ip" },
  { pattern: /blacklist/i, name: "Blocklist", type: "ip" },
  { pattern: /blocklist/i, name: "Blocklist", type: "ip" },
];

// SMTP Enhanced Status Code mapping (RFC 3463)
export const SMTP_CODE_MAP = {
  "5.1.1": "user_unknown",
  "5.1.2": "invalid_address",
  "5.1.3": "invalid_address",
  "5.1.6": "invalid_address",
  "4.1.1": "user_unknown",
  "5.2.0": "user_unknown",
  "5.2.1": "mailbox_disabled",
  "5.2.2": "mailbox_full",
  "5.2.3": "rate_limited",
  "4.2.0": "greylisting",
  "4.2.1": "rate_limited",
  "4.2.2": "mailbox_full",
  "5.3.0": "server_error",
  "5.3.1": "server_error",
  "5.3.2": "server_error",
  "4.3.0": "server_error",
  "4.3.1": "server_error",
  "4.3.2": "server_error",
  "5.4.1": "user_unknown",
  "5.4.4": "server_error",
  "4.4.1": "server_error",
  "4.4.2": "server_error",
  "5.5.0": "user_unknown",
  "5.5.1": "invalid_address",
  "5.5.2": "invalid_address",
  "5.6.1": "policy_blocked",
  "5.6.2": "policy_blocked",
  "5.7.0": "virus_detected",
  "5.7.1": "policy_blocked",
  "5.7.2": "relay_denied",
  "5.7.8": "auth_failure",
  "5.7.9": "auth_failure",
  "5.7.23": "auth_failure",
  "5.7.25": "auth_failure",
  "5.7.26": "auth_failure",
  "4.7.0": "rate_limited",
  "4.7.1": "rate_limited",
  "4.7.3": "rate_limited",
  "4.7.28": "rate_limited",
  "4.7.32": "rate_limited",
  "4.7.650": "rate_limited",
  "4.7.651": "rate_limited",
  "5.2.121": "rate_limited",
  "5.2.122": "rate_limited",
};

export const SMTP_MAIN_CODE_MAP = {
  421: "greylisting",
  450: "greylisting",
  451: "server_error",
  452: "server_error",
  500: "invalid_address",
  501: "invalid_address",
  502: "server_error",
  503: "server_error",
  504: "server_error",
  550: "user_unknown",
  551: "relay_denied",
  552: "mailbox_full",
  553: "invalid_address",
  554: "policy_blocked",
  571: "spam_blocked",
};

export const CODE_FALLBACK_THRESHOLD = 0.5;

/**
 * Extract SMTP codes from a message
 */
export function extractSmtpCodes(message) {
  const result = { mainCode: null, extendedCode: null };
  const mainMatch = message.match(/^(\d{3})[\s-]/);
  if (mainMatch) result.mainCode = mainMatch[1];
  const extMatch = message.match(/\b([245])\.(\d{1,3})\.(\d{1,3})\b/);
  if (extMatch)
    result.extendedCode = `${extMatch[1]}.${extMatch[2]}.${extMatch[3]}`;
  return result;
}

// Text-based pattern fallbacks for common patterns
// Note: .{0,100}? limits match length to prevent performance issues on long strings
const TEXT_PATTERN_FALLBACKS = [
  { pattern: /doesn't have a .{0,50}? account/i, label: "user_unknown" },
  { pattern: /user doesn't have .{0,50}? account/i, label: "user_unknown" },
  { pattern: /not a valid recipient/i, label: "user_unknown" },
  { pattern: /no such user/i, label: "user_unknown" },
  { pattern: /user unknown/i, label: "user_unknown" },
  { pattern: /mailbox not found/i, label: "user_unknown" },
  { pattern: /recipient rejected/i, label: "user_unknown" },
  { pattern: /sender is unauthenticated/i, label: "auth_failure" },
  { pattern: /requires .{0,50}? authenticate/i, label: "auth_failure" },
];

/**
 * Get fallback classification based on text patterns
 */
export function getTextBasedFallback(message) {
  for (const { pattern, label } of TEXT_PATTERN_FALLBACKS) {
    if (pattern.test(message)) {
      return label;
    }
  }
  return null;
}

/**
 * Get fallback classification based on SMTP codes
 */
export function getCodeBasedFallback(message) {
  // First try text-based patterns (more specific)
  const textFallback = getTextBasedFallback(message);
  if (textFallback) {
    return textFallback;
  }

  // Then try SMTP codes
  const codes = extractSmtpCodes(message);
  if (codes.extendedCode && SMTP_CODE_MAP[codes.extendedCode]) {
    return SMTP_CODE_MAP[codes.extendedCode];
  }
  if (codes.mainCode && SMTP_MAIN_CODE_MAP[codes.mainCode]) {
    return SMTP_MAIN_CODE_MAP[codes.mainCode];
  }
  return null;
}

// Retry timing patterns
// Note: .{0,50}? limits match length to prevent performance issues on long strings
const RETRY_PATTERNS = [
  {
    pattern: /try\s+again\s+in\s+(\d+)\s*(second|minute|hour|min|sec|hr)s?/i,
    unit: 2,
  },
  {
    pattern: /retry\s+in\s+(\d+)\s*(second|minute|hour|min|sec|hr)s?/i,
    unit: 2,
  },
  { pattern: /wait\s+(\d+)\s*(second|minute|hour|min|sec|hr)s?/i, unit: 2 },
  {
    pattern:
      /greylisted?\s+(?:for\s+)?(\d+)\s*(second|minute|hour|min|sec|hr)s?/i,
    unit: 2,
  },
  {
    pattern: /delayed?\s+(?:for\s+)?(\d+)\s*(second|minute|hour|min|sec|hr)s?/i,
    unit: 2,
  },
  {
    pattern: /come\s+back\s+in\s+(\d+)\s*(second|minute|hour|min|sec|hr)s?/i,
    unit: 2,
  },
  { pattern: /after\s+(\d+)\s*(second|minute|hour|min|sec|hr)s?/i, unit: 2 },
  { pattern: /\b(\d+)\s*(second|minute|hour)s?\b/i, unit: 2 },
  {
    pattern: /too\s+many.{0,50}?(\d+)\s*(second|minute|hour|min|sec|hr)s?/i,
    unit: 2,
  },
  {
    pattern: /greylist.{0,50}?(\d+)\s*(second|minute|hour|min|sec|hr)s?/i,
    unit: 2,
  },
];

function toSeconds(value, unit) {
  const num = parseInt(value, 10);
  const u = unit.toLowerCase();
  if (u.startsWith("sec") || u === "s") return num;
  if (u.startsWith("min") || u === "m") return num * 60;
  if (u.startsWith("hour") || u === "hr" || u === "h") return num * 3600;
  return num;
}

/**
 * Extract retry timing from message
 */
export function extractRetryTiming(message) {
  for (const { pattern, unit } of RETRY_PATTERNS) {
    const match = message.match(pattern);
    if (match && match[1]) {
      const seconds = toSeconds(match[1], match[unit] || "seconds");
      if (seconds >= 1 && seconds <= 86400) {
        return seconds;
      }
    }
  }
  return null;
}

/**
 * Identify blocklists mentioned in message
 */
export function identifyBlocklist(message) {
  const found = [];
  for (const { pattern, name, type } of BLOCKLIST_PATTERNS) {
    if (pattern.test(message)) {
      if (!found.find((b) => b.name === name)) {
        found.push({ name, type });
      }
    }
  }
  if (found.length === 0) return null;
  const specific = found.filter(
    (b) => !["RBL", "DNSBL", "Blocklist"].includes(b.name),
  );
  if (specific.length > 0) {
    return specific.length === 1 ? specific[0] : { lists: specific };
  }
  return found[0];
}

/**
 * Get recommended action based on category
 */
export function getAction(category) {
  return ACTION_MAP[category] || "review";
}

/**
 * Sanitize and validate input message
 * @param {*} message - Input to validate
 * @param {string} context - Context for error messages
 * @returns {string} Sanitized message
 */
function sanitizeMessage(message, context = "Message") {
  if (message === null || message === undefined) {
    throw new Error(`${context} must be a non-empty string`);
  }

  if (typeof message !== "string") {
    throw new Error(`${context} must be a string, got ${typeof message}`);
  }

  // Check for empty or whitespace-only strings
  if (message.trim().length === 0) {
    throw new Error(`${context} must not be empty or whitespace-only`);
  }

  // Truncate overly long messages to prevent performance issues
  if (message.length > MAX_MESSAGE_LENGTH) {
    return message.substring(0, MAX_MESSAGE_LENGTH);
  }

  return message;
}

// Singleton state
let weights = null;
let vocabMap = null;
let labels = null;
let isInitialized = false;
let initPromise = null;
let modelBasePath = null;

/**
 * Preprocess text for tokenization
 */
function preprocessText(text) {
  return text
    .toLowerCase()
    .replace(/[^\w\s]/g, " ")
    .replace(/\s+/g, " ")
    .trim();
}

/**
 * Tokenize text using vocabulary
 */
function tokenize(text) {
  const processed = preprocessText(text);
  const words = processed.split(" ");
  const tokens = new Array(MAX_LENGTH).fill(0);

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

/**
 * Load JSON file (works in both browser and Node.js)
 */
async function loadJson(filePath) {
  if (isBrowser) {
    const response = await fetch(filePath);
    if (!response.ok) {
      throw new Error(`Failed to fetch ${filePath}: ${response.status}`);
    }
    return response.json();
  } else {
    // Node.js - use dynamic import
    const fs = await import("fs");
    return JSON.parse(await fs.promises.readFile(filePath, "utf8"));
  }
}

/**
 * Load binary weights file
 */
async function loadWeights(filePath) {
  if (isBrowser) {
    const response = await fetch(filePath);
    if (!response.ok) {
      throw new Error(`Failed to fetch ${filePath}: ${response.status}`);
    }
    const buffer = await response.arrayBuffer();
    return new Float32Array(buffer);
  } else {
    const fs = await import("fs");
    const buffer = await fs.promises.readFile(filePath);
    return new Float32Array(
      buffer.buffer,
      buffer.byteOffset,
      buffer.byteLength / 4,
    );
  }
}

/**
 * Parse weights from binary data according to model structure
 * Order from model.json weightsManifest:
 * - dense/kernel: [64, 64]
 * - dense/bias: [64]
 * - dense_1/kernel: [64, 16]
 * - dense_1/bias: [16]
 * - embedding/embeddings: [5000, 64]
 */
function parseWeights(data) {
  let offset = 0;

  // Dense layer 1: kernel [64, 64] and bias [64]
  const dense1KernelSize = 64 * 64;
  const dense1Kernel = data.slice(offset, offset + dense1KernelSize);
  offset += dense1KernelSize;

  const dense1BiasSize = 64;
  const dense1Bias = data.slice(offset, offset + dense1BiasSize);
  offset += dense1BiasSize;

  // Dense layer 2: kernel [64, 16] and bias [16]
  const dense2KernelSize = 64 * NUM_LABELS;
  const dense2Kernel = data.slice(offset, offset + dense2KernelSize);
  offset += dense2KernelSize;

  const dense2BiasSize = NUM_LABELS;
  const dense2Bias = data.slice(offset, offset + dense2BiasSize);
  offset += dense2BiasSize;

  // Embedding: [5000, 64]
  const embedding = data.slice(offset);

  return {
    embedding,
    dense1Kernel,
    dense1Bias,
    dense2Kernel,
    dense2Bias,
  };
}

/**
 * ReLU activation function
 */
function relu(x) {
  return Math.max(0, x);
}

/**
 * Softmax activation function
 */
function softmax(arr) {
  const max = Math.max(...arr);
  const exps = arr.map((x) => Math.exp(x - max));
  const sum = exps.reduce((a, b) => a + b, 0);
  return exps.map((e) => e / sum);
}

/**
 * Forward pass through the neural network
 * Architecture: Embedding -> GlobalAveragePooling1D -> Dense(64, relu) -> Dense(16, softmax)
 */
function forward(tokens) {
  // Embedding lookup and global average pooling combined
  // Note: GlobalAveragePooling1D averages over ALL timesteps (including padding)
  // since the embedding layer has mask_zero=False
  const pooled = new Float32Array(EMBEDDING_DIM).fill(0);

  for (let i = 0; i < tokens.length; i++) {
    const tokenId = tokens[i];
    const embOffset = tokenId * EMBEDDING_DIM;
    for (let j = 0; j < EMBEDDING_DIM; j++) {
      pooled[j] += weights.embedding[embOffset + j];
    }
  }

  // Average over all timesteps (MAX_LENGTH = 100)
  for (let j = 0; j < EMBEDDING_DIM; j++) {
    pooled[j] /= MAX_LENGTH;
  }

  // Dense layer 1: [64] -> [64] with ReLU
  const hidden = new Float32Array(64);
  for (let i = 0; i < 64; i++) {
    let sum = weights.dense1Bias[i];
    for (let j = 0; j < 64; j++) {
      sum += pooled[j] * weights.dense1Kernel[j * 64 + i];
    }
    hidden[i] = relu(sum);
  }

  // Dense layer 2: [64] -> [16]
  const output = new Float32Array(NUM_LABELS);
  for (let i = 0; i < NUM_LABELS; i++) {
    let sum = weights.dense2Bias[i];
    for (let j = 0; j < 64; j++) {
      sum += hidden[j] * weights.dense2Kernel[j * NUM_LABELS + i];
    }
    output[i] = sum;
  }

  // Softmax
  return softmax(Array.from(output));
}

// Cache for computed model path
let cachedModelPath = null;

/**
 * Get default model path based on environment
 */
async function getDefaultModelPath() {
  if (cachedModelPath) {
    return cachedModelPath;
  }

  if (isBrowser) {
    // In browser, model should be served from same origin
    cachedModelPath = "./model";
    return cachedModelPath;
  }

  // Node.js - use dynamic imports
  const path = await import("path");
  const url = await import("url");

  // import.meta.url gives us the URL of this module
  const __filename = url.fileURLToPath(import.meta.url);
  const __dirname = path.dirname(__filename);
  cachedModelPath = path.join(__dirname, "..", "model");

  return cachedModelPath;
}

/**
 * Initialize the classifier
 * @param {Object} options - Configuration options
 * @param {string} options.modelPath - Path or URL to model directory (optional)
 */
export async function initialize(options = {}) {
  if (isInitialized) return;
  if (initPromise) return initPromise;

  // Validate modelPath option if provided
  if (options.modelPath !== undefined) {
    if (typeof options.modelPath !== "string") {
      throw new Error(
        `modelPath must be a string, got ${typeof options.modelPath}`,
      );
    }
    if (options.modelPath.trim() === "") {
      throw new Error("modelPath must not be empty");
    }
  }

  initPromise = (async () => {
    try {
      modelBasePath = options.modelPath || (await getDefaultModelPath());

      // Determine path joiner based on environment
      let joinPath;
      if (isBrowser) {
        joinPath = (...parts) => parts.join("/");
      } else {
        const path = await import("path");
        joinPath = path.join;
      }

      // Load vocabulary
      const vocabPath = joinPath(modelBasePath, "vocab.json");
      const vocabData = await loadJson(vocabPath);
      vocabMap = new Map();
      vocabData.forEach((word, index) => {
        vocabMap.set(word, index);
      });

      // Load labels
      const labelsPath = joinPath(modelBasePath, "labels.json");
      labels = await loadJson(labelsPath);

      // Load weights
      const weightsPath = joinPath(modelBasePath, "group1-shard1of1.bin");
      const weightsData = await loadWeights(weightsPath);
      weights = parseWeights(weightsData);

      isInitialized = true;
    } catch (error) {
      // Clear promise so next call can retry initialization
      initPromise = null;
      throw error;
    }
  })();

  return initPromise;
}

/**
 * Classify a bounce message
 * @param {string} message - The bounce/error message to classify
 * @returns {Promise<Object>} Classification result
 */
export async function classify(message) {
  await initialize();

  message = sanitizeMessage(message);

  const tokens = tokenize(message);
  const scores = forward(tokens);

  let maxScore = 0;
  let maxIndex = 0;
  const allScores = {};

  for (let i = 0; i < scores.length; i++) {
    const labelName = labels.id_to_label[i];
    allScores[labelName] = scores[i];
    if (scores[i] > maxScore) {
      maxScore = scores[i];
      maxIndex = i;
    }
  }

  let label = labels.id_to_label[maxIndex];
  let usedFallback = false;

  if (maxScore < CODE_FALLBACK_THRESHOLD) {
    const fallbackLabel = getCodeBasedFallback(message);
    if (fallbackLabel) {
      label = fallbackLabel;
      usedFallback = true;
    }
  }

  const result = {
    label,
    confidence: maxScore,
    action: getAction(label),
    scores: allScores,
  };

  if (usedFallback) result.usedFallback = true;

  const retryAfter = extractRetryTiming(message);
  if (retryAfter !== null) result.retryAfter = retryAfter;

  const blocklist = identifyBlocklist(message);
  if (blocklist !== null) result.blocklist = blocklist;

  return result;
}

/**
 * Get list of all possible labels
 * @returns {Promise<string[]>} Array of label names
 */
export async function getLabels() {
  await initialize();
  return Object.values(labels.id_to_label);
}

/**
 * Check if the classifier is initialized
 * @returns {boolean}
 */
export function isReady() {
  return isInitialized;
}

/**
 * Reset classifier state (for testing or re-initialization)
 */
export function reset() {
  weights = null;
  vocabMap = null;
  labels = null;
  isInitialized = false;
  initPromise = null;
  modelBasePath = null;
  cachedModelPath = null;
}

// Default export
export default {
  classify,
  getLabels,
  initialize,
  isReady,
  reset,
  extractRetryTiming,
  identifyBlocklist,
  getAction,
  extractSmtpCodes,
  getCodeBasedFallback,
  getTextBasedFallback,
  ACTION_MAP,
  BLOCKLIST_PATTERNS,
  SMTP_CODE_MAP,
  SMTP_MAIN_CODE_MAP,
  CODE_FALLBACK_THRESHOLD,
};
