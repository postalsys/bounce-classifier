/**
 * @postalsys/bounce-classifier
 * SMTP bounce message classifier using TensorFlow.js
 *
 * Copyright (c) Postal Systems OU
 * Licensed under MIT
 */

import * as tf from "@tensorflow/tfjs";
import { createRequire } from "module";

// Configuration
const MAX_LENGTH = 100;

// Detect environment
const isBrowser =
  typeof window !== "undefined" && typeof window.document !== "undefined";
const isNode =
  typeof process !== "undefined" &&
  process.versions != null &&
  process.versions.node != null;

// Create require function for ESM compatibility (works in both ESM and CJS after bundling)
const nodeRequire = isNode ? createRequire(import.meta.url) : null;

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
  const mainMatch = message.match(/^(\d{3})[\s\-]/);
  if (mainMatch) result.mainCode = mainMatch[1];
  const extMatch = message.match(/\b([245])\.(\d{1,3})\.(\d{1,3})\b/);
  if (extMatch)
    result.extendedCode = `${extMatch[1]}.${extMatch[2]}.${extMatch[3]}`;
  return result;
}

// Text-based pattern fallbacks for common patterns
const TEXT_PATTERN_FALLBACKS = [
  { pattern: /doesn't have a .* account/i, label: "user_unknown" },
  { pattern: /user doesn't have .* account/i, label: "user_unknown" },
  { pattern: /not a valid recipient/i, label: "user_unknown" },
  { pattern: /no such user/i, label: "user_unknown" },
  { pattern: /user unknown/i, label: "user_unknown" },
  { pattern: /mailbox not found/i, label: "user_unknown" },
  { pattern: /recipient rejected/i, label: "user_unknown" },
  { pattern: /sender is unauthenticated/i, label: "auth_failure" },
  { pattern: /requires .* authenticate/i, label: "auth_failure" },
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
    pattern: /too\s+many.*?(\d+)\s*(second|minute|hour|min|sec|hr)s?/i,
    unit: 2,
  },
  { pattern: /greylist.*?(\d+)\s*(second|minute|hour|min|sec|hr)s?/i, unit: 2 },
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

// Singleton state
let model = null;
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
    // Node.js - use nodeRequire for pkg compatibility
    const fs = nodeRequire("fs");
    return JSON.parse(fs.readFileSync(filePath, "utf8"));
  }
}

// Cache for computed model path
let cachedModelPath = null;

/**
 * Custom IO handler for loading model from local files in Node.js
 */
class NodeFileSystem {
  constructor(modelPath) {
    this.modelPath = modelPath;
  }

  async load() {
    // Use nodeRequire for pkg compatibility
    const fs = nodeRequire("fs");
    const path = nodeRequire("path");

    const modelJsonPath = path.join(this.modelPath, "model.json");
    const modelJSON = JSON.parse(fs.readFileSync(modelJsonPath, "utf8"));

    const weightsManifest = modelJSON.weightsManifest;
    const weightSpecs = [];
    const weightData = [];

    for (const group of weightsManifest) {
      for (const weight of group.weights) {
        weightSpecs.push(weight);
      }
      for (const filePath of group.paths) {
        const fullPath = path.join(this.modelPath, filePath);
        const buffer = fs.readFileSync(fullPath);
        weightData.push(
          buffer.buffer.slice(
            buffer.byteOffset,
            buffer.byteOffset + buffer.byteLength,
          ),
        );
      }
    }

    const totalBytes = weightData.reduce((acc, buf) => acc + buf.byteLength, 0);
    const concatenated = new ArrayBuffer(totalBytes);
    const view = new Uint8Array(concatenated);
    let offset = 0;
    for (const buf of weightData) {
      view.set(new Uint8Array(buf), offset);
      offset += buf.byteLength;
    }

    return {
      modelTopology: modelJSON.modelTopology,
      weightSpecs,
      weightData: concatenated,
      format: modelJSON.format,
      generatedBy: modelJSON.generatedBy,
      convertedBy: modelJSON.convertedBy,
    };
  }
}

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

  // Node.js - use nodeRequire for pkg compatibility
  const path = nodeRequire("path");
  const url = nodeRequire("url");

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

  initPromise = (async () => {
    modelBasePath = options.modelPath || (await getDefaultModelPath());

    // Determine path joiner based on environment
    const joinPath = isBrowser
      ? (...parts) => parts.join("/")
      : nodeRequire("path").join;

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

    // Load TensorFlow.js model
    if (isBrowser) {
      // Browser: use URL-based loading
      model = await tf.loadLayersModel(`${modelBasePath}/model.json`);
    } else {
      // Node.js: use custom file system handler
      const handler = new NodeFileSystem(modelBasePath);
      model = await tf.loadLayersModel(handler);
    }

    isInitialized = true;
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

  if (!message || typeof message !== "string") {
    throw new Error("Message must be a non-empty string");
  }

  const tokens = tokenize(message);
  const inputTensor = tf.tensor2d([tokens], [1, MAX_LENGTH], "int32");
  const prediction = model.predict(inputTensor);
  const scores = await prediction.data();

  inputTensor.dispose();
  prediction.dispose();

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
 * Classify multiple bounce messages in batch
 * @param {string[]} messages - Array of bounce messages to classify
 * @returns {Promise<Object[]>} Array of classification results
 */
export async function classifyBatch(messages) {
  await initialize();

  if (!Array.isArray(messages)) {
    throw new Error("Messages must be an array");
  }

  const tokenizedMessages = messages.map((msg) => tokenize(msg));
  const inputTensor = tf.tensor2d(
    tokenizedMessages,
    [messages.length, MAX_LENGTH],
    "int32",
  );
  const predictions = model.predict(inputTensor);
  const allScores = await predictions.data();

  inputTensor.dispose();
  predictions.dispose();

  const results = [];
  const numLabels = Object.keys(labels.id_to_label).length;

  for (let i = 0; i < messages.length; i++) {
    const offset = i * numLabels;
    let maxScore = 0;
    let maxIndex = 0;
    const scores = {};

    for (let j = 0; j < numLabels; j++) {
      const score = allScores[offset + j];
      const labelName = labels.id_to_label[j];
      scores[labelName] = score;
      if (score > maxScore) {
        maxScore = score;
        maxIndex = j;
      }
    }

    let label = labels.id_to_label[maxIndex];
    let usedFallback = false;

    if (maxScore < CODE_FALLBACK_THRESHOLD) {
      const fallbackLabel = getCodeBasedFallback(messages[i]);
      if (fallbackLabel) {
        label = fallbackLabel;
        usedFallback = true;
      }
    }

    const result = {
      label,
      confidence: maxScore,
      action: getAction(label),
      scores,
    };

    if (usedFallback) result.usedFallback = true;

    const retryAfter = extractRetryTiming(messages[i]);
    if (retryAfter !== null) result.retryAfter = retryAfter;

    const blocklist = identifyBlocklist(messages[i]);
    if (blocklist !== null) result.blocklist = blocklist;

    results.push(result);
  }

  return results;
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
  if (model) {
    model.dispose();
  }
  model = null;
  vocabMap = null;
  labels = null;
  isInitialized = false;
  initPromise = null;
  modelBasePath = null;
}

// Default export
export default {
  classify,
  classifyBatch,
  getLabels,
  initialize,
  isReady,
  reset,
  extractRetryTiming,
  identifyBlocklist,
  getAction,
  extractSmtpCodes,
  getCodeBasedFallback,
  ACTION_MAP,
  BLOCKLIST_PATTERNS,
  SMTP_CODE_MAP,
  SMTP_MAIN_CODE_MAP,
  CODE_FALLBACK_THRESHOLD,
};
