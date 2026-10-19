/**
 * @postalsys/bounce-classifier
 * SMTP bounce message classifier using pure JavaScript inference
 *
 * Copyright (c) Postal Systems OU
 * Licensed under MIT
 */

import { defaultModelUrl } from './model-location.js';

/**
 * Possible bounce classification labels
 */
export type BounceLabel =
    | 'auth_failure'
    | 'domain_blacklisted'
    | 'geo_blocked'
    | 'greylisting'
    | 'invalid_address'
    | 'ip_blacklisted'
    | 'mailbox_disabled'
    | 'mailbox_full'
    | 'policy_blocked'
    | 'rate_limited'
    | 'relay_denied'
    | 'server_error'
    | 'spam_blocked'
    | 'unknown'
    | 'user_unknown'
    | 'virus_detected';

/**
 * Recommended action based on bounce category
 */
export type BounceAction =
    | 'remove' // Permanent failure - remove from list
    | 'retry' // Temporary failure - retry later
    | 'retry_different_ip' // IP blocked - try different IP
    | 'fix_configuration' // Config issue - fix sender setup
    | 'review' // Needs manual review
    | 'remove_content'; // Content issue - remove problematic content

/**
 * Blocklist type
 */
export type BlocklistType = 'ip' | 'domain' | 'uri';

/**
 * Single blocklist identification result
 */
export interface BlocklistInfo {
    /** Name of the blocklist (e.g., 'Spamhaus ZEN', 'Barracuda') */
    name: string;
    /** Type of blocklist */
    type: BlocklistType;
    /** True when a DNSBL or lookup hostname matched, false for a wording match */
    host: boolean;
}

/**
 * Multiple blocklists identification result
 */
export interface MultipleBlocklistInfo {
    /** Array of identified blocklists */
    lists: BlocklistInfo[];
    /** True when any of the lists matched on a hostname */
    host: boolean;
}

/**
 * Blocklist pattern definition
 */
export interface BlocklistPattern {
    /** Regex pattern to match */
    pattern: RegExp;
    /** Name of the blocklist */
    name: string;
    /** Type of blocklist */
    type: BlocklistType;
    /** Whether the pattern matches a DNSBL or lookup hostname */
    host: boolean;
}

/**
 * Classification result from the bounce classifier
 */
export interface ClassificationResult {
    /** The predicted label */
    label: BounceLabel;
    /**
     * The model's probability (0-1) for the returned `label`. When a fallback
     * rule replaced the model's pick, this is the model's score for the
     * rule-chosen label, 0 if the model does not know that label.
     */
    confidence: number;
    /**
     * The model's own top label. Present only when a fallback rule returned a
     * different `label`.
     */
    modelLabel?: BounceLabel;
    /** Recommended action based on the label */
    action: BounceAction;
    /** Scores for all labels */
    scores: Record<BounceLabel, number>;
    /** Whether SMTP code fallback was used (present if true) */
    usedFallback?: boolean;
    /** Retry time in seconds (only present if timing found in message) */
    retryAfter?: number;
    /**
     * Identified blocklist. Present when a DNSBL hostname is named, or when
     * listing wording is found and the label is blocklist-related.
     */
    blocklist?: BlocklistInfo | MultipleBlocklistInfo;
}

/**
 * SMTP codes extraction result
 */
export interface SmtpCodes {
    /** Main 3-digit SMTP code (e.g., '550') */
    mainCode: string | null;
    /** Extended SMTP code (e.g., '5.1.1') */
    extendedCode: string | null;
}

/**
 * Progress event emitted during model initialization.
 */
export interface InitProgress {
    /** Which resource is loading. */
    phase: 'vocab' | 'labels' | 'weights' | 'config';
    /** Bytes loaded so far for this phase (or an opaque count for JSON phases). */
    loaded: number;
    /** Total bytes / units for this phase. May equal `loaded` when unknown. */
    total: number;
}

/**
 * Initialization options
 */
export interface InitializeOptions {
    /** Path or URL to model directory (optional, uses default if not provided) */
    modelPath?: string | undefined;
    /**
     * Optional progress callback. In the browser, the "weights" phase streams
     * the response body and fires multiple events with monotonically increasing
     * `loaded`; other phases fire once at completion.
     */
    onProgress?: ((progress: InitProgress) => void) | undefined;
}

/**
 * User-registered text-pattern fallback entry.
 */
export interface TextFallbackEntry {
    /** Regex to test against the bounce message. */
    pattern: RegExp;
    /** Label to assign when the pattern matches. Must be a non-empty string. */
    label: string;
}

/**
 * Model metadata returned by getModelInfo()
 */
export interface ModelInfo {
    /** Short SHA-256 hash of the weights file (first 16 hex chars), or null for older models */
    modelHash: string | null;
    /** ISO 8601 UTC timestamp of when the model was trained, or null */
    trainedAt: string | null;
    /** Number of training samples used, or null */
    trainingSamples: number | null;
    /** Validation accuracy from training (0-1), or null */
    validationAccuracy: number | null;
    /** Whether the classifier has been initialized. Metadata fields are null if false. */
    initialized: boolean;
}

// Configuration
const MAX_LENGTH = 100;
const MAX_MESSAGE_LENGTH = 10000; // Max characters per message
const EMBEDDING_DIM = 64;
const HIDDEN_DIM = 64;
const NUM_LABELS = 16;
const UNKNOWN_LABEL = 'unknown';
// Blocklist names that match almost any "blocked" message and would crowd
// out a more specific provider hit if they appeared in the result.
const GENERIC_BLOCKLIST_NAMES = new Set(['RBL', 'DNSBL', 'Blocklist']);

// Detect environment. Read off globalThis so the type checker does not need the DOM library.
const browserWindow = (globalThis as { window?: { document?: unknown } }).window;
const isBrowser = browserWindow !== undefined && browserWindow.document !== undefined;

// Node.js modules, loaded lazily on first use so the browser never loads them
interface NodeModules {
    fs: typeof import('fs');
    path: typeof import('path');
    url: typeof import('url');
}

let nodeModulesPromise: Promise<NodeModules> | null = null;

// Dynamic imports keep Node built-ins out of the browser's module graph. The CommonJS build
// compiles them to require() calls, which pkg can trace.
function nodeModules(): Promise<NodeModules> {
    nodeModulesPromise ??= (async () => ({ fs: await import('fs'), path: await import('path'), url: await import('url') }))();
    return nodeModulesPromise;
}

// Action mapping based on bounce category
export const ACTION_MAP: Record<BounceLabel, BounceAction> = {
    // Permanent failures - remove from list
    user_unknown: 'remove',
    invalid_address: 'remove',
    mailbox_disabled: 'remove',

    // Temporary failures - retry later
    greylisting: 'retry',
    rate_limited: 'retry',
    server_error: 'retry',
    mailbox_full: 'retry',

    // IP/domain issues - retry with different IP or fix configuration
    ip_blacklisted: 'retry_different_ip',
    domain_blacklisted: 'fix_configuration',

    // Authentication issues - fix sender configuration
    auth_failure: 'fix_configuration',

    // Content/policy issues - modify message or manual review
    spam_blocked: 'review',
    policy_blocked: 'review',
    virus_detected: 'remove_content',
    geo_blocked: 'retry_different_ip',
    relay_denied: 'fix_configuration',

    // Unknown - manual review
    unknown: 'review'
};

// Mail security vendors are named in ordinary rejections too (Mimecast links
// its "Invalid Recipient" help page, appliances sign "Protected by Barracuda
// Networks"), so a vendor only counts as a blocklist when its DNSBL or lookup
// hostname appears, or its name sits next to explicit listing wording.
const BLOCKLIST_WORDING = '\\b(?:block(?:ed|ing|list(?:ed)?)?|blacklist(?:ed)?|listed|rbl|dnsbl|reputation)\\b';

function nearWording(term: string, wording: string = BLOCKLIST_WORDING): RegExp {
    return new RegExp(`\\b${term}\\b.{0,60}${wording}|${wording}.{0,60}\\b${term}\\b`, 'i');
}

// A vendor yields a hostname-level entry (its DNSBL or lookup host was named,
// which is evidence on its own) and a wording-level entry (its name next to
// listing wording, trusted only when the classifier agrees on a block).
function vendorBlocklistEntries(vendor: string, name: string, hostnames?: string): BlocklistPattern[] {
    const entries: BlocklistPattern[] = [{ pattern: nearWording(vendor), name, type: 'ip', host: false }];
    if (hostnames) {
        entries.unshift({
            pattern: new RegExp(hostnames, 'i'),
            name,
            type: 'ip',
            host: true
        });
    }
    return entries;
}

// Classification labels a blocklist hit is reported for. Other labels (an
// unknown recipient, a full mailbox) are not caused by a listing, whatever
// the message happens to mention.
const BLOCKLIST_LABELS = new Set<string>(['ip_blacklisted', 'domain_blacklisted', 'spam_blocked', 'policy_blocked']);

// Known blocklists and their patterns
export const BLOCKLIST_PATTERNS: BlocklistPattern[] = [
    // Spamhaus
    { pattern: /spamhaus\.org/i, name: 'Spamhaus', type: 'ip', host: true },
    { pattern: /\bsbl\b/i, name: 'Spamhaus SBL', type: 'ip', host: false },
    { pattern: /\bxbl\b/i, name: 'Spamhaus XBL', type: 'ip', host: false },
    { pattern: /\bpbl\b/i, name: 'Spamhaus PBL', type: 'ip', host: false },
    {
        pattern: /\bdbl\.spamhaus/i,
        name: 'Spamhaus DBL',
        type: 'domain',
        host: true
    },
    { pattern: /\bzen\.spamhaus/i, name: 'Spamhaus ZEN', type: 'ip', host: true },

    // Barracuda
    ...vendorBlocklistEntries('barracuda', 'Barracuda', 'barracudacentral\\.org'),

    // SORBS
    { pattern: /sorbs\.net/i, name: 'SORBS', type: 'ip', host: true },
    { pattern: /dnsbl\.sorbs/i, name: 'SORBS', type: 'ip', host: true },

    // SpamCop
    { pattern: /spamcop\.net/i, name: 'SpamCop', type: 'ip', host: true },

    // URIBL
    { pattern: /uribl\.com/i, name: 'URIBL', type: 'uri', host: true },
    { pattern: /multi\.uribl/i, name: 'URIBL', type: 'uri', host: true },

    // Cloudmark
    ...vendorBlocklistEntries('cloudmark', 'Cloudmark', 'csi\\.cloudmark\\.com'),

    // Proofpoint
    ...vendorBlocklistEntries('proofpoint', 'Proofpoint', '(?:ipcheck|prs)\\.proofpoint\\.com'),

    // Mimecast
    ...vendorBlocklistEntries('mimecast', 'Mimecast'),

    // Microsoft
    {
        pattern: /\bS3150\b/i,
        name: 'Microsoft Blocklist',
        type: 'ip',
        host: false
    },

    // Invaluement
    { pattern: /invaluement/i, name: 'Invaluement', type: 'ip', host: false },

    // Hostkarma
    { pattern: /hostkarma/i, name: 'Hostkarma', type: 'ip', host: false },

    // Trend Micro
    ...vendorBlocklistEntries('trend\\s*micro', 'Trend Micro', 'ers\\.trendmicro\\.com'),

    // Generic RBL detection. A bare "RBL" also turns up in unrelated text, so
    // it needs listing wording nearby or a DNSBL hostname carrying the term.
    {
        pattern: /\b(?:dns|spam)?rbl\.[a-z0-9-]*[a-z]/i,
        name: 'RBL',
        type: 'ip',
        host: true
    },
    {
        pattern: nearWording('rbl', '\\b(?:block(?:ed|ing|list(?:ed)?)?|blacklist(?:ed)?|listed)\\b'),
        name: 'RBL',
        type: 'ip',
        host: false
    },
    { pattern: /\bdnsbl\b/i, name: 'DNSBL', type: 'ip', host: false },
    { pattern: /blacklist/i, name: 'Blocklist', type: 'ip', host: false },
    { pattern: /blocklist/i, name: 'Blocklist', type: 'ip', host: false }
];

// SMTP Enhanced Status Code mapping (RFC 3463)
export const SMTP_CODE_MAP: Record<string, BounceLabel> = {
    '5.1.1': 'user_unknown',
    '5.1.2': 'invalid_address',
    '5.1.3': 'invalid_address',
    '5.1.6': 'invalid_address',
    '4.1.1': 'user_unknown',
    '5.2.0': 'user_unknown',
    '5.2.1': 'mailbox_disabled',
    '5.2.2': 'mailbox_full',
    '5.2.3': 'rate_limited',
    '4.2.0': 'greylisting',
    '4.2.1': 'rate_limited',
    '4.2.2': 'mailbox_full',
    '5.3.0': 'server_error',
    '5.3.1': 'server_error',
    '5.3.2': 'server_error',
    '4.3.0': 'server_error',
    '4.3.1': 'server_error',
    '4.3.2': 'server_error',
    '5.4.1': 'user_unknown',
    '5.4.4': 'server_error',
    '4.4.1': 'server_error',
    '4.4.2': 'server_error',
    '5.5.0': 'user_unknown',
    '5.5.1': 'invalid_address',
    '5.5.2': 'invalid_address',
    '5.6.1': 'policy_blocked',
    '5.6.2': 'policy_blocked',
    '5.7.0': 'virus_detected',
    '5.7.1': 'policy_blocked',
    '5.7.2': 'relay_denied',
    '5.7.8': 'auth_failure',
    '5.7.9': 'auth_failure',
    '5.7.23': 'auth_failure',
    '5.7.25': 'auth_failure',
    '5.7.26': 'auth_failure',
    '4.7.0': 'rate_limited',
    '4.7.1': 'rate_limited',
    '4.7.3': 'rate_limited',
    '4.7.28': 'rate_limited',
    '4.7.32': 'rate_limited',
    '4.7.650': 'rate_limited',
    '4.7.651': 'rate_limited',
    '5.2.121': 'rate_limited',
    '5.2.122': 'rate_limited'
};

export const SMTP_MAIN_CODE_MAP: Record<string, BounceLabel> = {
    421: 'greylisting',
    450: 'greylisting',
    451: 'server_error',
    452: 'server_error',
    500: 'invalid_address',
    501: 'invalid_address',
    502: 'server_error',
    503: 'server_error',
    504: 'server_error',
    550: 'user_unknown',
    551: 'relay_denied',
    552: 'mailbox_full',
    553: 'invalid_address',
    554: 'policy_blocked',
    571: 'spam_blocked'
};

export const CODE_FALLBACK_THRESHOLD: number = 0.5;

/**
 * Extract SMTP codes from a message
 */
export function extractSmtpCodes(message: string): SmtpCodes {
    const result: SmtpCodes = { mainCode: null, extendedCode: null };
    const mainMatch = message.match(/^(\d{3})[\s-]/);
    if (mainMatch) result.mainCode = mainMatch[1]!;
    // Lookbehind/lookahead reject codes embedded inside IPv4 addresses
    // (e.g. `5.7.1.100` must not yield `5.7.1`, and `192.168.1.1` must not
    // yield `2.168.1`). Without these, RFC 3463 fallback misclassifies bounces
    // that mention an IP whose first octets coincide with a real status code.
    const extMatch = message.match(/(?<!\d\.)\b([245])\.(\d{1,3})\.(\d{1,3})(?!\.\d)\b/);
    if (extMatch) result.extendedCode = `${extMatch[1]}.${extMatch[2]}.${extMatch[3]}`;
    return result;
}

// User-registered text pattern fallbacks. Scanned BEFORE the built-ins so
// project-specific bounces (e.g. custom providers) can override default
// classification without forking. Survives `reset()` / `reload()`; cleared
// only via `clearTextFallbacks()`.
const USER_TEXT_FALLBACKS: TextFallbackEntry[] = [];

/**
 * Register a custom text-pattern fallback. User-registered patterns are
 * scanned before the built-in patterns and override default classification
 * when they match. Survives `reset()` / `reload()`; clear with
 * `clearTextFallbacks()`.
 */
export function registerTextFallback(entry: TextFallbackEntry): void {
    if (!entry || typeof entry !== 'object') {
        throw new Error('registerTextFallback: expected { pattern, label } object');
    }
    const { pattern, label } = entry;
    if (!(pattern instanceof RegExp)) {
        throw new Error('registerTextFallback: pattern must be a RegExp');
    }
    if (typeof label !== 'string' || label.length === 0) {
        throw new Error('registerTextFallback: label must be a non-empty string');
    }
    USER_TEXT_FALLBACKS.push({ pattern, label });
}

/**
 * Remove all user-registered text-pattern fallbacks. Built-in fallbacks
 * are not affected.
 */
export function clearTextFallbacks(): void {
    USER_TEXT_FALLBACKS.length = 0;
}

// Text-based pattern fallbacks for common patterns
// Note: .{0,100}? limits match length to prevent performance issues on long strings
const TEXT_PATTERN_FALLBACKS: { pattern: RegExp; label: BounceLabel }[] = [
    { pattern: /doesn't have a .{0,50}? account/i, label: 'user_unknown' },
    { pattern: /user doesn't have .{0,50}? account/i, label: 'user_unknown' },
    { pattern: /not a valid recipient/i, label: 'user_unknown' },
    { pattern: /no such user/i, label: 'user_unknown' },
    { pattern: /user unknown/i, label: 'user_unknown' },
    { pattern: /mailbox not found/i, label: 'user_unknown' },
    { pattern: /recipient rejected/i, label: 'user_unknown' },
    { pattern: /sender is unauthenticated/i, label: 'auth_failure' },
    { pattern: /requires .{0,50}? authenticate/i, label: 'auth_failure' },
    { pattern: /illegal attachment/i, label: 'virus_detected' },
    { pattern: /virus .{0,20}?detected/i, label: 'virus_detected' },
    { pattern: /infected .{0,20}?attachment/i, label: 'virus_detected' },
    { pattern: /malware .{0,20}?detected/i, label: 'virus_detected' },
    { pattern: /out of storage space/i, label: 'mailbox_full' },
    { pattern: /over ?quota/i, label: 'mailbox_full' },
    { pattern: /quota exceeded/i, label: 'mailbox_full' },
    { pattern: /mailbox.{0,20}?full/i, label: 'mailbox_full' },
    { pattern: /user unknown in/i, label: 'user_unknown' },
    { pattern: /address rejected.{0,30}?user unknown/i, label: 'user_unknown' },
    { pattern: /too many .{0,30}?connections/i, label: 'rate_limited' },
    { pattern: /too many .{0,30}?messages/i, label: 'rate_limited' },
    { pattern: /too many .{0,30}?recipients/i, label: 'rate_limited' },
    { pattern: /rate .{0,20}?limit/i, label: 'rate_limited' },
    { pattern: /sending .{0,20}?limit/i, label: 'rate_limited' },
    { pattern: /connection .{0,20}?limit/i, label: 'rate_limited' },
    { pattern: /throttl/i, label: 'rate_limited' }
];

/**
 * Get fallback classification based on text patterns. User-registered
 * patterns (via `registerTextFallback`) are scanned first; built-ins
 * second.
 * @returns Fallback label or null if no match
 */
export function getTextBasedFallback(message: string): BounceLabel | null {
    for (const { pattern, label } of USER_TEXT_FALLBACKS) {
        // A registered label may be one the model does not know
        if (pattern.test(message)) return label as BounceLabel;
    }
    for (const { pattern, label } of TEXT_PATTERN_FALLBACKS) {
        if (pattern.test(message)) return label;
    }
    return null;
}

/**
 * Get fallback classification based on SMTP codes alone (no text scan).
 */
function getSmtpCodeFallback(message: string): BounceLabel | null {
    const codes = extractSmtpCodes(message);
    if (codes.extendedCode && SMTP_CODE_MAP[codes.extendedCode]) {
        return SMTP_CODE_MAP[codes.extendedCode];
    }
    if (codes.mainCode && SMTP_MAIN_CODE_MAP[codes.mainCode]) {
        return SMTP_MAIN_CODE_MAP[codes.mainCode];
    }
    return null;
}

/**
 * Get fallback classification: text patterns first (more specific), then
 * SMTP codes.
 * @returns Fallback label or null if no match
 */
export function getCodeBasedFallback(message: string): BounceLabel | null {
    return getTextBasedFallback(message) ?? getSmtpCodeFallback(message);
}

// Retry timing patterns
// Note: .{0,50}? limits match length to prevent performance issues on long strings
const RETRY_PATTERNS = [
    {
        pattern: /try\s+again\s+in\s+(\d+)\s*(second|minute|hour|min|sec|hr)s?/i,
        unit: 2
    },
    {
        pattern: /retry\s+in\s+(\d+)\s*(second|minute|hour|min|sec|hr)s?/i,
        unit: 2
    },
    { pattern: /wait\s+(\d+)\s*(second|minute|hour|min|sec|hr)s?/i, unit: 2 },
    {
        pattern: /greylisted?\s+(?:for\s+)?(\d+)\s*(second|minute|hour|min|sec|hr)s?/i,
        unit: 2
    },
    {
        pattern: /delayed?\s+(?:for\s+)?(\d+)\s*(second|minute|hour|min|sec|hr)s?/i,
        unit: 2
    },
    {
        pattern: /come\s+back\s+in\s+(\d+)\s*(second|minute|hour|min|sec|hr)s?/i,
        unit: 2
    },
    { pattern: /after\s+(\d+)\s*(second|minute|hour|min|sec|hr)s?/i, unit: 2 },
    { pattern: /\b(\d+)\s*(second|minute|hour)s?\b/i, unit: 2 },
    {
        pattern: /too\s+many.{0,50}?(\d+)\s*(second|minute|hour|min|sec|hr)s?/i,
        unit: 2
    },
    {
        pattern: /greylist.{0,50}?(\d+)\s*(second|minute|hour|min|sec|hr)s?/i,
        unit: 2
    }
];

function toSeconds(value: string, unit: string): number {
    const num = parseInt(value, 10);
    const u = unit.toLowerCase();
    if (u.startsWith('sec') || u === 's') return num;
    if (u.startsWith('min') || u === 'm') return num * 60;
    if (u.startsWith('hour') || u === 'hr' || u === 'h') return num * 3600;
    return num;
}

/**
 * Extract retry timing from a bounce message
 * @returns Retry time in seconds, or null if not found
 */
export function extractRetryTiming(message: string): number | null {
    for (const { pattern, unit } of RETRY_PATTERNS) {
        const match = message.match(pattern);
        if (match && match[1]) {
            const seconds = toSeconds(match[1], match[unit] || 'seconds');
            if (seconds >= 1 && seconds <= 86400) {
                return seconds;
            }
        }
    }
    return null;
}

/**
 * Identify blocklists mentioned in a bounce message
 * @returns Blocklist info, or null if not found
 */
export function identifyBlocklist(message: string): BlocklistInfo | MultipleBlocklistInfo | null {
    const found: BlocklistInfo[] = [];
    for (const { pattern, name, type, host } of BLOCKLIST_PATTERNS) {
        if (pattern.test(message)) {
            const existing = found.find(b => b.name === name);
            if (existing) {
                existing.host = existing.host || host;
            } else {
                found.push({ name, type, host });
            }
        }
    }
    if (found.length === 0) return null;
    const specific = found.filter(b => !GENERIC_BLOCKLIST_NAMES.has(b.name));
    if (specific.length > 1) {
        return { lists: specific, host: specific.some(b => b.host) };
    }
    return specific.length === 1 ? specific[0] : found[0];
}

/**
 * Get recommended action based on bounce category. Unknown categories
 * (anything not in `ACTION_MAP`) fall back to `"review"`.
 */
export function getAction(category: BounceLabel | string): BounceAction {
    return Object.hasOwn(ACTION_MAP, category) ? ACTION_MAP[category as BounceLabel] : 'review';
}

/**
 * Sanitize and validate input message. Takes `unknown` because JavaScript
 * callers can pass anything.
 */
function sanitizeMessage(message: unknown, context = 'Message'): string {
    if (message === null || message === undefined) {
        throw new Error(`${context} must be a non-empty string`);
    }

    if (typeof message !== 'string') {
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
interface ModelWeights {
    embedding: Float32Array;
    dense1Kernel: Float32Array;
    dense1Bias: Float32Array;
    dense2Kernel: Float32Array;
    dense2Bias: Float32Array;
}

/** labels.json: the model's output index to label name */
interface ModelLabels {
    id_to_label: Record<string, BounceLabel>;
}

/** config.json, written by the trainer */
interface ModelConfig {
    model_hash?: string;
    trained_at?: string;
    training_samples?: number;
    validation_accuracy?: number;
}

/** A parser decides how to interpret the bytes of a model file */
interface ModelFileParser<T> {
    browser: (response: Response) => T | Promise<T>;
    node: (buffer: Buffer) => T;
}

let weights: ModelWeights | null = null;
let vocabMap: Map<string, number> | null = null;
let labels: ModelLabels | null = null;
let modelConfig: ModelConfig | null = null;
let isInitialized = false;
let initPromise: Promise<void> | null = null;
let modelBasePath: string | null = null;

// Concurrency tracking: `reload()` must wait for in-flight `classify()` calls
// to finish before swapping model state, otherwise a classification past its
// `await initialize()` line would read null weights and crash.
let inFlightClassifies = 0;
let drainWaiters: (() => void)[] = [];

function endClassify() {
    inFlightClassifies--;
    if (inFlightClassifies === 0 && drainWaiters.length > 0) {
        const waiters = drainWaiters;
        drainWaiters = [];
        for (const resolve of waiters) resolve();
    }
}

function waitForClassifyDrain() {
    if (inFlightClassifies === 0) return Promise.resolve();
    return new Promise<void>(resolve => drainWaiters.push(resolve));
}

/**
 * Preprocess text for tokenization
 */
function preprocessText(text: string): string {
    return text
        .toLowerCase()
        .replace(/[^\w\s]/g, ' ')
        .replace(/\s+/g, ' ')
        .trim();
}

/**
 * Tokenize text using vocabulary
 */
function tokenize(text: string, vocab: Map<string, number>): number[] {
    const processed = preprocessText(text);
    const words = processed.split(' ');
    const tokens: number[] = new Array<number>(MAX_LENGTH).fill(0);

    for (let i = 0; i < Math.min(words.length, MAX_LENGTH); i++) {
        // 1 is the OOV token
        tokens[i] = vocab.get(words[i]) ?? 1;
    }

    return tokens;
}

/**
 * Load a model file in either Node.js or the browser. The `parser` decides
 * how to interpret the bytes; errors are tagged with `modelBasePath` so a
 * misconfigured path is diagnosable.
 */
function withModelPath(err: unknown, filePath: string): unknown {
    if (err instanceof Error) {
        err.message = `Failed to load ${filePath} (model path: ${modelBasePath}): ${err.message}`;
    }
    return err;
}

async function loadModelFile<T>(filePath: string, parser: ModelFileParser<T>): Promise<T> {
    try {
        if (isBrowser) {
            const response = await fetch(filePath);
            if (!response.ok) {
                throw new Error(`HTTP ${response.status}`);
            }
            return parser.browser(response);
        }
        return parser.node(await (await nodeModules()).fs.promises.readFile(filePath));
    } catch (err) {
        throw withModelPath(err, filePath);
    }
}

const JSON_PARSER: ModelFileParser<any> = {
    browser: response => response.json(),
    node: buffer => JSON.parse(buffer.toString('utf8'))
};

const WEIGHTS_PARSER: ModelFileParser<Float32Array> = {
    browser: async response => new Float32Array(await response.arrayBuffer()),
    node: buffer => new Float32Array(buffer.buffer, buffer.byteOffset, buffer.byteLength / 4)
};

const loadJson = <T>(filePath: string): Promise<T> => loadModelFile<T>(filePath, JSON_PARSER);
const loadWeights = (filePath: string): Promise<Float32Array> => loadModelFile(filePath, WEIGHTS_PARSER);

/**
 * Load weights with incremental progress reporting. Uses a streaming
 * `ReadableStream` reader in the browser (so large model downloads show a
 * determinate bar); Node falls back to a single "done" ping after readFile.
 * Non-streaming paths delegate to `WEIGHTS_PARSER` so there's one Float32
 * conversion, not two.
 */
async function loadWeightsWithProgress(filePath: string, onProgress: (progress: InitProgress) => void): Promise<Float32Array> {
    const emit = (loaded: number, total: number): void => onProgress({ phase: 'weights', loaded, total });
    try {
        if (isBrowser) {
            const response = await fetch(filePath);
            if (!response.ok) throw new Error(`HTTP ${response.status}`);
            const total = Number(response.headers.get('Content-Length')) || 0;
            if (!response.body?.getReader) {
                const result = await WEIGHTS_PARSER.browser(response);
                emit(result.byteLength, total || result.byteLength);
                return result;
            }
            const reader = response.body.getReader();
            const chunks: Uint8Array[] = [];
            let loaded = 0;
            for (;;) {
                // Stream chunks arrive in order, one read at a time
                // eslint-disable-next-line no-await-in-loop
                const { done, value } = await reader.read();
                if (done) break;
                chunks.push(value);
                loaded += value.byteLength;
                emit(loaded, total);
            }
            // Blob concatenates chunks natively; avoids a JS-side copy loop.
            const buf = await new Blob(chunks).arrayBuffer();
            return new Float32Array(buf);
        }
        const buf = await (await nodeModules()).fs.promises.readFile(filePath);
        emit(buf.byteLength, buf.byteLength);
        return WEIGHTS_PARSER.node(buf);
    } catch (err) {
        throw withModelPath(err, filePath);
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
function parseWeights(data: Float32Array): ModelWeights {
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
        dense2Bias
    };
}

/**
 * ReLU activation function
 */
function relu(x: number): number {
    return Math.max(0, x);
}

/**
 * Softmax activation function. Single-pass over `arr`: find max, then
 * compute exponents/sum/normalize in one allocated output buffer.
 */
function softmax(arr: Float32Array): Float32Array {
    let max = -Infinity;
    for (let i = 0; i < arr.length; i++) {
        if (arr[i] > max) max = arr[i];
    }
    const out = new Float32Array(arr.length);
    let sum = 0;
    for (let i = 0; i < arr.length; i++) {
        const e = Math.exp(arr[i] - max);
        out[i] = e;
        sum += e;
    }
    for (let i = 0; i < arr.length; i++) {
        out[i] /= sum;
    }
    return out;
}

/**
 * Forward pass through the neural network
 * Architecture: Embedding -> GlobalAveragePooling1D -> Dense(64, relu) -> Dense(16, softmax)
 */
function forward(tokens: number[], weights: ModelWeights): Float32Array {
    // Embedding lookup and global average pooling combined.
    // GlobalAveragePooling1D averages over ALL timesteps (including padding)
    // because the trained embedding layer has mask_zero=False.
    const pooled = new Float32Array(EMBEDDING_DIM);

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

    // Dense layer 1: [EMBEDDING_DIM] -> [HIDDEN_DIM] with ReLU
    const hidden = new Float32Array(HIDDEN_DIM);
    for (let i = 0; i < HIDDEN_DIM; i++) {
        let sum = weights.dense1Bias[i];
        for (let j = 0; j < EMBEDDING_DIM; j++) {
            sum += pooled[j] * weights.dense1Kernel[j * HIDDEN_DIM + i];
        }
        hidden[i] = relu(sum);
    }

    // Dense layer 2: [HIDDEN_DIM] -> [NUM_LABELS]
    const output = new Float32Array(NUM_LABELS);
    for (let i = 0; i < NUM_LABELS; i++) {
        let sum = weights.dense2Bias[i];
        for (let j = 0; j < HIDDEN_DIM; j++) {
            sum += hidden[j] * weights.dense2Kernel[j * NUM_LABELS + i];
        }
        output[i] = sum;
    }

    // Softmax (Float32Array.prototype.map / reduce / max-spread are fine here).
    return softmax(output);
}

// Cache for computed model path
let cachedModelPath: string | null = null;

/**
 * Get default model path based on environment
 */
async function getDefaultModelPath(): Promise<string> {
    if (cachedModelPath) {
        return cachedModelPath;
    }

    if (isBrowser) {
        // In browser, model should be served from same origin
        cachedModelPath = './model';
        return cachedModelPath;
    }

    // Node.js: the model directory at the package root
    cachedModelPath = (await nodeModules()).url.fileURLToPath(defaultModelUrl);

    return cachedModelPath;
}

/**
 * Initialize the classifier by loading the model and vocabulary.
 * This is called automatically on first classification, but can be
 * called manually to pre-load the model.
 * @param options - Optional configuration
 */
export async function initialize(options: InitializeOptions = {}): Promise<void> {
    if (isInitialized) return;
    if (initPromise) return initPromise;

    // Validate modelPath option if provided
    if (options.modelPath !== undefined) {
        if (typeof options.modelPath !== 'string') {
            throw new Error(`modelPath must be a string, got ${typeof options.modelPath}`);
        }
        if (options.modelPath.trim() === '') {
            throw new Error('modelPath must not be empty');
        }
    }

    const onProgress = typeof options.onProgress === 'function' ? options.onProgress : null;
    const pingDone = (phase: InitProgress['phase'], bytes: number): void => {
        if (onProgress) onProgress({ phase, loaded: bytes, total: bytes });
    };

    initPromise = (async () => {
        try {
            const basePath = options.modelPath || (await getDefaultModelPath());
            modelBasePath = basePath;

            // Determine path joiner based on environment
            let joinPath: (...parts: string[]) => string;
            if (isBrowser) {
                joinPath = (...parts) => parts.join('/');
            } else {
                const { path } = await nodeModules();
                joinPath = (...parts) => path.join(...parts);
            }

            // Load vocabulary
            const vocabPath = joinPath(basePath, 'vocab.json');
            const vocabData = await loadJson<string[]>(vocabPath);
            vocabMap = new Map();
            vocabData.forEach((word, index) => {
                vocabMap!.set(word, index);
            });
            pingDone('vocab', vocabData.length);

            // Load labels
            const labelsPath = joinPath(basePath, 'labels.json');
            labels = await loadJson<ModelLabels>(labelsPath);
            pingDone('labels', Object.keys(labels.id_to_label || {}).length);

            // Load weights (streaming with progress in the browser when requested)
            const weightsPath = joinPath(basePath, 'group1-shard1of1.bin');
            const weightsData = onProgress ? await loadWeightsWithProgress(weightsPath, onProgress) : await loadWeights(weightsPath);
            weights = parseWeights(weightsData);

            // Load config (optional - older models may not have it)
            try {
                const configPath = joinPath(basePath, 'config.json');
                modelConfig = await loadJson<ModelConfig>(configPath);
            } catch {
                modelConfig = {};
            }
            pingDone('config', 1);

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
 * Classify a single bounce message
 * @param message - The bounce/error message to classify
 * @returns Classification result with label, confidence, action, and scores
 */
export async function classify(message: string): Promise<ClassificationResult> {
    await initialize();

    message = sanitizeMessage(message);

    // initialize() resolved, so the model is loaded. Nothing below awaits, so a concurrent
    // reload() can not swap it out mid-classification.
    const model = { weights: weights!, vocab: vocabMap!, labels: labels! };

    // Increment AFTER initialize() + sanitize so failed inputs don't count
    // against the in-flight tally (and can't block a pending reload()).
    inFlightClassifies++;
    try {
        const tokens = tokenize(message, model.vocab);
        const scores = forward(tokens, model.weights);

        let maxScore = 0;
        let maxIndex = 0;
        const allScores = {} as Record<BounceLabel, number>;

        for (let i = 0; i < scores.length; i++) {
            const labelName = model.labels.id_to_label[i];
            allScores[labelName] = scores[i]!;
            if (scores[i] > maxScore) {
                maxScore = scores[i]!;
                maxIndex = i;
            }
        }

        const modelLabel = model.labels.id_to_label[maxIndex];
        let label = modelLabel;
        let usedFallback = false;

        // Text patterns take priority (most reliable for specific phrases).
        // If they don't match and the model is uncertain (or punted to "unknown"),
        // try the SMTP-code map directly; getSmtpCodeFallback skips re-running
        // the text patterns we already proved don't match.
        const textFallback = getTextBasedFallback(message);
        if (textFallback) {
            label = textFallback;
            usedFallback = true;
        } else if (maxScore < CODE_FALLBACK_THRESHOLD || label === UNKNOWN_LABEL) {
            const codeFallback = getSmtpCodeFallback(message);
            if (codeFallback) {
                label = codeFallback;
                usedFallback = true;
            }
        }

        // `confidence` is the model's probability for the label actually
        // returned, so a rule-picked label never inherits the score of the
        // label it replaced. Labels the model does not know (user-registered
        // fallbacks) get 0.
        const result: ClassificationResult = {
            label,
            confidence: Object.hasOwn(allScores, label) ? allScores[label] : 0,
            action: getAction(label),
            scores: allScores
        };

        if (usedFallback) result.usedFallback = true;
        if (label !== modelLabel) result.modelLabel = modelLabel;

        const retryAfter = extractRetryTiming(message);
        if (retryAfter !== null) result.retryAfter = retryAfter;

        // A named DNSBL host is reported whatever the label; wording alone only
        // when the label says the bounce was a block.
        const blocklist = identifyBlocklist(message);
        if (blocklist !== null && (blocklist.host || BLOCKLIST_LABELS.has(label))) {
            result.blocklist = blocklist;
        }

        return result;
    } finally {
        endClassify();
    }
}

/**
 * Classify an array of bounce messages. Equivalent to calling `classify()`
 * on each input sequentially after a single `initialize()`, but returns a
 * contiguous array and wraps per-item errors with their `.index` so
 * partial failures are diagnosable.
 */
export async function classifyBatch(messages: string[]): Promise<ClassificationResult[]> {
    if (!Array.isArray(messages)) {
        throw new Error(`classifyBatch: expected an array of messages, got ${typeof messages}`);
    }
    await initialize();
    const results = new Array<ClassificationResult>(messages.length);
    for (let i = 0; i < messages.length; i++) {
        try {
            // Sequential on purpose: the first failure stops the batch and carries its index
            // eslint-disable-next-line no-await-in-loop
            results[i] = await classify(messages[i]);
        } catch (err) {
            const error = err as Error & { index?: number };
            error.index = i;
            error.message = `classifyBatch[${i}]: ${error.message}`;
            throw error;
        }
    }
    return results;
}

/**
 * Get list of all possible labels
 * @returns Array of label names
 */
export async function getLabels(): Promise<BounceLabel[]> {
    await initialize();
    return Object.values(labels!.id_to_label);
}

/**
 * Get model metadata (hash, training date, accuracy, etc.).
 *
 * Always returns an object. The `initialized` flag distinguishes an
 * uninitialized classifier (all metadata fields null) from an initialized
 * one with missing `config.json` entries. Legitimate falsy values from the
 * config (0 for accuracy, "" for hash) are preserved.
 */
export function getModelInfo(): ModelInfo {
    const src: ModelConfig = isInitialized && modelConfig ? modelConfig : {};
    return {
        modelHash: src.model_hash ?? null,
        trainedAt: src.trained_at ?? null,
        trainingSamples: src.training_samples ?? null,
        validationAccuracy: src.validation_accuracy ?? null,
        initialized: isInitialized
    };
}

/**
 * Check if the classifier is initialized
 */
export function isReady(): boolean {
    return isInitialized;
}

/**
 * Reset classifier state (for testing or re-initialization). Clears model
 * state and the in-flight / drain bookkeeping, but leaves user-registered
 * text fallbacks in place (those are user config, not model state; use
 * `clearTextFallbacks()` to remove them).
 */
export function reset(): void {
    weights = null;
    vocabMap = null;
    labels = null;
    modelConfig = null;
    isInitialized = false;
    initPromise = null;
    modelBasePath = null;
    cachedModelPath = null;
    inFlightClassifies = 0;
    drainWaiters = [];
}

/**
 * Reload the model, optionally from a new path. Waits for any in-flight
 * `classify()` calls to drain before swapping state, then re-initializes
 * from disk. Safe to call concurrently with `classify()`: pending
 * classifications complete against the old model; subsequent calls see
 * the new one.
 *
 * @param options - Optional configuration. If modelPath is omitted,
 *   reloads from the previously used path.
 */
export async function reload(options: InitializeOptions = {}): Promise<void> {
    // Before the first initialize() there is no previous path, and initialize() rejects the null
    const modelPath = (options.modelPath ?? modelBasePath) as string | undefined;
    await waitForClassifyDrain();
    reset();
    return initialize({ modelPath, onProgress: options.onProgress });
}

// Default export
export default {
    classify,
    classifyBatch,
    getLabels,
    initialize,
    isReady,
    getModelInfo,
    reset,
    reload,
    registerTextFallback,
    clearTextFallbacks,
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
    CODE_FALLBACK_THRESHOLD
};
