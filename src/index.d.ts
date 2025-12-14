/**
 * @postalsys/bounce-classifier
 * SMTP bounce message classifier using pure JavaScript inference
 *
 * Copyright (c) Postal Systems OU
 * Licensed under MIT
 */

/**
 * Possible bounce classification labels
 */
export type BounceLabel =
  | "auth_failure"
  | "domain_blacklisted"
  | "geo_blocked"
  | "greylisting"
  | "invalid_address"
  | "ip_blacklisted"
  | "mailbox_disabled"
  | "mailbox_full"
  | "policy_blocked"
  | "rate_limited"
  | "relay_denied"
  | "server_error"
  | "spam_blocked"
  | "unknown"
  | "user_unknown"
  | "virus_detected";

/**
 * Recommended action based on bounce category
 */
export type BounceAction =
  | "remove" // Permanent failure - remove from list
  | "retry" // Temporary failure - retry later
  | "retry_different_ip" // IP blocked - try different IP
  | "fix_configuration" // Config issue - fix sender setup
  | "review" // Needs manual review
  | "remove_content"; // Content issue - remove problematic content

/**
 * Blocklist type
 */
export type BlocklistType = "ip" | "domain" | "uri";

/**
 * Single blocklist identification result
 */
export interface BlocklistInfo {
  /** Name of the blocklist (e.g., 'Spamhaus ZEN', 'Barracuda') */
  name: string;
  /** Type of blocklist */
  type: BlocklistType;
}

/**
 * Multiple blocklists identification result
 */
export interface MultipleBlocklistInfo {
  /** Array of identified blocklists */
  lists: BlocklistInfo[];
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
}

/**
 * Classification result from the bounce classifier
 */
export interface ClassificationResult {
  /** The predicted label */
  label: BounceLabel;
  /** Confidence score (0-1) */
  confidence: number;
  /** Recommended action based on the label */
  action: BounceAction;
  /** Scores for all labels */
  scores: Record<BounceLabel, number>;
  /** Whether SMTP code fallback was used (present if true) */
  usedFallback?: boolean;
  /** Retry time in seconds (only present if timing found in message) */
  retryAfter?: number;
  /** Identified blocklist (only present if blocklist found in message) */
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
 * Initialization options
 */
export interface InitializeOptions {
  /** Path or URL to model directory (optional, uses default if not provided) */
  modelPath?: string;
}

/**
 * Action mapping from label to recommended action
 */
export const ACTION_MAP: Record<BounceLabel, BounceAction>;

/**
 * Known blocklist patterns for identification
 */
export const BLOCKLIST_PATTERNS: BlocklistPattern[];

/**
 * SMTP Enhanced Status Code mapping (RFC 3463)
 */
export const SMTP_CODE_MAP: Record<string, BounceLabel>;

/**
 * Main SMTP code mapping
 */
export const SMTP_MAIN_CODE_MAP: Record<string, BounceLabel>;

/**
 * Confidence threshold below which code-based fallback is used
 */
export const CODE_FALLBACK_THRESHOLD: number;

/**
 * Initialize the classifier by loading the model and vocabulary.
 * This is called automatically on first classification, but can be
 * called manually to pre-load the model.
 * @param options - Optional configuration
 */
export function initialize(options?: InitializeOptions): Promise<void>;

/**
 * Classify a single bounce message
 * @param message - The bounce/error message to classify
 * @returns Classification result with label, confidence, action, and scores
 */
export function classify(message: string): Promise<ClassificationResult>;

/**
 * Get list of all possible labels
 * @returns Array of label names
 */
export function getLabels(): Promise<BounceLabel[]>;

/**
 * Check if the classifier is initialized
 */
export function isReady(): boolean;

/**
 * Reset classifier state (for testing or re-initialization)
 */
export function reset(): void;

/**
 * Extract retry timing from a bounce message
 * @param message - The bounce message
 * @returns Retry time in seconds, or null if not found
 */
export function extractRetryTiming(message: string): number | null;

/**
 * Identify blocklists mentioned in a bounce message
 * @param message - The bounce message
 * @returns Blocklist info, or null if not found
 */
export function identifyBlocklist(
  message: string,
): BlocklistInfo | MultipleBlocklistInfo | null;

/**
 * Get recommended action based on bounce category
 * @param category - The bounce category/label
 * @returns Recommended action
 */
export function getAction(category: BounceLabel): BounceAction;

/**
 * Extract SMTP codes from a message
 * @param message - The bounce message
 * @returns Object with mainCode and extendedCode
 */
export function extractSmtpCodes(message: string): SmtpCodes;

/**
 * Get fallback classification based on SMTP codes
 * @param message - The bounce message
 * @returns Fallback label or null if no match
 */
export function getCodeBasedFallback(message: string): BounceLabel | null;

/**
 * Get fallback classification based on text patterns
 * @param message - The bounce message
 * @returns Fallback label or null if no match
 */
export function getTextBasedFallback(message: string): BounceLabel | null;

/**
 * Default export with all functions and constants
 */
declare const bounceClassifier: {
  classify: typeof classify;
  getLabels: typeof getLabels;
  initialize: typeof initialize;
  isReady: typeof isReady;
  reset: typeof reset;
  extractRetryTiming: typeof extractRetryTiming;
  identifyBlocklist: typeof identifyBlocklist;
  getAction: typeof getAction;
  extractSmtpCodes: typeof extractSmtpCodes;
  getCodeBasedFallback: typeof getCodeBasedFallback;
  getTextBasedFallback: typeof getTextBasedFallback;
  ACTION_MAP: typeof ACTION_MAP;
  BLOCKLIST_PATTERNS: typeof BLOCKLIST_PATTERNS;
  SMTP_CODE_MAP: typeof SMTP_CODE_MAP;
  SMTP_MAIN_CODE_MAP: typeof SMTP_MAIN_CODE_MAP;
  CODE_FALLBACK_THRESHOLD: typeof CODE_FALLBACK_THRESHOLD;
};

export default bounceClassifier;
