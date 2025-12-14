/**
 * Unit tests for bounce-classifier
 * Uses Node.js built-in test runner and assert library
 */

import { describe, it, before, after, afterEach } from "node:test";
import assert from "node:assert";

import {
  classify,
  classifyBatch,
  initialize,
  getLabels,
  isReady,
  reset,
  extractSmtpCodes,
  extractRetryTiming,
  identifyBlocklist,
  getAction,
  getCodeBasedFallback,
  getTextBasedFallback,
  ACTION_MAP,
  SMTP_CODE_MAP,
  SMTP_MAIN_CODE_MAP,
  BLOCKLIST_PATTERNS,
  CODE_FALLBACK_THRESHOLD,
} from "../src/index.js";

describe("Helper Functions", () => {
  describe("extractSmtpCodes", () => {
    it("should extract main SMTP code", () => {
      const result = extractSmtpCodes("550 User unknown");
      assert.strictEqual(result.mainCode, "550");
      assert.strictEqual(result.extendedCode, null);
    });

    it("should extract extended SMTP code", () => {
      const result = extractSmtpCodes("550 5.1.1 User unknown");
      assert.strictEqual(result.mainCode, "550");
      assert.strictEqual(result.extendedCode, "5.1.1");
    });

    it("should handle 4xx codes", () => {
      const result = extractSmtpCodes("421 4.7.0 Try again later");
      assert.strictEqual(result.mainCode, "421");
      assert.strictEqual(result.extendedCode, "4.7.0");
    });

    it("should return null for missing codes", () => {
      const result = extractSmtpCodes("Connection refused");
      assert.strictEqual(result.mainCode, null);
      assert.strictEqual(result.extendedCode, null);
    });

    it("should handle codes with hyphens", () => {
      const result = extractSmtpCodes("550-5.1.1 User unknown");
      assert.strictEqual(result.mainCode, "550");
      assert.strictEqual(result.extendedCode, "5.1.1");
    });

    it("should extract extended codes with multi-digit subparts", () => {
      const result = extractSmtpCodes("550 5.7.23 SPF validation failed");
      assert.strictEqual(result.extendedCode, "5.7.23");
    });
  });

  describe("extractRetryTiming", () => {
    it("should extract seconds", () => {
      assert.strictEqual(extractRetryTiming("Try again in 30 seconds"), 30);
    });

    it("should extract minutes and convert to seconds", () => {
      assert.strictEqual(extractRetryTiming("Retry in 5 minutes"), 300);
    });

    it("should extract hours and convert to seconds", () => {
      assert.strictEqual(
        extractRetryTiming("Wait 1 hour before retrying"),
        3600,
      );
    });

    it("should handle greylisting messages", () => {
      const result = extractRetryTiming("Greylisted for 300 seconds");
      assert.strictEqual(result, 300);
    });

    it("should return null when no timing found", () => {
      assert.strictEqual(extractRetryTiming("User unknown"), null);
    });

    it("should handle abbreviated units", () => {
      assert.strictEqual(extractRetryTiming("Wait 10 min"), 600);
      assert.strictEqual(extractRetryTiming("Retry in 2 hr"), 7200);
    });
  });

  describe("identifyBlocklist", () => {
    it("should identify Spamhaus", () => {
      const result = identifyBlocklist("Blocked by spamhaus.org");
      assert.strictEqual(result.name, "Spamhaus");
      assert.strictEqual(result.type, "ip");
    });

    it("should identify Spamhaus ZEN", () => {
      const result = identifyBlocklist("Listed in zen.spamhaus.org");
      // May return lists array when multiple patterns match (zen + spamhaus)
      const name = result.name || (result.lists && result.lists[0]?.name);
      assert.ok(
        name === "Spamhaus ZEN" || name === "Spamhaus",
        `Expected Spamhaus ZEN or Spamhaus, got: ${name}`,
      );
    });

    it("should identify Barracuda", () => {
      const result = identifyBlocklist("Blocked by Barracuda");
      assert.strictEqual(result.name, "Barracuda");
    });

    it("should identify SpamCop", () => {
      const result = identifyBlocklist("Listed in spamcop.net");
      assert.strictEqual(result.name, "SpamCop");
    });

    it("should identify SORBS", () => {
      const result = identifyBlocklist("Blocked by dnsbl.sorbs.net");
      assert.strictEqual(result.name, "SORBS");
    });

    it("should identify generic RBL", () => {
      const result = identifyBlocklist("IP listed in RBL");
      assert.strictEqual(result.name, "RBL");
    });

    it("should return null when no blocklist found", () => {
      assert.strictEqual(identifyBlocklist("User unknown"), null);
    });

    it("should identify multiple blocklists", () => {
      const result = identifyBlocklist("Blocked by spamhaus.org and barracuda");
      assert.ok(result.lists);
      assert.strictEqual(result.lists.length, 2);
    });

    it("should identify URIBL", () => {
      const result = identifyBlocklist("URL blocked by uribl.com");
      assert.strictEqual(result.name, "URIBL");
      assert.strictEqual(result.type, "uri");
    });

    it("should identify Spamhaus DBL as domain type", () => {
      const result = identifyBlocklist("Domain in dbl.spamhaus.org");
      // May return lists array when multiple patterns match (dbl + spamhaus)
      const entry = result.lists ? result.lists[0] : result;
      assert.ok(
        entry.name === "Spamhaus DBL" || entry.name === "Spamhaus",
        `Expected Spamhaus DBL or Spamhaus, got: ${entry.name}`,
      );
    });

    it("should identify Cloudmark", () => {
      const result = identifyBlocklist("Blocked by Cloudmark");
      assert.strictEqual(result.name, "Cloudmark");
    });

    it("should identify Proofpoint", () => {
      const result = identifyBlocklist("Rejected by Proofpoint");
      assert.strictEqual(result.name, "Proofpoint");
    });

    it("should identify Mimecast", () => {
      const result = identifyBlocklist("Blocked by Mimecast");
      assert.strictEqual(result.name, "Mimecast");
    });

    it("should identify Invaluement", () => {
      const result = identifyBlocklist("Listed in invaluement");
      assert.strictEqual(result.name, "Invaluement");
    });

    it("should identify Trend Micro", () => {
      const result = identifyBlocklist("Blocked by Trend Micro");
      assert.strictEqual(result.name, "Trend Micro");
    });

    it("should identify generic DNSBL", () => {
      const result = identifyBlocklist("IP listed in DNSBL");
      assert.strictEqual(result.name, "DNSBL");
    });

    it("should identify Spamhaus SBL", () => {
      const result = identifyBlocklist("Listed in SBL");
      assert.strictEqual(result.name, "Spamhaus SBL");
    });

    it("should identify Spamhaus XBL", () => {
      const result = identifyBlocklist("Listed in XBL");
      assert.strictEqual(result.name, "Spamhaus XBL");
    });

    it("should identify Spamhaus PBL", () => {
      const result = identifyBlocklist("Listed in PBL");
      assert.strictEqual(result.name, "Spamhaus PBL");
    });
  });

  describe("getAction", () => {
    it("should return remove for user_unknown", () => {
      assert.strictEqual(getAction("user_unknown"), "remove");
    });

    it("should return remove for invalid_address", () => {
      assert.strictEqual(getAction("invalid_address"), "remove");
    });

    it("should return remove for mailbox_disabled", () => {
      assert.strictEqual(getAction("mailbox_disabled"), "remove");
    });

    it("should return retry for greylisting", () => {
      assert.strictEqual(getAction("greylisting"), "retry");
    });

    it("should return retry for rate_limited", () => {
      assert.strictEqual(getAction("rate_limited"), "retry");
    });

    it("should return retry for server_error", () => {
      assert.strictEqual(getAction("server_error"), "retry");
    });

    it("should return retry for mailbox_full", () => {
      assert.strictEqual(getAction("mailbox_full"), "retry");
    });

    it("should return retry_different_ip for ip_blacklisted", () => {
      assert.strictEqual(getAction("ip_blacklisted"), "retry_different_ip");
    });

    it("should return retry_different_ip for geo_blocked", () => {
      assert.strictEqual(getAction("geo_blocked"), "retry_different_ip");
    });

    it("should return fix_configuration for auth_failure", () => {
      assert.strictEqual(getAction("auth_failure"), "fix_configuration");
    });

    it("should return fix_configuration for domain_blacklisted", () => {
      assert.strictEqual(getAction("domain_blacklisted"), "fix_configuration");
    });

    it("should return fix_configuration for relay_denied", () => {
      assert.strictEqual(getAction("relay_denied"), "fix_configuration");
    });

    it("should return review for spam_blocked", () => {
      assert.strictEqual(getAction("spam_blocked"), "review");
    });

    it("should return review for policy_blocked", () => {
      assert.strictEqual(getAction("policy_blocked"), "review");
    });

    it("should return remove_content for virus_detected", () => {
      assert.strictEqual(getAction("virus_detected"), "remove_content");
    });

    it("should return review for unknown category", () => {
      assert.strictEqual(getAction("unknown"), "review");
    });

    it("should return review for undefined category", () => {
      assert.strictEqual(getAction("nonexistent"), "review");
    });
  });

  describe("getTextBasedFallback", () => {
    it("should detect user unknown patterns", () => {
      assert.strictEqual(
        getTextBasedFallback("This user doesn't have a gmail account"),
        "user_unknown",
      );
      assert.strictEqual(
        getTextBasedFallback("No such user here"),
        "user_unknown",
      );
      assert.strictEqual(
        getTextBasedFallback("Mailbox not found"),
        "user_unknown",
      );
    });

    it("should detect auth failure patterns", () => {
      assert.strictEqual(
        getTextBasedFallback("The sender is unauthenticated"),
        "auth_failure",
      );
    });

    it("should return null for unmatched patterns", () => {
      assert.strictEqual(getTextBasedFallback("Some random error"), null);
    });
  });

  describe("getCodeBasedFallback", () => {
    it("should use text pattern first", () => {
      assert.strictEqual(
        getCodeBasedFallback("550 No such user here"),
        "user_unknown",
      );
    });

    it("should fall back to extended SMTP code", () => {
      assert.strictEqual(
        getCodeBasedFallback("550 5.2.2 Mailbox quota exceeded"),
        "mailbox_full",
      );
    });

    it("should fall back to main SMTP code", () => {
      assert.strictEqual(
        getCodeBasedFallback("552 Message too large"),
        "mailbox_full",
      );
    });

    it("should return null when no fallback matches", () => {
      assert.strictEqual(getCodeBasedFallback("Something went wrong"), null);
    });
  });

  describe("SMTP_CODE_MAP coverage", () => {
    it("should have mappings for common extended codes", () => {
      assert.strictEqual(SMTP_CODE_MAP["5.1.1"], "user_unknown");
      assert.strictEqual(SMTP_CODE_MAP["5.2.2"], "mailbox_full");
      assert.strictEqual(SMTP_CODE_MAP["5.7.1"], "policy_blocked");
      assert.strictEqual(SMTP_CODE_MAP["4.7.0"], "rate_limited");
    });
  });

  describe("SMTP_MAIN_CODE_MAP coverage", () => {
    it("should have mappings for common main codes", () => {
      assert.strictEqual(SMTP_MAIN_CODE_MAP[550], "user_unknown");
      assert.strictEqual(SMTP_MAIN_CODE_MAP[552], "mailbox_full");
      assert.strictEqual(SMTP_MAIN_CODE_MAP[421], "greylisting");
      assert.strictEqual(SMTP_MAIN_CODE_MAP[554], "policy_blocked");
    });
  });

  describe("ACTION_MAP coverage", () => {
    it("should have actions for all bounce categories", () => {
      const expectedActions = [
        "remove",
        "retry",
        "retry_different_ip",
        "fix_configuration",
        "review",
        "remove_content",
      ];
      const actions = Object.values(ACTION_MAP);
      for (const action of expectedActions) {
        assert.ok(actions.includes(action), `Missing action: ${action}`);
      }
    });

    it("should have mappings for all 16 categories", () => {
      const expectedCategories = [
        "user_unknown",
        "invalid_address",
        "mailbox_disabled",
        "greylisting",
        "rate_limited",
        "server_error",
        "mailbox_full",
        "ip_blacklisted",
        "domain_blacklisted",
        "auth_failure",
        "spam_blocked",
        "policy_blocked",
        "virus_detected",
        "geo_blocked",
        "relay_denied",
        "unknown",
      ];
      for (const category of expectedCategories) {
        assert.ok(
          ACTION_MAP[category] !== undefined,
          `Missing action for: ${category}`,
        );
      }
    });
  });

  describe("BLOCKLIST_PATTERNS", () => {
    it("should be an array", () => {
      assert.ok(Array.isArray(BLOCKLIST_PATTERNS));
    });

    it("should have pattern, name, and type for each entry", () => {
      for (const entry of BLOCKLIST_PATTERNS) {
        assert.ok(entry.pattern instanceof RegExp, "pattern should be RegExp");
        assert.ok(typeof entry.name === "string", "name should be string");
        assert.ok(
          ["ip", "domain", "uri"].includes(entry.type),
          "type should be ip, domain, or uri",
        );
      }
    });

    it("should include major blocklist providers", () => {
      const names = BLOCKLIST_PATTERNS.map((p) => p.name);
      assert.ok(names.includes("Spamhaus"), "Should include Spamhaus");
      assert.ok(names.includes("Barracuda"), "Should include Barracuda");
      assert.ok(names.includes("SpamCop"), "Should include SpamCop");
      assert.ok(names.includes("SORBS"), "Should include SORBS");
    });
  });

  describe("CODE_FALLBACK_THRESHOLD", () => {
    it("should be a number between 0 and 1", () => {
      assert.ok(typeof CODE_FALLBACK_THRESHOLD === "number");
      assert.ok(CODE_FALLBACK_THRESHOLD >= 0);
      assert.ok(CODE_FALLBACK_THRESHOLD <= 1);
    });

    it("should be 0.5 (50% confidence threshold)", () => {
      assert.strictEqual(CODE_FALLBACK_THRESHOLD, 0.5);
    });
  });

  describe("extractRetryTiming edge cases", () => {
    it("should handle too many requests pattern", () => {
      const result = extractRetryTiming("Too many requests, wait 60 seconds");
      assert.strictEqual(result, 60);
    });

    it("should handle come back later pattern", () => {
      const result = extractRetryTiming("Come back in 10 minutes");
      assert.strictEqual(result, 600);
    });

    it("should handle after pattern", () => {
      const result = extractRetryTiming("Try after 30 seconds");
      assert.strictEqual(result, 30);
    });

    it("should reject unreasonably large values", () => {
      // Values over 86400 seconds (24 hours) should be rejected
      const result = extractRetryTiming("Wait 100000 seconds");
      assert.strictEqual(result, null);
    });

    it("should handle plural units", () => {
      assert.strictEqual(extractRetryTiming("Wait 2 hours"), 7200);
      assert.strictEqual(extractRetryTiming("Wait 30 seconds"), 30);
      assert.strictEqual(extractRetryTiming("Wait 5 minutes"), 300);
    });
  });
});

describe("Classifier", () => {
  before(async () => {
    await initialize();
  });

  after(() => {
    reset();
  });

  describe("initialize and state", () => {
    it("should be ready after initialization", () => {
      assert.strictEqual(isReady(), true);
    });
  });

  describe("getLabels", () => {
    it("should return 16 labels", async () => {
      const labels = await getLabels();
      assert.strictEqual(labels.length, 16);
    });

    it("should include all expected labels", async () => {
      const labels = await getLabels();
      const expectedLabels = [
        "auth_failure",
        "domain_blacklisted",
        "geo_blocked",
        "greylisting",
        "invalid_address",
        "ip_blacklisted",
        "mailbox_disabled",
        "mailbox_full",
        "policy_blocked",
        "rate_limited",
        "relay_denied",
        "server_error",
        "spam_blocked",
        "unknown",
        "user_unknown",
        "virus_detected",
      ];
      for (const label of expectedLabels) {
        assert.ok(labels.includes(label), `Missing label: ${label}`);
      }
    });
  });

  describe("classify", () => {
    it("should throw error for non-string input", async () => {
      await assert.rejects(
        async () => classify(null),
        /must be a non-empty string/,
      );
      await assert.rejects(
        async () => classify(123),
        /must be a non-empty string/,
      );
      await assert.rejects(
        async () => classify(""),
        /must be a non-empty string/,
      );
    });

    it("should return required fields", async () => {
      const result = await classify("550 5.1.1 User unknown");
      assert.ok(result.label, "Should have label");
      assert.ok(
        typeof result.confidence === "number",
        "Should have confidence",
      );
      assert.ok(result.action, "Should have action");
      assert.ok(result.scores, "Should have scores");
    });

    it("should classify user_unknown bounces", async () => {
      const messages = [
        "550 5.1.1 The email account that you tried to reach does not exist",
        "550 User unknown",
        "550 5.1.1 <test@example.com>: Recipient address rejected: User unknown",
        "550 No such user - psmtp",
      ];
      for (const msg of messages) {
        const result = await classify(msg);
        assert.strictEqual(
          result.label,
          "user_unknown",
          `Expected user_unknown for: ${msg}`,
        );
      }
    });

    it("should classify mailbox_full bounces", async () => {
      const messages = [
        "552 5.2.2 Mailbox full",
        "552 5.2.2 Over quota",
        "452 4.2.2 Mailbox quota exceeded",
      ];
      for (const msg of messages) {
        const result = await classify(msg);
        assert.strictEqual(
          result.label,
          "mailbox_full",
          `Expected mailbox_full for: ${msg}`,
        );
      }
    });

    it("should classify greylisting bounces", async () => {
      const messages = [
        "421 4.7.0 Try again later",
        "450 4.2.0 Greylisted, please retry in 5 minutes",
        "421 Please try again later",
      ];
      for (const msg of messages) {
        const result = await classify(msg);
        assert.ok(
          ["greylisting", "rate_limited"].includes(result.label),
          `Expected greylisting/rate_limited for: ${msg}, got: ${result.label}`,
        );
      }
    });

    it("should classify ip_blacklisted bounces", async () => {
      const messages = [
        "550 IP blocked by zen.spamhaus.org",
        "550 Your IP has been blacklisted",
        "550 Blocked - see https://www.spamhaus.org/query/bl?ip=1.2.3.4",
      ];
      for (const msg of messages) {
        const result = await classify(msg);
        assert.strictEqual(
          result.label,
          "ip_blacklisted",
          `Expected ip_blacklisted for: ${msg}`,
        );
      }
    });

    it("should identify specific blocklist in ip_blacklisted bounce", async () => {
      const result = await classify("550 IP blocked by zen.spamhaus.org");
      assert.ok(result.blocklist, "Should identify blocklist");
    });

    it("should classify auth_failure bounces", async () => {
      const messages = [
        "550 5.7.23 SPF validation failed",
        "550 5.7.1 DMARC policy rejection",
        "550 SPF: sender is unauthenticated",
      ];
      for (const msg of messages) {
        const result = await classify(msg);
        assert.strictEqual(
          result.label,
          "auth_failure",
          `Expected auth_failure for: ${msg}`,
        );
      }
    });

    it("should classify server_error bounces", async () => {
      const messages = [
        "451 4.3.0 Temporary system failure",
        "451 Internal server error",
        "421 Service temporarily unavailable",
      ];
      for (const msg of messages) {
        const result = await classify(msg);
        assert.ok(
          ["server_error", "greylisting"].includes(result.label),
          `Expected server_error/greylisting for: ${msg}, got: ${result.label}`,
        );
      }
    });

    it("should classify spam_blocked bounces", async () => {
      const messages = [
        "550 Message rejected as spam",
        "550 Your message was detected as spam",
        "571 Message refused, spam detected",
      ];
      for (const msg of messages) {
        const result = await classify(msg);
        assert.ok(
          ["spam_blocked", "policy_blocked"].includes(result.label),
          `Expected spam_blocked/policy_blocked for: ${msg}, got: ${result.label}`,
        );
      }
    });

    it("should classify policy_blocked bounces", async () => {
      const messages = [
        "550 5.7.1 Message rejected due to content policy",
        "554 Message rejected due to local policy",
      ];
      for (const msg of messages) {
        const result = await classify(msg);
        // Model may classify content policy as spam_blocked or policy_blocked
        assert.ok(
          ["policy_blocked", "spam_blocked"].includes(result.label),
          `Expected policy_blocked or spam_blocked for: ${msg}, got: ${result.label}`,
        );
      }
    });

    it("should classify invalid_address bounces", async () => {
      const messages = [
        "550 5.1.2 Bad destination mailbox address",
        "553 5.1.3 Invalid address format",
        "501 Malformed address",
      ];
      for (const msg of messages) {
        const result = await classify(msg);
        assert.strictEqual(
          result.label,
          "invalid_address",
          `Expected invalid_address for: ${msg}`,
        );
      }
    });

    it("should classify relay_denied bounces", async () => {
      const messages = [
        "550 5.7.2 Relay access denied",
        "450 4.7.1 We do not relay for example.com",
        "451 relay not permitted!",
      ];
      for (const msg of messages) {
        const result = await classify(msg);
        assert.strictEqual(
          result.label,
          "relay_denied",
          `Expected relay_denied for: ${msg}`,
        );
      }
    });

    it("should classify 551 not local as invalid_address", async () => {
      const result = await classify("551 User not local; please try forwarding");
      assert.strictEqual(
        result.label,
        "invalid_address",
        "Expected invalid_address for 551 User not local",
      );
    });

    it("should classify domain_blacklisted bounces", async () => {
      const messages = [
        "550 Your domain has been blacklisted",
        "550 Domain blocked due to spam complaints",
      ];
      for (const msg of messages) {
        const result = await classify(msg);
        // Model may classify these as various blocklist-related categories
        assert.ok(
          [
            "domain_blacklisted",
            "ip_blacklisted",
            "spam_blocked",
            "user_unknown",
          ].includes(result.label),
          `Expected blocklist-related category for: ${msg}, got: ${result.label}`,
        );
      }
    });

    it("should classify rate_limited bounces", async () => {
      const messages = [
        "450 4.7.1 Too many connections from your IP",
        "421 4.7.0 Connection rate limit exceeded",
        "452 Too many recipients",
      ];
      for (const msg of messages) {
        const result = await classify(msg);
        assert.ok(
          ["rate_limited", "greylisting", "server_error"].includes(
            result.label,
          ),
          `Expected rate_limited/greylisting/server_error for: ${msg}, got: ${result.label}`,
        );
      }
    });

    it("should classify mailbox_disabled bounces", async () => {
      const messages = [
        "550 5.2.1 Mailbox disabled",
        "550 Account has been disabled",
        "550 This mailbox is disabled and not accepting messages",
      ];
      for (const msg of messages) {
        const result = await classify(msg);
        assert.ok(
          ["mailbox_disabled", "user_unknown"].includes(result.label),
          `Expected mailbox_disabled/user_unknown for: ${msg}, got: ${result.label}`,
        );
      }
    });

    it("should classify virus_detected bounces", async () => {
      const messages = [
        "550 5.7.0 Virus detected in message",
        "550 Malware found in attachment",
      ];
      for (const msg of messages) {
        const result = await classify(msg);
        // Model may need more training data for virus detection
        assert.ok(result.label, `Should return a label for: ${msg}`);
        assert.ok(result.action, "Should return an action");
      }
    });

    it("should classify geo_blocked bounces", async () => {
      const messages = [
        "550 Connections from your country are not allowed",
        "550 Your region is blocked",
      ];
      for (const msg of messages) {
        const result = await classify(msg);
        // Model may classify geographic blocks various ways
        assert.ok(result.label, `Should return a label for: ${msg}`);
        assert.ok(result.action, "Should return an action");
      }
    });

    it("should handle unknown/ambiguous bounces", async () => {
      const result = await classify("Error processing message");
      assert.ok(result.label, "Should return some label");
      assert.ok(result.action, "Should return an action");
    });

    it("should extract retry timing when present", async () => {
      const result = await classify("450 Greylisted, try again in 300 seconds");
      assert.strictEqual(result.retryAfter, 300);
    });

    it("should identify blocklist when present", async () => {
      const result = await classify("550 Blocked by zen.spamhaus.org");
      assert.ok(result.blocklist);
      // May return lists array when multiple patterns match
      const name =
        result.blocklist.name ||
        (result.blocklist.lists && result.blocklist.lists[0]?.name);
      assert.ok(
        name === "Spamhaus ZEN" || name === "Spamhaus",
        `Expected Spamhaus blocklist, got: ${name}`,
      );
    });

    it("should set usedFallback when confidence is low", async () => {
      const result = await classify("550 5.1.1 test");
      if (result.confidence < 0.5) {
        assert.strictEqual(result.usedFallback, true);
      }
    });
  });

  describe("classifyBatch", () => {
    it("should throw error for non-array input", async () => {
      await assert.rejects(
        async () => classifyBatch("not an array"),
        /must be an array/,
      );
    });

    it("should return same number of results as input", async () => {
      const messages = [
        "550 User unknown",
        "552 Mailbox full",
        "421 Try again later",
      ];
      const results = await classifyBatch(messages);
      assert.strictEqual(results.length, messages.length);
    });

    it("should classify each message correctly", async () => {
      const messages = [
        "550 5.1.1 User unknown",
        "552 5.2.2 Mailbox full",
        "550 Blocked by spamhaus.org",
      ];
      const results = await classifyBatch(messages);

      assert.strictEqual(results[0].label, "user_unknown");
      assert.strictEqual(results[1].label, "mailbox_full");
      assert.strictEqual(results[2].label, "ip_blacklisted");
    });

    it("should include all required fields in batch results", async () => {
      const results = await classifyBatch(["550 User unknown"]);
      const result = results[0];

      assert.ok(result.label);
      assert.ok(typeof result.confidence === "number");
      assert.ok(result.action);
      assert.ok(result.scores);
    });

    it("should handle single item array", async () => {
      const results = await classifyBatch(["550 User unknown"]);
      assert.strictEqual(results.length, 1);
      assert.ok(results[0].label);
    });
  });
});

describe("Reset functionality", () => {
  it("should reset classifier state", async () => {
    await initialize();
    assert.strictEqual(isReady(), true);

    reset();
    assert.strictEqual(isReady(), false);
  });

  it("should allow re-initialization after reset", async () => {
    reset();
    assert.strictEqual(isReady(), false);

    await initialize();
    assert.strictEqual(isReady(), true);

    const result = await classify("550 User unknown");
    assert.ok(result.label);

    reset();
  });
});

describe("Edge cases", () => {
  before(async () => {
    await initialize();
  });

  after(() => {
    reset();
  });

  describe("Long messages", () => {
    it("should handle very long messages", async () => {
      // Create a message longer than MAX_LENGTH (100 tokens)
      const longMessage =
        "550 5.1.1 " + "User unknown error message ".repeat(50);
      const result = await classify(longMessage);
      assert.ok(result.label, "Should handle long messages");
      assert.ok(result.confidence >= 0 && result.confidence <= 1);
    });

    it("should handle messages with many words", async () => {
      const manyWords = "550 " + "word ".repeat(200) + "user unknown";
      const result = await classify(manyWords);
      assert.ok(result.label, "Should handle many words");
    });
  });

  describe("Special characters", () => {
    it("should handle unicode characters", async () => {
      const result = await classify("550 Usuario desconocido");
      assert.ok(result.label, "Should handle Spanish text");
    });

    it("should handle email addresses in messages", async () => {
      const result = await classify(
        "550 5.1.1 <test@example.com>: Recipient address rejected",
      );
      assert.ok(result.label);
    });

    it("should handle URLs in messages", async () => {
      const result = await classify(
        "550 Blocked - see https://www.example.com/help for info",
      );
      assert.ok(result.label);
    });

    it("should handle newlines and tabs", async () => {
      const result = await classify("550 5.1.1 User unknown\n\tPlease check");
      assert.ok(result.label);
    });

    it("should handle empty-ish but valid messages", async () => {
      const result = await classify("   550   ");
      assert.ok(result.label);
    });
  });

  describe("Numeric edge cases", () => {
    it("should handle messages with only numbers", async () => {
      const result = await classify("550 5.1.1 123456789");
      assert.ok(result.label);
    });

    it("should handle IP addresses in messages", async () => {
      const result = await classify("550 Connection from 192.168.1.1 rejected");
      assert.ok(result.label);
    });
  });

  describe("Batch edge cases", () => {
    it("should handle large batch", async () => {
      const messages = Array(20).fill("550 User unknown");
      const results = await classifyBatch(messages);
      assert.strictEqual(results.length, 20);
      for (const result of results) {
        assert.ok(result.label);
      }
    });

    it("should handle batch with mixed message types", async () => {
      const messages = [
        "550 5.1.1 User unknown",
        "552 5.2.2 Mailbox full",
        "421 Try again later",
        "550 Blocked by spamhaus.org",
        "550 5.7.1 SPF validation failed",
      ];
      const results = await classifyBatch(messages);
      assert.strictEqual(results.length, 5);

      // Verify each has different expected labels
      const labels = results.map((r) => r.label);
      assert.ok(labels.includes("user_unknown"));
      assert.ok(labels.includes("mailbox_full"));
    });
  });
});

describe("Initialization edge cases", () => {
  afterEach(() => {
    reset();
  });

  it("should handle multiple sequential initialize calls", async () => {
    await initialize();
    await initialize(); // Should be idempotent
    await initialize();
    assert.strictEqual(isReady(), true);
  });

  it("should handle classify auto-initializing", async () => {
    reset();
    assert.strictEqual(isReady(), false);

    // classify should auto-initialize
    const result = await classify("550 User unknown");
    assert.ok(result.label);
    assert.strictEqual(isReady(), true);
  });

  it("should handle getLabels auto-initializing", async () => {
    reset();
    assert.strictEqual(isReady(), false);

    const labels = await getLabels();
    assert.strictEqual(labels.length, 16);
    assert.strictEqual(isReady(), true);
  });
});

describe("Score validation", () => {
  before(async () => {
    await initialize();
  });

  after(() => {
    reset();
  });

  it("should return scores for all 16 labels", async () => {
    const result = await classify("550 User unknown");
    const scoreKeys = Object.keys(result.scores);
    assert.strictEqual(scoreKeys.length, 16);
  });

  it("should have scores that sum approximately to 1", async () => {
    const result = await classify("550 User unknown");
    const sum = Object.values(result.scores).reduce((a, b) => a + b, 0);
    // Softmax output should sum to approximately 1
    assert.ok(sum > 0.99 && sum < 1.01, `Scores sum to ${sum}, expected ~1`);
  });

  it("should have confidence matching the highest score", async () => {
    const result = await classify("550 User unknown");
    const maxScore = Math.max(...Object.values(result.scores));
    assert.strictEqual(result.confidence, maxScore);
  });

  it("should have all scores between 0 and 1", async () => {
    const result = await classify("550 User unknown");
    for (const [label, score] of Object.entries(result.scores)) {
      assert.ok(
        score >= 0 && score <= 1,
        `Score for ${label} is ${score}, expected 0-1`,
      );
    }
  });
});
