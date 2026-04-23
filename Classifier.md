# Classifier — Technical Overview

This document explains how `@postalsys/bounce-classifier` turns a free-text SMTP bounce message into a label and an operational action. It covers the end-to-end pipeline, the fallback strategy, metadata enrichment, and the model-update loop.

For the low-level neural-network math (weight layout, matrix multiplications, softmax numerics), see [`docs/inference.md`](docs/inference.md). This document references that one rather than duplicating it.

---

## 1. What the classifier does (and doesn't)

**Input.** A single bounce/error string — typically the human-readable diagnostic text from an SMTP rejection or a DSN's `Diagnostic-Code: smtp; …` field. Not a MIME message; not a full DSN envelope. Pair it with your own DSN/ARF parser if you have one.

**Output.** A result object with:

- `label` — one of 16 mutually-exclusive bounce categories (`user_unknown`, `mailbox_full`, `greylisting`, …).
- `confidence` — softmax probability of the top label, in `[0, 1]`.
- `action` — the *recommended operational step*, one of six: `remove`, `retry`, `retry_different_ip`, `fix_configuration`, `review`, `remove_content`.
- `scores` — softmax probabilities over all 16 labels.
- Optional enrichment: `retryAfter` (seconds), `blocklist` (identified RBL/URIBL), `usedFallback` (set when post-model rules changed the label).

**Design goals.** Sub-millisecond classification in JS, no native deps, deterministic per model version, works offline in Node and browser, and produces an *action* — not just a label — so the caller never has to write the "what do I do with a `user_unknown` result" logic itself.

**Non-goals.** Parsing MIME/DSN structure, looking up DNS, reading PTR records, reasoning about sender reputation. These belong above (or beside) the classifier, not inside it.

---

## 2. End-to-end pipeline

```
message: string
   │
   ▼
┌──────────────────┐
│ sanitizeMessage  │  reject null/empty; truncate to 10k chars
└──────────────────┘
   │
   ▼
┌──────────────────┐
│ tokenize         │  lowercase → strip punctuation → split →
│                  │  vocab lookup → pad/truncate to 100 tokens
└──────────────────┘
   │  int32[100]
   ▼
┌──────────────────┐
│ forward pass     │  embed → pool → dense(relu) → dense →
│                  │  softmax  (see docs/inference.md)
└──────────────────┘
   │  probs[16]
   ▼
┌──────────────────┐
│ argmax + label   │  top label + confidence
└──────────────────┘
   │
   ▼
┌──────────────────┐
│ fallback chain   │  user text patterns → built-in text patterns →
│                  │  SMTP extended code → SMTP main code
└──────────────────┘   (overrides model when rules are more reliable)
   │
   ▼
┌──────────────────┐
│ action lookup    │  label → operational action
└──────────────────┘
   │
   ▼
┌──────────────────┐
│ enrichment       │  retryAfter (timing), blocklist (RBL name)
└──────────────────┘
   │
   ▼
ClassificationResult
```

Everything runs in-process. There are no network calls, no database lookups, no DNS. Total per-call cost on a warm path is ~0.1–0.5 ms on a modern CPU.

Source: [`src/index.js`](src/index.js). The function `classify()` is the orchestrator; each stage below is factored into a small, individually-exported helper so they're usable in isolation (for logging, feature engineering, or testing).

---

## 3. Input sanitization

Defined in [`sanitizeMessage`](src/index.js):

- Rejects `null`, `undefined`, non-strings, and whitespace-only input with a descriptive `Error`.
- Truncates messages longer than `MAX_MESSAGE_LENGTH` (10,000 chars) rather than erroring. The model only looks at the first 100 tokens anyway; the larger cap exists so regex-based fallbacks don't pathologically scan 1 MB of text.

Sanitization runs *before* the in-flight counter increments, so a malformed call can't block a pending `reload()`.

---

## 4. Tokenization

Three-step normalization, then vocabulary mapping to a fixed-size `Int32Array(100)`:

```javascript
function preprocessText(text) {
  return text
    .toLowerCase()              // case-fold
    .replace(/[^\w\s]/g, " ")   // punctuation → space
    .replace(/\s+/g, " ")       // collapse whitespace
    .trim();
}
```

Words are looked up in a 5,000-entry `vocab.json`; unknown words map to token ID `1` (OOV), padding uses token ID `0`. Everything past the 100th word is dropped.

**Why this shape?** Bounce messages are short and highly templated — a 100-token window captures the operative text in virtually all real-world bounces. A larger window would cost more compute per call and wouldn't improve recall.

**Why strip punctuation?** SMTP codes (`5.1.1`) and email addresses (`<user@host>`) are still representable after stripping — the code becomes `5 1 1` (three separate tokens that the embedding learns to associate), and email fragments survive as their component words. The trade-off is losing the literal dot-separated-code form, which is fine because we recover SMTP codes via a dedicated regex in the enrichment step.

---

## 5. Neural network forward pass

Architecture (details in [`docs/inference.md`](docs/inference.md#1-model-architecture)):

```
Int32[100]
  → Embedding(5000 → 64)      [100, 64]
  → GlobalAveragePooling1D     [64]
  → Dense(64 → 64, ReLU)       [64]
  → Dense(64 → 16, Softmax)    [16]
```

**325,200 parameters total. 1,300,800 bytes on disk.**

This is a deliberately small model — bigger than bag-of-words-plus-logistic, smaller than anything resembling a transformer. The inductive bias is "a linear combination of averaged word embeddings, followed by a single hidden layer." That's enough capacity for bounce classification because:

1. **Vocabulary is narrow.** SMTP diagnostic text is written by a handful of MTA implementations (Postfix, Exim, Sendmail, Exchange, Gmail, Outlook, provider-specific MTAs). The same phrases recur across millions of messages.
2. **Labels are coarse.** 16 classes, mostly well-separated semantically. A model big enough to disambiguate `spam_blocked` from `policy_blocked` (the only genuinely hard pair) is also big enough for everything else.
3. **Inference has to be fast in JS.** A full JS matmul loop for the current model is ~0.1 ms; doubling the hidden layer quadruples the dense-matmul cost without comparable accuracy improvement.

**Averaging includes padding.** GlobalAveragePooling1D here divides by the full `MAX_LENGTH=100`, not by the non-padding token count. This matches TensorFlow's `mask_zero=False` behavior in the original Keras model. Short messages get attenuated pooled vectors (the non-zero embeddings are diluted by zeros from padded positions); the classifier layer learns to compensate. Changing this would require retraining.

The softmax output is interpreted two ways:

- **argmax → candidate label**, becomes `result.label` unless a fallback overrides it.
- **All 16 scores → `result.scores`**, exposed verbatim for callers who want to build their own decision logic (e.g. ensemble, route on top-2 disagreement, threshold per label).

---

## 6. The fallback chain

Raw argmax over softmax is *not* the classifier's final answer. A deterministic rule cascade runs after the model; it can override the ML prediction when a more reliable signal is available.

### 6.1 Why fallbacks exist

Two categories of input are genuinely better handled by rules than by a 325k-parameter embedding net:

- **Hyper-specific provider phrases.** `"illegal attachment"` (Gmail for infected mail), `"no such user"` (dozens of MTAs for user_unknown). These are short, exact, and the ML model's bag-of-embeddings representation can struggle when the diagnostic text is a single line with a rare word.
- **RFC 3463 enhanced status codes.** `5.1.1` means `user_unknown`. Full stop. When the SMTP code is explicit, no amount of ML can be *more* right than mapping the code directly.

The fallback chain makes the classifier robust on inputs the model was trained on *and* on the long tail of rare-phrasing bounces that fall outside the training distribution.

### 6.2 Order of evaluation

`classify()` runs the fallback chain in this order, short-circuiting on the first hit:

```
1. User-registered text patterns     (USER_TEXT_FALLBACKS)
   ↓ (if no match AND model uncertain)
2. Built-in text patterns            (TEXT_PATTERN_FALLBACKS)
   ↓
3. SMTP extended code map            (SMTP_CODE_MAP, 40+ entries)
   ↓
4. SMTP main code map                (SMTP_MAIN_CODE_MAP, 15 entries)
   ↓
   fall back to model's argmax label
```

Two important nuances:

- **Text patterns always take priority over the model**, even when the model is confident. If a bounce contains `"illegal attachment"`, it gets `virus_detected`. This is deliberate: text patterns are *curated*, they encode a human-specified certainty that doesn't get "outvoted" by a noisy embedding.
- **SMTP-code fallback triggers only when the model is uncertain** — specifically when `maxScore < 0.5` (the `CODE_FALLBACK_THRESHOLD`) *or* the model picked `unknown`. A confident model prediction beats the RFC code, because the code is often generic (`5.7.1 Message rejected for policy reasons` says nothing about which policy).

### 6.3 Text patterns

Defined in `TEXT_PATTERN_FALLBACKS` ([`src/index.js`](src/index.js)). A list of `{pattern: RegExp, label: string}` pairs, scanned in order; first match wins. Built-ins cover the most common user_unknown / auth_failure / virus_detected / mailbox_full / rate_limited phrasings, with `.{0,N}?` bounded quantifiers to prevent catastrophic backtracking on adversarial input.

Users can prepend their own via [`registerTextFallback({pattern, label})`](README.md#registertextfallback-pattern-label---cleartextfallbacks). User patterns are scanned *before* built-ins, so a project-specific bounce from an in-house MTA can be classified without retraining. See §10.

### 6.4 SMTP code extraction

`extractSmtpCodes()` parses both the 3-digit main code (e.g. `550`) and the RFC 3463 enhanced code (e.g. `5.1.1`) out of free-form text. Notable subtlety: the extended-code regex uses lookbehind/lookahead to avoid matching the first three octets of an IPv4 address (`5.7.1.100` must not yield `5.7.1`; `192.168.1.1` must not yield `2.168.1`). Without this guard, any bounce mentioning an IP whose octets coincide with a real status code would be misclassified — this was a genuine production bug, fixed in commit `665d332`.

Once extracted:

- `SMTP_CODE_MAP` maps 40+ extended codes to labels (e.g. `5.2.2 → mailbox_full`, `4.7.28 → rate_limited`).
- `SMTP_MAIN_CODE_MAP` maps 15 main codes when no extended code is present (e.g. `421 → greylisting`, `552 → mailbox_full`).

When either fires, `result.usedFallback = true` so downstream code can distinguish rule-based from model-based classifications.

---

## 7. Metadata enrichment

After labeling, `classify()` runs two optional extractors that attach structured fields to the result.

### 7.1 Retry timing

[`extractRetryTiming()`](src/index.js) scans the message for phrases like `"try again in 5 minutes"`, `"retry in 30 seconds"`, `"wait 2 hours"`, `"greylisted for 300 seconds"`, `"come back in 10 minutes"`. It returns an integer number of seconds in `[1, 86400]`, or `null`.

The 24-hour upper bound filters regex false-positives (e.g. an arbitrary `1000000` in a message isn't a real delay). The patterns are ordered from most specific ("greylisted for N") to most generic ("N seconds"), so the richer context wins when multiple patterns match.

`result.retryAfter` is useful even for non-retry labels — a `policy_blocked` bounce that includes a delay hint tells you the sender was retry-eligible despite the label, which can guide human review.

### 7.2 Blocklist identification

[`identifyBlocklist()`](src/index.js) checks the message against 24+ patterns covering Spamhaus (SBL, XBL, PBL, DBL, ZEN), Barracuda, SORBS, SpamCop, URIBL, Cloudmark, Proofpoint, Mimecast, Microsoft S3150, Invaluement, Hostkarma, Trend Micro, and generic "RBL"/"DNSBL"/"blacklist" terms.

Output shape is either:

- `{name, type}` when a single specific blocklist matches (`{name: "Spamhaus ZEN", type: "ip"}`).
- `{lists: [{name, type}, …]}` when multiple specific blocklists match.

Generic names (`RBL`, `DNSBL`, `Blocklist`) are deprioritized: if a specific provider matches *and* the message also contains the word "RBL", only the specific one is returned. Otherwise the generic name is returned as a fallback. This prevents low-signal matches from crowding out high-signal ones.

`type` is one of `"ip"`, `"domain"`, `"uri"` — important because `ip_blacklisted` and `domain_blacklisted` map to *different* recommended actions (retry from a different IP vs. fix your sender config).

---

## 8. Label → action mapping

The classifier's final product is `result.action`, a string enum that answers "what should the operator do now?" The mapping ([`ACTION_MAP`](src/index.js)) collapses 16 labels into 6 actions:

| Action                  | Labels                                                     | Meaning                                              |
| ----------------------- | ---------------------------------------------------------- | ---------------------------------------------------- |
| `remove`                | `user_unknown`, `invalid_address`, `mailbox_disabled`      | Permanent address failure — remove from list.        |
| `retry`                 | `greylisting`, `rate_limited`, `server_error`, `mailbox_full` | Temporary — resend after backoff (use `retryAfter` if present). |
| `retry_different_ip`    | `ip_blacklisted`, `geo_blocked`                            | Sender IP is the problem — route via a different IP. |
| `fix_configuration`     | `domain_blacklisted`, `auth_failure`, `relay_denied`       | Sender identity/config is the problem — human fix required. |
| `review`                | `spam_blocked`, `policy_blocked`, `unknown`                | Needs human judgment — either content, local policy, or the classifier couldn't decide. |
| `remove_content`        | `virus_detected`                                           | Message itself is problematic — don't retry this message; remove the attachment. |

This mapping is the library's opinionated product surface. The label vocabulary is what the model learned; the action vocabulary is what an operator cares about. Keeping them separate means the model can be retrained with finer label grain in the future without churning every caller's switch statement.

`getAction(label)` returns the action for any label; unknown labels default to `"review"`.

---

## 9. Confidence: when to trust the result

`result.confidence` is the softmax probability of the top label. Practical heuristics:

- **> 0.85**: very likely correct for in-distribution bounces. Auto-action safely.
- **0.5 – 0.85**: probably correct but worth logging. Useful to pair with the fallback chain — if `usedFallback` is also true, rules and model agreed on a final label through different paths, which is a strong signal.
- **< 0.5**: the SMTP-code fallback already ran (by design). If it produced a label, `usedFallback` is true and the final label comes from deterministic rules rather than the model. If it didn't, the classifier punts to `unknown` → `review`.

`result.scores` exposes the full distribution for callers who want more nuanced logic (e.g. "route to human if top-2 margin < 0.2", or "ensemble with a second model"). The scores always sum to ~1 (softmax) and each is in `[0, 1]`.

**Important**: published ~95% validation accuracy is *in-distribution* on a held-out slice of the trainer corpus. Real-world accuracy on your specific sender mix depends on how well your providers are represented in the training data. Non-English bounces are under-represented and classify less reliably; contributing samples to the trainer service (§11) is the fix.

---

## 10. Extension points

The classifier is intentionally opinionated but exposes three surfaces for customization without forking:

### 10.1 Custom text fallbacks

```javascript
import { registerTextFallback, clearTextFallbacks } from "@postalsys/bounce-classifier";

registerTextFallback({
  pattern: /XYZZY-PROVIDER-\d+/,
  label: "spam_blocked",
});
```

User patterns are scanned before built-ins and before SMTP codes, so they effectively override *everything*. They survive `reset()` and `reload()` (they're config, not model state); `clearTextFallbacks()` removes them. Validation is strict: `pattern` must be a `RegExp`, `label` must be a non-empty string.

Use this for project-specific bounce phrasings from in-house MTAs or niche providers the public trainer hasn't seen.

### 10.2 Custom model path

`initialize({modelPath})` or `reload({modelPath})` let you point at a different model directory — useful for A/B testing a retrained model, or for loading a model bundled in a custom format. The directory must contain `vocab.json`, `labels.json`, and `group1-shard1of1.bin`; `config.json` is optional metadata.

### 10.3 Low-level helpers

The internals are all exported so you can build your own pipeline:

- `extractSmtpCodes`, `extractRetryTiming`, `identifyBlocklist`, `getAction`
- `getTextBasedFallback`, `getCodeBasedFallback`
- Constants: `ACTION_MAP`, `BLOCKLIST_PATTERNS`, `SMTP_CODE_MAP`, `SMTP_MAIN_CODE_MAP`, `CODE_FALLBACK_THRESHOLD`

These aren't stable-versioned as strongly as `classify()`, but they're there so you can, for instance, log the extracted SMTP code alongside your own classification.

---

## 11. Model lifecycle

The neural network is *not* trained in this repo. Training happens in a separate service at [bounces.postalsys.com](https://bounces.postalsys.com) ("the Bounce Trainer"), which:

1. Accepts user-submitted labeled bounces from the community.
2. Periodically retrains the Keras model on the accumulated corpus.
3. Publishes the latest weights, vocab, labels, and metadata at `https://bounces.postalsys.com/api/model`.

This repo ships with a script, [`scripts/update-model.js`](scripts/update-model.js), that fetches the current model archive, hash-checks it against the local version, and updates `model/` in place. It runs automatically via `prepublishOnly` before each npm publish, and via `.github/workflows/pages.yml` on every push to master (so the live demo always serves the current model).

The trainer ↔ classifier separation means the published npm package can ship a fresh model without any source-code churn, and downstream users can retrain on their own corpus and swap in their weights via `modelPath`.

### 11.1 Model metadata

Each model ships with a `config.json` carrying:

- `model_hash` — short SHA-256 of the weights file (first 16 hex chars).
- `trained_at` — ISO 8601 UTC timestamp.
- `training_samples` — number of labeled bounces in the training set.
- `validation_accuracy` — held-out accuracy in `[0, 1]`.
- Architecture hyperparameters (`max_tokens`, `max_length`, `embedding_dim`, `num_labels`) used as runtime sanity checks.

`getModelInfo()` returns this metadata for display or logging. Callers writing durable records (e.g. storing classifications in a database for later audit) should persist `model_hash` alongside the result, so re-analysis later knows which model produced which prediction.

### 11.2 Reloading without restart

`reload()` re-reads the model from disk. This lets long-running processes pick up model updates without a full restart. The reload drains in-flight `classify()` calls before swapping state, so it's safe under concurrency.

---

## 12. Limitations and explicit trade-offs

- **Small model, small vocabulary.** 5,000 words, 325k parameters. Niche phrasings outside the trainer's corpus may misclassify.
- **English-biased.** The trainer corpus is predominantly English. Bounces in other languages classify less reliably. Contribute samples to the trainer.
- **100-token window.** Very long bounces get truncated at the token level; the model sees only the first 100 tokens after tokenization. This is almost never a problem for real bounces (they're short and front-load the diagnostic text) but is worth knowing.
- **No context across messages.** Each `classify()` is stateless. The classifier doesn't know that this is the 50th `greylisting` bounce from the same sender this hour — that's a policy layer above, not the classifier's job.
- **No PII redaction.** The classifier processes bounce text as-is, which often contains the full recipient email address. Data doesn't leave the process (no network calls) but if you log `result.scores` with the original message, you're logging PII. Redact at the log boundary.
- **Action mapping is opinionated.** `policy_blocked → review` is one view. Some operators want `policy_blocked → remove`. If you disagree with the mapping, wrap `result.label` in your own action lookup instead of using `result.action`.

---

## 13. Further reading

- [`docs/inference.md`](docs/inference.md) — weight file format, forward-pass math, environment compatibility.
- [`README.md`](README.md) — API reference, usage examples, labels table.
- [`bounces.postalsys.com`](https://bounces.postalsys.com) — Bounce Trainer service; submit labels here.
- RFC 3463 — Enhanced Mail System Status Codes (the SMTP extended codes the fallback chain uses).
- RFC 3464 — DSN format (the envelope that carries diagnostic text; you parse this *outside* the classifier).
