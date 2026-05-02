# SAFE-M-5: Content Sanitization

## Overview
**Mitigation ID**: SAFE-M-5  
**Category**: Input Validation  
**Effectiveness**: Medium  
**Implementation Complexity**: Low-Medium  
**First Published**: 2025-01-03

## Description
Content Sanitization is a rule-based filter applied at *inbound* MCP pipeline emit points — tool-description load and retrieved-memory ingest — to strip hidden content patterns and instruction markers before that content enters the model context. It is the deterministic stage of an M-5 → M-3 escalation pipeline: rule hits with low confidence escalate to M-3 *AI-Powered Content Analysis* for model-based classification. It uses pattern matching and structural analysis against an operator-tunable ruleset, with hard-floor rules (always-block) distinguished from tunable rules (operator-configurable threshold). Each sanitization decision (pass / strip / block) emits a structured event to SAFE-M-12 *Audit Logging* so SAFE-M-11 *Behavioral Monitoring* can baseline filter-firing rates over time.

This mitigation is intentionally a layer in defense-in-depth, not a standalone defense. Pattern-based filtering alone is necessarily incomplete: novel attack patterns evade rule sets until added, and adversaries iterate evasion variants. Pair M-5 with [SAFE-M-1](../SAFE-M-1/README.md) *Architectural Defense - Control/Data Flow Separation* (the ambient architectural control that M-5 runs inside), [SAFE-M-3](../SAFE-M-3/README.md) *AI-Powered Content Analysis* (the second-stage classifier for low-confidence M-5 hits, escalation-gated by an operator-tunable suspicion-score threshold), [SAFE-M-4](../SAFE-M-4/README.md) *Unicode Sanitization and Filtering* (the narrow Unicode-specific specialization run as a deterministic pre-pass), and [SAFE-M-22](../SAFE-M-22/README.md) *Semantic Output Validation* (the symmetric output-side gate; M-22 owns outbound surfaces that are intentionally not part of M-5).

## Mitigates

The mitigation directly addresses the following techniques (curated against the actual citation graph; 3 mislabels and 4 partial-fit citers excluded — see Out of scope):

- [SAFE-T1001](../../techniques/SAFE-T1001/README.md): Tool Poisoning Attack (TPA) — sanitization strips hidden instruction patterns and unusual control characters from tool descriptions before they reach the model context.
- [SAFE-T1102](../../techniques/SAFE-T1102/README.md): Prompt Injection (Multiple Vectors) — pattern matching at retrieved-memory and tool-description ingest points removes the most common injection markers (role-prompt phrasing, instruction-override attempts) before they enter the context.
- [SAFE-T1401](../../techniques/SAFE-T1401/README.md): Line Jumping — content arriving at inbound emit points is filtered before it can be ordered ahead of trusted prompt segments in the context window.
- [SAFE-T1604](../../techniques/SAFE-T1604/README.md): Multi-Modal Cross-Channel Injection — text-channel content arriving via inbound emit points is sanitized; multi-modal channels with their own preprocessing add filter coverage at their respective emit points.
- [SAFE-T1705](../../techniques/SAFE-T1705/README.md): Cross-Server Tool Description Conflict — tool-description sanitization at load time strips embedded instructions before any conflict resolution occurs in the host.
- [SAFE-T1910](../../techniques/SAFE-T1910/README.md): Output Format Manipulation — inbound content is filtered before it can manipulate the model into emitting attacker-controlled output formats. (Output-side validation is M-22's responsibility.)
- [SAFE-T2105](../../techniques/SAFE-T2105/README.md): Disinformation Output — sanitizing inbound content (retrieved memory, tool descriptions) reduces the corpus of attacker-controllable inputs that could shape model output toward disinformation. Pair with M-22 for output-side validation.

Three citers reference M-5 with non-matching control concepts and four cite M-5 with matching concept but expect functionality outside M-5's content-sanitization scope. See Out of scope below for the per-citer detail.

## Technical Implementation

### Core Principles

1. **Multi-stage filtering at inbound emit points only** — M-5 emits at *inbound* pipeline points only: tool-description load (pre-context) and retrieved-memory ingest (pre-context). Output-side validation (LLM outputs, tool-call argument schema) is M-22's surface, not M-5's. Each emit point has its own pattern set tuned to that surface.
2. **Defense-in-depth, not standalone defense** — M-5 is a deterministic rule-based filter. Suspicious content that exceeds an operator-tunable suspicion-score threshold escalates to M-3 *AI-Powered Content Analysis* for model-based classification. M-1 is the ambient architectural control providing separation guarantees that M-5 operates within — M-5 does not "escalate to M-1"; M-1 always applies.
3. **Fail-loud-not-silent** — every M-5 sanitization decision (pass / strip / block) emits a structured event to M-12 *Audit Logging* including a `confidence_score` (or per-pattern `match_count`) field so operators can empirically tune the suspicion-score threshold during the burn-in period before enabling enforcement. M-11 *Behavioral Monitoring* baselines the resulting filter-firing-rate stream over time.
4. **Pattern set is operator-tunable with hard-floor distinction** — provide a baseline ruleset but require operators to extend it per their own threat model. Hard-floor patterns (always-block, no operator override) and tunable patterns (operator-configurable threshold, suspicions counted toward escalation) are first-class distinctions in the ruleset schema. Suppression policy follows the same governance pattern as M-11: explicit owner, expiry timestamp (default 30 days, max 90 days), audit event on create and modify, mandatory review cadence.
5. **Regex-engine choice matters** — operator-provided patterns can cause catastrophic backtracking under adversarial input (Regular Expression Denial of Service / ReDoS). Where supported, use a linear-time engine (e.g., RE2) rather than backtracking engines (e.g., PCRE) for operator-defined patterns. If PCRE is required, validate operator-supplied patterns against a backtracking-complexity check before installing them and run a fuzzer against representative adversarial inputs in CI.

### Architecture Components

```text
                 ┌──────────────────────────────────────┐
                 │             MCP Host                 │
                 │   (running inside M-1's data plane)  │
                 │                                      │
  Tool desc ───► │  M-5 emit point 1 (pre-context)      │ ──► to model context
                 │       │                              │
                 │       ├──→ M-12 audit event          │
                 │       │   (with confidence_score)    │
                 │       │                              │
                 │       └──→ (low-confidence) M-3      │
                 │                                      │
  Retrieved mem► │  M-5 emit point 2 (pre-context)      │ ──► to model context
                 │       │                              │
                 │       ├──→ M-12 audit event          │
                 │       │                              │
                 │       └──→ (low-confidence) M-3      │
                 │                                      │
                 │  (output side: M-22, not M-5)        │
                 └──────────────────────────────────────┘
```

The two emit points are deliberately limited to inbound surfaces. Tool-call output validation, LLM-output validation, and parameter-schema validation are M-22's territory and intentionally not in scope for M-5. Parameter sanitization (allowlisting, unused-parameter stripping, value sanitization), pre-storage memory-write hygiene, and prompt-path sanitization are also out of scope; see Limitations and Out of scope for the rationale and the partial-fit follow-up cluster.

### Prerequisites

- A pattern ruleset maintained as code (versioned, review-gated changes).
- A regex engine choice — RE2 (linear-time) preferred for operator-defined patterns; if PCRE, add a pre-install backtracking-complexity check and CI fuzzer step.
- A suppression-policy store with owner / expiry / audit guarantees.
- [SAFE-M-12](../SAFE-M-12/README.md) *Audit Logging* deployed (M-5's emit destinations).
- (Recommended) [SAFE-M-3](../SAFE-M-3/README.md) deployed for second-stage escalation; [SAFE-M-1](../SAFE-M-1/README.md) deployed as the ambient architectural control; [SAFE-M-4](../SAFE-M-4/README.md) deployed as a Unicode-specific pre-pass.

### Implementation Steps

1. **Design Phase**:
   - Define the pattern set per emit point — separate hard-floor (always-block) from tunable (operator-configurable threshold).
   - Define the suppression-policy schema (owner, expiry, audit-event triggers, review cadence).
   - Define the suspicion-score threshold for M-3 escalation; plan a burn-in period during which the threshold is calibrated against M-12 audit data before enforcement.
   - Choose the regex engine and document the ReDoS-safety strategy.

2. **Development Phase**:
   - Implement the inbound emit-point hooks in the MCP host (tool-description load, retrieved-memory ingest).
   - Implement the pattern matcher with `confidence_score` / `match_count` emission to M-12.
   - Implement the suppression-policy API with audit-event emission.
   - Implement the M-3 escalation hook gated by the suspicion-score threshold.

3. **Deployment Phase**:
   - Roll out in **shadow-rule mode** first — rules fire to M-12 audit but do not block; collect per-rule firing rates and confidence-score distributions for the burn-in period (~2-4 weeks).
   - Calibrate the suspicion-score threshold empirically from the burn-in audit data.
   - Enable enforcement for hard-floor rules first; tunable rules after calibration.
   - Monitor M-3 escalation queue depth continuously after enforcement; an unexpected surge usually indicates the suspicion-score threshold is too low or a rule mis-tune.

## Benefits
- **Deterministic rule-based filtering** of common injection patterns at inbound emit points — bounded behavior under linear-time engines (RE2); debuggable per-rule.
- **Defense-in-depth complement** to M-1 (architectural separation), M-3 (model-based classification), M-4 (Unicode-specific), and M-22 (output-side validation). Each layer has different cost, coverage, and confidence tradeoffs.
- **Operational signal** — M-5's audit stream feeds M-11 *Behavioral Monitoring* baselining and M-70 anomaly detection. Operators see filter-firing-rate trends, suppression usage, and escalation volume.
- **Operator-tunable** — hard-floor vs tunable distinction lets operators tighten coverage per environment without losing the always-on baseline.

## Limitations
- **Insufficient alone** — pattern-based filtering is necessarily incomplete; novel attack patterns evade rule sets until added. M-5 must be paired with M-1 / M-3 / M-22 for layered defense. This is the primary honest framing the prior version of M-5 already acknowledged and this expansion preserves.
- **False-positive cost** — overly aggressive rules block legitimate content (e.g., a tool description that legitimately discusses prompt-injection mitigations). Suppression governance addresses this but doesn't eliminate it; operators must own the tradeoff.
- **Adversarial-evasion arms race** — attackers learn rule sets and craft evasion variants; baselines drift and need maintenance. Periodic ruleset review is mandatory operational hygiene, not optional.
- **ReDoS risk for operator-extended patterns** — backtracking engines (PCRE-style) can be exploited via crafted input causing exponential matching time. Mitigate via RE2 (linear-time guarantee) or pre-install pattern-complexity validation plus CI fuzzing.
- **Unicode-specific tricks are M-4's territory** — zero-width characters, RTL override, homoglyph substitution. M-5 should delegate, not duplicate. Maintaining Unicode rules in two places creates operational drift.
- **Output sanitization is M-22's territory** — M-5 is inbound-only. Tool-call output validation, LLM-output validation, and parameter-schema validation are M-22's surface.
- **Prompt-path filtering is out of scope** — user-prompt content is not a M-5 emit point. M-5 only fires at the two named inbound emit points (tool-description load and retrieved-memory ingest); prompt-text inspection requires a separate prompt-path sanitization control, which is tracked as a partial-fit follow-up (see Out of scope).
- **Parameter sanitization is not in scope** — argument allowlisting, unused-parameter stripping, and parameter-value validation belong to a parameter-validation control (likely a new mitigation; see Out of scope).
- **Memory-write/storage sanitization is not in scope** — M-5 covers retrieval-time, not write-time. Pre-storage hygiene belongs to a storage-side control (likely a new mitigation; see Out of scope).
- **Pattern-policy version skew across MCP host instances** will silently degrade coverage; alarm on it via M-12.

## Out of scope

Seven of the 14 techniques that cite SAFE-M-5 are excluded from the curated Mitigates list above. Three are mislabels (cite M-5 with non-matching control concepts); four are partial-fit (cite M-5 with matching concept but expect functionality outside M-5's content-sanitization scope). Each is tracked for follow-up rather than papered over.

### Mislabel cluster (3 citers — cite M-5 but want different controls)

These citations name M-5 but the actual ask is for a different canonical mitigation. Tracked for redirect-in-followup; redirect targets to be chosen per-case after reading each technique's mitigation-section context.

- `techniques/SAFE-T1202/README.md` cites M-5 as **"Secure Token Storage"** — wants token-storage controls (likely M-31 *Proof of Possession Tokens* or M-37 *Token Rotation and Invalidation*).
- `techniques/SAFE-T1704/README.md` cites M-5 as **"Context Boundary Isolation"** — wants isolation/boundary controls (likely M-1 *Architectural Defense - Control/Data Flow Separation* or M-29 *Explicit Privilege Boundaries*).
- `techniques/SAFE-T2103/README.md` cites M-5 as **"Least-Privilege Agents"** — wants privilege-boundary controls (likely M-29 *Explicit Privilege Boundaries*).

### Partial-fit cluster (4 citers — cite M-5 with matching concept, but the primary ask falls outside M-5's scope)

These citations correctly invoke M-5 as one of several mitigations, but each technique's primary defensive ask requires a control M-5 does not provide. The corpus likely needs new mitigations for these surfaces; a small subset may plausibly redirect to existing canonical mitigations as noted.

- **`techniques/SAFE-T1302/README.md`** ("High-Privilege Tool Misuse") expects **argument allowlisting + shell-metacharacter rejection on tool parameters**. M-5 does not validate parameters. Redirect candidate: **likely a new "Parameter Validation" mitigation** — M-22 *Semantic Output Validation* covers schema validation in a related sense but does not address shell-metacharacter rejection specifically; the corpus does not currently have a parameter-validation mitigation.
- **`techniques/SAFE-T1702/README.md`** ("Memory Retrieval Abuse") expects **pre-storage memory-write sanitization**. M-5 covers retrieval-time only. Redirect candidate: **likely a new "Memory-Write Hygiene" mitigation** — M-22 does not cover storage-side; no existing canonical maps cleanly.
- **`techniques/SAFE-T1801/README.md`** ("Tool/Resource Exfiltration via Indirect Prompt Injection") expects **prompt-path sanitization against script-like instructions in user prompts**. M-5 has no prompt-path emit point. Redirect candidate: **plausibly M-22 if M-22 is extended to cover inbound prompt validation**, otherwise a new "Prompt-Path Sanitization" mitigation. Of the four partial-fits, this is the only one that *might* redirect cleanly to an existing canonical mitigation rather than requiring new authoring.
- **`techniques/SAFE-T1911/README.md`** ("Parameter Exfiltration") expects **unused-parameter stripping + parameter-value sanitization**. Same gap as T1302 — M-5 does not validate parameters. Redirect candidate: **same new "Parameter Validation" mitigation** as T1302.

The mislabel cluster and partial-fit cluster are tracked separately in `pr-ledger.yaml` as `safe-m-5-mislabel-cluster` and `safe-m-5-partial-fit-cluster` follow-up entries. The partial-fit cluster also signals a corpus-side gap: the canonical mitigation set may need new entries for parameter validation, memory-write hygiene, and prompt-path sanitization. That gap analysis is out of scope for this PR.

## Implementation Examples

### Example 1: Multi-stage Python sanitizer with M-12 audit emission

This implementation is paired with the ruleset schema in Example 2 — it honors `applies_to`, the per-rule `weight` field, and the `weighted_sum` aggregator described there.

```python
import hashlib
from dataclasses import dataclass
from enum import Enum
from typing import Callable

class Decision(Enum):
    PASS = "pass"     # content unchanged
    STRIP = "strip"   # matched substrings removed; rest of content forwarded
    BLOCK = "block"   # entire content rejected

@dataclass
class SanitizationResult:
    decision: Decision
    sanitized: str
    confidence_score: float        # 0.0 (clean) to ruleset.scoring.cap (high-confidence)
    match_count: int               # total matched substrings across all hit rules
    matched_pattern_ids: list[str]

class M5InboundSanitizer:
    def __init__(self, ruleset, audit_emit: Callable, m3_escalate: Callable):
        # `ruleset` is the operator-tunable schema from Example 2:
        #   .hard_floor_patterns / .tunable_patterns (each rule has .id, .regex,
        #   .weight, .applies_to: list[str])
        #   .scoring (.aggregator, .cap, .suspicion_threshold)
        #   .active_suppressions (list with .applies(rule_id, emit_point, source_id))
        self._ruleset = ruleset
        self._audit_emit = audit_emit
        self._m3_escalate = m3_escalate

    def _matching_rules(self, content: str, emit_point: str, patterns):
        """Return [(rule, match_count)] for rules where applies_to includes emit_point and at least one match found."""
        hits = []
        for rule in patterns:
            if emit_point not in rule.applies_to:
                continue   # honor applies_to from Example 2 schema
            matches = rule.regex.findall(content)
            if matches:
                hits.append((rule, len(matches)))
        return hits

    def _drop_suppressed(self, hits, emit_point: str, source_id: str):
        """Filter out hits suppressed by an active operator suppression."""
        return [(r, c) for (r, c) in hits
                if not any(s.applies(r.id, emit_point, source_id)
                           for s in self._ruleset.active_suppressions)]

    def _score(self, hits) -> float:
        """Aggregate per the YAML schema's `aggregator` field."""
        agg = self._ruleset.scoring.aggregator
        if agg == "weighted_sum":
            raw = sum(rule.weight * count for rule, count in hits)
        else:
            # Other aggregators may be defined per ruleset; fail loud on unknown.
            raise ValueError(f"unknown ruleset aggregator: {agg}")
        return min(self._ruleset.scoring.cap, raw)

    def _strip(self, content: str, hits) -> str:
        """Remove matched substrings, preserving surrounding content."""
        sanitized = content
        for rule, _ in hits:
            sanitized = rule.regex.sub('', sanitized)
        return sanitized

    def sanitize_tool_description(self, description: str, mcp_server: str, session_id: str):
        return self._sanitize(description, "tool_description_load", mcp_server, session_id)

    def sanitize_memory_chunk(self, chunk: str, source_id: str, session_id: str):
        return self._sanitize(chunk, "memory_chunk", source_id, session_id)

    def _sanitize(self, content: str, emit_point: str, source_id: str, session_id: str) -> SanitizationResult:
        # 1. Hard-floor check — block immediately if any hard-floor rule applies-to AND matches.
        hard_hits = self._matching_rules(content, emit_point, self._ruleset.hard_floor_patterns)
        if hard_hits:
            total = sum(c for _, c in hard_hits)
            ids = [r.id for r, _ in hard_hits]
            result = SanitizationResult(
                decision=Decision.BLOCK, sanitized="", confidence_score=self._ruleset.scoring.cap,
                match_count=total, matched_pattern_ids=ids)
            self._audit_emit(emit_point=emit_point, source_id=source_id, session_id=session_id,
                             content_sha256=_hash(content), result=result)
            return result

        # 2. Tunable scoring — apply weights from Example 2's schema, then drop suppressed hits.
        tunable_hits_raw = self._matching_rules(content, emit_point, self._ruleset.tunable_patterns)
        tunable_hits = self._drop_suppressed(tunable_hits_raw, emit_point, source_id)
        score = self._score(tunable_hits)
        match_count = sum(c for _, c in tunable_hits)
        matched_ids = [r.id for r, _ in tunable_hits]
        threshold = self._ruleset.scoring.suspicion_threshold

        # 3. Decision branches:
        #    - score < threshold              → PASS (unchanged content)
        #    - threshold <= score < cap       → escalate to M-3 for second-stage classification
        #    - score == cap                   → BLOCK (M-5 alone is confident enough)
        if score < threshold:
            decision, sanitized = Decision.PASS, content
        elif score >= self._ruleset.scoring.cap:
            decision, sanitized = Decision.BLOCK, ""
        else:
            m3 = self._m3_escalate(content=content, context=emit_point,
                                   m5_score=score, m5_matched_ids=matched_ids)
            if m3.malicious:
                decision, sanitized = Decision.BLOCK, ""
            elif m3.suspicious_but_legitimate:
                # Content has injection-pattern features but M-3 says it's not adversarial
                # (e.g., a security-research tool description that legitimately discusses
                # prompt-injection markers). STRIP the matched substrings rather than
                # blocking the whole content.
                decision, sanitized = Decision.STRIP, self._strip(content, tunable_hits)
            else:
                decision, sanitized = Decision.PASS, content

        result = SanitizationResult(
            decision=decision, sanitized=sanitized, confidence_score=score,
            match_count=match_count, matched_pattern_ids=matched_ids)
        self._audit_emit(emit_point=emit_point, source_id=source_id, session_id=session_id,
                         content_sha256=_hash(content), result=result)
        return result

def _hash(s: str) -> str:
    return hashlib.sha256(s.encode()).hexdigest()
```

The `confidence_score` and `match_count` fields in every audit event let operators baseline the suspicion-score threshold empirically during the burn-in period before enabling enforcement. The `STRIP` decision branch is reserved for the case where M-3 classifies a M-5 hit as "suspicious but legitimate" — content with injection-pattern features that the model classifier judges non-adversarial; M-5 then removes the matched substrings rather than blocking the whole content.

### Example 2: Pattern-ruleset YAML schema with operator-tunable + suppression governance

```yaml
ruleset_version: "2026.05.02"
ruleset_owner: "platform-security@example"

hard_floor_patterns:
  - id: hard_001
    description: "explicit instruction-override phrasing in tool descriptions"
    regex: '(?i)(ignore|disregard) (the|all) (above|previous) (instructions?|prompts?)'
    applies_to: [tool_description_load, memory_chunk]
    rationale: "hardcoded prompt-injection marker; no legitimate use case in MCP content"

tunable_patterns:
  - id: tune_001
    description: "role-prompt impersonation"
    regex: '(?i)you are (now |an? )?(system|admin|root|superuser)'
    weight: 0.4   # contributes to suspicion_score
    applies_to: [tool_description_load, memory_chunk]
  - id: tune_002
    description: "tool-call request from data plane"
    regex: '(?i)(call|invoke|execute) (the )?tool'
    weight: 0.3
    applies_to: [memory_chunk]    # less suspicious in tool descriptions

scoring:
  aggregator: "weighted_sum"      # operators may extend with custom aggregators
  cap: 1.0
  suspicion_threshold: 0.6        # tunable — calibrate during burn-in
  m3_escalation: enabled          # escalate hits with score >= threshold to M-3

suppressions:
  - id: supp_2026_05_001
    description: "github_mcp tool legitimately mentions 'system' in its description"
    pattern_ids: [tune_001]
    target: tool_description_load
    target_filter:
      mcp_server: "github-mcp-prod"
    owner: "alice@example"
    created_at: "2026-05-02T14:30:00Z"
    expires_at: "2026-06-01T00:00:00Z"   # max 90 days
    audit_required_for: [create, modify, delete, expire]
```

### Example 3: M-3 escalation hook with configurable suspicion-score threshold

```python
def m3_escalation_hook(content: str, context: str, threshold: float) -> "M3Result":
    """When M-5 produces a low-confidence hit (multiple weak matches but no
    hard-floor), defer the final block/pass decision to M-3's ML classifier.

    The threshold is operator-tunable. Setting it too low (e.g., 0.2) will
    flood M-3's queue with noise and degrade its latency for genuinely
    suspicious cases; setting it too high (e.g., 0.9) loses defense-in-depth
    benefit. Calibrate empirically against M-12 audit data during burn-in.

    Production guidance: monitor M-3 escalation queue depth and the
    M-5-fired/M-3-confirmed rate. If queue depth grows unboundedly, the
    threshold needs tightening; if M-3 rejects most M-5 escalations, the
    threshold may be too aggressive and is wasting M-3 cycles."""
    return m3_classifier.classify(content=content, context=context)
```

## Testing and Validation

1. **Security Testing**:
   - Replay a known prompt-injection corpus (e.g., the AgentDojo evaluation set) at the sanitizer's input; verify hard-floor patterns fire deterministically.
   - Replay corpus variants with adversarial encoding (Unicode tricks, leet substitution, character spacing) to measure false-negative rate; cross-check with M-4's Unicode pre-pass coverage.
   - Replay legitimate content with prompt-injection-related text (e.g., a tool description for a security-research tool) to measure false-positive rate.
   - Replay ReDoS-suspect patterns (catastrophic-backtracking inputs against operator-defined patterns) to confirm engine handles them in bounded time.

2. **Functional Testing**:
   - Sanitization latency per emit point under realistic load.
   - M-12 audit event correctness — every decision produces an event with `confidence_score`, `match_count`, `matched_pattern_ids`, and the standard correlation fields.
   - Suppression-expiry workflow — confirm expired suppressions auto-deactivate and reactivation requires owner approval with fresh audit event.

3. **Integration Testing**:
   - M-5 escalation → M-3 classification handoff under varying suspicion-score thresholds.
   - M-5 audit → M-11 baselining alarm on filter-firing-rate spike (synthetic spike injected; alarm latency measured).
   - Suppression-policy version skew alarm — deploy two M-5 instances with different policy versions, verify the skew alarm fires.

## Deployment Considerations

### Resource Requirements
- Pattern-matching adds CPU per emit point; precise overhead depends on ruleset size and regex engine choice. Measure under expected load.
- Ruleset memory scales with rule count; suppression-policy store scales with active suppression count plus audit-event retention.

### Performance Impact
- Latency overhead per emit point depends on ruleset depth and regex engine choice. RE2-style linear-time engines bound the worst case; PCRE-style backtracking engines may degrade unpredictably under adversarial input. No specific timing claim without measurement against your workload.
- M-3 escalation adds latency for low-confidence hits — calibrate the suspicion-score threshold so escalation is reserved for the genuinely-suspicious tail.

### Monitoring and Alerting
- Alarm on (a) sudden drop in rule-firing rate (possible upstream issue or sanitizer bypass), (b) sudden spike (possible attack or rule mis-tune), (c) suppression-policy version skew across hosts, (d) M-3 escalation-queue depth growth (suspicion-score threshold likely too low), (e) M-3-confirmed-malicious rate vs M-5-escalated rate (calibrate the suspicion-score threshold against this ratio).
- *Operational note*: the pattern ruleset is a high-value config. Version it as code; gate updates with M-69 *Out-of-Band Authorization* if the ruleset controls high-risk paths.

## Current Status (2026)

General input-validation guidance is well-established ([OWASP Input Validation Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html), [NIST SP 800-53 SI-10 (Information Input Validation)](https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final)). LLM-specific prompt-injection guidance recognizes pattern filtering as a layer in defense-in-depth, not a standalone defense ([OWASP Top 10 for Large Language Model Applications, LLM01: Prompt Injection](https://owasp.org/www-project-top-10-for-large-language-model-applications/)).

## References
- [OWASP Input Validation Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html)
- [NIST SP 800-53 Rev 5 — SI-10 Information Input Validation](https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final)
- [OWASP Top 10 for Large Language Model Applications — LLM01: Prompt Injection](https://owasp.org/www-project-top-10-for-large-language-model-applications/)
- [Model Context Protocol Specification](https://modelcontextprotocol.io/specification)
- [Russ Cox — Regular Expression Matching Can Be Simple And Fast (2007)](https://swtch.com/~rsc/regexp/regexp1.html) — foundational article on linear-time regex matching that motivates the RE2 engine choice for operator-defined patterns.

## Related Mitigations
- [SAFE-M-1](../SAFE-M-1/README.md): Architectural Defense - Control/Data Flow Separation — the ambient architectural control that M-5 runs inside. M-5 cannot replace M-1's separation guarantees; it reduces injection surface within them. M-5 does NOT escalate to M-1 — M-1 always applies as architecture, not as runtime decision.
- [SAFE-M-3](../SAFE-M-3/README.md): AI-Powered Content Analysis — the ML-based second-stage classifier. M-5 produces a deterministic rule-based signal; suspicious M-5 hits (configurable suspicion-score threshold) escalate to M-3 for higher-cost model classification.
- [SAFE-M-4](../SAFE-M-4/README.md): Unicode Sanitization and Filtering — the narrow Unicode-specific specialization. M-4 runs as a deterministic Unicode-specific pre-pass; M-5 then handles the residual general-pattern surface. Delegate, don't duplicate.
- [SAFE-M-22](../SAFE-M-22/README.md): Semantic Output Validation — the output-side complement. M-5 = inbound lexical/pattern; M-22 = output-side semantic/schema. The two are cleanly separated and do not overlap.
- [SAFE-M-12](../SAFE-M-12/README.md): Audit Logging — the audit substrate where M-5 sanitization decisions are recorded. M-11 *Behavioral Monitoring* baselines the resulting filter-firing-rate stream.

## Version History
| Version | Date | Changes | Author |
|---------|------|---------|--------|
| 0.1 | 2025-01-03 | Initial stub | Frederick Kautz |
| 0.2 | 2025-01-09 | Generalized from tool descriptions to all MCP content | Frederick Kautz |
| 1.0 | 2026-05-02 | Expanded stub to template parity per corpus mitigation quality audit; authored Technical Implementation (5 Core Principles including ReDoS engine-choice guidance), Architecture diagram with inbound-only emit points, Prerequisites, Implementation Steps with shadow-rule burn-in and suspicion-score calibration, Benefits, Limitations (with explicit "insufficient alone" honesty plus scope-boundary statements for output / parameters / memory-write / prompts), Implementation Examples (multi-stage Python sanitizer with M-12 confidence_score emission, pattern-ruleset YAML schema with operator-tunable + suppression governance, M-3 escalation hook with configurable threshold), Testing and Validation including ReDoS-suspect input replay, Deployment Considerations, Current Status (source-backed only); curated Mitigates list to 7 directly-mapped citers with technique-specific rationale (4 partial-fit citers and 3 mislabel citers excluded with reason notes — tracked as safe-m-5-partial-fit-cluster and safe-m-5-mislabel-cluster follow-ups); corrected NIST SP 800-53 reference to SI-10 (Information Input Validation); expanded Related Mitigations to include M-1 (ambient architectural control — not escalation target), M-12 (audit substrate), M-22 (output-side complement — non-overlapping); kept M-3 and M-4 with sharper boundary descriptions | bishnu bista |
