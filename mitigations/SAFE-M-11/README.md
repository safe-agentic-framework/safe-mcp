# SAFE-M-11: Behavioral Monitoring

## Overview
**Mitigation ID**: SAFE-M-11  
**Category**: Detective Control  
**Effectiveness**: High  
**Implementation Complexity**: Medium-High  
**First Published**: 2025-01-03

## Description
Behavioral Monitoring is the **real-time pattern detector** layered above SAFE-M-12's structured-event substrate. M-11 consumes the M-12 event stream — tool-description loads, tool invocations, server connections, prompt-lineage events, OAuth operations — and emits alerts when sequences, correlations, identity drift, or content patterns indicate compromise. M-11 is a *cross-event / session* analytics surface: it owns prompt-lineage shifts, cross-tool contamination, output-to-action correlation, identity drift, and memory-retrieval-to-sensitive-action chains. Per-invocation rate, volume, cardinality, and destination baselining is SAFE-M-70's job; M-11 *consumes* M-70's features and alerts as inputs rather than redefining the per-tool baselining stack.

In an MCP deployment, M-11 defends against the most common LLM-driven attack patterns: poisoned tool descriptions (T1001) become detectable when M-11 correlates a tool-description load event with subsequent invocation chains; coercion attempts (T1309) surface when prompt-lineage shifts coincide with first-time-in-session privileged tool use; cross-tool contamination (T1702) is caught when memory-retrieval events directly precede sensitive-action invocations; output-content drift (T1904 / T2105) is detectable when M-11 cross-correlates `llm_output_ref` payloads with downstream consumer actions. M-11 supports an explicit two-mode design — *metadata-driven* patterns (no payload access required) for the bulk of detections, and *content-aware* patterns (require payload features from M-12's restricted raw-payload archive when retained per the M-12 forensic floor) for output-drift and backchannel detection. Adaptive baselining is paired with anti-poisoning controls — frozen reference windows for high-risk signals, shadow baselining trained on confirmed-clean data, hard-floor rules that adaptive learning cannot suppress, and explicit suppression governance — so attacker-shaped behavior cannot be slow-rolled into the baseline.

## Mitigates

The mitigation directly addresses the following techniques (curated against the actual citation graph; T1305 excluded as a systematic substitution misdirection — see Out of scope):

- [SAFE-T1001](../../techniques/SAFE-T1001/README.md): Tool Poisoning Attack (TPA) — captures behavioral signatures of poisoned tool descriptions across agent runs (load events correlated with subsequent invocation chains).
- [SAFE-T1102](../../techniques/SAFE-T1102/README.md): Prompt Injection (Multiple Vectors) — detects sudden context switches, execution of unrelated commands, and acknowledgment of instructions not in the original user request.
- [SAFE-T1106](../../techniques/SAFE-T1106/README.md): Identical Call Loops — detects cyclic / identical-call patterns indicative of automated probing or stuck-reasoning loops.
- [SAFE-T1112](../../techniques/SAFE-T1112/README.md): Sampling Request Abuse — correlates per-server sampling frequency, approval patterns, and sampling↔sensitive-action sequences. Operates on M-12's `tool_invocation` event stream (M-12 Principle 2 explicitly folds T1112 sampling-request logging under `tool_invocation`, including the `approval` field) plus subsequent in-session tool chain.
- [SAFE-T1202](../../techniques/SAFE-T1202/README.md): OAuth Token Persistence *(cited as "Token Lifecycle Monitoring" in T1202)* — captures full OAuth lifecycle correlation (issue / refresh / revoke / use), post-logout use, and concurrent or location-anomalous reuse.
- [SAFE-T1302](../../techniques/SAFE-T1302/README.md): High-Privilege Tool Abuse — detects runtime-identity drift and first-time-in-session privileged tool use.
- [SAFE-T1303](../../techniques/SAFE-T1303/README.md): Container Sandbox Escape via Runtime Exec — detects process / cwd / mount-set anomalies relative to baseline.
- [SAFE-T1309](../../techniques/SAFE-T1309/README.md): Privileged Tool Invocation via Prompt Manipulation — detects unexpected tool sequences, sudden context switches, acknowledgment of unstated instructions, first-time-in-session privileged use, and **privileged calls immediately following external-content ingestion**.
- [SAFE-T1401](../../techniques/SAFE-T1401/README.md): Line Jumping — detects anomalous context-window source ordering distributions.
- [SAFE-T1702](../../techniques/SAFE-T1702/README.md): Memory Retrieval Abuse — detects memory-retrieval-to-sensitive-action chains and first-time access patterns.
- [SAFE-T1803](../../techniques/SAFE-T1803/README.md): Database Dump — detects bulk-export patterns: full-table scans, unplanned backup operations, writes to new export destinations (consumes M-70's per-tool result-size and destination baselines for the per-invocation layer).
- [SAFE-T1904](../../techniques/SAFE-T1904/README.md) / [SAFE-T2105](../../techniques/SAFE-T2105/README.md): Chat-Based Backchannel / Disinformation Output — detects output-content drift and correlates LLM outputs with downstream consumer actions (content-aware mode; requires retained `llm_output_ref` from M-12).
- [SAFE-T1911](../../techniques/SAFE-T1911/README.md): Parameter Exfiltration — detects parameter entropy / size / encoding anomalies indicating covert exfiltration via tool args.
- [SAFE-T2102](../../techniques/SAFE-T2102/README.md): Excessive Agency / Resource Exhaustion — detects anomalous fan-out, spend / token velocity, and endpoint volume (consumes M-70's per-actor invocation baselines).

See also — additional citing techniques whose Mitigation Strategies reference SAFE-M-11 with generic "Behavioral Monitoring" framing; their specific concerns are subsumed by the patterns above:

- Initial-access / tool-poisoning variants: SAFE-T1004, SAFE-T1005, SAFE-T1006, SAFE-T1103
- Persistence and server-side patterns: SAFE-T1204, SAFE-T1304, SAFE-T1502, SAFE-T1604, SAFE-T1606
- Cross-server / contamination patterns: SAFE-T1704, SAFE-T1705
- Operational and post-incident triage: SAFE-T1801, SAFE-T1804, SAFE-T1910, SAFE-T1912

## Technical Implementation

### Core Principles

1. **Stream-on-events, two operating modes** — M-11 consumes M-12's structured event stream and operates in two modes:
   - **Metadata-driven (default)**: works on event metadata only (event type, IDs, timestamps, hashes, schema-validated summaries). No raw-payload access required. Covers Patterns 1-8 and 10-13.
   - **Content-aware (opt-in per pattern)**: requires payload features from M-12's restricted raw-payload archive when retained per M-12's forensic floor. Covers Pattern 9 (output-content drift). Operators must explicitly grant the M-11 detector restricted-archive read access for this mode.
2. **Cross-event / session analytics, not per-invocation baselining** — M-11's analytical surface is *cross-event*: prompt-lineage shifts, cross-tool sequences, identity drift, memory→action chains, content drift. Per-invocation rate / volume / cardinality / destination baselining is **M-70's job**; M-11 calls into M-70's outputs (e.g., "did M-70 alert on rate spike for this actor?") rather than re-implementing rate baselining.
3. **Adaptive baselining with anti-poisoning controls** — M-11 transitions from hardcoded prior-art rules to per-tenant adaptive thresholds with explicit poisoning controls (see *Anti-poisoning controls* below). Adaptive baselining without these controls is unsafe — sustained low-volume malicious traffic will normalize attacker-shaped behavior.
4. **Alert → triage path** — every M-11 alert carries the M-12 `correlation_id` so an analyst can pivot to the raw-payload archive (when retained per the M-12 forensic floor). M-11 produces alerts; it does not retain raw evidence — that is M-12's job.
5. **Suppression governance** — per-actor / per-tool suppressions are first-class objects with explicit owner, expiry timestamp, audit-event-on-create-and-modify, and review cadence. Without these, suppression sprawl becomes its own attack surface (whitelisting attacker-shaped patterns is a documented MITRE ATT&CK technique, T1562.006).

### Anti-poisoning controls

- **Frozen reference windows** for high-risk signals (privileged-tool first-use, OAuth refresh on new device, runtime-identity change). Use a fixed historical window as the baseline rather than a rolling adaptive one, so attackers cannot normalize their pattern via sustained low-volume traffic.
- **Shadow baselining** — maintain a parallel baseline trained on **confirmed-clean events only** (events with no analyst-attached malicious label), ideally with a one- to two-week training delay so freshly-ingested malicious traffic cannot leak into shadow training. Flag drift between the live adaptive baseline and the shadow baseline as a poisoning signal.
- **Exclusion of malicious-confirmed events** — any event flagged by an analyst (or by a high-confidence detection layer) is excluded from baseline retraining permanently. Confirmation-label provenance is itself logged via M-12.
- **Hard floor rules** for irreducible-risk signals — privileged-tool first-use in session, OAuth grant from new geo+device tuple, runtime-identity field change mid-session: always alert regardless of adaptive thresholds. Baselining can only escalate, not suppress, these signals.
- **Suppression expiry + audit** — every suppression has an owner (a person, not a team alias), an expiry timestamp (default 30 days, max 90 days), and an audit event on creation and on every modification. Expired suppressions auto-deactivate; reactivation requires explicit owner approval and a fresh audit event.

### Architecture Components

```text
                   ┌──────────────────────────────────────┐
                   │            MCP Host                  │
                   │   (M-12 emits structured events)     │
                   └────────────────┬─────────────────────┘
                                    │ event stream
                                    ▼
                   ┌──────────────────────────────────────┐
                   │   M-12 SIEM tier (metadata stream)   │
                   └─────┬──────────────────────────┬─────┘
                         │                          │
              ┌──────────┘                          └──────────┐
              ▼                                                ▼
   ┌─────────────────────┐                          ┌──────────────────────┐
   │  M-11 streaming     │                          │  M-11 batch          │
   │  detector           │  ←──── M-70 features ────│  baseliner +         │
   │  (real-time rules)  │  ←──── M-22 outcomes ────│  shadow baseliner    │
   │                     │  ←──── M-69 decisions ───│  (with anti-poison)  │
   │                     │  ←─ M-20 alerts (when ───│                      │
   │                     │      M-20 expanded)      │                      │
   └──────────┬──────────┘                          └──────────────────────┘
              │ alerts                                          │ baseline drift signal
              ▼                                                 ▼
   ┌─────────────────────┐                          ┌──────────────────────┐
   │  Alert triage UX    │                          │  Poisoning detector  │
   │  + correlation_id   │ ───── pivot via correlation_id ─→ M-12 raw      │
   │                     │       (when forensic-floor retained)            │
   └─────────────────────┘                          └──────────────────────┘
```

The two execution paths above the diagram (streaming detector + batch baseliner) are *processing topology*, distinct from the **two operating modes** (metadata-driven vs content-aware) defined in Core Principles. Content-aware patterns route from the streaming detector to M-12's restricted raw-payload archive when their detection rule fires.

### Telemetry prerequisites (per pattern)

Each detection pattern requires specific M-12 fields. Where M-12's current schema does not yet cover a field, the prerequisite is stated as a **Feature Request for M-12** so M-12 maintainers know what to extend.

| Pattern | Required M-12 fields |
|---|---|
| 1 (T1001 tool-poisoning behavioral signature) | `tool_description_loaded.tool_description_sha256`, `previous_sha256`; subsequent `tool_invocation` event chain joined by `session_id` |
| 2 (T1102 / T1309 prompt-injection signatures) | `prompt_lineage.preceding_turns_hash_chain`, `context_structure.items[].source_type` |
| 3 (T1106 identical-call loops) | `tool_invocation.request_metadata.args_hash` (canonicalized-args hash) over rolling time window (Feature Request for M-12 v1.2: M-12 v1.1 replaced the original `args_summary` with structured `args_field_tree` for SAFE-M-70 cardinality features; add `args_hash` for value-equivalence detection — `args_field_tree` is structure-only and would alias value-different but shape-identical calls) |
| 4 (T1202 OAuth lifecycle, location-anomalous reuse) | `auth_operation.op` / `subject` / `device_fingerprint` / `correlation_token` / **`geo_hint`** / `source_ip` (Feature Request for M-12 v1.1: ensure `geo_hint` and `source_ip` are populated when available) |
| 5 (T1302 / T1303 identity drift) | `tool_invocation.actor` field stability — `effective_uid`, `service_account`, `container_id`, `cwd`, `mounts` (per SAFE-M-12 Principle 3, these are direct keys on the `actor` block, not nested under a `runtime_identity` sub-key) |
| 6 (T1309 external-content → privileged) | `prompt_lineage.context_structure` with `source_type=tool_response` directly preceding privileged `tool_invocation` |
| 7 (T1401 context-window ordering) | `context_structure.items` ordering distribution |
| 8 (T1702 memory→sensitive-action) | `tool_invocation` with `tool_name` matching memory-retrieval pattern → subsequent privileged `tool_invocation` chain joined by `session_id` |
| 9 (T1904 / T2105 content drift) | **Requires retained `llm_output_ref` archive content** (forensic-floor-retained or policy-retained); not metadata-only |
| 10 (T1911 parameter entropy) | `tool_invocation.request_metadata.args_size_bytes` and **`args_entropy_estimate`** (Feature Request for M-12 v1.1: add an `args_entropy_estimate` field to `request_metadata`; without it M-11 can only baseline size, not entropy) |
| 11 (T2102 fan-out / spend / endpoint volume) | `tool_invocation.cost_estimate` / `tokens_in` / `tokens_out` / `destination` (the external sink URL or host being called, per SAFE-M-12 v1.1) aggregated per actor + endpoint set; consumes M-70's per-actor invocation baselines |
| 12 (T1112 sampling-then-sensitive-action) | `tool_invocation` events for sampling-request logging (per SAFE-M-12 Principle 2, T1112's sampling-request capture is folded under `tool_invocation` with the `approval` field carrying granted/denied state) + subsequent `tool_invocation` chain via `session_id` |
| 13 (T1803 bulk-export with coercion-context) | M-70's bulk-export alerts (per-invocation `response_metadata.row_count` and `destination` baselines) + preceding `prompt_lineage.context_structure` items, joined by `session_id` |

### Prerequisites

- [SAFE-M-12](../SAFE-M-12/README.md) *Audit Logging* deployed with the structured-event schema. M-11 has no signal to consume otherwise.
- [SAFE-M-70](../SAFE-M-70/README.md) *Detective Control - Tool-Invocation Anomaly Detection & Baselining* deployed. Pattern 11 and Pattern 13 consume M-70's per-tool / per-actor baselines (specifically, M-70 Rules A and C — the result-row and destination-first-seen rules) as input features rather than reproducing them. Pattern 12 operates directly on M-12's `tool_invocation` event stream and does not require an M-70 baseline.
- Pattern 4 (OAuth lifecycle anomaly) operates directly on M-12's `auth_operation` event stream (op `issue` / `refresh` / `revoke` / `use`, plus `subject`, `device_fingerprint`, `geo_hint`, `correlation_token` per M-12 Principle 4); it does not depend on an upstream baselining mitigation. `source_ip` remains a Feature Request to M-12 v1.2 (the Pattern 4 Telemetry prereq row carries the same FR note); concurrent-reuse and post-logout-use detection work without it, but cross-continent geo-anomaly detection benefits from it. [SAFE-M-20](../SAFE-M-20/README.md) is the canonical OAuth-layer anomaly detection mitigation, but is currently a stub (implementation `[To be documented]`); when M-20 is fully developed it can serve as a complementary feature source for Pattern 4. Pattern 4 must NOT be routed through M-70 — M-70's input contract is `tool_invocation` events (per M-70 README §Prerequisites), so OAuth ops on the `auth_operation` stream are not visible to it.
- A streaming or near-real-time analytics platform (Splunk, Elastic, Loki+Promtail, or equivalent) with rule-based + ML-based detection.
- An alerting mechanism with an operator triage UX (M-11 alert → M-12 raw-archive pivot via `correlation_id`).
- A suppression-policy store with expiry, owner, and audit guarantees (per Core Principle 5).

### Implementation Steps

1. **Design Phase**:
   - Define which patterns operate in metadata-driven mode vs content-aware mode (the latter requires restricted-archive read access).
   - Define the suppression schema (owner, expiry, audit-event triggers, review cadence).
   - Define the anti-poisoning policy: which signals get frozen reference windows, which use shadow baselining, which have hard floors.
   - Identify cross-mitigation feature consumers (M-70 alerts, M-22 outcomes, M-69 decisions) and the join keys (`session_id`, `correlation_id`, `actor.service_account`).

2. **Development Phase**:
   - Implement the metadata-driven detection rules (Patterns 1-8 and 10-13) against the M-12 SIEM tier first; defer content-aware Pattern 9 until the restricted-archive integration is hardened.
   - Implement the live and shadow baselines as parallel pipelines. The shadow baseline trains on a rolling 7- to 14-day delayed window of confirmed-clean events; the live baseline trains on the rolling 24- to 48-hour fresh window.
   - Implement the suppression API with audit-event emission to M-12.
   - Integrate M-70 / M-22 / M-69 feature consumption (and M-20 once it is expanded beyond stub state).

3. **Deployment Phase**:
   - Roll out in observe-only mode (rules fire to a staging SIEM; no operator-visible alerts) for the burn-in period (~2-4 weeks) so the live baseline can stabilize.
   - Validate shadow-baseline drift signals against synthetic poisoning attempts before enabling enforcement.
   - Enable enforcement for hard-floor rules first (no adaptive component), then for the rest in waves.
   - Monitor false-positive rates, suppression-expiry approaching, and shadow-baseline drift continuously.

## Detection Patterns

| # | Pattern | Citing techniques | M-12 fields | Threshold / rule type | False-positive notes / anti-poisoning |
|---|---|---|---|---|---|
| 1 | Tool-poisoning behavioral signature | T1001 | tool_description_loaded chain + invocation chain | Rule-based: poisoned-description hash on a session that subsequently invokes a privileged tool | Frozen reference window for first-use of any tool description |
| 2 | Prompt-injection signature (context switch / unrelated command / unstated-instruction acknowledgment) | T1102, T1309 | prompt_lineage, context_structure | Heuristic + ML on lineage transitions | Hard-floor rule for acknowledgment-of-unstated-instructions; no adaptive suppression |
| 3 | Identical-call loops / cyclic graphs | T1106 | tool_invocation.request_metadata.args_hash over window (FR for M-12 v1.2 — see Telemetry prerequisites Pattern 3) | Rule-based: ≥ N identical calls within W seconds, or A → B → A cycle ≥ M times | Whitelist legitimate retry loops with explicit owner+expiry suppressions |
| 4 | OAuth lifecycle anomaly (concurrent reuse, location-anomalous reuse, post-logout use) | T1202 | auth_operation.op + subject + device_fingerprint + geo_hint + correlation_token (per M-12 Principle 4); `source_ip` is a Feature Request to M-12 v1.2 — see Pattern 4 Telemetry prereq | Rule-based: post-logout `use`, concurrent reuse from disparate geos | Hard-floor for cross-continent concurrent reuse |
| 5 | Runtime-identity drift | T1302, T1303 | tool_invocation.actor field stability (effective_uid / service_account / container_id / cwd / mounts — direct keys on actor per SAFE-M-12 Principle 3) | Rule-based: any change in effective_uid, service_account, container_id, or mount set within session | Hard-floor; no adaptive suppression |
| 6 | External-content → privileged-tool correlation | T1309 | prompt_lineage.context_structure source_type=tool_response → privileged tool_invocation | Rule-based: privileged tool call within K events of a tool_response context item | Operator allowlist for known automation patterns; suppressions expire |
| 7 | Context-window ordering anomalies | T1401 | context_structure.items ordering distribution | Statistical: per-actor ordering distribution diverges from baseline | Shadow-baseline drift alarm catches gradual reordering |
| 8 | Memory-retrieval → sensitive-action chain | T1702 | tool_invocation chain via session_id | Rule-based: memory-retrieval tool → privileged tool within K events | Hard-floor for first-time-in-session retrieval-then-privileged |
| 9 | Output-content drift / backchannel signal | T1904, T2105 | llm_output_ref archive content (content-aware mode required) | ML: output embedding drift from baseline; cross-correlation with downstream_actions | Content-aware mode operational coupling — patterns degrade if M-12 retention policy excludes outputs |
| 10 | Parameter entropy / size anomaly | T1911 | tool_invocation.request_metadata.args_size_bytes + args_entropy_estimate | Statistical: per-tool entropy / size baseline + threshold | Feature Request for M-12 v1.1: `args_entropy_estimate` field; until then M-11 can only baseline size |
| 11 | Anomalous fan-out / spend / endpoint volume | T2102 | tool_invocation.cost_estimate / tokens / destination per actor (per SAFE-M-12 v1.1 the field is `destination`, not `endpoint`) | Consumes M-70's per-actor invocation baseline; M-11 layers spend / fan-out + destination-set anomaly | Shadow baseline + frozen reference window for new destinations |
| 12 | Sampling-then-sensitive-action correlation | T1112 | tool_invocation events for sampling-request logging (per M-12 Principle 2) with the `approval` field + subsequent tool_invocation chain via session_id | Rule-based: ≥ N approved sampling requests within window, followed by sensitive `tool_invocation` (privileged tool, large `response_metadata.row_count`, or new `destination`) within K events | Hard-floor for first-time-in-session sampling→privileged-tool chain; suppressions for known automation that legitimately triggers sampling-then-action |
| 13 | Bulk-export with coercion-context correlation | T1803 | M-70 bulk-export alert (large `response_metadata.row_count` and/or new `destination`) + preceding `prompt_lineage.context_structure` items in the same session | Rule-based: M-70 bulk-export alert AND preceding `source_type=tool_response` or memory-retrieval context within K events in the same session | Hard-floor for first-time-in-session bulk export to a new `destination`; whitelist scheduled batch jobs with explicit owner+expiry suppressions |

## Out of scope

Several techniques cite SAFE-M-11 with non-matching control concepts or appear in earlier audit drafts but are not present in the citation graph. They are excluded from the curated Mitigates list:

- **SAFE-T1305** (cited as "User Namespace Isolation"). M-11 is Behavioral Monitoring, not isolation; the citation is a systematic-substitution misdirection. The same misdirection appears against SAFE-M-12, tracked as `t1305-m12-misdirection-fix` in the upstream PR ledger.
- **SAFE-T1101** and **SAFE-T1701**. Listed as M-11 citers in earlier audit drafts, but a fresh grep against `techniques/SAFE-T1101/README.md` and `techniques/SAFE-T1701/README.md` confirms neither file references SAFE-M-11. Removed as phantom citations.

The 14 additional citing techniques in the Mitigates "See also" subsection reference SAFE-M-11 with generic "Behavioral Monitoring" framing only; their specific concerns are subsumed by Patterns 1-13 above and do not need dedicated rows. They are listed there for traceability.

## Benefits

- **Real-time MCP attack detection** across the full citing-technique graph (poisoned tools, prompt injection, OAuth abuse, privilege escalation, coercion, exfiltration, disinformation).
- **Operator-tunable** — rule thresholds, suppression policies, and pattern enablement are all operator-configurable.
- **Baselining adapts** to environment without normalizing attacker behavior, thanks to the anti-poisoning controls.
- **Pivots to forensic evidence** via M-12 `correlation_id` — every alert is a triage entry point into the M-12 raw archive when retained.
- **Layered with M-70 and M-22** — M-11 is the cross-event correlation layer atop M-70's per-invocation baselining and M-22's per-call validation. Operators can run all three for defense in depth without redundant detection.
- **Composes with M-69** — M-11 baselines approval-pattern anomalies (deny-rate spike, response-time-to-approval distribution shift indicating rubber-stamping).

## Limitations

- **Adversarial patience defeats threshold-based detection** — slow-drift attacks below per-event thresholds can avoid all rule-based detections. Anti-poisoning controls help (shadow baselining catches sustained drift) but do not eliminate the risk.
- **Cold-start gap** — until the live baseline stabilizes (~2-4 weeks), M-11 runs on hardcoded prior-art rules with higher false-positive rates. Document the burn-in period explicitly.
- **M-11 needs M-12** — if M-12 is hollow or its schema is incomplete, M-11 sees no signal. Several patterns require M-12 schema extensions (Patterns 4 and 10 — see Telemetry prerequisites).
- **Whitelist sprawl** is itself a risk — suppression governance addresses this but requires discipline. Expired suppressions auto-deactivate; review cadence is mandatory.
- **Rule-bound coverage** — novel attacks not in the rule set are invisible until added. Post-incident pattern authoring is a real cost; budget for it.
- **Content-aware operational coupling** — Pattern 9 requires the M-12 forensic floor to retain `llm_output_ref` payloads. If retention is conservative, Pattern 9 degrades to metadata-only and loses backchannel-detection capability.
- **Cross-mitigation dependency** — Pattern 11 and Pattern 13 consume M-70's per-tool baselines (Rules A / C). If M-70 is not deployed, those patterns alert spuriously or degrade. Pattern 4 (OAuth) operates standalone on M-12's `auth_operation` stream; once SAFE-M-20 is fully developed (currently a stub) it can serve as a complementary feature source. Pattern 12 (T1112 sampling) operates standalone on M-12's `tool_invocation` stream. Prerequisites and deployment order matter.

## Implementation Examples

### Example 1: Splunk SPL detection rule for Pattern 6 (T1309 — privileged call after external content ingestion)

```spl
| union
    [search index=mcp_audit event_type=prompt_lineage context_structure.items{}.source_type="tool_response"
     | stats max(_time) as last_external_content_time by session_id, correlation_id
     | eval event_kind="external_content"]
    [search index=mcp_audit event_type=tool_invocation tool_name IN (privileged_tool_list)
     | eval external_content_followed_by_privileged_at=_time, event_kind="privileged_call"]
| stats
    max(last_external_content_time) as last_external_content_time,
    max(external_content_followed_by_privileged_at) as priv_at,
    values(tool_name) as tool_name,
    values(actor.service_account) as actor
  by session_id
| where isnotnull(last_external_content_time) AND isnotnull(priv_at)
| where (priv_at - last_external_content_time) <= 30 AND priv_at >= last_external_content_time
| eval alert_severity = "high"
| table priv_at, session_id, actor, tool_name, last_external_content_time
```

The 30-second window is operator-tunable; the hard floor is "ever, in this session" for first-time-in-session privileged use. Adapt the `context_structure.items{}.source_type` field path to your Splunk JSON-extraction config; some deployments require an `spath` step before filtering on nested fields.

### Example 2: Elastic EQL rule for Pattern 8 (T1702 — memory-retrieval → sensitive-action chain)

```eql
sequence by session_id with maxspan=5m
  [tool_invocation where tool_name in ("memory.retrieve", "vector_store.query", "kv.get")]
  [tool_invocation where
     actor.effective_uid in ("0", "root", "admin") and
     event.outcome != "policy_violation"]
```

`maxspan=5m` is the chain-window; tighten for high-sensitivity environments. The privileged-UID set (`"0", "root", "admin"`) is illustrative — replace with the concrete list of privileged identities for your environment. The `event.outcome != "policy_violation"` predicate excludes calls already blocked by M-69 (those generate their own alert via M-69's audit trail).

### Example 3: Python streaming detector for Pattern 3 (T1106 — identical-call loops)

```python
from collections import deque

class IdenticalCallLoopDetector:
    def __init__(self, window_seconds=60, threshold=10):
        self.window = window_seconds
        self.threshold = threshold
        self.recent_calls = {}  # actor → deque of (timestamp, args_hash)

    def observe(self, event):
        if event["event_type"] != "tool_invocation":
            return None
        actor = event["actor"]["service_account"]
        ts = event["timestamp_utc"]
        args_hash = event["request_metadata"]["args_hash"]  # canonicalized-args hash from M-12 (FR for v1.2)
        q = self.recent_calls.setdefault(actor, deque())
        q.append((ts, args_hash))
        # Drop entries outside the window
        while q and q[0][0] < ts - self.window:
            q.popleft()
        # Count identical args within window
        identical_count = sum(1 for _, h in q if h == args_hash)
        if identical_count >= self.threshold:
            return {
                "alert": "identical_call_loop",
                "actor": actor,
                "tool_name": event["tool_name"],
                "correlation_id": event["correlation_id"],
                "count_in_window": identical_count,
            }
        return None
```

This is a metadata-only detector — it never reads the raw request body; it works on M-12's `args_hash` field (a canonicalized-args content hash; Feature Request for M-12 v1.2 — see Pattern 3 Telemetry prerequisites). The threshold and window are operator-tunable; suppressions for legitimate retry loops are applied upstream.

### Example 4: Anti-poisoning shadow-baseline drift alarm

```python
def shadow_baseline_drift_alarm(live_baseline, shadow_baseline, signal_name, drift_threshold=0.30):
    """
    Compare the live (potentially-poisoned) adaptive baseline against the
    shadow baseline (trained on confirmed-clean events with a 7-day delay).
    Alarm if the divergence exceeds drift_threshold.

    The shadow baseline is the ground truth for "what the baseline should look
    like absent poisoning." Drift between live and shadow indicates either
    legitimate environmental change OR a poisoning attempt — escalate to
    operator review either way.
    """
    live_mean, live_stdev = live_baseline.summary(signal_name)
    shadow_mean, shadow_stdev = shadow_baseline.summary(signal_name)
    if shadow_mean == 0:
        return None  # cold-start
    relative_drift = abs(live_mean - shadow_mean) / shadow_mean
    if relative_drift > drift_threshold:
        return {
            "alert": "baseline_drift",
            "signal": signal_name,
            "live_mean": live_mean,
            "shadow_mean": shadow_mean,
            "relative_drift": relative_drift,
            "recommended_action": "operator review; suspend adaptive learning for signal",
        }
    return None
```

This is the meta-detection layer — M-11 not only detects attacks but also detects attempts to manipulate its own baseline. Operators receive a baseline-drift alert; investigation can then determine whether the drift is legitimate (environmental change, e.g., new MCP server deployed) or malicious (sustained low-volume poisoning traffic).

## Testing and Validation

1. **Security Testing**:
   - Synthetic-event replay per pattern: generate M-12 events for each citing-technique scenario (T1001 poisoned tool description, T1309 coercion sequence, T1106 identical-call loop, T1702 memory→sensitive chain, T1803 bulk-export pattern, T1904 output-drift sequence, T1911 parameter-entropy spike, T2102 fan-out spike) and verify the corresponding M-11 pattern fires within target latency (e.g., < 30s for streaming patterns).
   - Anti-poisoning attack simulation: inject sustained low-volume malicious traffic over a 14-day synthetic timeline; verify that the live baseline begins to normalize the malicious pattern but the shadow-baseline drift alarm fires before adaptive suppression of any hard-floor signal.
   - M-69 / M-22 / M-70 feature integration: verify that suppressions and approval-pattern anomalies route correctly between mitigations.

2. **Functional Testing**:
   - False-positive rate measurement on a representative non-malicious traffic sample, per pattern, with operator-defined acceptable thresholds.
   - Alert latency measurement (event-emission → M-11 alert → analyst-visible).
   - Suppression-expiry workflow: confirm expired suppressions auto-deactivate and reactivation requires owner approval with fresh audit event.

3. **Integration Testing**:
   - End-to-end alert → M-12 raw-archive pivot via `correlation_id` for each pattern (when retention fired).
   - Suppression-policy version skew alarm: deploy two M-11 instances with different policy versions, verify the skew alarm fires.
   - Burn-in dry run: simulate a 4-week burn-in with synthetic event velocity, verify baselines stabilize and the shadow→live drift converges.

## Deployment Considerations

### Resource Requirements
- **CPU**: streaming detector cost is moderate — pattern-matching at SIEM ingest rate. Anti-poisoning shadow baseliner adds ~50% over the live baseliner alone (parallel pipeline).
- **Memory**: per-actor baseline state proportional to active-actor count × pattern count.
- **Storage**: shadow baseline ~1.5x live baseline storage (delayed training window + parallel state).
- **Network**: feature consumption from M-70 / M-22 / M-69 adds modest cross-mitigation API traffic.

### Performance Impact
- **Latency**: streaming detection target < 30s p95 from M-12 emit to M-11 alert. Batch baselining target ≤ 1h recompute interval.
- **Throughput**: well-instrumented detectors handle thousands of M-12 events per second per worker.
- **Burn-in**: ~2-4 weeks before the live baseline stabilizes; document this expectation explicitly to operators.

### Monitoring and Alerting
- Rule-firing rates per pattern (alarm on sudden drop — possible upstream issue or suppression-policy regression).
- False-positive cohort tracking (alarm on cohort growth indicating rule drift).
- Shadow→live baseline drift score (the meta-detection signal — alarm on excursion).
- Suppression expiry approaching (warn 7 days before; force-expire on date).
- Suppression-policy version skew across M-11 instances.

## Current Status (2026)

General behavioral-monitoring guidance is well-established in industry frameworks ([NISTIR 8219](https://csrc.nist.gov/publications/detail/nistir/8219/final), [MITRE CAR](https://car.mitre.org/)). Adversarial-poisoning literature for ML-based detectors is mature ([Anomaly Detection: A Survey, ACM Computing Surveys 2009](https://dl.acm.org/doi/10.1145/1541880.1541882)). LLM-specific anomaly detection guidance is documented in recent literature ([Large Language Models for Forecasting and Anomaly Detection: A Systematic Literature Review, 2024](https://arxiv.org/abs/2402.10350)).

## References

- [MITRE CAR — Cyber Analytics Repository](https://car.mitre.org/)
- [NISTIR 8219: Securing Manufacturing Industrial Control Systems: Behavioral Anomaly Detection](https://csrc.nist.gov/publications/detail/nistir/8219/final)
- [Anomaly Detection: A Survey — ACM Computing Surveys (2009)](https://dl.acm.org/doi/10.1145/1541880.1541882)
- [Large Language Models for Forecasting and Anomaly Detection: A Systematic Literature Review (2024)](https://arxiv.org/abs/2402.10350)
- [Finding Cyber Threats with ATT&CK-Based Analytics — MITRE](https://www.mitre.org/publications/technical-papers/finding-cyber-threats-with-attck-based-analytics)
- [MITRE ATT&CK T1562.006 — Indicator Blocking](https://attack.mitre.org/techniques/T1562/006/) — adversary technique that suppression-policy abuse can enable; M-11's suppression governance is a defense.

## Related Mitigations

- [SAFE-M-12](../SAFE-M-12/README.md): Audit Logging — the structured-event substrate M-11 consumes. M-11 cannot operate without M-12 (no signal). Strong, concrete dependency.
- [SAFE-M-70](../SAFE-M-70/README.md): Detective Control - Tool-Invocation Anomaly Detection & Baselining — owns per-tool / per-entity invocation baselines. M-11 consumes M-70's features rather than reproducing them. M-11 envelops M-70 conceptually but defers per-invocation analytics to it.
- [SAFE-M-22](../SAFE-M-22/README.md): Semantic Output Validation — produces per-call validation outcomes; M-11 baselines them over time (e.g., per-actor validation-flag rate spike).
- [SAFE-M-69](../SAFE-M-69/README.md): Out-of-Band Authorization for Privileged Tool Invocations — produces approval / deny / timeout decisions; M-11 baselines approval-pattern anomalies (deny-rate spike, response-time-to-approval distribution shift indicating rubber-stamping).

## Version History
| Version | Date | Changes | Author |
|---------|------|---------|--------|
| 0.1 | 2025-01-03 | Initial stub | Frederick Kautz |
| 0.2 | 2025-01-09 | Added explicit prompt injection monitoring | Frederick Kautz |
| 1.0 | 2026-04-30 | Expanded stub to template parity per corpus mitigation quality audit; authored Technical Implementation (5 Core Principles, Anti-poisoning controls, Architecture, per-pattern Telemetry prerequisites, Prerequisites, Implementation Steps), Detection Patterns (11-pattern table covering 14 directly-mapped citing techniques), Benefits, Limitations, Implementation Examples (Splunk SPL T1309, Elastic EQL T1702, Python streaming T1106, anti-poisoning shadow-baseline drift alarm), Testing and Validation, Deployment Considerations, Current Status sections; curated Mitigates list against actual citation graph (excluded T1305 misdirection, removed phantom T1101 / T1701 entries) | bishnu bista |
| 1.1 | 2026-05-03 | Added Patterns 12 (T1112 sampling-then-sensitive-action correlation) and 13 (T1803 bulk-export with coercion-context correlation) — both previously claimed in Mitigates but undocumented in the patterns and telemetry tables. Pattern 13 layers atop M-70 Rules A and C; Pattern 12 operates directly on M-12's `tool_invocation` event stream (per M-12 Principle 2 which folds T1112 sampling-request logging under `tool_invocation` with the `approval` field) — corrected an early draft that incorrectly cited M-70 sampling-rate alerts (M-70 has no such alert) and `auth_operation` events for sampling approvals (M-12 reserves `auth_operation` for OAuth lifecycle only). Removed Pattern 4's incorrect M-70 dependency: Pattern 4 (OAuth lifecycle anomaly) operates standalone on M-12's `auth_operation` event stream (M-12 Principle 4 — `op`, `subject`, `device_fingerprint`, `geo_hint`, `correlation_token` — sufficient for concurrent-reuse and post-logout-use detection without external baselining; `source_ip` remains a Feature Request to M-12 v1.2 per the existing Pattern 4 Telemetry prereq note). SAFE-M-20 (currently a stub with implementation `[To be documented]`) is documented as a complementary feature source for when M-20 is expanded. Updated Prerequisites, Limitations, Architecture diagram, and Implementation Steps to reflect Patterns 1-8 and 10-13 metadata-driven coverage. Aligned schema field names with SAFE-M-12 v1.1: `args_summary` → `args_hash` (Feature Request for M-12 v1.2 — `args_field_tree` is structure-only and would alias value-different but shape-identical calls, defeating T1106 detection); `actor.runtime_identity.effective_uid` → `actor.effective_uid` (M-12 has never had a `runtime_identity` wrapper — direct keys on the actor block); `endpoint` → `destination` (per M-12 v1.1 Principle 2). Field-name fixes applied in Telemetry prerequisites table, Detection Patterns table, Example 2 EQL, and Example 3 Python. Added `## Out of scope` section to back the existing "see Out of scope" reference in the Mitigates intro. | bishnu bista |
