# SAFE-M-70: Detective Control - Tool-Invocation Anomaly Detection & Baselining

## Overview
**Mitigation ID**: SAFE-M-70  
**Category**: Detective Control  
**Effectiveness**: Medium-High (depends on baseline quality and window tuning)  
**Implementation Complexity**: Medium  
**First Published**: 2026-04-14

## Description
Tool-Invocation Anomaly Detection & Baselining is a detective control that profiles **per-agent, per-user, per-tool** baselines of MCP tool-call behavior and raises alerts when live invocations deviate from those baselines along one or more feature dimensions. The goal is to catch tool-call events whose *shape* does not match what a given principal normally does — even when the individual call is syntactically valid and would pass static policy checks.

Unlike coarse rate-limits or static allowlists, this mitigation models behavior at the tool-invocation layer: which tool was called, by which user/agent/session, with what argument cardinality, returning what result volume, at what time of day, to what destination. Anomalous deviations — a first-ever call to a privileged filesystem tool by a reporting agent, or a `sql_query` returning substantially more rows than this user's historical distribution — are scored and surfaced to a SIEM, approval gate, or human reviewer.

**Distinction from SAFE-M-11 (Behavioral Monitoring).** SAFE-M-11 covers LLM behavioral analytics across the entire agent session, including model-generated text, reasoning patterns, tool-usage *sequences*, and conversation-level deviations. SAFE-M-70 is narrower: it operates on the single-event tool-invocation log stream, with per-entity statistical baselines over the numeric and categorical features of individual calls (volume, cardinality, destination, time). Deployments typically run both — M-11 for cross-turn behavioral signals, M-70 for per-call tool-stream baselines — with M-70 providing the high-precision per-invocation alerts that feed M-11's broader session-level correlation.

It complements — not replaces — preventive controls such as explicit privilege boundaries (SAFE-M-29) and binding authorization; its role is to detect coercion and abuse that slip past prevention, especially for techniques such as SAFE-T1309 (privileged tool invocation via prompt manipulation) and SAFE-T1803 (database dump via MCP tools) where individual calls can look structurally legitimate.

## Mitigates
- [SAFE-T1309](../../techniques/SAFE-T1309/README.md): Privileged Tool Invocation via Prompt Manipulation
- [SAFE-T1803](../../techniques/SAFE-T1803/README.md): Database Dump
- [SAFE-T1104](../../techniques/SAFE-T1104/README.md): Over-Privileged Tool Abuse

## Technical Implementation

### Core Principles
1. **Per-entity baselining, not global**: Baselines are keyed by `(tenant, user, agent, tool)` — or a coarser subset when data is sparse — so that a new-hire analyst is not compared to a nightly batch service account.
2. **Multi-dimensional features**: No single feature (e.g., call rate) is sufficient. Track volume, argument cardinality, result size, destination, and temporal features together so that an adversary cannot evade by flattening one axis.
3. **Degrade open until tuned**: During initial rollout, anomaly signals are alert-only (SIEM/notification). Only promote high-confidence rules to blocking or approval-gating after false-positive rates are characterized.
4. **First-time-use is a first-class signal**: First-ever use of a privileged tool by a given principal, or first-ever destination for an export, is often more valuable than statistical deviation.
5. **Bounded baseline windows**: Use rolling windows (e.g., 30–90 days) with decay, so legitimate drift is learned but stale behavior does not mask compromise.

### Architecture Components
```text
 ┌───────────────────────┐      ┌──────────────────────┐      ┌─────────────────────┐
 │ MCP Host / Server     │      │ Feature Extraction   │      │ Baseline Store      │
 │ tool-invocation log ──┼─────▶│ (per-call features)  │─────▶│ (per-entity stats,  │
 │ (SAFE-M-12 substrate) │      │                      │      │  rolling windows)   │
 └───────────────────────┘      └──────────┬───────────┘      └──────────┬──────────┘
                                           │                              │
                                           ▼                              ▼
                                  ┌──────────────────────────────────────────────┐
                                  │ Anomaly Scorer                               │
                                  │  - z-score / robust z on numeric features    │
                                  │  - isolation forest on joint feature vector  │
                                  │  - first-time-use / rare-category rules      │
                                  └──────────────────┬───────────────────────────┘
                                                     │ scored events
                                                     ▼
                                  ┌──────────────────────────────────────────────┐
                                  │ Alert Pipeline                               │
                                  │  - SIEM (Splunk / Sentinel / Elastic)        │
                                  │  - Approval gate (human-in-the-loop)         │
                                  │  - Case management / on-call paging          │
                                  └──────────────────────────────────────────────┘
```

### Prerequisites
- Structured MCP tool-invocation logging in place — see [SAFE-M-12: Audit Logging](../SAFE-M-12/README.md) — emitting at minimum: timestamp, tenant, user id, agent id, session id, tool name, a serialized form of the arguments (or a structured argument tree) sufficient to compute byte-size and field-cardinality features, result row-count and byte-size, destination (if applicable), and outcome.
- A stable identity schema for users, service accounts, and agents so baselines can be keyed consistently.
- Access to at least **30 days** of historical tool-invocation data before enabling production alerting; 60–90 days is preferred for workloads with weekly/monthly seasonality.
- A SIEM or equivalent alert sink capable of ingesting scored events and supporting analyst triage.
- (Optional but recommended) a tool inventory classifying each tool as `privileged` or `non-privileged` to prioritize rules.

### Implementation Steps
1. **Design Phase**:
   - Enumerate the tool surface and tag each tool with sensitivity (privileged vs. non-privileged) and data class (bulk-read, mutation, egress, etc.).
   - Define the entity key hierarchy (tenant > user > agent > tool) and the fallback policy when a finer key has insufficient data.
   - Select the initial feature set (see extraction example below) and document thresholds.

2. **Development Phase**:
   - Implement feature extraction over the tool-invocation log substrate.
   - Build the baseline store using rolling aggregates (e.g., per-entity mean/stddev, per-entity HyperLogLog for cardinality, per-entity destination sets).
   - Implement scorers: robust z-score for numeric features, first-time-use rule for categorical features, isolation forest (or similar) over the joint feature vector for tail anomalies.
   - Instrument alert enrichment with the raw tool call, entity baselines, and a human-readable reason string.

3. **Deployment Phase**:
   - Run in shadow mode for at least 2 baseline windows; review false-positive rate and tune.
   - Enable SIEM alerting for high-severity rules (privileged-tool first-use, large-magnitude robust-z result-size anomalies).
   - Later, gate a narrow subset of highest-severity anomalies behind a human approval step at the MCP host.
   - Review and retune at least quarterly, or after any material change to the agent/tool fleet.

## Benefits
- **Catches semantically valid but behaviorally abnormal calls**: Detects abuse patterns where a call is structurally legitimate but wrong for this principal (coerced privileged invocation, bulk-export abuse).
- **Complements preventive controls**: Fills the gap when prevention (SAFE-M-29, authorization gates) is bypassed or misconfigured.
- **Leverages existing log substrate**: Builds on the MCP tool-invocation logs required by SAFE-M-12; marginal cost is modeling and alerting, not new instrumentation.
- **Supports forensics**: The baseline store itself is a useful investigative artifact during incident response.

## Limitations
- **Cold start**: New users, new agents, and newly deployed tools have no baseline; these are either over-alerted (first-time-use firing constantly) or under-alerted (statistical rules silent until enough data accumulates).
- **Legitimate bursty workloads**: Scheduled jobs, migrations, quarter-end reporting, and large backfills legitimately spike volume/cardinality and will generate false positives unless modeled as separate entities or given explicit exemptions.
- **Slow-roll evasion**: A patient adversary can stay under per-call thresholds (e.g., exfiltrating in many small queries over days). Mitigation requires session- and principal-level aggregation with long windows, which increases detection latency.
- **Per-entity data sparsity**: Very fine-grained keys (per-user, per-tool) often have too few samples for stable statistics; coarsening the key trades specificity for stability.
- **Not a prevention control**: This mitigation detects after invocation. It must be paired with preventive controls for high-impact tools.

## Implementation Examples

### Example 1: Feature extraction (pseudocode)
```python
# Pseudocode — not a complete implementation.
# Input: a single tool-invocation event from the SAFE-M-12 audit log.
def extract_features(event):
    return {
        "entity_key":      (event.tenant, event.user_id, event.agent_id, event.tool_name),
        "session_id":      event.session_id,
        "tool_name":       event.tool_name,
        "is_privileged":   TOOL_INVENTORY[event.tool_name].privileged,
        "arg_byte_size":   len(event.arguments_serialized),
        "arg_cardinality": count_distinct_fields(event.arguments),
        "result_rows":     event.result.get("row_count", 0),
        "result_bytes":    event.result.get("bytes", 0),
        "destination":     event.result.get("destination"),       # e.g. s3://... or None
        "hour_of_day":     event.timestamp.hour,
        "day_of_week":     event.timestamp.weekday(),
    }
```

### Example 2: Scoring rules
```python
# Robust z-score on a numeric feature vs per-entity baseline.
def robust_z(value, baseline):
    # baseline: {"median": float, "mad": float, "n": int}
    if baseline["n"] < 30 or baseline["mad"] == 0:
        return None  # insufficient data; fall back to first-time-use rule
    return 0.6745 * (value - baseline["median"]) / baseline["mad"]

def score_event(features, baselines):
    alerts = []

    # Rule A: result_rows far above this entity's historical median -> possible SAFE-T1803 bulk export.
    # A robust z-score over the log-transformed row count is a unitless deviation measure; the
    # threshold 3.5 is a commonly cited extreme-outlier cut for MAD-based scores (not a fixed
    # row-count multiple). Calibrate per deployment.
    rz = robust_z(features["result_rows"], baselines["result_rows"])
    if rz is not None and rz > 3.5:
        alerts.append(("result_rows.extreme", rz))

    # Rule B: first-ever use of a privileged tool by this principal -> possible SAFE-T1309
    if features["is_privileged"] and features["entity_key"] not in baselines["seen_entities"]:
        alerts.append(("privileged_tool.first_use", 1.0))

    # Rule C: new destination for an export tool
    dest = features["destination"]
    if dest and dest not in baselines["destinations"]:
        alerts.append(("destination.first_seen", 1.0))

    return alerts
```

### Example 3: SIEM query sketch (Splunk-style)
First-time-use is an **all-time** signal, not a within-window one. The pattern below joins
the live window against a persisted lookup of every `(user, agent, tool)` triple ever observed;
the lookup is refreshed by a separate daily job that appends newly seen entities. The live
query fires only when the current triple is absent from that persisted history.

```text
index=mcp_tool_invocations sourcetype=mcp:tool_call earliest=-1h
| join type=left tool_name [| inputlookup tool_inventory.csv where privileged=true]
| where privileged=true
| lookup seen_entities.csv user_id agent_id tool_name OUTPUT first_seen
| where isnull(first_seen)
| eval alert="privileged_tool.first_use"
```

A separate scheduled job maintains `seen_entities.csv`:
```text
index=mcp_tool_invocations earliest=-90d
| stats min(_time) as first_seen by user_id, agent_id, tool_name
| outputlookup seen_entities.csv
```

## Testing and Validation
1. **Security Testing**:
   - Replay synthetic SAFE-T1309 traces (privileged tool invoked after a coercion prompt) and verify `privileged_tool.first_use` or argument-cardinality rules fire.
   - Replay synthetic SAFE-T1803 traces (wide-table `SELECT` returning 10^6+ rows) and verify result-size robust-z rules fire.
   - Verify rules do not fire for a matched-entity legitimate replay.

2. **Functional Testing**:
   - Validate baseline store updates are idempotent and survive replay.
   - Measure end-to-end scoring latency for a realistic event rate (target: sub-second for SIEM path, a few seconds is acceptable).

3. **Integration Testing**:
   - Confirm alerts land in SIEM with the expected schema and severity.
   - Confirm approval-gated tools actually pause execution pending human response when the high-severity path is enabled.

## Deployment Considerations

### Resource Requirements
- **CPU**: Modest; per-event feature extraction and scoring is O(1) per event against a cached baseline.
- **Memory**: Dominated by the baseline store (per-entity sketches). Plan roughly 1–10 KB per `(user, tool)` pair; size accordingly.
- **Storage**: Historical baselines and rolling windows — commonly 10s of GB for mid-size deployments; reuse existing log storage where possible.
- **Network**: Negligible beyond SIEM ingestion.

### Performance Impact
- **Latency**: Out-of-band scoring adds none to tool execution. An inline approval gate adds whatever human-response latency the policy requires.
- **Throughput**: Designed to run asynchronously; should not throttle MCP traffic.
- **Resource Usage**: Modest and predictable; dominated by the SIEM pipeline, not the MCP host.

### Monitoring and Alerting
- Alerts-per-hour per rule (watch for alert storms from poorly tuned thresholds).
- Baseline freshness per entity (stale baselines indicate ingestion problems).
- Coverage: fraction of tool calls with a matched baseline entity key.
- Mean time between a privileged-tool-first-use alert and analyst acknowledgement.

## Current Status (2026)
UEBA-style analytics for LLM agents and MCP tool usage remain **nascent** as of 2026. Practitioner writeups indicate that most production deployments still rely on **hard thresholds** (per-tool rate limits, fixed row-count caps, destination allowlists) rather than learned per-entity baselines [1][2]. Research on anomaly detection for LLM-driven systems exists [3], but production-grade MCP-specific UEBA is still catching up with the rapid growth of the agent ecosystem. Defenders adopting this mitigation today should expect to invest in baseline tuning, accept a cold-start period, and pair it with preventive controls rather than treating it as a standalone defense.

## References
- [1] [Model Context Protocol Specification](https://modelcontextprotocol.io/specification)
- [2] [OWASP Top 10 for Large Language Model Applications](https://owasp.org/www-project-top-10-for-large-language-model-applications/)
- [3] [Large Language Models for Forecasting and Anomaly Detection: A Systematic Literature Review (2024)](https://arxiv.org/abs/2402.10350)
- [4] [NIST SP 800-92: Guide to Computer Security Log Management](https://csrc.nist.gov/publications/detail/sp/800-92/final)
- [5] [NISTIR 8219: Securing Manufacturing Industrial Control Systems — Behavioral Anomaly Detection](https://csrc.nist.gov/publications/detail/nistir/8219/final)
- [6] [Anomaly Detection: A Survey — Chandola, Banerjee, Kumar, ACM Computing Surveys 2009](https://dl.acm.org/doi/10.1145/1541880.1541882)
- [7] [Isolation Forest — Liu, Ting, Zhou, ICDM 2008](https://ieeexplore.ieee.org/document/4781136)
- [8] [MITRE ATT&CK T1213 — Data from Information Repositories](https://attack.mitre.org/techniques/T1213/)

## Related Mitigations
- [SAFE-M-11](../SAFE-M-11/README.md): Behavioral Monitoring — broader LLM behavioral analytics over model outputs and sequences; SAFE-M-70 is a specialization focused on the tool-invocation event stream.
- [SAFE-M-12](../SAFE-M-12/README.md): Audit Logging — provides the structured log substrate on which SAFE-M-70 operates; a hard prerequisite.
- [SAFE-M-20](../SAFE-M-20/README.md): Anomaly Detection (OAuth request patterns) — complementary control at the OAuth/auth layer; SAFE-M-70 covers the in-session tool-call layer.
- [SAFE-M-29](../SAFE-M-29/README.md): Explicit Privilege Boundaries — preventive counterpart for SAFE-T1309; SAFE-M-70 detects what slips past it.
- [SAFE-M-36](../SAFE-M-36/README.md): Model Behavior Monitoring — complementary, focused on model inputs/outputs rather than the tool-invocation event stream.

## Version History
| Version | Date | Changes | Author |
|---------|------|---------|--------|
| 1.0 | 2026-04-14 | Initial documentation | bishnu bista |
