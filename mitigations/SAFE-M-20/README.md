# SAFE-M-20: Anomaly Detection

## Overview
**Mitigation ID**: SAFE-M-20  
**Category**: Detective Control  
**Effectiveness**: Medium-High (depends on training-data quality, baseline tuning, and the specific event sources ingested)  
**Implementation Complexity**: High  
**First Published**: 2025-06-01

## Description
Anomaly Detection is a detective control that applies machine-learning and behavioral-analytics techniques to surface anomalous patterns across multiple SAFE-MCP control-plane event streams — OAuth flows, tool-invocation logs (the SAFE-M-12 substrate), network and discovery telemetry, and scope-usage events. Where signature-based detection requires a known attack pattern and rule-based detection requires explicit thresholds, SAFE-M-20 surfaces unknown-shape anomalies via clustering, density estimation, first-seen rules, and ML-based pattern recognition.

SAFE-M-20 sits at a specific layer in the MCP detection stack and is complementary to two related controls. **SAFE-M-11 (Behavioral Monitoring)** covers LLM behavioral analytics across the agent session — model-generated text, reasoning patterns, conversation-level deviations. SAFE-M-20 operates on the structured event-stream layer below the LLM, ingesting telemetry from multiple control planes and applying ML pattern recognition to surface novel patterns. **SAFE-M-70 (Detective Control - Tool-Invocation Anomaly Detection & Baselining)** is narrower in *event scope*, not in method: it applies per-`(tenant, user, agent, tool)` rolling baselines, robust z-scores on numeric features, isolation-forest scoring on the joint feature vector, and first-time-use / rare-category rules — all to a single event source, the per-call tool-invocation log stream. SAFE-M-20 broadens the *event surface* to heterogeneous sources beyond per-call tool invocations — OAuth flows, scope-usage events, identity / discovery telemetry — and provides the cross-source correlation layer that combines per-source signals (including SAFE-M-70's per-call scores when present) into a composite session-level signal. SAFE-M-20 and SAFE-M-70 thus share many scoring methods but apply them to different event surfaces and at different aggregation levels; deployments typically run all three (M-11, M-70, M-20) with each owning a distinct portion of the detection surface.

## Mitigates
- [SAFE-T1004](../../techniques/SAFE-T1004/README.md): Server Impersonation / Name-Collision
- [SAFE-T1007](../../techniques/SAFE-T1007/README.md): OAuth Authorization Phishing
- [SAFE-T1009](../../techniques/SAFE-T1009/README.md): Authorization Server Mix-up
- [SAFE-T1106](../../techniques/SAFE-T1106/README.md): Autonomous Loop Exploit
- [SAFE-T1112](../../techniques/SAFE-T1112/README.md): Sampling Request Abuse
- [SAFE-T1308](../../techniques/SAFE-T1308/README.md): Token Scope Substitution
- [SAFE-T2102](../../techniques/SAFE-T2102/README.md): Service Disruption via External API Flooding

## Technical Implementation

### Core Principles

1. **Multi-source event ingestion**: SAFE-M-20 ingests structured events from multiple SAFE-MCP control planes — OAuth flow logs, tool-invocation logs (the SAFE-M-12 audit substrate; SAFE-M-70 already operates here as the per-call statistical and ML scoring layer), network and discovery telemetry, and scope-usage events. SAFE-M-20's value is correlating signals across these sources to surface attacks whose joint footprint exceeds any single source's anomaly score, a capability that single-source baselining (SAFE-M-70 included) does not provide on its own.

2. **ML pattern recognition over heterogeneous features**: Unsupervised anomaly detectors (e.g., isolation forest), clustering (e.g., DBSCAN), density estimation, and first-seen / rare-category rules form the core scoring layer. These methods detect patterns that do not fit any single per-entity statistical profile and are well-suited to heterogeneous feature vectors that combine numeric (volume, latency), categorical (issuer, destination, geographic region), and temporal (hour-of-day, day-of-week, inter-arrival time) features. SAFE-M-70 applies similar method families to per-call tool-invocation events; SAFE-M-20 applies them across the broader cross-source event surface and adds the cross-source correlation step (Core Principle 3) that single-source baselining does not perform.

3. **Cross-source correlation**: Events that fire anomaly signals on multiple sources concurrently — a first-seen OAuth issuer combined with a first-time-use of a privileged tool combined with an unusual destination, all within one session — receive a higher composite score than any single-source signal. This correlation layer is what distinguishes SAFE-M-20 from per-source baselines and is the primary mechanism by which the mitigation surfaces multi-stage attacks. Initial deployments use rule-based composite scoring (sum of per-source z-scores above thresholds); migration to learned correlation is appropriate only after the rule-based behavior is well understood.

4. **Adaptive baselining with anti-poisoning**: Baselines drift legitimately over time as users adopt new tools, agents are added, and traffic patterns shift. The risk that an adversary slowly biases the baseline toward acceptance of malicious patterns ("baseline poisoning") is addressed by maintaining a frozen reference window during initial deployment, applying explicit clean-corpus admission criteria to candidate training data, and decaying old samples on a fixed schedule rather than allowing unbounded drift. The clean-corpus admission criteria must be defined per deployment but at minimum should: (a) admit only data from a trusted-bootstrap window (typically pre-deployment or a post-incident known-clean period); (b) exclude data from active investigation windows or analyst-quarantine periods; (c) admit allowlisted synthetic / known-good test data only when explicitly tagged as such; (d) exclude any activity flagged for analyst review even if it passed policy gates at the time it occurred. Audit-log evidence from [SAFE-M-12](../SAFE-M-12/README.md) and approval traces from [SAFE-M-29](../SAFE-M-29/README.md) / [SAFE-M-69](../SAFE-M-69/README.md) inform these criteria as evidence and context, not as cleanliness labels in themselves: an event having been logged or having passed an approval workflow does not by itself make the event clean training data, and an attacker who can produce logged or approved activity during the reference window can still poison the baseline if these signals are treated as labels rather than as inputs to an explicit admission decision. This anti-poisoning framing is owned by SAFE-M-20's own design and is independent of any sibling mitigation's implementation.

5. **Degrade-open during tuning**: At deployment, anomaly signals are alert-only (SIEM / notification). Promotion to gating or approval-gating happens only after false-positive rates per signal type have been characterized over at least two baseline windows. This conservative posture is appropriate for ML-based detection where initial model behavior is not fully predictable and over-aggressive blocking would erode trust in the detection layer; it also matches the deployment guidance in SAFE-M-70 for the same reason.

6. **Scoring output is itself audited**: Every emitted anomaly score, the contributing per-source signals, the composite-score breakdown, and the model version that produced the score are logged via the SAFE-M-12 audit substrate. This gives analysts a forensic trail of what was alerted and why over time, lets incident response replay historical events through the current or a prior model, and is a prerequisite for the post-incident root-cause analysis that drives model retraining and threshold adjustment.

### Architecture Components

The architecture below shows the four registered feature sources — OAuth, tool-invocation (the SAFE-M-12 substrate), network / discovery, and scope-usage — feeding a per-source extraction stage, then a single ML scoring stage, then a cross-source correlator that combines per-source scores (including SAFE-M-70's per-call statistical scores when present) into a composite score per logical session, and finally an alert pipeline. The diagram boxes below show three of the four sources for layout reasons; scope-usage is the fourth registered source and is handled by the same per-source extraction pattern (its registered name and per-source extractor appear in the §Implementation Examples REGISTERED_SOURCES tuple). Per-source feature extraction and the ML scorer are decoupled so they can be retrained and tuned independently.

Beyond the four currently-registered sources, additional sources can be added by extending the REGISTERED_SOURCES set, implementing a per-source feature-extraction module that conforms to the cross-source feature schema (numeric / categorical / temporal feature types), and registering its output with the correlator; the ML scorer and the alert pipeline do not need to be re-engineered for each new source. This decoupling is what allows SAFE-M-20 to grow its registered-source set (e.g., agent lifecycle events, additional MCP discovery telemetry, custom tenant-specific sources) over time without invalidating prior baselines.

```text
 ┌──────────────────────┐  ┌──────────────────────┐  ┌──────────────────────┐
 │ OAuth Flow Logs      │  │ Tool-Invocation Logs │  │ Network / Discovery  │
 │ (issuer, destination,│  │ (SAFE-M-12 substrate)│  │ Telemetry            │
 │  client, geo, time)  │  │                      │  │                      │
 └──────────┬───────────┘  └──────────┬───────────┘  └──────────┬───────────┘
            │                         │                         │
            └─────────────┬───────────┴─────────────────────────┘
                          ▼
              ┌──────────────────────────────┐
              │ Per-Source Feature Extraction│
              │ (numeric / categorical / time)│
              └──────────────┬───────────────┘
                             ▼
              ┌──────────────────────────────┐
              │ ML Scorer                    │
              │  - iForest (unsupervised)    │
              │  - DBSCAN (clustering)       │
              │  - density / first-seen rules│
              │  - rare-category detection   │
              └──────────────┬───────────────┘
                             ▼
              ┌──────────────────────────────┐
              │ Cross-Source Correlator      │ ◀─ SAFE-M-70 per-call statistical
              │ (joint scoring across        │    scores fed in here as one
              │  concurrent source signals)  │    input among many
              └──────────────┬───────────────┘
                             ▼
              ┌──────────────────────────────┐
              │ Alert Pipeline               │
              │  - SIEM (Splunk / Elastic /  │
              │    Sentinel)                 │
              │  - Approval gate (M-29 / M-69)│
              │  - Case management / on-call │
              └──────────────────────────────┘
```

### Prerequisites

- Structured tool-invocation logging substrate per [SAFE-M-12: Audit Logging](../SAFE-M-12/README.md) emitting at minimum: timestamp, tenant, user (normalized to canonical `principal` at ingest per the tenant-scoped-keys bullet below), agent, session (normalized to canonical `session_id` at ingest per the same bullet), tool name, serialized arguments, result size, destination, and outcome. The source-native `user` and `session` field names from SAFE-M-12 are mapped to the canonical SAFE-M-20 schema (`principal`, `session_id`) by the per-source normalization step before validation and assembly.
- OAuth telemetry sufficient for cross-source correlation, including at minimum the mandatory correlation-key tuple (per the tenant-scoped correlation bullet below) plus: issuer, authorization endpoint, token destination, client identifier, request timestamp, and (where available) geographic / network metadata of the requesting client. This OAuth-side feature substrate is owned by SAFE-M-20's deployment regardless of which control plane emits it; [SAFE-M-18: OAuth Flow Monitoring](../SAFE-M-18/README.md) is the related high-level OAuth monitoring control that operationalizes the same telemetry for an analyst-facing view.
- **Tenant-scoped, mandatory correlation keys on every event source.** Every source contributing to SAFE-M-20 — OAuth, tool-invocation (the SAFE-M-12 substrate), network / discovery, scope-usage — must carry the canonical correlation tuple `(tenant, principal, agent, session_id)` after per-source normalization at ingest. The four canonical field names are: `tenant` (the tenant boundary identifier); `principal` (the user or service-account identifier); `agent` (the agent or service-principal identifier — sources that natively emit `service_principal` or another equivalent must be normalized to `agent` at ingest); and `session_id` (the session or correlation identifier — sources that natively emit `correlation_id` or `trace_id` must be normalized to `session_id` at ingest). The cross-source correlator joins events strictly within a single tenant boundary; a same-username principal in two different tenants must never be conflated. Events missing any canonical key after normalization must **fail closed** — excluded from the cross-source correlator and routed to a quarantine stream for analyst triage rather than joined under degraded keys. This requirement is what enables the cross-source joins described in §Architecture Components above and is the single largest source of multi-tenant correctness risk if violated; deployments must validate the canonical key set on every source at ingest time, after the per-source normalization step.
- At least 30 days of historical event data for model training; 60–90 days is preferred for workloads with weekly or monthly seasonality.
- A SIEM or analytics platform capable of ingesting scored events, enriching them with raw context from contributing sources, and supporting analyst triage.
- (Optional, recommended) a tool-and-service inventory classifying assets by sensitivity to prioritize ML model investment toward high-impact event sources.

### Implementation Steps

1. **Design Phase**:
   - Enumerate the event sources to be ingested (OAuth, tool-invocation, network, scope-usage) and define the feature schema per source.
   - Choose an ML model family for the scoring layer — isolation forest is a reasonable first choice for tabular feature vectors; DBSCAN or sequence-aware models (HMM, autoencoder) for ordered event sequences such as tool-call graphs.
   - Define the **statistical-baseline coarsening policy** for sparse-sample buckets: coarsening (e.g., grouping per-user baseline buckets into per-agent or per-tenant buckets when a finer bucket has too few samples for stable statistics) applies ONLY to the per-bucket statistical baselines maintained downstream of assembly. It does **not** apply to cross-source assembly or correlation — those steps require the full mandatory canonical `(tenant, principal, agent, session_id)` tuple per §Prerequisites and fail-closed on missing keys. Coarsening must remain tenant-scoped (never collapse across tenants) and must never replace `tenant` / `principal` / `agent` / `session_id` in session identity or alert enrichment.
   - Specify the cross-source correlation rules at design time — start with rule-based composite scoring (sum of per-source z-scores above thresholds) and plan to migrate to learned correlation only after rule-based behavior is well understood.

2. **Development Phase**:
   - Implement per-source feature extraction over the defined log substrates.
   - Build the ML scorer (initial choice: isolation forest from scikit-learn or equivalent) and persist trained models with version metadata.
   - Implement the cross-source correlator that consumes scored events from each source and emits a composite score per logical session.
   - Instrument alert enrichment so each surfaced anomaly carries the raw events from all contributing sources, the per-source scores, and the composite score, plus a human-readable reason string for analyst triage.

3. **Deployment Phase**:
   - Run in shadow mode for at least two baseline windows (typically 60+ days). Compare scored events against analyst review of the same period to characterize false-positive rate per signal type.
   - Enable SIEM alerting for high-confidence rules first (typically: cross-source composite scores above the 99th percentile of the calibration window, or first-seen events for high-sensitivity tools).
   - Promote a narrow subset of highest-severity anomalies to approval gating (via SAFE-M-29 or SAFE-M-69) only after at least one quarter of stable alert-only operation.
   - Retrain models and re-tune thresholds at least quarterly, or after any material change to the agent / tool / user fleet.

## Benefits

- **Catches semantically valid but behaviorally novel patterns**: Detects attack shapes where individual events are structurally legitimate but their combination across sources is unprecedented, including patterns that signature-based and rule-based detection cannot enumerate in advance.
- **Cross-source correlation surfaces multi-stage attacks**: An attack that walks across OAuth flows, tool invocations, and scope-usage events leaves a faint signal on each source individually but a strong joint signal across sources; SAFE-M-20 is positioned to surface that joint signal.
- **Complementary, not redundant, with SAFE-M-11 and SAFE-M-70**: The three controls operate on distinct event surfaces (per-session LLM behavioral, per-call tool-invocation, cross-source heterogeneous) with distinct correlation responsibilities, even where individual scoring methods (z-scores, isolation forest, first-time-use rules) overlap between SAFE-M-20 and SAFE-M-70. Deployments typically run all three.
- **Trained model is itself a forensic artifact**: The fitted ML model and the per-source baselines it learned from are useful investigative artifacts during incident response; analysts can replay historical events through the model to reconstruct the activity that should have been alerted.

## Limitations

- **Cold start**: New users, new agents, new tools, and newly added event sources have no baseline. Until enough samples accumulate (typically a baseline window), these entities are either over-alerted (first-seen rules firing constantly) or under-alerted (statistical rules silent until enough data accumulates).
- **Model drift requires retraining cadence**: Legitimate behavior changes — new tooling adopted, new business workflows, new geographies — drift the baseline. Without a retraining cadence (quarterly is a defensible default), the model gradually loses precision and either misses real anomalies or generates increasing false positives.
- **Slow-and-low evasion**: A patient adversary who stays under the model's per-feature decision boundary, spreads activity across long time windows, and avoids first-seen events can evade detection. Mitigation requires longer correlation windows (weeks rather than hours), which increases detection latency and grows the per-entity baseline storage footprint; the trade-off is intentional and should be documented per deployment.

- **Adversarial pressure on the baseline itself**: Beyond passive evasion, an adversary with prior access can attempt to bias the baseline by injecting plausible-looking activity during the training window. The anti-poisoning controls in Core Principle 4 (frozen reference windows, shadow baselining on confirmed-clean data, fixed decay schedules) are the structural defense; an audit gap in the SAFE-M-12 substrate that admits unverified events into the training corpus undermines that defense.
- **Higher computational cost than per-call statistical baselines**: ML scoring (isolation forest, clustering) is more expensive than the per-entity z-score computation that SAFE-M-70 uses. SAFE-M-20 typically runs as a batch or near-real-time pipeline downstream of SAFE-M-70 rather than on the per-call hot path.
- **Not a prevention control**: SAFE-M-20 detects after the event has occurred. It must be paired with preventive controls — [SAFE-M-29: Explicit Privilege Boundaries](../SAFE-M-29/README.md) for high-impact tools, [SAFE-M-69: Out-of-Band Authorization for Privileged Tool Invocations](../SAFE-M-69/README.md) for privileged operations — to actually block attacks rather than only surface them after the fact.

## Implementation Examples

### Example 1: Cross-source feature extraction

```python
# Pseudocode — not a complete implementation.
# Combines events from the four registered sources (OAuth,
# tool-invocation, network/discovery, scope-usage) into a single
# feature vector for the ML scorer. The session_events dict is assembled upstream
# by joining events on the FULL mandatory correlation tuple
# (tenant, principal, agent, session_id) per §Prerequisites — never
# on session_id alone, since session IDs are not globally unique
# across tenants and agents. The four canonical field names below
# are the per-source-NORMALIZED form: a source emitting
# `service_principal` must be normalized to `agent` at ingest, and
# a source emitting `correlation_id` (or `trace_id`) must be
# normalized to `session_id` at ingest, so REQUIRED_KEYS validation
# operates on a single canonical schema across all sources. Per the
# fail-closed requirement, events missing any tuple member after
# normalization are rejected at the assembly stage and routed to a
# quarantine stream (see assemble_session_events below) before
# reaching this function.

REQUIRED_KEYS = ("tenant", "principal", "agent", "session_id")  # canonical (post-normalization) field names

# Registered event sources. Adding a new source = (a) extend this tuple,
# (b) add a per-source extractor in extract_features below, (c) add a
# per-source feature-extraction module that conforms to the cross-source
# feature schema (per §Architecture Components). Unknown source names are
# quarantined at assembly so that misconfigured pipelines fail closed
# instead of silently dropping events.
REGISTERED_SOURCES = ("oauth", "tool_invocations", "network", "scope_usage")

def assemble_session_events(raw_events_per_source, quarantine_sink):
    """
    Assembles per-session event dicts by joining sources strictly within
    a single tenant boundary on the full correlation tuple. Events that
    cannot supply every member of REQUIRED_KEYS are rejected at this
    stage and routed to quarantine_sink for analyst triage; they are
    never joined under degraded keys. Events from a source name not in
    REGISTERED_SOURCES are also quarantined (unregistered-source path)
    so misconfigured pipelines fail closed instead of silently dropping.

    The validated identity tuple is carried INTO each assembled session
    dict (not just used as the join key) so downstream feature extraction
    consumes the normalized identity from a single authoritative location
    rather than reconstructing it from partial event fields. Per-source
    event buckets are initialized dynamically from REGISTERED_SOURCES so
    adding a new source does not require touching this function.
    """
    sessions = {}
    for source_name, events in raw_events_per_source.items():
        if source_name not in REGISTERED_SOURCES:
            quarantine_sink.emit(source=source_name, event=None,
                                 reason="unregistered_source",
                                 count=len(events))
            continue
        for e in events:
            if any(getattr(e, k, None) in (None, "") for k in REQUIRED_KEYS):
                quarantine_sink.emit(source=source_name, event=e,
                                     reason="missing_correlation_key")
                continue
            key = tuple(getattr(e, k) for k in REQUIRED_KEYS)  # tenant-scoped
            if key not in sessions:
                tenant, principal, agent, session_id = key
                sess = {
                    "tenant":            tenant,
                    "principal":         principal,
                    "agent":             agent,
                    "session_id":        session_id,
                    # duration_seconds is derived after assembly completes:
                    # max(event_ts) - min(event_ts) across all registered sources.
                    "duration_seconds":  None,
                }
                # Initialize per-source buckets from REGISTERED_SOURCES so
                # the same code handles any number of currently-registered sources.
                for src in REGISTERED_SOURCES:
                    sess[src] = []
                sessions[key] = sess
            sessions[key][source_name].append(e)
    # After all events ingested, derive duration_seconds across the same
    # registered-source set (no hard-coded source list):
    for sess in sessions.values():
        all_ts = [e.timestamp for src in REGISTERED_SOURCES for e in sess[src]]
        sess["duration_seconds"] = (max(all_ts) - min(all_ts)).total_seconds() if all_ts else 0
    return sessions

def extract_features(session_events):
    """
    session_events: dict with one key per registered source name
                    (REGISTERED_SOURCES = oauth, tool_invocations, network,
                    scope_usage), plus the full correlation tuple
                    ('tenant', 'principal', 'agent', 'session_id') and
                    'duration_seconds'. The correlation tuple is invariant
                    across all source events for a given session by
                    construction (assemble_session_events).
    Returns a feature dict suitable for the ML scorer.
    """
    oauth_events = session_events.get("oauth", [])
    tool_events = session_events.get("tool_invocations", [])
    network_events = session_events.get("network", [])
    scope_events = session_events.get("scope_usage", [])  # registered source

    return {
        # Identity (full correlation tuple — not session_id alone)
        "tenant":             session_events["tenant"],
        "principal":          session_events["principal"],
        "agent":              session_events["agent"],
        "session_id":         session_events["session_id"],

        # OAuth-source features
        "oauth_issuer_set":   {e.issuer for e in oauth_events},
        "oauth_dest_set":     {e.token_destination for e in oauth_events},
        "oauth_first_seen":   first_seen_count(oauth_events, "issuer"),

        # Tool-invocation features (from SAFE-M-12 substrate)
        "tool_count":         len(tool_events),
        "tool_priv_count":    sum(1 for e in tool_events if TOOL_INV[e.name].privileged),
        "tool_first_use":     first_use_count(tool_events, "principal"),

        # Scope-usage features (per the registered source set above)
        "scope_count":        len(scope_events),
        "scope_first_use":    first_use_count(scope_events, "scope"),

        # Network-source features
        "net_dest_set":       {e.destination for e in network_events},
        "net_volume_bytes":   sum(e.bytes for e in network_events),

        # Cross-source temporal features
        "session_duration":   session_events["duration_seconds"],
        "concurrency":        max_concurrent_calls(tool_events),
    }
```

### Example 2: ML scoring with isolation forest + composite score

```python
# Pseudocode — not a complete implementation.
# Trains an isolation forest on a frozen reference window of
# confirmed-clean historical features and scores live events
# with a composite score that combines the model output with
# rule-based first-seen and cross-source signals.

from sklearn.ensemble import IsolationForest

def train_baseline(historical_feature_vectors):
    """Fit the model on a frozen reference window of confirmed-clean data."""
    model = IsolationForest(
        n_estimators=200,
        contamination="auto",
        random_state=42,
    )
    model.fit(numeric_view(historical_feature_vectors))
    return model

def score_event(model, model_version, feature_vector, safe_m70_scores=None):
    """
    Return a structured anomaly result whose composite_score is, by
    construction, the sum of the per-source contributions plus the two
    cross-source components plus the optional SAFE-M-70 input component.
    The per_source map is therefore an auditable DECOMPOSITION of
    composite_score, not adjacent context: any non-zero contribution
    directly affects threshold behavior, and the integration test in
    §Testing and Validation can reconcile each contribution against the
    thresholded composite score.

    Reconciliation invariant (asserted by the integration test):
        composite_score == sum(per_source.values())
                           + first_seen_component
                           + cross_source_component
                           + safe_m70_component

    The model_version field is carried through into the alert payload per
    Core Principle 6 so analysts can replay historical events through the
    exact scoring artifact that produced any given alert.

    Higher composite_score = more anomalous.
    """
    # Per-source ML contributions: each registered source produces its own
    # isolation-forest sub-score on its source-specific feature subset, so
    # the breakdown automatically extends when new sources are registered
    # via REGISTERED_SOURCES.
    per_source = {src: per_source_iso_score(model, feature_vector, src)
                  for src in REGISTERED_SOURCES}
    first_seen_score = first_seen_rule_score(feature_vector)
    cross_source_score = cross_source_rule_score(feature_vector)
    # SAFE-M-70 per-call scores feed the cross-source correlator as one
    # input among many (per §Architecture Components). Sum them into a
    # named component so the reconciliation invariant accounts for them
    # explicitly; default 0 if the deployment is not running M-70 yet.
    safe_m70_component = sum(safe_m70_scores) if safe_m70_scores else 0
    composite = (sum(per_source.values())
                 + first_seen_score
                 + cross_source_score
                 + safe_m70_component)
    return {
        "composite_score":         composite,
        "per_source":              per_source,
        "first_seen_component":    first_seen_score,
        "cross_source_component":  cross_source_score,
        "safe_m70_component":      safe_m70_component,
        "model_version":           model_version,
    }

def alert_if_above_threshold(event, scored, threshold, sink):
    """
    Emit a SIEM event with the full per-source + cross-source + SAFE-M-70
    breakdown when the composite score is high. Per the reconciliation
    invariant in score_event, the emitted per_source map and the named
    components sum to the thresholded composite_score — preserved here so
    analyst triage and the integration test can verify that each source's
    contribution is a real component of the thresholding decision. The
    model_version is included so historical events can be replayed through
    the scoring artifact that produced the alert (Core Principle 6).
    """
    if scored["composite_score"] >= threshold:
        sink.emit({
            "event":                   event,
            "composite_score":         scored["composite_score"],
            "per_source":              scored["per_source"],
            "first_seen_component":    scored["first_seen_component"],
            "cross_source_component":  scored["cross_source_component"],
            "safe_m70_component":      scored["safe_m70_component"],
            "model_version":           scored["model_version"],
            "threshold":               threshold,
            "reason":                  human_readable_reason(event, scored),
        })
```

## Testing and Validation

1. **Security Testing**:
   - Replay known anomalous sessions (recorded incidents or synthetic adversarial sequences) and verify the scorer produces above-threshold composite scores.
   - Run negative tests using benign sessions from a known-clean window and verify the false-positive rate is within the deployment SLO.
   - Specifically test cross-source correlation by feeding sessions where each individual source's signal is below threshold but the joint signal is above; the composite scorer should surface these even though no per-source rule alone would.

2. **Functional Testing**:
   - Measure false-positive rate per signal type over a calibration window; reject the deployment if FP rate exceeds the configured SLO.
   - Verify the model retraining pipeline runs to completion on a recent reference window and produces a model with comparable or better calibration metrics versus the prior model.
   - Verify alert enrichment produces the expected raw-event payload, per-source scores, composite score, and human-readable reason for each surfaced anomaly.
   - **Verify missing-correlation-key quarantine** (per the §Prerequisites tenant-scoped-keys requirement): inject synthetic events that omit each member of the canonical `(tenant, principal, agent, session_id)` tuple in turn, and confirm every such event is rejected at assembly and routed to the quarantine sink rather than joined under degraded keys.
   - **Verify per-source field normalization**: inject synthetic events that use the documented alternative field names (e.g., `service_principal` instead of `agent`; `correlation_id` or `trace_id` instead of `session_id`); confirm the per-source normalization step rewrites them to the canonical names before validation, so a source using alternative field names is admitted while a source missing any key after normalization still fails closed.
   - **Verify unregistered-source quarantine**: inject events tagged with a `source_name` that is not in the deployment's registered-source set (REGISTERED_SOURCES in the implementation example); confirm the events are routed to the quarantine sink with reason `unregistered_source` rather than silently dropped or assembled into a session bucket. This guards against misconfigured pipelines that emit events from a source the cross-source correlator has not been extended to handle. All three tests (missing-key quarantine, normalization, unregistered-source quarantine) must pass before any new event source is admitted to the cross-source correlator.

3. **Integration Testing**:
   - End-to-end: emit a synthetic anomalous session into all four registered feature sources (OAuth, tool-invocation, network/discovery, scope-usage) and verify the alert lands in the SIEM with full enrichment. Assert (i) the per-source breakdown contains a key for every member of REGISTERED_SOURCES; (ii) the **reconciliation invariant** holds — `composite_score == sum(per_source.values()) + first_seen_component + cross_source_component + safe_m70_component` — so the per-source contributions and the SAFE-M-70 input provably decompose the thresholded score rather than being adjacent context; (iii) the alert payload carries the `model_version` of the scoring artifact (per Core Principle 6) so analysts can replay historical events through the same model. When SAFE-M-70 is deployed alongside SAFE-M-20, also assert that a non-zero `safe_m70_component` actually moves the composite_score (proving M-70 input is wired in, not silently dropped).
   - Verify that approval-gated escalations to [SAFE-M-29](../SAFE-M-29/README.md) or [SAFE-M-69](../SAFE-M-69/README.md) carry the SAFE-M-20 composite score and contributing-source breakdown.
   - Verify per-call SAFE-M-70 statistical scores arrive as inputs to the cross-source correlator and are combined into the composite score correctly.

## Deployment Considerations

### Resource Requirements

- **CPU**: ML scoring (isolation forest, clustering) is moderate; budget for the steady-state event rate plus the periodic retraining job. Retraining typically runs nightly or weekly on the historical reference window.
- **Memory**: Holds the trained model and a rolling window of recent features. Memory grows linearly with the number of active **statistical-baseline buckets** (tenants × users × agents × tools); plan for the bucket-coarsening policy described in §Implementation Steps Design Phase when the count grows large. Coarsening is a baseline-bucket optimization only; it does not relax the cross-source assembly/correlation tuple requirement from §Prerequisites.
- **Storage**: Historical event store sized for the longest retraining window (typically 60–90 days), plus the persisted model artifacts and per-entity baseline metadata.
- **Network**: Inbound from each event source; outbound to the SIEM and approval gate. Bandwidth depends on event rate and per-event payload size.

### Performance Impact

- **Latency**: Scoring runs asynchronously downstream of the event sources; there is no per-call hot-path impact on tool invocation or OAuth flows. Alert latency is dominated by the analytics pipeline (typically seconds to minutes).
- **Throughput**: Determined by the event ingest rate. Most deployments run the scorer in a streaming framework (Kafka + Flink / Spark Streaming) or a serverless event pipeline.
- **Resource Usage**: Highest during retraining; steady-state scoring is small relative to the underlying event-source infrastructure.

### Monitoring and Alerting

- Track model drift via calibration metrics (e.g., score distribution shift week-over-week).
- Track false-positive rate per signal type; alert if FP rate degrades past the deployment SLO.
- Track alert volume and triage outcome (true positive / false positive / inconclusive); feed these labels back into shadow-baselining.
- Track the number of active **statistical-baseline buckets** and per-bucket sample density; alert when too many buckets fall below the minimum-sample threshold (signal that the baseline-bucket coarsening policy from §Implementation Steps Design Phase needs to apply at a coarser bucketing level — within tenant scope; cross-source assembly/correlation keys remain unchanged).

## Current Status (2026)

Anomaly detection is a long-established security-analytics technique with academic coverage in the Chandola et al. survey [3] and the Isolation Forest paper [4], and standards-body treatment of behavioral anomaly detection in industrial control settings in NISTIR 8219 [6]; the per-event audit-log substrate that this control depends on is documented separately in NIST SP 800-92 [5].

Within this SAFE-MCP corpus, all seven directly-mapped citing techniques invoke SAFE-M-20 with their own framing of what cross-source ML anomaly detection should provide: SAFE-T1004 (Server Impersonation / Name-Collision) calls out detection of unexpected discovery and resolution-drift behavior on the routing telemetry; SAFE-T1007 (OAuth Authorization Phishing) calls out identification of unusual patterns in OAuth requests across MCP servers; SAFE-T1009 (Authorization Server Mix-up) calls out first-seen domains, geographic anomalies, and multiple-AS-configuration patterns; SAFE-T1106 (Autonomous Loop Exploit) calls out detection of non-convergent sequences and abnormal call densities on the tool-call graph; SAFE-T1112 (Sampling Request Abuse) calls out departures from learned baselines for sampling-burst and quota-drain patterns; SAFE-T1308 (Token Scope Substitution) calls out baseline scope-usage patterns and detection of scope-elevation deviations; SAFE-T2102 (Service Disruption via External API Flooding) calls out ML baselines for RPS and concurrency across agents. SAFE-M-20 implements the cross-source ML layer that operationalizes the union of these technique-specific expectations.

SAFE-M-70 (per-call tool-invocation baselining and scoring) and SAFE-M-11 (per-session LLM behavioral analytics) coexist with SAFE-M-20 in the corpus and are referenced in §Related Mitigations; the three controls operate on distinct event surfaces and do not duplicate each other's event-surface ownership or correlation responsibilities, even where individual scoring methods (z-scores, isolation forest, first-time-use rules) overlap.

## References

- [1] [Model Context Protocol Specification](https://modelcontextprotocol.io/specification)
- [2] [OWASP Top 10 for Large Language Model Applications](https://owasp.org/www-project-top-10-for-large-language-model-applications/)
- [3] [Anomaly Detection: A Survey — Chandola, Banerjee, Kumar, ACM Computing Surveys 2009](https://dl.acm.org/doi/10.1145/1541880.1541882)
- [4] [Isolation Forest — Liu, Ting, Zhou, ICDM 2008](https://ieeexplore.ieee.org/document/4781136)
- [5] [NIST SP 800-92: Guide to Computer Security Log Management](https://csrc.nist.gov/publications/detail/sp/800-92/final)
- [6] [NISTIR 8219: Securing Manufacturing Industrial Control Systems — Behavioral Anomaly Detection](https://csrc.nist.gov/publications/detail/nistir/8219/final)
- [7] [Large Language Models for Forecasting and Anomaly Detection: A Systematic Literature Review (2024)](https://arxiv.org/abs/2402.10350)

## Related Mitigations
- [SAFE-M-12](../SAFE-M-12/README.md): Audit Logging — the structured log substrate SAFE-M-20 ingests from for tool-invocation features.
- [SAFE-M-18](../SAFE-M-18/README.md): OAuth Flow Monitoring — related high-level OAuth monitoring control; SAFE-M-20 owns its own OAuth-telemetry schema as documented in Prerequisites.
- [SAFE-M-11](../SAFE-M-11/README.md): Behavioral Monitoring — per-session LLM behavioral analytics; complementary canonical mitigation operating at a different layer.
- [SAFE-M-70](../SAFE-M-70/README.md): Detective Control - Tool-Invocation Anomaly Detection & Baselining — per-`(tenant, user, agent, tool)` baselining and scoring on the per-call tool-invocation event source; complementary canonical mitigation operating on a single event surface. SAFE-M-70 and SAFE-M-20 share many scoring methods (z-scores, isolation forest, first-time-use rules); SAFE-M-20 broadens the event surface beyond per-call tool invocations and adds cross-source correlation. Per-call scores from SAFE-M-70 can feed SAFE-M-20's cross-source correlator as one input among many.
- [SAFE-M-29](../SAFE-M-29/README.md): Explicit Privilege Boundaries — preventive control that SAFE-M-20 detective findings escalate into; SAFE-M-29 already cross-references SAFE-M-20 in its own Related Mitigations section.

## Version History
| Version | Date | Changes | Author |
|---------|------|---------|--------|
| 1.0 | 2026-05-03 | Initial documented version. Replaces a 19-line cohort-variant stub (M-13..M-20 Type/Complexity schema, OAuth-only Description, no prior Version History table). Schema normalized to canonical Category/Effectiveness/Implementation Complexity/First Published. Description broadened from OAuth-only to cross-source ML anomaly detection. Mitigates section curated from 12 raw citers to 7 directly-mapped (T1004, T1007, T1009, T1106, T1112, T1308, T2102); 5 mislabels (T1002, T1203, T1403, T1503, T2103) excluded and tracked as a follow-up cleanup cluster. Added: Technical Implementation (6 Core Principles, Architecture Components with prose framing, Prerequisites, Implementation Steps), Benefits, Limitations, Implementation Examples (cross-source feature extraction + isolation-forest scoring), Testing and Validation, Deployment Considerations, Current Status (2026) with NIST + ACM citations, References, Related Mitigations cross-links to SAFE-M-12 / SAFE-M-18 / SAFE-M-11 / SAFE-M-70 / SAFE-M-29. | bishnu bista |
