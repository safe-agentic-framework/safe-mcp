# SAFE-M-12: Audit Logging

## Overview
**Mitigation ID**: SAFE-M-12  
**Category**: Detective Control  
**Effectiveness**: Medium-High  
**Implementation Complexity**: Low-Medium  
**First Published**: 2025-01-03

## Description
Audit Logging is the structured-event substrate that records every tool description loaded into an MCP host, every tool invocation dispatched through it, every authentication event, every server-presence change, and the prompt provenance and downstream consequence of each LLM-driven action. Its job is not to *detect* attacks in real time — that is what M-11 *Behavioral Monitoring* and M-70 *Tool-Invocation Anomaly Detection & Baselining* do — but to *preserve the evidence trail* those detective controls consume, plus the trail forensic investigators rely on after an incident.

In an MCP deployment, the audit-logging layer sits between the host's tool dispatcher and the MCP server it is calling, and between the agent's reasoning step and the LLM provider. Capturing structured events at those junctions defends against the most common MCP attack patterns: poisoned tool descriptions (SAFE-T1001) become detectable when their content hash is logged on every load and version shift; rug-pull substitutions (SAFE-T1201) surface when the previous-vs-current hash differs; coercion attempts (SAFE-T1309) are reconstructable from the preceding-turn lineage; database-dump exfiltration (SAFE-T1803) is correlatable when MCP tool logs are joined to downstream DB and warehouse audit logs; and the impact of LLM-output-driven downstream actions (SAFE-T1904 / SAFE-T2105) is traceable from generation through consumer action via explicit `downstream_actions` events. A two-tier architecture — a broadly-accessible SIEM metadata stream plus a restricted-access raw-payload archive retained selectively under policy — keeps the detective surface useful without spraying sensitive payloads broadly.

## Mitigates
The mitigation directly addresses the following techniques (curated against citing-technique expectations rather than mirroring raw grep output):

- [SAFE-T1001](../../techniques/SAFE-T1001/README.md): Tool Poisoning Attack (TPA) — captures the full tool-description load event with content hash, enabling poisoned-description detection on subsequent loads.
- [SAFE-T1112](../../techniques/SAFE-T1112/README.md): Sampling Request Abuse — logs sampling requests, approval decisions, requested tools, follow-on actions, and provider cost/token metadata.
- [SAFE-T1201](../../techniques/SAFE-T1201/README.md): MCP Rug Pull Attack — captures `previous_sha256` alongside the current hash so version-shift attacks are detectable on each load.
- [SAFE-T1202](../../techniques/SAFE-T1202/README.md): OAuth Token Persistence — captures OAuth token operations (issue, refresh, revoke, use), device fingerprint, and auth-event correlation across services.
- [SAFE-T1302](../../techniques/SAFE-T1302/README.md): High-Privilege Tool Abuse — captures effective runtime identity (`effective_uid`, `service_account`, `container_id`, `process_args`) so privilege escalation is distinguishable from legitimate elevated invocation.
- [SAFE-T1303](../../techniques/SAFE-T1303/README.md): Container Sandbox Escape via Runtime Exec — captures `cwd` and `mounts` for every runtime invocation so sandbox escapes leave forensic evidence.
- [SAFE-T1309](../../techniques/SAFE-T1309/README.md): Privileged Tool Invocation via Prompt Manipulation — captures preceding-turn lineage and prompt provenance for coercion-context reconstruction.
- [SAFE-T1401](../../techniques/SAFE-T1401/README.md): Line Jumping — captures context-window structure (item ordering and source attribution) at decision time.
- [SAFE-T1407](../../techniques/SAFE-T1407/README.md): Server Proxy Masquerade — captures full TLS certificate chains and pinning verification results on every server connection.
- [SAFE-T1601](../../techniques/SAFE-T1601/README.md): MCP Server Enumeration — captures server-registered, server-deregistered, and server-probed events with rate metadata to baseline normal probing vs enumeration scanning.
- [SAFE-T1803](../../techniques/SAFE-T1803/README.md): Database Dump — captures correlation IDs that join MCP tool logs to downstream DB audit, warehouse export, and object-storage write logs.
- [SAFE-T1904](../../techniques/SAFE-T1904/README.md) / [SAFE-T2105](../../techniques/SAFE-T2105/README.md): Chat-Based Backchannel / Disinformation Output — captures `llm_output_ref`, `downstream_actions`, and optional `feedback_or_correction_ref` so the chain from generation to real-world consequence is reconstructable.

See also (additional techniques whose Mitigation Strategies reference SAFE-M-12 but whose specific expectations are subsumed by the schema above): tactical clusters around token misuse, behavioral baselining, output validation, and incident triage.

## Technical Implementation

### Core Principles

The audit-logging layer emits structured events at six functional categories. Every event carries the universal envelope: `session_id`, `tenant`, `user_id` (the logical principal — distinct from the runtime-identity `actor` block in Principle 3, which captures privilege/context for escalation analysis), `agent_id` (the LLM agent or service driving the call; `null` for human-direct events), `actor` (see Principle 3), `timestamp_utc`, `correlation_id`, `outcome` (`success` / `error` / `policy_violation`), and `archive_ref` (set in-event when raw-payload retention fires per the retention rule below; `null` otherwise).

1. **Tool-description and server-registration events** (T1001, T1201, T1601) — emit structured events for the full lifecycle of tool descriptions and MCP server presence:
   - `event_type="tool_description_loaded"` with `mcp_server`, `tool_name`, `tool_description_sha256`, `tool_description_version`, `loaded_at`, `previous_sha256` (for rug-pull detection per T1201).
   - `event_type="server_registered"` / `"server_deregistered"` / `"server_probed"` (T1601 enumeration detection) with `mcp_server`, `endpoint`, `actor`, `probe_attempt_count_window`, `result` (success / auth-failure / timeout). Probe events MUST include rate metadata so M-11 / M-70 can baseline normal probing vs scanning.
   - The tool-description body itself is captured to the restricted archive on first-load (`previous_sha256 == null`) and on version-shift (`previous_sha256 != tool_description_sha256`) events as a forensic-floor guarantee — T1001 / T1201 reviewers need the actual body to inspect for poisoning, not just a hash. Other load events (steady-state re-fetches with unchanged hash) follow operator-tunable retention.

2. **Tool-invocation events** (T1112; canonical input substrate for SAFE-M-70's per-entity baselining) — for every tool call: `event_type="tool_invocation"`, plus the universal envelope (`tenant`, `user_id`, `agent_id`, `session_id`, `actor`, `timestamp_utc`, `correlation_id`, `outcome`, `archive_ref`), plus `tool_name`, `mcp_server`, `request_metadata` (`args_size_bytes`; `args_field_tree` — a structure-only summary preserving key names, types, and nesting depth so SAFE-M-70 can compute argument-cardinality features without retaining raw values; `schema_validated`), `response_metadata` (`size_bytes`; `row_count` — present whenever the tool returns a row-shaped result, required for SAFE-M-70's bulk-export detection per SAFE-T1803; `status`; `latency_ms`; `tokens_in`; `tokens_out`), `destination` (the external sink the tool writes to or queries — e.g. `s3://...`, `bq://project.dataset.table`, `https://api.example.com/...`, or `null` for in-memory tools; required for SAFE-M-70's first-seen-destination rule), `approval` (granted / denied + by whom + via M-69 if used), `cost_estimate`. The `(tenant, user_id, agent_id, tool_name)` quadruple plus the metadata above is the documented input contract for [SAFE-M-70 Prerequisites](../SAFE-M-70/README.md#prerequisites) — schema changes here must remain compatible with that contract. Raw request/response bodies are captured to the restricted archive only when the retention policy says so.

3. **Effective runtime identity** (T1302, T1303) — every event carries an `actor` field of the form:

   ```json
   "actor": {
     "effective_uid": "1000",
     "service_account": "mcp-host-prod",
     "container_id": "...",
     "process_args": ["..."],
     "cwd": "/srv/mcp",
     "mounts": [{"src": "/data/db-export", "dst": "/mnt/export", "ro": false}]
   }
   ```

   This replaces vague labels like `"actor": "agent"`; the explicit fields are required for distinguishing legitimate elevated invocation from privilege escalation.

4. **Auth-event correlation** (T1202) — for OAuth and other auth-related events: `event_type="auth_operation"`, `op` (`issue` / `refresh` / `revoke` / `use`), `subject`, `device_fingerprint`, `geo_hint` (when available), `correlation_token`. Linked to tool-invocation events via `session_id` and `correlation_id` so a token-use event reaches its consequent tool calls.

5. **Prompt provenance, context structure, and downstream consumption** (T1309, T1401, T1904, T2105) — emitted at decision time and at consumption time:
   - `prompt_lineage = { user_turn_index, preceding_turns_hash_chain, system_prompt_id, context_window_summary }` (T1309 coercion reconstruction).
   - `context_structure = { items: [{source_type, source_id, position, length}] }` (T1401 context-window ordering).
   - `llm_output_ref = { generation_id, model, output_sha256, archive_ref }` — output content is referenced by hash; raw output goes to the restricted archive only when policy retains it (T1904 disinformation tracing).
   - `downstream_actions = [{ tool_name, action_id, triggered_by_generation_id, status }]` — captures the chain from generation to its consequence (T2105 impact tracing — was the LLM output acted on, where, with what result?).
   - `feedback_or_correction_ref` (optional) — links a downstream user or system correction or override back to the originating generation.

6. **Connection events** (T1407) — `event_type="server_connection"` with `endpoint`, `tls_cert_chain` (full chain — small, structured), `cert_pinning_result`, `connect_at`, `disconnect_at`, `bytes_sent`, `bytes_received`. Required for MITM detection per T1407.

### Architecture Components

```text
                    ┌────────────────────────────────────────────────────┐
                    │                    MCP Host                        │
  User Agent ─────► │                                                    │
                    │   Tool dispatcher  ───►  Audit-log emitter         │
                    │           │                  │     │               │
                    │           ▼                  │     │               │
                    │      MCP Server              │     │               │
                    └──────────┬───────────────────┘     │               │
                               │                          │               │
                  ┌────────────┴───────────────┐          │               │
                  │                            │          │               │
            ┌─────▼─────┐              ┌───────▼──────────▼─────┐         │
            │ Downstream│              │   SIEM / observability │         │
            │ system    │              │   (structured metadata,│         │
            │ logs      │              │   broad analyst access)│         │
            │ (DB audit,│              └────────────┬───────────┘         │
            │ warehouse,│                           │                     │
            │ object    │                           ▼                     │
            │ storage,  │              ┌────────────────────────┐         │
            │ network)  ◄──── join ────┤   Restricted raw-      │         │
            └───────────┘   on         │   payload archive      │         │
                            correlation│   (retained selectively│         │
                            IDs        │   per retention rule;  │         │
                                       │   write-once; access   │         │
                                       │   logged separately)   │         │
                                       └────────────────────────┘
```

The host emits every event to the SIEM stream. Raw payloads — tool description bodies, raw request/response, raw prompts, raw LLM outputs — are routed to the restricted archive **only when the retention rule says so**. Both destinations carry a shared `correlation_id` so analysts can move between them when authorized.

Downstream log sources to correlate against (per T1803): DB audit logs (`pg_audit`, MySQL audit, SQL Server Extended Events), warehouse export logs (BigQuery audit logs, Snowflake `query_history`, Redshift STL logs), object-storage write events (S3 / GCS / Azure Blob), and network flow logs.

### Retention Rule

Raw payloads are retained **selectively under policy**. The SIEM stream always carries the structured event with `archive_ref` set **in-event** to a real archive locator when retention fired (analysts reading the primary event must not need to wait for or join against a follow-up event for the link), or `null` when it did not. Within that selective-retention model, the following triggers form a **forensic floor** that always retains, regardless of operator-defined sampling:

- `event.outcome == error` — any tool-invocation that errored or timed out
- `event.outcome == policy_violation` — a redaction policy, M-69 OOB-auth denial, or schema-validation failure fired
- `event.security_tag == true` — session or invocation explicitly marked for elevated retention by an operator or detection rule
- `event_type == "tool_description_loaded"` AND `previous_sha256 == null` — first-load of a tool description (T1001 surface; reviewers need the body, not just a hash)
- `event_type == "tool_description_loaded"` AND `previous_sha256 != tool_description_sha256` — version-shift of a tool description (T1201 rug-pull surface; reviewers need the new body alongside the old one)

Beyond these mandatory triggers, retention is operator-tunable per data-classification policy: sampled fraction, per-tool-sensitivity overrides, or custom triggers are all valid additions. The forensic-floor triggers cannot be opted out — they are the minimum guarantee the rest of the corpus's detective controls assume.

### Prerequisites

- A structured-log-capable MCP host (JSON output or OpenTelemetry trace events).
- A SIEM or log pipeline supporting WORM or append-only writes for the metadata stream.
- A separate restricted-access bucket or object store for the raw-payload archive, with its own IAM scope.
- A redaction policy (which fields are tokenized, hashed, dropped, or retained) maintained as code and version-controlled alongside the host instrumentation.
- An access-logging layer for the raw-payload archive itself, so reads against retained payloads are themselves auditable.

### Implementation Steps

1. **Design Phase**:
   - Define the structured event schema (fields per Core Principle, plus the universal `session_id` / `actor` / `correlation_id` envelope).
   - Define the redaction policy: which fields are sent to the SIEM stream, which are tokenized or hashed, and which trigger raw retention. Express this as code, not prose.
   - Define retention TTL, access-control scope, and break-glass procedure for the restricted archive.

2. **Development Phase**:
   - Instrument the MCP host's tool dispatcher to emit `tool_description_loaded`, `tool_invocation`, `server_registered` / `_deregistered` / `_probed`, and `server_connection` events at the canonical junctions.
   - Instrument the agent's prompt construction and response consumption paths to emit `prompt_lineage`, `context_structure`, `llm_output_ref`, and `downstream_actions` events.
   - Implement the two-tier emit: every event flows to the SIEM stream synchronously (or near-synchronously); raw payloads are routed to the restricted archive only when the policy classifier fires retention.
   - Implement the forensic-floor classifier: errors, policy violations, security-tagged sessions, and tool-description first-load / version-shift events force retention even when operator-tunable sampling would not.

3. **Deployment Phase**:
   - Roll out in **observe-only** mode first (events emit but no downstream consumers alarm) and validate that redaction is firing correctly before opening SIEM access to broad analyst groups.
   - Wire the SIEM correlation views that join MCP tool-invocation events to downstream DB audit, warehouse, and object-storage logs.
   - Enable the M-11 / M-70 baselining consumers on the SIEM stream once the schema is stable.
   - Treat redaction-policy changes as a deploy event in their own right; alarm on policy version skew between MCP hosts and the policy store.

## Benefits

- **Forensic reconstruction**: every tool description loaded, every tool call dispatched, every approval, every connection, every LLM-output-driven downstream action is reconstructable from the event stream and (when retained) the raw archive.
- **Compliance evidence**: events map to common compliance log-management requirements (SOC 2 CC7.2, ISO 27001 A.12.4, HIPAA §164.312(b)).
- **Enables adjacent detective controls**: M-11 *Behavioral Monitoring* and M-70 *Tool-Invocation Anomaly Detection & Baselining* both consume the M-12 event stream as their detection substrate; without M-12 they have no signal to baseline against.
- **Captures M-69 audit trail**: M-69 *Out-of-Band Authorization for Privileged Tool Invocations* explicitly emits structured grant / deny / timeout / revocation events; M-12 is the destination that preserves them.
- **Deters insider abuse**: visible, tamper-evident audit logging is itself a deterrent against intentional misuse, separately from its detective value.

## Limitations

- **Log volume can be substantial.** Full prompts, full responses, full tool descriptions, and full LLM outputs are individually KB to MB; storing every body categorically would dwarf the SIEM tier. The two-tier design partially mitigates by keeping the SIEM stream metadata-only and routing raw bodies to the restricted archive only when policy fires.
- **Restricted-archive disclosure risk.** Raw payloads in the archive carry residual disclosure risk if access controls fail or are misconfigured. Pair with M-72 *Data Loss Prevention on Tool Outputs* for runtime sanitization at emit time, so that even retained payloads have known-sensitive fields redacted.
- **Detection, not prevention.** Logs reveal misuse after the fact. For high-risk privileged calls, pair with M-69 *Out-of-Band Authorization for Privileged Tool Invocations* so the call itself requires explicit approval before dispatch.
- **MCP-layer coverage only.** Tools called outside the MCP layer (e.g., direct API calls bypassing the host) are blind spots. Defense-in-depth requires complementary network-flow logging.
- **Identity is only as trustworthy as its source.** M-12 captures `effective_uid`, `service_account`, and OAuth subject claims, but it does not itself verify them. Pair with M-13 *OAuth Flow Verification* (or an equivalent identity-binding mitigation) for a trustworthy `actor` field.
- **Correlation requires schema discipline.** The `session_id`, `correlation_id`, and `generation_id` fields must be consistently propagated through every layer (MCP host, MCP server, downstream system) for the join to work. Schema drift across versions breaks correlation silently.

## Implementation Examples

### Example 1: Tool-invocation event with redaction baseline (Python)

```python
import hashlib, json, time, uuid

def emit_tool_invocation(host_ctx, tool_call, response, approval, classifier):
    correlation_id = str(uuid.uuid4())
    event = {
        "event_type": "tool_invocation",
        # Universal envelope
        "session_id":     host_ctx.session_id,
        "tenant":         host_ctx.tenant,
        "user_id":        host_ctx.user_id,           # logical principal
        "agent_id":       host_ctx.agent_id,          # null for human-direct
        "actor":          host_ctx.runtime_identity(),  # runtime identity, see Principle 3
        "timestamp_utc":  time.time(),
        "correlation_id": correlation_id,
        "outcome":        response.outcome,           # "success" | "error" | "policy_violation"
        "archive_ref":    None,                       # set below if retention fires
        # Event-specific fields (also the SAFE-M-70 input contract)
        "tool_name":      tool_call.name,
        "mcp_server":     tool_call.server,
        "request_metadata": {
            "args_size_bytes": len(json.dumps(tool_call.args)),
            "args_field_tree": classifier.field_tree(tool_call.args),  # structure only — no raw values
            "schema_validated": True,
        },
        "response_metadata": {
            "size_bytes":  len(response.body or b""),
            "row_count":   response.row_count,        # required for SAFE-M-70 bulk-export detection (T1803)
            "status":      response.status,
            "latency_ms":  response.latency_ms,
            "tokens_in":   response.tokens_in,
            "tokens_out":  response.tokens_out,
        },
        "destination":    response.destination,       # e.g. "s3://...", "bq://...", or None
        "approval": {
            "granted":       approval.granted,
            "decided_by":    approval.decided_by,
            "via_safe_m_69": approval.via_oob_auth,
        },
        "cost_estimate":  response.cost_estimate,
        "security_tag":   host_ctx.security_tag,
    }

    # Restricted archive first (when retention policy says so), so the primary
    # SIEM event carries archive_ref in-band — no follow-up event to join against.
    if classifier.should_retain_raw(event, tool_call, response):
        event["archive_ref"] = restricted_archive.write(
            payload={"args": tool_call.args, "response_body": response.body},
            session_id=host_ctx.session_id,
            correlation_id=correlation_id,
        )

    # SIEM tier: emit the complete metadata event (with archive_ref already attached if set).
    siem.emit(event)
```

The `classifier.should_retain_raw` enforces the retention rule. Errors, policy violations, security-tagged sessions, and `tool_description_loaded` events with `previous_sha256 == null` (first-load) or `previous_sha256 != tool_description_sha256` (version-shift) short-circuit it to `True` regardless of operator sampling. Production code should also define an explicit fail-mode for `restricted_archive.write` failures (fail-closed: drop the SIEM event and alert; fail-open: emit with `archive_ref=null` and a `retention_failure=true` tag) — the example above does not specify one and would silently fail-closed by raising.

### Example 2: Tool-description load event

```json
{
  "event_type": "tool_description_loaded",
  "session_id": "s-2026-04-30-hgz",
  "tenant": "acme-prod",
  "user_id": "svc-mcp-host",
  "agent_id": null,
  "correlation_id": "c-7f3a-...",
  "timestamp_utc": 1714435200,
  "mcp_server": "github-mcp-prod",
  "tool_name": "create_pull_request",
  "tool_description_sha256": "9f2a3b...",
  "tool_description_version": "v3.2.1",
  "previous_sha256": "1c8e4d...",
  "actor": { "effective_uid": "1000", "service_account": "mcp-host-prod", "container_id": "..." },
  "outcome": "success",
  "archive_ref": "s3://mcp-rawpayload/2026/04/30/c-7f3a-..."
}
```

The body of the tool description itself is at `archive_ref`, mandatorily retained because `previous_sha256 != tool_description_sha256` matches the version-shift forensic-floor trigger (T1201 rug-pull surface). First-load events (`previous_sha256 == null`) trigger the same floor (T1001 surface).

### Example 3: Redacted prompt-lineage event for T1309 coercion reconstruction

```json
{
  "event_type": "prompt_lineage",
  "session_id": "s-2026-04-30-hgz",
  "tenant": "acme-prod",
  "user_id": "alice@acme.example",
  "agent_id": "research-assistant-v3",
  "correlation_id": "c-2b8f-...",
  "timestamp_utc": 1714435210,
  "user_turn_index": 7,
  "preceding_turns_hash_chain": ["a1b2...", "c3d4...", "e5f6..."],
  "system_prompt_id": "sys-prompt-v4.0",
  "context_window_summary": "6512 tokens across 4 items (system_prompt, user_turn x2, tool_response)",
  "context_structure": {
    "items": [
      {"source_type": "system_prompt", "source_id": "sys-prompt-v4.0", "position": 0, "length": 1024},
      {"source_type": "user_turn", "source_id": "turn-1", "position": 1024, "length": 412},
      {"source_type": "tool_response", "source_id": "github.fetch_issue", "position": 1436, "length": 2048},
      {"source_type": "user_turn", "source_id": "turn-7", "position": 6100, "length": 412}
    ]
  },
  "actor": { "effective_uid": "1000", "service_account": "mcp-host-prod" },
  "outcome": "success",
  "archive_ref": null
}
```

Note: full prompt text is *not* included in the SIEM event. The `preceding_turns_hash_chain` enables tamper-evident reconstruction (an analyst with archive access can fetch the bodies for hashes that match), and the `context_structure` lets M-11 detect anomalous source ordering without the SIEM tier carrying every prompt verbatim. `archive_ref` is `null` here because no retention trigger fired; if a downstream tool call from `turn-7` hits an error or policy_violation, the forensic floor will retain the lineage at that point.

### Example 4: SIEM ingest config (OpenTelemetry collector + dual destination)

```yaml
exporters:
  otlphttp/siem:
    endpoint: https://siem.internal/v1/traces
    headers:
      authorization: ${SIEM_HEC_TOKEN}
    sending_queue:
      enabled: true
      queue_size: 5000
  awss3/restricted_archive:
    s3uploader:
      region: us-east-1
      s3_bucket: mcp-rawpayload-restricted   # IAM scoped to forensics group only
      s3_prefix: "raw/"
    timeout: 30s

processors:
  filter/redact:
    traces:
      span:
        - 'attributes["event_type"] == "tool_invocation"'
        - 'attributes["archive_ref"] != nil'
    # Redaction is enforced via the host-side classifier, not here. This filter
    # only routes spans that already carry archive_ref to the restricted bucket.

service:
  pipelines:
    traces/siem_metadata:
      receivers: [otlp]
      exporters: [otlphttp/siem]
    traces/restricted_archive:
      receivers: [otlp]
      processors: [filter/redact]
      exporters: [awss3/restricted_archive]
```

The two pipelines have **different IAM scopes**: the SIEM pipeline runs under a broad-access analyst role; the restricted archive runs under a forensics-only role with a separate audit log on its own access events.

## Testing and Validation

1. **Security Testing**:
   - Replay a known-poisoned tool description (per T1001) against the host and verify the `tool_description_loaded` event captures the full content hash and the body lands in the restricted archive on first-load retention.
   - Simulate a rug-pull (T1201) by changing a server's tool description; verify `previous_sha256 != tool_description_sha256` and that an alarm fires in M-11 / M-70 consumers downstream.
   - Trigger a TLS certificate change (T1407) on a known-good MCP server; verify the `server_connection` event captures the full chain and `cert_pinning_result == "fail"` fires retention.
   - Attempt to tamper with the SIEM stream (delete an event, modify a hash); verify the WORM/append-only protection blocks it and the access-log records the attempt.

2. **Functional Testing**:
   - Generate realistic load (1k tool invocations / minute) and verify SIEM ingest latency stays under target (e.g., p95 < 5 seconds).
   - Verify redaction correctness: emit synthetic events containing known-secret strings (test API tokens, fake PII) and assert they do *not* appear in the SIEM stream and *do* appear (encrypted) in the restricted archive.
   - Verify the forensic-floor: with sampling set to 0%, emit synthetic `error` and `policy_violation` events plus a `tool_description_loaded` event with `previous_sha256 == null` (first-load) and another with `previous_sha256 != tool_description_sha256` (version-shift); assert raw-payload retention still fires for all four cases.

3. **Integration Testing**:
   - End-to-end trace: fire a database-export tool call (T1803) through the host, query the SIEM for the `tool_invocation` event, and verify the `correlation_id` joins to a corresponding `pg_audit` row in the DB log and an S3 `PutObject` event in the bucket log.
   - Cross-tier consistency: pull a `correlation_id` from the SIEM stream, locate the matching raw payload in the restricted archive (when retained), verify the access itself is logged.

## Deployment Considerations

### Resource Requirements
- **CPU**: minor — synchronous event emit adds 1-5ms per tool call; async batching reduces this to <1ms with a bounded loss-on-crash window.
- **Memory**: per-host event buffer ~50MB at default batch sizes.
- **Storage**: SIEM stream is moderate (KB per invocation, growing with `context_structure` summaries). Restricted archive is heavy (full bodies); plan storage and retention TTLs per data-classification policy.
- **Network**: SIEM ingest bandwidth scales with invocation rate. Plan for the 95th-percentile burst, not the average.

### Performance Impact
- **Latency**: 1-5ms synchronous emit; <1ms with async batching. The two-tier design adds no extra cost on the SIEM tier (everything flows there); raw-archive writes are async and don't block the tool dispatch.
- **Throughput**: well-instrumented hosts have shipped thousands of events per second per worker without tool-call regression.
- **Resource Usage**: SIEM and archive storage costs are the dominant ongoing line item.

### Monitoring and Alerting
- **Pipeline gaps**: alarm on no events from a previously-active host for > N minutes.
- **SIEM ingest failures**: alarm on rejected-event rates > target.
- **Retention-policy version skew**: alarm if MCP host's policy version differs from the policy store's published version.
- **Restricted-archive access anomalies**: alarm on unusual read patterns against the raw archive (M-12 protects the audit trail; the audit trail itself must be audited).
- **Forensic-floor regression**: alarm if any forensic-floor event lands with `archive_ref == null` — `outcome == error`, `outcome == policy_violation`, `security_tag == true`, or `tool_description_loaded` with first-load (`previous_sha256 == null`) or version-shift (`previous_sha256 != tool_description_sha256`) state.

## Current Status (2026)

Tamper-evident logging guidance for general systems is well-established ([NIST SP 800-92 §5](https://csrc.nist.gov/publications/detail/sp/800-92/final)).

## References

- [NIST SP 800-92: Guide to Computer Security Log Management](https://csrc.nist.gov/publications/detail/sp/800-92/final)
- [OWASP Logging Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html)
- [MITRE ATT&CK T1562.008 — Impair Defenses: Disable or Modify Cloud Logs](https://attack.mitre.org/techniques/T1562/008/) — adversary techniques against audit logging that this mitigation defends against.
- [CIS Critical Security Controls v8 — Control 8: Audit Log Management](https://www.cisecurity.org/controls/audit-log-management) — operational guidance on audit log generation, storage, retention, and review.
- [OpenTelemetry Tracing Specification](https://opentelemetry.io/docs/specs/otel/trace/) — recommended structured-event substrate for the SIEM tier described in Architecture Components.
- [Model Context Protocol Specification](https://modelcontextprotocol.io/specification) — the protocol layer at which most M-12 events are emitted.

## Related Mitigations

- [SAFE-M-11](../SAFE-M-11/README.md): Behavioral Monitoring — consumes the M-12 event stream as its real-time pattern-detection substrate. M-11 detects; M-12 retains. M-11 is impossible without M-12.
- [SAFE-M-70](../SAFE-M-70/README.md): Detective Control - Tool-Invocation Anomaly Detection & Baselining — sits above M-12 as the baselining and alerting layer; baselines normal tool-invocation rates, payload sizes, and destinations against the M-12 stream.
- [SAFE-M-69](../SAFE-M-69/README.md): Out-of-Band Authorization for Privileged Tool Invocations — emits structured grant / deny / timeout / revocation events that M-12 preserves; the audit trail of M-69 decisions lives in M-12. Strong, concrete relation.
- [SAFE-M-22](../SAFE-M-22/README.md): Semantic Output Validation — flags content; M-12 preserves the flagged content, the decision, and the actor. Pair so that flag decisions are recoverable for incident review.
- [SAFE-M-72](../SAFE-M-72/README.md): Data Security — Data Loss Prevention on Tool Outputs — runtime sanitization at emit time complements M-12's at-rest redaction policy. Pair so that retained raw payloads in the M-12 archive have known-sensitive fields already removed by M-72 before they land.

## Version History
| Version | Date | Changes | Author |
|---------|------|---------|--------|
| 0.1 | 2025-01-03 | Initial stub | Frederick Kautz |
| 1.0 | 2026-04-30 | Expanded stub to template parity per corpus mitigation quality audit; authored Technical Implementation (6 Core Principles tied to citing-technique expectations T1001/T1112/T1201/T1202/T1302/T1303/T1309/T1401/T1407/T1601/T1803/T1904/T2105), Architecture Components, Retention Rule with forensic-floor triggers, Benefits, Limitations, Implementation Examples (4, including redacted-event examples), Testing and Validation, Deployment Considerations, Current Status, References, Related Mitigations sections; curated Mitigates list (13 IDs across 12 entries); excluded T1305 (misdirected citation — separate follow-up PR) and T1408 (stale post-PR-#200) | bishnu bista |
| 1.1 | 2026-05-03 | Aligned `tool_invocation` schema with the documented [SAFE-M-70 input contract](../SAFE-M-70/README.md#prerequisites): added `tenant`, `user_id`, `agent_id` to the universal envelope; replaced opaque `args_summary` with structured `args_field_tree` for SAFE-M-70 cardinality features; added `response_metadata.row_count` for SAFE-T1803 bulk-export detection; added top-level `destination` for first-seen-destination rule. Fixed `archive_ref` ordering in Example 1 — primary SIEM event now carries `archive_ref` in-band rather than as a follow-up `raw_archive_ref` event. Promoted tool-description first-load and version-shift to forensic-floor retention triggers (T1001 / T1201 reviewers need bodies, not just hashes); back-propagated to Implementation Steps, Functional Testing, Examples 2 and 3, post-Example 1 prose, and the Monitoring forensic-floor regression alarm. Documented an explicit fail-mode requirement for `restricted_archive.write` failures in production. | bishnu bista |
