# SAFE-M-73: Sampling Budget and Iteration Caps

## Overview
**Mitigation ID**: SAFE-M-73  
**Category**: Preventive Control  
**Effectiveness**: High  
**Implementation Complexity**: Low  
**First Published**: 2026-04-14

## Description
Sampling Budget and Iteration Caps enforces hard, client-side limits on how much nested model work an MCP server can trigger through `sampling/createMessage` during a single user-intent flow or session. Limits cover per-request `maxTokens`, per-session cumulative sampling token spend, total count of sampling requests per user task, and maximum tool-loop iterations for tool-enabled sampling. The caps are enforced by the client runtime before the request is forwarded to the configured language model, independent of any policy the server requests in the sampling payload.

MCP's sampling primitive allows servers to issue nested LLM calls through the client without holding provider API keys, and the protocol explicitly notes that "Clients **SHOULD** implement rate limiting" and "Both parties **SHOULD** implement iteration limits for tool loops" ([MCP Specification — Client: Sampling](https://modelcontextprotocol.io/specification/2025-11-25/client/sampling)). Without concrete client-enforced budgets, a malicious or compromised server can issue oversized or repeated sampling requests to drain user quota, bias subsequent reasoning, or drive tool-loop exhaustion while the user-visible output remains small.

## Mitigates
- [SAFE-T1112](../../techniques/SAFE-T1112/README.md): Sampling Request Abuse — caps on `maxTokens`, sampling request count, and tool-loop iterations directly bound the quota-bleed, conversation-carryover, and tool-enabled-pivot variants

## Technical Implementation

### Core Principles

1. **Client enforces, not server**: The client runtime holds the authoritative budget counters; the server cannot negotiate past them by including larger `maxTokens` in the request.
2. **Per-intent scoping**: Budgets reset on a per-user-intent basis (typically one user prompt or one approved task), not per-process, so a long-running session cannot be drained by a single intent.
3. **Distinct tiers for tool-enabled sampling**: Tool-enabled sampling (client declares `sampling.tools` capability) uses stricter iteration caps than text-only sampling because each loop iteration can trigger follow-on actions.
4. **Fail-closed**: When a cap is hit, the client rejects the sampling request with a distinct error code and surfaces the reason to the user, rather than silently truncating.

### Architecture Components

```
         +------------------+
 Server ─┤ sampling request ├──► Client runtime
         +------------------+            │
                                         ▼
                            +---------------------------+
                            │  Sampling Budget Enforcer │
                            │  ─────────────────────── │
                            │  • Per-server cap profile│
                            │  • Per-intent counters   │
                            │  • Per-session counters  │
                            │  • Tool-loop iteration   │
                            │    counter (per request) │
                            +---------------------------+
                                         │
                            cap breach?  │
                              ┌──────────┴──────────┐
                             yes                   no
                              │                     │
                              ▼                     ▼
                   JSON-RPC error to server   forward to model
                   + structured log record    + accumulate usage
                   + user-visible warning
```

Components:
- **Per-server cap profile**: configured defaults + per-server overrides.
- **Counter store**: short-lived in-memory counters keyed by (session_id, intent_id, server_id).
- **Budget enforcer**: middleware that sits between the server's `sampling/createMessage` request and the client's model-forwarding path.
- **Logger**: structured emitter for cap breaches, consumed by [SAFE-M-12](../SAFE-M-12/README.md) Audit Logging and [SAFE-M-11](../SAFE-M-11/README.md) Behavioral Monitoring.
- **User notifier**: surfaces cap breaches with provenance via [SAFE-M-15](../SAFE-M-15/README.md) User Warning Systems.

### Recommended Default Caps

These defaults are starting points; clients should tune them per deployment and per-server trust tier.

| Limit | Default | Notes |
|---|---|---|
| `maxTokens` per request | 2,000 | Most summarization and analysis tasks fit well under this. |
| Sampling requests per user intent | 3 | A single user task should not need many nested model calls. |
| Cumulative `maxTokens` per session | 20,000 | Hard ceiling across all sampling in a session. |
| Tool-loop iterations per sampling request | 3 | Aligns with the MCP spec's guidance that "Both parties **SHOULD** implement iteration limits for tool loops". |
| Tool-enabled sampling requests per session | 5 | Separate, lower ceiling than text-only. |

### Prerequisites
- Client runtime exposes hooks for pre-forwarding sampling requests to the model (to enforce per-request caps) and post-response hooks (to accumulate usage).
- Per-server trust configuration so caps can be tightened for untrusted or new servers.

### Implementation Steps

1. **Design Phase**:
   - Define the budget accounting units (tokens, request count, loop iterations) your client will track.
   - Decide cap scope: per-intent vs. per-session vs. per-server-profile.
   - Choose error semantics for cap breaches (typically a JSON-RPC error with a distinct `code` and a human-readable `message`).

2. **Development Phase**:
   - In the client's sampling handler, intercept every `sampling/createMessage` request before forwarding to the model.
   - Check the request's `maxTokens` against the per-request cap; reject if exceeded.
   - Increment per-intent and per-session counters; reject if the request would push a counter past its cap.
   - For tool-enabled sampling, track the tool-loop iteration count within a single `sampling/createMessage` exchange (each follow-up request from the server with tool results counts as one iteration); reject any follow-up request that would exceed the iteration cap with a distinct JSON-RPC error code, consistent with the fail-closed model. Do not rewrite the server's `toolChoice` field — `toolChoice: {mode: "none"}` is a separate server-side convention the spec describes for servers that self-cap, not a client enforcement mechanism.
   - Surface cap breaches to the user with provenance (which server, which cap, what it tried to do).

3. **Deployment Phase**:
   - Ship with conservative defaults; allow operators to relax per trusted server profile.
   - Log every cap breach with server ID, cap name, and user intent correlation ID.
   - Monitor cap-breach rates per server as an input to [SAFE-M-11](../SAFE-M-11/README.md) (Behavioral Monitoring).

## Benefits
- **Direct bound on quota drain**: A server that emits oversized sampling cannot consume more than one `maxTokens` cap per request or one session cap per session.
- **Upper bound on tool-loop exhaustion**: Tool-enabled sampling cannot infinite-loop through the client; the iteration cap forces termination.
- **Simple to implement and audit**: Numeric thresholds and counters — no ML or heuristics required to enforce.

## Limitations
- **Does not detect subtle bias**: Within-budget malicious sampling (e.g., a single well-crafted prompt that biases later reasoning) is unaffected; pair with [SAFE-M-21](../SAFE-M-21/README.md) (Output Context Isolation) and [SAFE-M-11](../SAFE-M-11/README.md) (Behavioral Monitoring).
- **Legitimate long-running workflows may hit caps**: Operators must tune per-server profiles for trusted long-running assistants. Fail-closed with clear user messaging is essential to avoid confusing silent degradation.
- **Per-intent boundaries require user-task semantics**: Clients without a notion of "current user intent" must fall back to per-session caps only, which are less precise.

## Implementation Examples

### Example: Client-side cap enforcement (pseudocode)

```python
class SamplingBudget:
    def __init__(self, caps):
        self.caps = caps  # dict of cap name -> int
        self.intent_tokens = 0
        self.intent_requests = 0
        self.session_tokens = 0
        self.session_tool_requests = 0

    def check_and_account(self, request, server_id, is_tool_enabled):
        max_tokens = request["params"].get("maxTokens", 0)

        if max_tokens > self.caps["max_tokens_per_request"]:
            raise SamplingCapExceeded("max_tokens_per_request", server_id, max_tokens)

        if self.intent_requests + 1 > self.caps["requests_per_intent"]:
            raise SamplingCapExceeded("requests_per_intent", server_id)

        if self.session_tokens + max_tokens > self.caps["session_tokens"]:
            raise SamplingCapExceeded("session_tokens", server_id)

        if is_tool_enabled and self.session_tool_requests + 1 > self.caps["tool_requests_per_session"]:
            raise SamplingCapExceeded("tool_requests_per_session", server_id)

        self.intent_requests += 1
        self.session_tokens += max_tokens
        if is_tool_enabled:
            self.session_tool_requests += 1
```

### Example: Per-server cap profile (configuration)

```json
{
  "default_caps": {
    "max_tokens_per_request": 2000,
    "requests_per_intent": 3,
    "session_tokens": 20000,
    "tool_loop_iterations_per_request": 3,
    "tool_requests_per_session": 5
  },
  "per_server_overrides": {
    "trusted.example.com": {
      "session_tokens": 80000,
      "tool_requests_per_session": 20
    }
  }
}
```

## Testing and Validation
1. **Security Testing**:
   - Simulate a server that requests `maxTokens: 100000` — confirm the client rejects without forwarding.
   - Simulate a burst of 10 sampling requests in one user intent — confirm the 4th is rejected.
   - Simulate a tool-loop of 10 follow-up sampling requests — confirm the client rejects the 4th follow-up (when the cap is 3) with a distinct JSON-RPC error code and does not forward it to the model.
2. **Functional Testing**:
   - Confirm a legitimate 1-request / 1500-token sampling flow completes unaffected.
   - Verify per-server override relaxation works for a configured trusted server.
3. **Integration Testing**:
   - Exercise the budget enforcer against a real MCP client with multiple connected servers and confirm counters are scoped per-server (a greedy server's counters do not bleed into a trusted server's quota).
   - Verify that cap-breach log events are consumed correctly by downstream Behavioral Monitoring and Audit Logging pipelines (SAFE-M-11, SAFE-M-12).
   - Confirm user-notification handoff to the configured User Warning Systems path (SAFE-M-15) on a cap breach.
4. **Observability**:
   - Every cap breach produces a structured log entry with server ID, cap name, attempted value, and user intent correlation ID.

## Deployment Considerations

### Resource Requirements
- **CPU**: Negligible. The enforcer runs a constant-time check per `sampling/createMessage`; overhead dominated by JSON parsing the client already performs.
- **Memory**: Counters are ~tens of bytes per active (session, intent, server) tuple. For a client with 100 concurrent sessions and 5 servers each, <100 KB.
- **Storage**: No persistent storage required for counters (in-memory per session). Cap-breach logs are append-only and size-bounded by log retention policy already in place for SAFE-M-12.
- **Network**: None — entirely client-local enforcement.

### Performance Impact
- **Latency**: Sub-millisecond per request in the common path (counter check + integer comparison). No additional network round-trip.
- **Throughput**: Unaffected at typical sampling volumes; the enforcer is not a serialization point because counters are per-session.
- **Resource Usage**: Linear in concurrent sessions; negligible in practice.

### Monitoring and Alerting
- Metric: cap-breach count per server per hour.
- Metric: sampling token spend per session (distribution) to tune caps without over-restricting legitimate use.
- Alert: any server with repeated breaches of the `requests_per_intent` cap within a short window.

## References
- [MCP Specification — Client: Sampling (2025-11-25)](https://modelcontextprotocol.io/specification/2025-11-25/client/sampling) — "Clients **SHOULD** implement rate limiting" and "Both parties **SHOULD** implement iteration limits for tool loops"
- [New Prompt Injection Attack Vectors Through MCP Sampling — Unit 42, December 2025](https://unit42.paloaltonetworks.com/model-context-protocol-attack-vectors/)

## Related Mitigations
- [SAFE-M-11](../SAFE-M-11/README.md): Behavioral Monitoring — consumes cap-breach logs to identify abusive servers
- [SAFE-M-12](../SAFE-M-12/README.md): Audit Logging — records each sampling request and the budget counters at decision time
- [SAFE-M-15](../SAFE-M-15/README.md): User Warning Systems — surfaces cap breaches to the user with provenance
- [SAFE-M-21](../SAFE-M-21/README.md): Output Context Isolation — complements caps by bounding the influence of any output that did get through
- [SAFE-M-29](../SAFE-M-29/README.md): Explicit Privilege Boundaries — per-server profiles for cap overrides align with per-server privilege tiers

## Version History
| Version | Date | Changes | Author |
|---------|------|---------|--------|
| 1.0 | 2026-04-14 | Initial documentation for sampling-specific budget and iteration caps | bishnu bista |
