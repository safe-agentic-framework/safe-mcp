# SAFE-M-1: Architectural Defense - Control/Data Flow Separation

## Overview
**Mitigation ID**: SAFE-M-1  
**Category**: Architectural Defense  
**Effectiveness**: High (Provable Security)  
**Implementation Complexity**: High  
**First Published**: 2025-01-03

## Description
Control/Data Flow Separation is an architectural defense that creates a protective system layer around LLMs by explicitly separating control flow (from trusted queries) from data flow (including untrusted tool descriptions). This approach ensures that malicious instructions embedded in data cannot influence program execution.

A notable implementation is CaMeL (Control and Memory Language), developed by researchers from Google and other institutions, which on the AgentDojo benchmark achieves **77% secure task completion under attack vs 84% for the undefended baseline** — a 7-percentage-point security/utility tradeoff with provable security guarantees over the threat model evaluated.

## Mitigates

The mitigation directly addresses the following techniques (curated against the actual citation graph; 4 mislabeled citers excluded — see Out of scope):

- [SAFE-T1001](../../techniques/SAFE-T1001/README.md): Tool Poisoning Attack (TPA) — separation prevents poisoned tool descriptions from being interpreted as control instructions; the malicious payload is confined to the data plane.
- [SAFE-T1008](../../techniques/SAFE-T1008/README.md): Stored Prompt Injection (Persistent Tool/Repo Storage) — persistent untrusted content cannot influence the control plane that selects subsequent operations.
- [SAFE-T1102](../../techniques/SAFE-T1102/README.md): Prompt Injection (Multiple Vectors) — direct, indirect, and reflected injection attempts land in the data plane; the control plane is sourced only from trusted queries.
- [SAFE-T1204](../../techniques/SAFE-T1204/README.md): Persistent Tool Redefinition — separation ensures that tool descriptions modified post-load cannot redefine control flow at invocation time.
- [SAFE-T1304](../../techniques/SAFE-T1304/README.md): High-Privilege Tool Misuse via Indirect Prompt Injection — CaMeL-style capability gating in the dispatch layer prevents data-plane content from minting privileged calls.
- [SAFE-T1309](../../techniques/SAFE-T1309/README.md): Privileged Tool Invocation via Prompt Manipulation — the control plane that selects which privileged tool to call is isolated from the prompt content delivered to the model.
- [SAFE-T1401](../../techniques/SAFE-T1401/README.md): Line Jumping — context-window items cannot escalate from data items into control directives because the parser only extracts control flow from trusted sources.
- [SAFE-T1502](../../techniques/SAFE-T1502/README.md): Persistence via Repository Implants — repository content lives in the data plane; persisted implants cannot mint control-plane state.
- [SAFE-T1705](../../techniques/SAFE-T1705/README.md): Cross-Server Tool Shadowing — separation enforces that tool-name resolution and dispatch happens in the control plane against an explicit trusted registry.
- [SAFE-T1801](../../techniques/SAFE-T1801/README.md): Tool/Resource Exfiltration via Indirect Prompt Injection — exfiltration attempts that ride on data-plane content cannot mint dispatch decisions for new exfil tool calls.
- [SAFE-T2105](../../techniques/SAFE-T2105/README.md): Disinformation Output — even when the LLM produces compromised output, downstream consumer actions are gated by control-plane decisions, not by the model output itself.

Four citers reference SAFE-M-1 with labels that don't match its actual concept (Control/Data Flow Separation) — they ask for different mitigations and are excluded from this list pending the `safe-m-1-mislabel-cluster` follow-up. See Out of scope for detail.

## Technical Implementation

### Core Principles
1. **Explicit Control Flow Extraction**: Parse and extract control flow from trusted sources only.
2. **Data Isolation**: Treat all external inputs (tool descriptions, API responses, retrieved memory, file content) as pure data with no executable semantics.
3. **Capability-Based Security**: Implement fine-grained, explicitly-issued capabilities for any privileged data access or flow operation. Capabilities are minted by control-plane authorities the model cannot impersonate; they bind to a specific tool, argument digest, subject, session, and expiry.

### Architecture Components
```
┌─────────────────┐
│  Trusted Query  │
└────────┬────────┘
         │
    ┌────▼─────┐
    │  Parser  │ ← Extracts control flow
    └────┬─────┘
         │
┌────────▼────────┐     ┌──────────────┐
│ Control Engine  │────►│ Data Handler │
│ (Protected)     │     │ (Sandboxed)  │
└────────┬────────┘     └──────────────┘
         │
    ┌────▼─────┐
    │   LLM    │
    └──────────┘
```

### Prerequisites
- A trusted query source / control-plane definition that explicitly declares the trusted set (e.g., system prompt, allowlisted user roles).
- A capability model that enumerates fine-grained permissions per data class.
- A parser/extractor that can reliably distinguish control-flow-relevant tokens from data-flow tokens in trusted inputs.
- A sandboxed data handler (process, container, or in-process capability boundary) where untrusted data lives.
- A dispatch layer that mediates between control engine and data handler with no leak of data into control flow.

### Implementation Steps
1. **Design Phase**:
   - Define trust boundaries — enumerate every input source and label it `trusted` (control-plane allowed) or `untrusted` (data-plane only).
   - Identify all data sources — tool descriptions, API responses, retrieved memory, file content, web fetches.
   - Design the capability model — per-data-class permissions, issuance authorities, binding fields, expiry policy.

2. **Development Phase**:
   - Implement the control flow parser against the trusted-source schema.
   - Create the data sandboxing layer (process / container / capability-boundary).
   - Build capability issuance and verification with replay protection.

3. **Deployment Phase**:
   - Configure the trust-boundary manifest and version it as code.
   - Set up monitoring for trust-boundary violations and capability-forgery attempts.
   - Train the operations team on the dispatch model and incident-response procedures.

## Benefits
- **Provable Security**: Mathematical guarantees against the prompt-injection class of attacks under the modeled threat surface — see the CaMeL paper for the specific guarantee statements.
- **Defense in Depth**: Works even if the underlying LLM is vulnerable to injection at the model level — the protection is architectural, not behavioral.
- **No Model Retraining**: Can be applied to existing LLMs without modifying model weights or fine-tuning data.

## Limitations
- **Performance Impact**: 7-percentage-point trade between secure task completion (77%) and undefended baseline (84%) on the AgentDojo benchmark per the CaMeL paper. The exact runtime overhead per tool call depends on capability-check granularity and parser implementation — published latency benchmarks are limited.
- **Complexity**: Requires significant architectural changes — a dispatch layer, capability issuance and verification, and a trust-boundary manifest. Not a configuration-only mitigation.
- **Not Universal**: Some agent task patterns (e.g., open-ended exploration over untrusted content) may be incompatible with strict separation; operators may need to opt-out specific workflows or design data-driven extension paths that respect the control/data split.

## Implementation Examples

### Example 1: Tool Call Protection
```python
# Traditional vulnerable approach
def execute_tool(tool_description, parameters):
    # Tool description can influence execution
    return llm.execute(f"{tool_description}\n{parameters}")

# CaMeL-style protected approach
def execute_tool_protected(tool_id, parameters):
    # Control flow predetermined, description is data only
    control_flow = trusted_registry.get_control_flow(tool_id)
    tool_data = untrusted_sources.get_tool_description(tool_id)
    
    # Description cannot alter execution path
    return protected_executor.run(
        control=control_flow,
        data={'description': tool_data, 'params': parameters}
    )
```

### Example 2: Host-bound capability grant for a privileged tool call

This example demonstrates one way to satisfy Core Principle 3 (Capability-Based Security) — a host-issued, replay-safe capability grant that the dispatch layer verifies before allowing a privileged tool call. CaMeL supports a capability concept; this code is *one* implementation pattern, not the canonical CaMeL implementation.

```python
# Host issues a capability grant; the model's data plane never holds or
# routes the granted token. Verification fails closed.

import hmac, hashlib, json, secrets, time
from typing import Mapping

# Capability granting authority — runs in the control plane, NOT model-callable.
class HostCapabilityIssuer:
    def __init__(self, signing_key: bytes):
        self._key = signing_key

    def issue(self, *, tool: str, args_digest: str, subject: str,
              session_id: str, ttl_seconds: int = 30) -> dict:
        """Issue a capability grant bound to a specific tool call."""
        claims = {
            "ver": 1,
            "tool": tool,
            "args_digest": args_digest,    # SHA-256 of the canonicalized arguments
            "subject": subject,             # service account / human approver
            "session_id": session_id,
            "exp": int(time.time()) + ttl_seconds,
            "jti": secrets.token_urlsafe(16),  # unique per grant; replay-protection key
        }
        payload = json.dumps(claims, sort_keys=True).encode()
        sig = hmac.new(self._key, payload, hashlib.sha256).hexdigest()
        # Return claims + signature; opaque to the data plane.
        return {"payload": payload.decode(), "signature": sig}

# Verifier — runs in the dispatch layer, between data plane and tool execution.
class HostCapabilityVerifier:
    def __init__(self, signing_key: bytes, jti_store):
        """jti_store must implement consume_once_or_raise(jti, exp) atomically.
        See note below — the in-memory `set` shown in tests is NOT
        concurrency-safe and must not be used in production."""
        self._key = signing_key
        self._jti_store = jti_store

    def verify(self, grant: Mapping, *, expected_tool: str,
               expected_args: dict, expected_subject: str,
               expected_session: str) -> None:
        """Verify a capability grant. Raises on any mismatch — fail closed."""
        # 1. Verify signature first; any field read before this is attacker-controllable.
        expected_sig = hmac.new(
            self._key, grant["payload"].encode(), hashlib.sha256
        ).hexdigest()
        if not hmac.compare_digest(expected_sig, grant["signature"]):
            raise PermissionError("capability signature invalid")

        # 2. Parse claims from the verified payload only.
        claims = json.loads(grant["payload"])
        if claims.get("ver") != 1:
            raise PermissionError("unsupported capability version")

        # 3. Expiry check before consume.
        if claims["exp"] < int(time.time()):
            raise PermissionError("capability expired")

        # 4. Bind to the actual call.
        if claims["tool"] != expected_tool:
            raise PermissionError("tool mismatch")
        if claims["session_id"] != expected_session:
            raise PermissionError("session mismatch")
        if claims["subject"] != expected_subject:
            raise PermissionError("subject mismatch")
        digest = hashlib.sha256(
            json.dumps(expected_args, sort_keys=True).encode()
        ).hexdigest()
        if not hmac.compare_digest(claims["args_digest"], digest):
            raise PermissionError("arguments do not match signed grant")

        # 5. Atomic consume-once. Implementation MUST be atomic (e.g. Redis
        # `SET NX EX`, a database unique-constraint INSERT, or a
        # transactional check-and-add). A non-atomic check-then-add
        # check on a Python `set` is NOT replay-safe under concurrency
        # — two concurrent verifies of the same grant can both pass.
        self._jti_store.consume_once_or_raise(claims["jti"], claims["exp"])
```

**Replay-store contract.** `jti_store.consume_once_or_raise(jti, exp)` MUST atomically (a) reject if `jti` is already recorded as consumed, (b) record `jti` as consumed with TTL = `exp`, and (c) raise `PermissionError("capability replay detected")` on rejection. Reference implementations: Redis `SET <jti> 1 NX EX <ttl>` returning `OK` on success or `nil` on duplicate; PostgreSQL `INSERT INTO consumed_jtis (jti, exp) VALUES (?, ?) ON CONFLICT DO NOTHING RETURNING jti` returning a row only on first insert. **Do not substitute a Python `set` outside unit tests** — the check-then-add pattern that sets allow is not atomic under concurrent verification and will let a captured grant be replayed.

**Argument-canonicalization contract.** `args_digest` is computed by both the issuer and the verifier from the *same* canonicalization routine (in this example, `json.dumps(args, sort_keys=True)`). Any divergence — different key ordering, different whitespace handling, different float-precision rules, different Unicode normalization — silently breaks binding. Issuer and verifier must share the canonicalization implementation (same library, same version) and add a contract test that round-trips representative argument shapes.

**Critical design constraints** that distinguish this from a vulnerable bearer-token pattern:

- The grant is **issued by a host authority the model cannot impersonate** — `HostCapabilityIssuer` runs in the control plane and is not exposed to the data plane (not callable by the LLM, not present in tool-call output paths).
- The grant **binds to (tool, args_digest, subject, session_id, expiry)** — a model that captures a grant for one call cannot replay it for a different tool, different arguments, a different session, or after expiry. The unique `jti` per grant is the replay-protection primitive; the verifier must consume it via an atomic store (see Replay-store contract above).
- Verification **fails closed** on every mismatch and validates the signature *before* reading any other claim.
- **Replay protection** via `jti` consume-once.
- **No token material is routed back through the LLM context** — the grant flows through dispatch infrastructure; the model never sees, returns, or echoes the grant. Operational policy: alarm via SAFE-M-12 *Audit Logging* if any LLM output ever contains a string matching the grant signature shape.

## Testing and Validation
1. **Security Testing**:
   - Replay known prompt-injection corpus (e.g., the AgentDojo evaluation set used by the CaMeL paper) against a protected configuration; verify the data plane cannot mint control-plane decisions.
   - Test capability-grant binding by altering each bound field individually (tool, args, subject, session) and verifying fail-closed rejection.
   - Test replay detection by replaying a previously-consumed grant and verifying rejection.
   - Test trust-boundary enforcement by feeding crafted "trusted-source" content with embedded control directives; verify the parser rejects malformed trusted input.

2. **Functional Testing**:
   - Ensure legitimate operations still work — run the full agent test suite under the protected configuration; measure task-completion delta vs unprotected.
   - Measure dispatch overhead per tool call.
   - Validate error handling: capability-rejection paths, parser rejection paths, dispatch-layer fault paths.

## Deployment Considerations

### Resource Requirements
- Control-plane parser and data-sandbox introduce additional memory/process overhead; the exact profile depends on parser implementation, sandbox type (in-process capability boundary vs separate process vs container), and capability-check granularity. Measure in staging before production rollout.
- Capability issuance and verification require a durable replay-protection store (e.g., Redis or a database) for the consumed `jti` set; size this for peak grant velocity × TTL window.

### Performance Impact
- Per the CaMeL paper (arXiv 2503.18813 v2, June 24, 2025), the protected configuration achieves **77% secure task completion under attack on the AgentDojo benchmark vs 84% for the undefended baseline** — a 7-percentage-point trade between utility and security guarantees, not a 7% relative reduction.
- Latency overhead per tool call depends on capability-check granularity and parser depth; published per-call latency benchmarks for CaMeL-style separation are limited as of 2026-04. Measure against your specific workload.

### Monitoring and Alerting
- Alarm on attempted capability escalation that's denied — repeated denials for the same actor + tool indicate either misconfiguration or attack reconnaissance.
- Alarm on parser rejection of trusted-source input — potential trust-boundary violation upstream.
- Alarm on data-plane attempts to invoke control-plane primitives — direct evidence of an injection attempt that the architecture caught.
- Alarm on capability-grant forgery attempts (signature verification failures).
- **Hard-floor alert**: detection of capability material (signature shape, jti, payload fragment) appearing in any LLM output or tool-call output. The architecture's correctness depends on capability material never traversing the model context; a violation is a direct indicator of either implementation bug or active exfiltration attempt.

### Operational Note
The trust-boundary manifest and capability-issuance signing keys are themselves high-value config. Version the manifest as code (review-gated changes), audit every modification via SAFE-M-12 *Audit Logging*, and gate manifest updates with SAFE-M-69 *Out-of-Band Authorization for Privileged Tool Invocations*.

## Current Status (2026)

Reference implementation [CaMeL (Defeating Prompt Injections by Design, Google Research / arXiv 2503.18813)](https://arxiv.org/abs/2503.18813) demonstrates 77% secure task completion under attack on the AgentDojo benchmark vs an 84% undefended baseline. The CaMeL repository describes the public release as a research artifact, notes that it may contain bugs, and explicitly states it might not be fully secure — production deployments should treat it as a starting point for hardening rather than a turn-key system.

General capability-based security frameworks are well-established ([Saltzer & Schroeder, 1975](https://web.mit.edu/Saltzer/www/publications/protection/)); the application of these principles to LLM-driven agentic systems is an active research area where CaMeL is one notable implementation as of 2026-04.

## References
- [Defeating Prompt Injections by Design — Google Research, arXiv 2503.18813 (2025)](https://arxiv.org/abs/2503.18813)
- [Saltzer & Schroeder — The Protection of Information in Computer Systems (1975)](https://web.mit.edu/Saltzer/www/publications/protection/) — foundational treatment of capability-based security and the principles of least privilege, fail-safe defaults, and complete mediation that this mitigation builds on.
- [NIST SP 800-160 Vol 2 — Developing Cyber-Resilient Systems, Appendix F (Design Principles for Cyber Resilient Systems)](https://csrc.nist.gov/publications/detail/sp/800-160/vol-2-rev-1/final) — Segregation, Non-Persistence, and related design principles that map to control/data flow separation.
- [OWASP Top 10 for Large Language Model Applications — LLM01: Prompt Injection](https://owasp.org/www-project-top-10-for-large-language-model-applications/) — the threat class this mitigation primarily addresses.
- [Model Context Protocol Specification](https://modelcontextprotocol.io/specification) — the protocol layer at which the dispatch boundary is implemented in MCP deployments.

## Related Mitigations
- [SAFE-M-2](../SAFE-M-2/README.md): Cryptographic Integrity for Tool Descriptions — protects the trusted-source content that the control-plane parser reads, ensuring the parser is operating on authentic input.
- [SAFE-M-22](../SAFE-M-22/README.md): Semantic Output Validation — runs in M-1's data plane on LLM outputs; M-22 validates content, M-1 ensures that data-plane content cannot mint control-plane decisions even when validation fails.
- [SAFE-M-69](../SAFE-M-69/README.md): Out-of-Band Authorization for Privileged Tool Invocations — privileged-tool gating that consumes M-1's separation guarantees. M-1 ensures the control plane decides *which* privileged tool to invoke; M-69 ensures *whether* that invocation is authorized via an out-of-band channel.

## Version History
| Version | Date | Changes | Author |
|---------|------|---------|--------|
| 1.0 | 2025-01-03 | Initial documentation | Frederick Kautz |
| 2.0 | 2026-05-02 | Additive expansion to template parity per corpus mitigation quality audit; authored Deployment Considerations and Current Status (2026) sections, added Prerequisites sub-section under Technical Implementation, expanded Mitigates list to 11 directly-mapped citing techniques (curated from 15 raw citers; 4 mislabels excluded with reason notes — tracked as safe-m-1-mislabel-cluster follow-up), added Implementation Example 2 (host-bound capability grant with replay protection and explicit no-token-through-LLM constraint), expanded References (Saltzer & Schroeder 1975, NIST SP 800-160 Vol 2 Appendix F, OWASP LLM01, MCP Specification), updated Related Mitigations (replaced M-3 with M-69 and M-22; preserved M-2). Corrected CaMeL performance framing to "7 percentage-point drop (77% vs 84% on AgentDojo)" with explicit research-artifact caveat | bishnu bista |
