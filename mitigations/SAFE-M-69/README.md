# SAFE-M-69: Out-of-Band Authorization for Privileged Tool Invocations

## Overview
**Mitigation ID**: SAFE-M-69  
**Category**: Preventive Control (Architectural)  
**Effectiveness**: High  
**Implementation Complexity**: Medium-High  
**First Published**: 2026-04-14

## Description
Out-of-Band Authorization for Privileged Tool Invocations is a host-side control that requires every call to a privileged MCP tool to pass through an authorization step whose decision is made and enforced **outside the model's context window**. In-prompt assertions ("I'm the admin", "the user already approved", "we're in maintenance mode") cannot, on their own, satisfy the check. Instead, a distinct authorization channel — a human-in-the-loop confirmation UI, a policy engine, a signed short-lived capability token, or an approval message routed through a separate service such as Slack, email, or an incident-ticket workflow — must produce an explicit, verifiable grant before the MCP host dispatches the tool call.

The control addresses the failure mode in which a prompt-manipulated agent decides to invoke a privileged tool and the host executes the call without any independent check. By moving the authorization boundary off the model-reachable surface, SAFE-M-69 makes the privileged-invocation decision resistant to natural-language coercion: even a fully compromised model context cannot produce the approval artifact, because the approval is issued by a principal or a service the model cannot impersonate. This mitigation is the load-bearing tool-invocation-time control for SAFE-T1309 (Privileged Tool Invocation via Prompt Manipulation); it composes with, but is distinct from, static allowlisting or privilege-tier definitions.

## Mitigates
- [SAFE-T1309](../../techniques/SAFE-T1309/README.md): Privileged Tool Invocation via Prompt Manipulation
- [SAFE-T1104](../../techniques/SAFE-T1104/README.md): Over-Privileged Tool Abuse

## Technical Implementation

### Core Principles
1. **Authorization outside the context window**: The check that gates a privileged tool call must be evaluated by code or a human the model cannot reach, prompt, or speak for. An LLM saying "I will only run this with approval" is not out-of-band authorization; the enforcement must exist in the host, not in the model.
2. **Fail closed**: In the absence of a valid, unexpired, scope-matching authorization artifact, the invocation is denied. Missing or malformed approvals never default to "allow".
3. **Bind the grant to the call**: The authorization artifact (signed token, approval record, confirmation click) must reference the specific tool, the specific arguments (or a digest of them), the requesting session, and a short expiry. A generic "the user is logged in" session flag is insufficient.
4. **Privilege derives from session identity, not from arguments or prose**: The caller's right to request approval is determined by the authenticated session's role, not by text the model emitted or the user typed into the prompt.
5. **Auditable**: Every grant, denial, and timeout is logged with the full request context so that post-incident review can reconstruct who approved what and when.

### Architecture Components
```
+---------------------+        proposed tool call         +-------------------------+
|      LLM / Agent    | --------------------------------> |        MCP Host         |
| (reasoning, text)   |    {tool, args, session_id}       |  (tool dispatch layer)  |
+---------------------+                                   +-----------+-------------+
                                                                      |
                                                   privileged?        | yes
                                                                      v
                                              +---------------------------------------+
                                              |  OOB Authorization Gate (out-of-band) |
                                              |---------------------------------------|
                                              |  - policy engine check                |
                                              |  - capability-token verification      |
                                              |  - human confirmation UI prompt       |
                                              |  - approval via Slack / email / ticket|
                                              +-----+----------------+---------+------+
                                                    |                |         |
                                           grant    | deny   timeout |         | reviewer
                                                    v                v         v
                                            +----------------+  +-------------------+
                                            | Tool Execution |  | Denied + Audited  |
                                            | (MCP server)   |  | (no dispatch)     |
                                            +----------------+  +-------------------+

Legend:
  - The model can observe that approval was requested but cannot forge the grant.
  - The grant artifact is produced by a principal/service outside the model's reach.
  - Decisions (allow/deny/timeout) are logged to an append-only audit sink.
```

### Prerequisites
- A working classification of which tools are "privileged" and a privilege hierarchy (see [SAFE-M-29](../SAFE-M-29/README.md)). SAFE-M-29 defines the boundary (which tools are privileged, the privilege levels, and the escalation rules between them). SAFE-M-69 supplies the **per-invocation authorization artifact** that the gate checks — the capability token, human-approval signal, or out-of-band grant that the caller must present. M-29 can reference M-69 as one implementation choice for its escalation step; M-69 composes with M-29 but does not subsume it.
- An authenticated session identity for the user on whose behalf the agent is acting (OIDC, SSO, or equivalent). In-prompt role claims are not identities.
- A secure channel for carrying approval requests to a human or policy service (signed webhook, authenticated UI, mTLS to a policy engine).
- Key material and rotation process if capability tokens are used (HSM- or KMS-backed signing key, short token TTLs).
- Audit logging infrastructure capable of correlating the tool call, the approval request, and the approver's response.

### Implementation Steps
1. **Design Phase**:
   - Inventory tools and mark each as privileged or non-privileged (coordinate with SAFE-M-29).
   - For each privileged tool, define the required approval mode: human confirmation, policy-engine decision, capability token, or multi-party approval.
   - Specify the binding: what fields of the tool call (tool id, argument digest, session id, expiry) the grant must cover.
   - Decide the deny-on-timeout policy (default: deny after N seconds with an audit record).

2. **Development Phase**:
   - Implement a host-side interception point that every tool dispatch must traverse.
   - Integrate the policy engine and/or approval UI. For capability tokens, implement issuance, signature verification, replay protection (nonce + expiry), and revocation.
   - Ensure the model cannot observe or influence the approver's channel (the approval UI is rendered by the host, not by a tool the model can call).
   - Emit structured audit events for request, grant, deny, timeout, and revocation.

3. **Deployment Phase**:
   - Roll out in **log-only** mode first: record what *would* have required approval without blocking, so approval-fatigue and false-positive rates can be measured.
   - Tune the privileged-tool list and bundling rules (see Limitations: approval fatigue) before enabling enforce mode.
   - Enable enforcement, monitor denial rates, and iterate. Treat a spike in denials as a potential ongoing SAFE-T1309 attempt.

## Benefits
- **Breaks the SAFE-T1309 coercion chain**: Since the grant is produced outside the model's context, natural-language manipulation of the model cannot forge it; the worst a compromised context can do is request approval it should not have.
- **Composes with static controls**: Works alongside privilege-tier definitions (SAFE-M-29), server allowlisting (SAFE-M-14), and token-scope limiting (SAFE-M-16) to produce defense in depth across configuration time and invocation time.
- **Produces forensic evidence**: Every privileged invocation yields a signed or logged approval record, which is invaluable for incident reconstruction and for regulatory audit trails.
- **Supports graduated friction**: Low-risk privileged calls can route through a fast capability-token flow; high-risk calls can require explicit human review or multi-party approval, without changing the underlying architecture.

## Limitations
- **Approval fatigue is a real failure mode**: If users are prompted to confirm too often, they click "approve" without reading, which collapses the control's effectiveness. This is explicitly noted in the OWASP Top 10 for LLM Applications discussion of excessive agency. Mitigate by narrowing the privileged set (SAFE-M-14, SAFE-M-29), bundling related calls into a single approval, batching repetitive low-risk calls under a short-lived capability token, and designing approval UX that surfaces the distinguishing fields (path, host, SQL, dollar amount) rather than a generic "Allow this tool?" prompt.
- **Latency and workflow friction**: Out-of-band approval adds time, especially for human-in-the-loop flows. Interactive sessions may become unusable if every call blocks on a human. Capability tokens with narrow scope and short TTL partially mitigate this by amortising the approval over a bounded session.
- **Does not defend against a compromised host**: If the host process itself is compromised or if the approval UI is spoofed by the model through a vulnerable rendering surface (prompt-injected UI elements), the control degrades. The approval channel must not be addressable from the model's output.
- **Relies on correct privilege classification**: A tool incorrectly marked non-privileged bypasses this control entirely. Misclassification pushes the failure mode upstream to SAFE-M-29.
- **Possible single-point-of-failure for approvers**: Human approvers become an availability dependency. Off-hours on-call rotations and a documented break-glass procedure (with elevated logging) should be defined in advance.

## Implementation Examples

### Example 1: Signed, scoped, short-lived capability token
A policy engine issues a DSSE- or JWT-style token binding the grant to a specific tool, an argument digest, a session id, and a short expiry. The MCP host verifies the token before dispatch.

```python
# Host-side verification (illustrative; use a vetted JWT/DSSE library in production)
import hmac, hashlib, json, time

# Persistent store of JTIs already consumed. Backed by Redis / DB in production;
# must outlive the process and be shared across all host instances that verify tokens.
_used_jtis: "set[str]" = set()

def verify_capability_token(token: dict, expected: dict, public_key) -> dict:
    """Verify a capability token and return the authenticated claims. Fail closed."""
    # 1. Verify the cryptographic signature FIRST. Any field read before this point is
    #    attacker-controllable; only `payload` + `signature` are trustworthy as inputs.
    verify_signature(token["payload"], token["signature"], public_key)  # raises on failure

    # 2. Parse claims from the verified payload. Do not trust any unsigned top-level field.
    claims = json.loads(token["payload"])

    if claims.get("ver") != 1:
        raise PermissionError("unsupported token version")

    # 3. Replay protection: every token carries a unique `jti` and a short-lived `nonce`
    #    bound into the signed claims. Consume the jti exactly once.
    jti = claims["jti"]
    if jti in _used_jtis:
        raise PermissionError("token replay detected")
    if claims["exp"] < int(time.time()):
        raise PermissionError("token expired")

    # 4. Bind the token to the concrete call being dispatched.
    if claims["tool"] != expected["tool"]:
        raise PermissionError("tool mismatch")
    if claims["session_id"] != expected["session_id"]:
        raise PermissionError("session mismatch")
    args_digest = hashlib.sha256(
        json.dumps(expected["arguments"], sort_keys=True).encode()
    ).hexdigest()
    if not hmac.compare_digest(claims["args_digest"], args_digest):
        raise PermissionError("arguments do not match signed grant")

    _used_jtis.add(jti)  # only after every other check passes
    return claims

def dispatch_privileged_tool(call, token, public_key):
    verify_capability_token(token, expected={
        "tool": call.tool,
        "session_id": call.session_id,
        "arguments": call.arguments,
    }, public_key=public_key)
    return execute_tool(call)  # only reached on successful verification
```

Key properties: the token is issued by a service the model cannot reach; the arguments digest binds the grant to the exact call; the short `exp` limits replay; `verify_signature` failing closes the path.

### Example 2: Human-in-the-loop confirmation UX (host-rendered)
The host renders an approval dialog directly in the user's UI — not via a tool the model can call — and shows the tool, the exact arguments, and the session context.

```text
+-----------------------------------------------------------+
| Privileged action requested                               |
|-----------------------------------------------------------|
| Tool:      filesystem.write                               |
| Path:      /etc/app/config.json                           |
| Size:      142 bytes                                      |
| Session:   user=alice (SSO)  agent=assistant-prod         |
| Requested: 2026-04-14 09:41:22 UTC                        |
|                                                           |
| Preview:                                                  |
|   { "debug": true, "overrideSecurity": true }             |
|                                                           |
|      [ Approve ]   [ Deny ]   (auto-deny in 25s)          |
+-----------------------------------------------------------+
```

Design rules that make this resistant to SAFE-T1309:
- The dialog text is rendered by the host from structured fields, not from free-form model output.
- The "Approve" control triggers a host-side function; the model cannot synthesise a click.
- The preview shows the distinguishing arguments, forcing the user's attention onto *what is being changed*, not onto a generic "tool call" prompt (reduces approval fatigue).
- Timeout defaults to deny, not allow.

### Example 3: Policy-engine configuration
```yaml
# Host-side configuration binding privileged tools to approval modes.
privileged_tool_authorization:
  mode: "enforce"   # log-only | enforce
  default_timeout_seconds: 30
  default_on_timeout: "deny"

  tools:
    filesystem.write:
      approval: "human_confirm"
      bind_fields: ["path", "content_sha256"]
      scope_constraints:
        - "path must be within session.workspace OR approver.role == 'admin'"

    shell.exec:
      approval: "policy_then_human"   # policy engine first; human on non-allowlisted commands
      bind_fields: ["command", "args", "cwd"]

    admin.rotate_credential:
      approval: "multi_party"
      approvers_required: 2
      approver_roles: ["sre", "security"]
      bind_fields: ["credential_id"]
      ttl_seconds: 600
```

## Testing and Validation
1. **Security Testing**:
   - Attempt each SAFE-T1309 coercion pattern (authority spoofing, debug/simulation pretexting, pre-authorization assertion, role/mode override) against the host and verify that *no* privileged tool executes without a valid out-of-band artifact.
   - Replay a previously issued capability token after expiry and verify denial.
   - Submit a token whose `args_digest` does not match the call and verify denial.
   - Attempt to induce the model to render a UI that mimics the approval dialog and confirm the real dialog is visually/structurally distinguishable (host-chromed).
   - Verify fail-closed behaviour when the policy engine is unreachable.

2. **Functional Testing**:
   - Measure end-to-end latency added by the gate for each approval mode.
   - Measure approval-fatigue proxy metrics (approvals per session, time-to-decide, approval/deny ratio).
   - Verify that non-privileged tools are not affected.

3. **Integration Testing**:
   - Exercise the capability-token issuance, verification, and revocation lifecycle.
   - Confirm audit events are emitted for grant, deny, timeout, and revocation, and that they can be correlated by session id.
   - Run in log-only mode across a representative workload to tune the privileged list before enforcement.

## Deployment Considerations

### Resource Requirements
- **CPU**: Low. Signature verification and policy evaluation are cheap relative to LLM inference.
- **Memory**: Low. A small cache of active capability tokens per session.
- **Storage**: Moderate. Audit logs for every privileged invocation and its decision; size scales with tool-call volume. Plan retention per compliance requirements.
- **Network**: One extra synchronous hop per privileged call to the approval service or UI. For human flows, an out-of-band push channel (web socket, mobile push, Slack webhook).

### Performance Impact
- **Latency**: Milliseconds for capability-token or policy-engine flows; seconds-to-minutes for human-confirmation flows. Design the privileged-tool list so that the common path is the fast one.
- **Throughput**: Unaffected for non-privileged tools. Privileged throughput is bounded by the approval channel's capacity.
- **Resource Usage**: Negligible in the host process; human-attention cost is the dominant real-world resource.

### Monitoring and Alerting
- Approval request rate per session and per user (detect brute-forcing of the approval channel).
- Denial rate and reasons (expired, mismatched args, policy-denied, timeout).
- Time-to-decide distribution for human flows; alert on degradation.
- Alert on approval requests for tools this session has never invoked before (possible ongoing SAFE-T1309 attempt).
- Alert on capability tokens that verify but reference arguments lexically identical to the preceding user turn (possible dictated-call signal; combine with SAFE-T1309 detection guidance and SAFE-M-70 baselines).

## Current Status (2026)
The MCP specification places the consent and tool-safety burden on the host application and does not prescribe a specific mechanism ([Model Context Protocol Specification — Security and Trust & Safety](https://modelcontextprotocol.io/specification)). Implementations vary widely: some desktop hosts prompt for every tool call, others approve tools per-session at attach time, and headless/agentic deployments frequently skip per-invocation approval altogether in favour of pre-granted scopes. Public analyses of MCP deployments have repeatedly identified invocation-time authorization as an unevenly implemented control ([The Security Risks of Model Context Protocol (MCP) — Pillar Security, 2025](https://www.pillar.security/blog/the-security-risks-of-model-context-protocol-mcp)). Capability-based approaches with signed, short-lived grants are well-established in the broader security literature (see the capability-security references below) but are not yet standard practice in MCP host implementations.


## References
- [Model Context Protocol Specification — Security and Trust & Safety](https://modelcontextprotocol.io/specification) — primary source for the host-side consent and tool-safety principles this mitigation operationalises.
- [OWASP Top 10 for Large Language Model Applications — LLM06: Excessive Agency](https://owasp.org/www-project-top-10-for-large-language-model-applications/) — framework context for over-autonomous tool invocation and the approval-fatigue failure mode.
- [OWASP A01:2021 — Broken Access Control](https://owasp.org/Top10/A01_2021-Broken_Access_Control/) — general access-control framing for the authorization boundary at the tool-invocation layer.
- [NIST SP 800-53 Rev. 5 — Access Control (AC) family](https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final) — control families (AC-3 Access Enforcement, AC-6 Least Privilege, AC-17 Remote Access) that this mitigation maps to.
- [Capability-Based Computer Systems — Henry M. Levy, 1984](https://homes.cs.washington.edu/~levy/capabook/) — canonical reference on capability-based security, the model underlying scoped, unforgeable grants.
- [Capability Myths Demolished — Miller, Yee, Shapiro, 2003](https://srl.cs.jhu.edu/pubs/SRL2003-02.pdf) — foundational paper clarifying capability-security properties, relevant to the capability-token design in Example 1.
- [RFC 8392 — CBOR Web Token (CWT)](https://datatracker.ietf.org/doc/html/rfc8392) and [RFC 7519 — JSON Web Token (JWT)](https://datatracker.ietf.org/doc/html/rfc7519) — standard carrier formats for short-lived, signed authorization artifacts.
- [The Security Risks of Model Context Protocol (MCP) — Pillar Security, 2025](https://www.pillar.security/blog/the-security-risks-of-model-context-protocol-mcp) — community analysis highlighting invocation-time authorization gaps in MCP deployments.

## Related Mitigations
- [SAFE-M-29](../SAFE-M-29/README.md): Explicit Privilege Boundaries — complementary. SAFE-M-29 defines privilege levels, the boundaries between them, and the escalation rules that govern crossing those boundaries. SAFE-M-69 supplies the concrete per-invocation authorization artifact (capability token, human-approval signal, policy-engine grant) that M-29's escalation step consumes. Deployments use both: M-29 for the hierarchy and escalation policy, M-69 for the call-time artifact that proves the escalation was granted.
- [SAFE-M-14](../SAFE-M-14/README.md): Server Allowlisting — narrows the surface of tools that can ever reach the authorization gate, reducing approval-fatigue load on SAFE-M-69.
- [SAFE-M-16](../SAFE-M-16/README.md): Token Scope Limiting — bounds the blast radius of a successfully authorized privileged invocation by ensuring the underlying credentials are minimally scoped.
- [SAFE-M-1](../SAFE-M-1/README.md): Architectural Defense — Control/Data Flow Separation — complementary upstream control that prevents tool outputs and retrieved content from acting as instructions, reducing the rate at which the authorization gate is asked to adjudicate injection-driven calls.
- [SAFE-M-12](../SAFE-M-12/README.md): Audit Logging — consumes the grant/deny events emitted by SAFE-M-69 for detection and post-incident reconstruction.

## Version History
| Version | Date       | Changes               | Author       |
|---------|------------|-----------------------|--------------|
| 1.0     | 2026-04-14 | Initial documentation | bishnu bista |
