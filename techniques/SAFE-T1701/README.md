# SAFE-T1701: Cross-Tool Contamination

## Overview
**Tactic**: Lateral Movement (ATK-TA0008)  
**Technique ID**: SAFE-T1701  
**Severity**: High  
**First Observed**: Not observed in production (Conceptual technique based on MCP multi-tool orchestration patterns)  
**Last Updated**: 2025-12-06

## Description
Cross-Tool Contamination is a lateral movement technique in Model Context Protocol (MCP)–based systems where an attacker that controls one MCP tool (the *entry tool*) uses shared credentials, configuration, or trust relationships to drive actions through **other** tools or connectors in the same host or workspace.

Because MCP is explicitly designed to let AI applications connect to many external systems (files, APIs, databases, cloud services) through a common tool interface, a single host or agent framework often orchestrates multiple MCP servers and tools in one place. If the runtime does not enforce strong isolation between tools—especially around secret storage, network egress, and policy—compromising any one tool can give an attacker an entry point to pivot into other connected services and systems.

Instead of directly exploiting every target tool or SaaS connector, the adversary: (1) Gains influence over one tool (e.g., via prompt injection, malicious MCP server, or compromised package), (2) Enumerates shared credentials or capabilities exposed to that tool's runtime, (3) Reuses those credentials or trust relationships to access higher-value tools, services, or tenants that were never meant to be reachable from the original tool. This pattern combines elements of unsecured credentials, use of alternate authentication material, and valid accounts abuse.

## Attack Vectors
- **Primary Vector**: Compromised MCP tool reusing shared secrets from global credential stores (environment variables, config files, unscoped secrets managers, or client-level authorization headers)
- **Secondary Vectors**: 
  - Misconfigured privilege boundaries where all tools run under same OS user with identical filesystem and network access
  - Multi-MCP/multi-server orchestration aggregating tools from different security domains without segregation
  - Supply chain attacks via malicious MCP servers registered through marketplaces receiving same credentials as trusted tools
  - Tool interaction policies that are allow-by-default, enabling any tool to invoke any connector

## Technical Details

### Prerequisites
- Tool compromise or coercion (attacker controls behavior of at least one MCP tool through prompt injection, malicious server, trojanized package, or misconfigured hook)
- Shared or insufficiently scoped credentials (secrets stored in locations readable by all tools: common env vars, global files, shared secrets manager)
- Weak tool isolation (tools share filesystem namespace and process identity with no strict tool-to-secrets mapping)
- Limited monitoring of per-tool behavior (logs don't attribute actions to specific tool identity; no baseline for expected service calls per tool)

### Attack Flow

1. **Entry Tool Compromise**: Attacker gains control of low-privilege tool (e.g., `markdown_helper`, `log_viewer`, `notes_search`) via prompt injection, malicious MCP server implementation, or compromised dependency
2. **Environment & Credential Discovery**: From compromised tool's runtime, attacker reads environment variables for API keys/OAuth tokens/service principals, enumerates config directories (`~/.config`, app data dirs), queries secrets manager or host keychain, uses MCP discovery APIs to list available tools/servers and metadata
3. **Target Identification**: Using discovered metadata and secrets, attacker identifies higher-value connectors (cloud deployment/CI-CD tools, database/CRM connectors, internal admin tooling)
4. **Cross-Tool Pivot**: Attacker replays/reuses credentials meant for other tools by presenting cloud API keys, OAuth tokens, or refresh tokens to REST endpoints the compromised tool never normally calls, either directly via raw HTTP or indirectly via client impersonating another tool identity
5. **Post-Pivot Actions**: With newly obtained access, attacker exfiltrates data from other tools' backends, modifies infrastructure, plants persistence via new tools/webhooks/scheduled jobs, or triggers actions across multiple tenants/projects sharing same host or credentials

### Example Scenario

```json
{
  "entry_tool": {
    "name": "docs_summarizer",
    "scope": ["read_repo"],
    "compromise": "prompt_injection"
  },
  "shared_credentials": {
    "store": "~/.mcp/credentials.json",
    "contains": [
      "cloud_admin_pat",
      "ci_cd_pat"
    ],
    "permissions": "readable_by_all_tools"
  },
  "pivot": {
    "target_tool": "deployment_admin",
    "target_service": "cloud-api.company.com",
    "required_scope": "cloud:DeployFull",
    "method": "reuse cloud_admin_pat over HTTPS"
  },
  "impact": {
    "action": "deploy modified container image to staging and production",
    "scope": "multi-environment"
  }
}
```

**Note**: All values are illustrative and not derived from a specific platform. Replace field names and paths with your actual telemetry schema when modeling this technique.

## Impact Assessment
- **Confidentiality**: High - A low-scope tool can be abused to reach tools and backends holding sensitive customer data, credentials, or internal code
- **Integrity**: High - Attackers can modify infrastructure, pipelines, configurations, or records managed by higher-privilege tools
- **Availability**: Medium–High - Misuse of deployment or automation connectors can degrade or disrupt environments (e.g., scaling malicious workloads or deleting resources)
- **Scope**: Workspace/Organization-wide - Single host often aggregates many MCP tools and connectors; contamination can fan out across services, tenants, and environments

## Detection Methods

### Telemetry Requirements

To detect Cross-Tool Contamination, you need (or should derive) fields such as:

**Tool-level identity and scope:**
- `source_tool_id`, `source_tool_name`
- `source_tool_scope` (e.g., helper, read_only, admin)

**Target service/tool information:**
- `dest_service`, `dest_service_scope`
- `dest_tenant_id` / `dest_project_id`

**Authentication and token metadata:**
- Token or credential identifiers (`token_id`, `credential_id`)
- OAuth audience/client (`oauth_aud`, `oauth_client_id`)
- Flags for token reuse or audience mismatch if available

**Session and user context:**
- `user_id`, `session_id`
- `workspace_id` or `tenant_id`

**Tool invocation graph:**
- Sequences of tools invoked within a session
- Number of distinct services reached by each tool in a time window

### Indicators of Compromise (IoCs)
- Low-privilege or "helper" tool suddenly calling administrative endpoints (project creation, deployment, user management) or cloud/SaaS APIs usually associated with different, higher-privilege tools
- Short-lived sequences where `source_tool_scope` is read_only or helper, but `dest_service_scope` is admin, cloud_superuser, or equivalent
- Single tool uses same token identifier as multiple other tools or services within small time window
- MCP sessions where same OAuth access token or API key is seen across multiple unrelated tools
- Tool that historically only touches one backend suddenly fans out to several new services
- Audit logs showing creation or modification of resources (pipelines, cloud deployments, secrets) attributed to tool that normally lacks such capabilities
- Tool invocations that conflict with configured privilege boundaries or policy definitions

### Detection Rules

**Important**: The following rule is written in Sigma format and contains example patterns only. Attackers continuously develop new injection techniques and obfuscation methods. Organizations should:
- Use AI-based anomaly detection to identify novel attack patterns
- Regularly update detection rules based on threat intelligence
- Implement multiple layers of detection beyond pattern matching
- Consider behavioral analytics of per-tool service access patterns

```yaml
# EXAMPLE SIGMA RULE - Not comprehensive
title: Cross-Tool Contamination Detection
id: c9fbeec2-8120-4bb0-b835-fe13c420d918
status: experimental
description: Detects potential cross-tool contamination in MCP environments by identifying low-scope tools reusing credentials to access higher-privilege services or an unusual fan-out to multiple services in short sessions
author: SAFE-MCP Team
date: 2025-12-06
references:
  - https://github.com/safe-mcp/techniques/SAFE-T1701
  - https://attack.mitre.org/techniques/T1550/
  - https://attack.mitre.org/techniques/T1552/
  - https://attack.mitre.org/techniques/T1078/
logsource:
  product: mcp
  service: tool_runtime
detection:
  selection_scope_mismatch:
    source_tool_scope:
      - read_only
      - helper
    dest_service_scope:
      - admin
      - cloud_superuser
      - ci_controller
  selection_credential_reuse:
    token_reused: true
    oauth_audience_mismatch: true
  selection_service_fanout:
    source_tool_scope:
      - read_only
      - helper
    distinct_target_services|gte: 3
    timeframe: 5m
  condition: (selection_scope_mismatch and selection_credential_reuse) or selection_service_fanout
falsepositives:
  - Break-glass workflows that temporarily let helper tools drive admin actions under strict approval
  - Automated maintenance jobs that legitimately reuse shared service accounts for multi-service operations
  - Bulk migration or onboarding tasks where helper tool is intentionally granted broader temporary access
level: high
tags:
  - attack.lateral_movement
  - attack.t1078
  - attack.t1550
  - attack.t1552
  - safe.t1701
```

### Behavioral Indicators
- Read-only tools performing admin actions unexpectedly
- Sudden cross-tenant or cross-project access from tools with no documented need
- Rapid reuse of same credential across unrelated tools within short time windows
- First-time service calls from tools that have never accessed those backends historically
- Privilege escalation patterns where helper tools chain to admin connectors
- Unusual network egress from low-privilege tools to production cloud APIs or internal admin services

## Mitigation Strategies

### Preventive Controls
1. **[SAFE-M-29: Explicit Privilege Boundaries](../../mitigations/SAFE-M-29/README.md)**: Enforce deny-by-default interaction policies so that tools cannot automatically call higher-privilege connectors or access unrelated domains without explicit allowlists and approvals
2. **[SAFE-M-16: Token Scope Limiting](../../mitigations/SAFE-M-16/README.md)**: Issue short-lived, least-privileged OAuth scopes and API keys per tool. Warn or block when an MCP server requests more permissions than its documented function requires
3. **Per-Tool Secret Isolation**: Use OS keychains, encrypted stores, or secrets managers with access control such that each tool or MCP server gets its own secret namespace. Avoid shared "global" credential files or environment variables readable by all tools
4. **Domain & Network Isolation**: Partition tools by security domain (e.g., "local utilities", "prod cloud admin") and enforce separate containers/VMs where feasible with network egress policies restricting which destinations each tool can reach
5. **Secure Plugin / MCP Server Onboarding**: Maintain an allowlisted registry of approved MCP servers and tools. Review and sign configurations before exposing new tools that connect to sensitive systems

### Detective Controls
1. **Per-Tool Audit Logging**: Log every tool invocation with tool identity, destination service, credential/token identifier (hashed), and user/session context
2. **Behavioral Analytics**: Build baselines for typical services and scopes used per tool, normal fan-out (number of services) per tool session. Alert on deviations like read-only tools performing admin actions or sudden cross-tenant/cross-project access
3. **Token-Use Analytics**: Track where each token or credential is used. Raise alerts when same token is seen across unrelated tools or services. Correlate with time windows to spot rapid reuse pivots

### Response Procedures
1. **Immediate Actions**:
   - Disable or quarantine the compromised tool or MCP server
   - Revoke or rotate tokens and API keys observed in suspicious cross-tool use
   - Temporarily restrict high-privilege tools and connectors to manual approval only
2. **Investigation Steps**:
   - Reconstruct tool invocation graphs for affected sessions
   - Identify which tools, services, and tenants were touched using reused credentials
   - Review code and configuration of compromised tool (and any new tools registered during incident)
3. **Remediation**:
   - Introduce or tighten privilege boundaries and per-tool secret isolation
   - Update onboarding processes for MCP servers and tools (security review, signing)
   - Add or refine analytics to detect similar pivot patterns earlier

## Related Techniques
- [SAFE-T1702](../SAFE-T1702/README.md): Shared-Memory Poisoning - Poisoned shared vector stores can influence higher-privilege agents that then drive cross-tool actions
- [SAFE-T1703](../SAFE-T1703/README.md): Tool-Chaining Pivot - Uses implicit trust and chaining between tools to escalate privileges, often complementary with Cross-Tool Contamination
- [SAFE-T1001](../SAFE-T1001/README.md): Tool Poisoning Attack - Provides initial compromise vector for tools that then execute Cross-Tool Contamination pivots

## References
- [Model Context Protocol Specification](https://modelcontextprotocol.io/specification)
- [Model Context Protocol – Tools Specification](https://modelcontextprotocol.io/specification/2025-06-18/server/tools)
- [Model Context Protocol – Introductory Overview](https://modelcontextprotocol.io/docs/getting-started/intro)
- [LangChain Security Policy (Least-Privilege & Sandbox Guidance)](https://python.langchain.com/docs/security/)
- [OWASP Top 10 for Large Language Model Applications (LLM05, LLM07)](https://owasp.org/www-project-top-10-for-large-language-model-applications/)
- [MCP Security Checklist (SlowMist) – Multi-MCP, Isolation, and Tool Permissions](https://github.com/slowmist/MCP-Security-Checklist)
- [MCP Security: Key Risks, Controls & Best Practices](https://www.reco.ai/learn/mcp-security)

## MITRE ATT&CK Mapping
- [TA0008 - Lateral Movement](https://attack.mitre.org/tactics/TA0008/)
- [T1078 - Valid Accounts](https://attack.mitre.org/techniques/T1078/)
- [T1550 - Use Alternate Authentication Material](https://attack.mitre.org/techniques/T1550/)
- [T1552 - Unsecured Credentials](https://attack.mitre.org/techniques/T1552/)

## Version History
| Version | Date | Changes | Author |
|---------|------|---------|--------|
| 1.0 | 2025-12-06 | Initial documentation | Arjun Subedi (Astha.ai) |
