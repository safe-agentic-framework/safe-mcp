# SAFE-T1604: Server Version Enumeration

## Overview
**Tactic**: Discovery (ATK-TA0007)
**Technique ID**: SAFE-T1604
**Severity**: High
**First Observed**: Research-based analysis (2025)
**Last Updated**: 2026-01-26

## Description
Server Version Enumeration is a reconnaissance technique where adversaries identify MCP server software versions through endpoint probing and HTTP header analysis. Unlike general server enumeration (SAFE-T1601), this technique specifically targets version strings to map vulnerable builds and enable targeted exploitation.

Attackers query common endpoints (`/version`, `/health`, `/status`), analyze HTTP response headers (`Server`, `X-Powered-By`), and inspect MCP protocol responses (JSON-RPC `initialize`, SSE handshakes) to extract precise version information. This intelligence enables CVE targeting, supply chain assessment, and patch gap analysis across MCP deployments.

The MCP ecosystem's rapid evolution makes version disclosure particularly dangerous. Servers may have critical vulnerabilities patched in newer releases that attackers can exploit once they identify outdated deployments. The vulnerable SQLite MCP server, forked over 5,000 times before being archived, exemplifies how version identification enables targeting of known flaws at scale.

## Attack Vectors
- **Primary Vector**: Direct endpoint probing for version-exposing URLs (`/version`, `/health`, `/status`, `/info`, `/api/version`)
- **Secondary Vectors**:
  - MCP protocol responses containing `serverInfo.name` and `serverInfo.version` in JSON-RPC `initialize` response
  - SSE handshake metadata revealing version strings
  - HTTP response headers (`Server`, `X-Powered-By`, `X-MCP-Version`, `X-Server-Version`)
  - Error responses exposing stack traces with version-revealing file paths
  - Infrastructure headers from reverse proxies (nginx, Traefik), load balancers, and Kubernetes annotations
  - Cloud metadata endpoints exposing container image tags and deployment labels

## Technical Details

### Prerequisites
- Network access to target MCP server (direct or via proxy)
- HTTP client or MCP-compatible tooling
- Knowledge of common version endpoint patterns and MCP protocol structure

### Attack Flow
1. **Reconnaissance**: Probe standard version endpoints (`/version`, `/health`, `/status`) and analyze HTTP response headers for version disclosure
2. **Protocol Interaction**: Establish MCP connection and capture `initialize` response containing `serverInfo` with version details
3. **Error Triggering**: Send malformed requests to trigger error responses that may expose stack traces with version information
4. **Infrastructure Mapping**: Identify proxy/load balancer version headers and correlate with cloud provider metadata
5. **Intelligence Correlation**: Match discovered versions to CVE databases, identify supply chain lineage from forked repositories, and map patch gaps across targets

### Example Scenario

**Endpoint Probing:**
```bash
# Scan common version endpoints
curl -s https://target:8080/version
curl -s https://target:8080/health
curl -s https://target:8080/api/v1/info
```

**Version Response:**
```json
{
  "name": "mcp-sqlite-server",
  "version": "1.2.3",
  "build": "2024-12-01T10:30:00Z"
}
```

**Header Analysis:**
```http
HTTP/1.1 200 OK
Server: MCP-Server/1.2.3 (Node.js/18.17.0)
X-Powered-By: Express/4.18.2
X-MCP-Version: 0.9.1
```

**MCP Protocol Version Disclosure:**
```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "result": {
    "protocolVersion": "2024-11-05",
    "serverInfo": {
      "name": "vulnerable-sqlite-mcp",
      "version": "1.0.0-fork"
    },
    "capabilities": {}
  }
}
```

**Error-Triggered Disclosure:**
```
Error: Cannot process request
    at MCPServer.handle (/app/node_modules/mcp-server/v1.2.3/lib/handler.js:42)
    at ...
```

### Advanced Attack Techniques (2025 Research)

According to research from [Trend Micro](https://www.trendmicro.com/en_us/research/25/f/why-a-classic-mcp-server-vulnerability-can-undermine-your-entire-ai-agent.html) and [MCP security analysis](https://arxiv.org/abs/2504.03767), attackers have developed systematic version enumeration approaches:

1. **Automated Scanning**: Using tools like nuclei and httpx to probe version endpoints at scale across cloud provider IP ranges
2. **Supply Chain Fingerprinting**: Matching version strings to known vulnerable forks (e.g., "v1.0.0-fork" patterns indicating unpatched derivatives)
3. **Differential Analysis**: Comparing versions across an organization's MCP fleet to identify unpatched outliers for targeted exploitation

## Impact Assessment
- **Confidentiality**: High - Exposes software versions, build dates, dependency information, and deployment architecture
- **Integrity**: Medium - Enables targeted exploitation of version-specific vulnerabilities
- **Availability**: Low - Enumeration itself is non-destructive; impact comes from follow-on attacks
- **Scope**: Network-wide - Can map version landscape across entire MCP infrastructure

### Current Status (2025)
According to [Trend Micro research](https://www.trendmicro.com/en_us/research/25/f/why-a-classic-mcp-server-vulnerability-can-undermine-your-entire-ai-agent.html), the MCP ecosystem's rapid growth has outpaced security awareness:
- Many MCP servers expose version information through standard endpoints without authentication
- The vulnerable SQLite MCP server was forked over 5,000 times, creating extensive attack surface for version-targeted exploitation
- MCP protocol specification includes `serverInfo` in initialize responses, making version disclosure a protocol-level concern

## Detection Methods

### Indicators of Compromise (IoCs)
- Sequential requests to `/version`, `/health`, `/status`, `/info` from same source IP
- HTTP requests with scanner user-agents (curl, httpie, nuclei, httpx, python-requests, Go-http-client)
- High-frequency probing of multiple version endpoints within short timeframes
- Requests specifically targeting `/.well-known/` or `/api/version` paths
- Unusual `Accept` headers probing for JSON version responses

### Detection Rules

**Important**: The following rule is written in Sigma format and contains example patterns only. Organizations should:
- Use AI-based anomaly detection to identify novel enumeration patterns
- Regularly update detection rules based on threat intelligence
- Implement multiple layers of detection beyond pattern matching
- Consider correlation with subsequent exploitation attempts

```yaml
# EXAMPLE SIGMA RULE - Not comprehensive
title: MCP Server Version Enumeration Attempt
id: 7a8b9c0d-1e2f-3a4b-5c6d-7e8f9a0b1c2d
status: experimental
description: Detects potential version enumeration of MCP servers through endpoint probing
author: SAFE-MCP Team
date: 2025-01-26
references:
  - https://github.com/safe-mcp/techniques/SAFE-T1604
logsource:
  category: webserver
  product: nginx
detection:
  selection_endpoints:
    cs-uri-stem|contains:
      - '/version'
      - '/health'
      - '/status'
      - '/info'
      - '/api/version'
  selection_scanners:
    cs-user-agent|contains:
      - 'curl'
      - 'httpie'
      - 'nuclei'
      - 'httpx'
      - 'python-requests'
      - 'Go-http-client'
  selection_frequency:
    EventCount|gte: 3
    TimeWindow: '60s'
  condition: selection_endpoints and (selection_scanners or selection_frequency)
falsepositives:
  - Legitimate health monitoring systems
  - CI/CD deployment checks
  - Load balancer health probes
level: medium
tags:
  - attack.discovery
  - attack.t1592
  - safe.t1604
```

### Behavioral Indicators
- Single source IP querying version endpoints across multiple MCP servers
- Requests immediately followed by MCP protocol `initialize` handshakes
- Version endpoint access from IPs not associated with legitimate clients
- Probing patterns correlating with newly published CVEs

## Mitigation Strategies

### Preventive Controls
1. **[SAFE-M-14: Server Allowlisting](../../mitigations/SAFE-M-14/README.md)**: Restrict MCP server access to trusted clients; deny access to version endpoints from untrusted sources
2. **[SAFE-M-45: Tool Manifest Signing & Server Attestation](../../mitigations/SAFE-M-45/README.md)**: Implement cryptographic identity verification before exposing any server metadata
3. **[SAFE-M-5: Content Sanitization](../../mitigations/SAFE-M-5/README.md)**: Filter error responses to prevent stack trace and version disclosure through error messages
4. **Version Endpoint Hardening**: Remove `/version`, `/status` from production; use internal-only health checks with authentication
5. **Header Stripping**: Configure reverse proxy to remove `Server`, `X-Powered-By`, `X-MCP-Version` headers from responses
6. **serverInfo Customization**: Return generic `serverInfo.name` in MCP initialize (e.g., "MCP Server" without version number)

### Detective Controls
1. **[SAFE-M-12: Audit Logging](../../mitigations/SAFE-M-12/README.md)**: Log all requests to version-related endpoints with source IP, user-agent, and response details
2. **[SAFE-M-11: Behavioral Monitoring](../../mitigations/SAFE-M-11/README.md)**: Track patterns of version endpoint access to detect systematic enumeration attempts
3. **[SAFE-M-36: Model Behavior Monitoring](../../mitigations/SAFE-M-36/README.md)**: Monitor for anomalies following version disclosure that may indicate follow-on exploitation

### Response Procedures
1. **Immediate Actions**:
   - Block source IPs showing enumeration patterns
   - Audit all version-exposing endpoints across MCP fleet
   - Verify sensitive endpoints are not externally accessible
2. **Investigation Steps**:
   - Review access logs for enumeration scope and targeted systems
   - Identify which version information was disclosed
   - Check for follow-on exploitation attempts using disclosed version data
3. **Remediation**:
   - Review and update server configurations to minimize version disclosure
   - Implement header stripping at proxy layer
   - Deploy detection rules for ongoing monitoring

## Related Techniques
- [SAFE-T1601](../SAFE-T1601/README.md): MCP Server Enumeration - Parent technique; version enumeration often follows server discovery
- [SAFE-T1602](../SAFE-T1602/README.md): Tool Enumeration - Follow-on technique; enumerate exploitable tools after identifying vulnerable versions
- [SAFE-T1605](../SAFE-T1605/README.md): Capability Mapping - Complementary technique; version + capabilities = complete attack surface
- [SAFE-T1101](../SAFE-T1101/README.md): Command Injection - Exploitation technique; version info enables targeting known injection flaws
- [SAFE-T1001](../SAFE-T1001/README.md): Tool Poisoning Attack - Exploitation technique; vulnerable versions may be susceptible to tool poisoning

## References
- [Model Context Protocol Specification](https://modelcontextprotocol.io/specification)
- [MCP Specification - Initialize](https://modelcontextprotocol.io/specification#initialize)
- [OWASP Top 10 for LLM Applications](https://owasp.org/www-project-top-10-for-large-language-model-applications/)
- [OWASP Information Disclosure Testing](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/)
- [CWE-200: Exposure of Sensitive Information to an Unauthorized Actor](https://cwe.mitre.org/data/definitions/200.html)
- [Why a Classic MCP Server Vulnerability Can Undermine Your Entire AI Agent - Trend Micro, 2025](https://www.trendmicro.com/en_us/research/25/f/why-a-classic-mcp-server-vulnerability-can-undermine-your-entire-ai-agent.html)
- [MCP Safety Audit Research - arXiv 2504.03767](https://arxiv.org/abs/2504.03767)
- [NIST SP 800-53 Rev. 5 - Security and Privacy Controls for Information Systems and Organizations](https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final)

## MITRE ATT&CK Mapping
- [T1592 - Gather Victim Host Information](https://attack.mitre.org/techniques/T1592/)

## Version History
| Version | Date | Changes | Author |
|---------|------|---------|--------|
| 1.0 | 2026-01-26 | Initial documentation of Server Version Enumeration technique | Sumit Yadav |
