# SAFE-T1004: Server Impersonation / Name-Collision

## Overview
**Tactic**: Credential Access (ATK-TA0006), Initial Access (ATK-TA0001)  
**Technique ID**: SAFE-T1004  
**Severity**: High  
**First Observed**: Documented in DNS cache poisoning attacks (2008)  
**Last Updated**: 2026-02-24

## Description
Server Impersonation / Name-Collision is an adversary-in-the-middle technique where attackers register or advertise a malicious server using the same name or identifier as a trusted one. By exploiting weaknesses in naming and discovery systems (for example DNS, mDNS, or local MCP server registries), clients can be redirected to attacker-controlled endpoints.

This technique is dangerous in MCP environments because trust decisions are often made before strong identity checks. If clients accept duplicated names, unsigned metadata, or weak certificates, an attacker can intercept authentication flows, alter tool responses, and capture sensitive data.

### Registry Context (ODR / Local Registry)
In this technique, **ODR** refers to host-local discovery or registry layers used by MCP host applications to store server metadata (name, endpoint, and trust attributes). On Windows, this concept aligns with the On-Device Agent Registry tooling (`odr.exe`) for MCP server registration and discovery. Implementations vary by platform and product; if your environment does not use ODR by name, apply the same controls to its equivalent local registry/discovery mechanism.

## Attack Vectors
- **Primary Vector**: Malicious server registration with a trusted server's name or identifier
- **Secondary Vectors**:
  - DNS cache poisoning or DNS hijacking
  - Rogue DHCP infrastructure distributing attacker-controlled DNS settings
  - Duplicate local registry entries for an existing trusted server
  - TLS certificate misuse, weak validation, or certificate pinning gaps
  - ARP spoofing on local networks
  - Service redeployment windows where identity checks are temporarily bypassed

## Technical Details

### Prerequisites
- Attacker network position (local segment, rogue upstream DNS, or other interception path)
- Weak discovery protections (no DNSSEC validation, permissive local registry behavior, or missing duplicate-name checks)
- Trust model that treats name as identity without robust certificate validation
- Ability to register or advertise a malicious endpoint with legitimate-appearing metadata

### Attack Flow
1. **Preparation**: Attacker deploys a malicious endpoint that mimics a trusted MCP server name.
2. **Discovery Hijack**: DNS/mDNS responses or local registry entries are poisoned or duplicated.
3. **Connection**: Client resolves the trusted name to the attacker endpoint and initiates session setup.
4. **Impersonation**: Attacker presents weak or mismatched identity material and intercepts traffic.
5. **Exploitation**: Credentials, tokens, and sensitive data are harvested; malicious responses may be injected.
6. **Post-Exploitation**: Attacker persists through registry poisoning and can pivot to additional systems.

### Example Scenario
```json
{
  "service_name": "analytics-hub.local",
  "endpoint": "192.168.1.50",
  "certificate_fingerprint": "untrusted-self-signed",
  "source": "local-registry"
}
```

### Advanced Attack Techniques (Research Published)
According to public reporting and ATT&CK campaign tracking, attackers use multiple identity-hijack layers:

1. **DNS Cache Poisoning**: False DNS responses direct clients to malicious infrastructure.
2. **Registrar Hijacking**: Domain and DNS control are taken over to reroute traffic at scale (for example [Sea Turtle / G1041](https://attack.mitre.org/groups/G1041/)).
3. **Hybrid Discovery Poisoning**: DNS hijack combined with local network attacks (ARP/DHCP) to increase reliability and evade single-layer controls.

## Impact Assessment
- **Confidentiality**: High - credentials and sensitive data can be intercepted.
- **Integrity**: High - malicious responses can alter workflow outputs and decisions.
- **Availability**: Medium - service resolution failures and trust breaks can interrupt operations.
- **Scope**: Network-wide - affects any client relying on poisoned discovery/identity signals.

### Current Status (2026)
Organizations are increasingly prioritizing stronger discovery and identity controls, but coverage remains uneven:
- DNSSEC adoption continues to expand, but not all enterprise resolvers and zones validate consistently.
- MCP roadmap work includes stronger server identity/discovery signals through `.well-known` metadata endpoints.
- Teams with mixed legacy protocols and inconsistent registry governance remain exposed to name-collision attacks.

## Detection Methods

### Indicators of Compromise (IoCs)
- Sudden DNS resolution drift for trusted MCP server names
- Duplicate or conflicting server entries in local MCP registries
- ARP anomalies and MAC/IP mismatch events around MCP traffic
- TLS certificate mismatch or unexpected self-signed certificate acceptance
- Authentication failures and suspicious reconnect loops after resolution changes

### Detection Rules
**Important**: The following Sigma-style rule is an example. Organizations should tailor fields and event IDs to their telemetry pipeline and operating system logging configuration.

```yaml
title: Detection of Server Impersonation / Name-Collision (SAFE-T1004)
id: 9f3c2a8e-7d4b-4c2f-9a1e-8e2b7f9c1d23
status: experimental
description: Detects indicators of server impersonation or name-collision attacks across DNS, ARP, TLS, and local registry events
author: Ryan Jennings
date: 2025-11-22
modified: 2026-02-24
references:
  - https://github.com/SAFE-MCP/safe-mcp/tree/main/techniques/SAFE-T1004
  - https://attack.mitre.org/techniques/T1557/
  - https://attack.mitre.org/techniques/T1565/002/
logsource:
  product: windows
  service: system
detection:
  selection_dns:
    EventID: 1014
    Provider_Name: "Microsoft-Windows-DNS-Client"
    Message|contains:
      - "timed out after none of the configured DNS servers responded"
      - "DNSSEC validation failed"
  selection_odr:
    Provider_Name: "ODR"
    Message|contains:
      - "duplicate service registration"
      - "name collision"
  selection_arp:
    Provider_Name: "Microsoft-Windows-TCPIP"
    Message|contains:
      - "duplicate ARP entry"
      - "MAC address mismatch"
  selection_tls:
    EventID: 36882
    Provider_Name: "Schannel"
    Message|contains:
      - "certificate mismatch"
      - "self-signed certificate"
  condition: selection_dns or selection_odr or selection_arp or selection_tls
falsepositives:
  - Legitimate service redeployments that temporarily create duplicate registry entries
  - Controlled test environments using self-signed certificates
  - Planned DNS cutovers during maintenance windows
level: high
tags:
  - attack.credential_access
  - attack.t1557
  - attack.t1557.002
  - attack.t1565.002
  - safe.t1004
```

### Behavioral Indicators
- New duplicate service names for trusted MCP endpoints
- Increased DNS cache refreshes and resolver warning events for previously stable names
- Clients connecting to unexpected IP ranges for known servers
- TLS handshake failures or fallback behavior after certificate mismatches
- Correlated ARP anomalies near authentication or token exchange failures

## Mitigation Strategies

### Preventive Controls
1. **[SAFE-M-14: Server Allowlisting](../../mitigations/SAFE-M-14/README.md)**: Restrict MCP connections to explicit trusted domains/endpoints.
2. **[SAFE-M-2: Cryptographic Integrity for Tool Descriptions](../../mitigations/SAFE-M-2/README.md)**: Sign and verify tool metadata to reduce tampering and spoofing risk.
3. **[SAFE-M-6: Tool Registry Verification](../../mitigations/SAFE-M-6/README.md)**: Enforce trusted registry source controls and signature validation.
4. **[SAFE-M-45: Tool Manifest Signing & Server Attestation](../../mitigations/SAFE-M-45/README.md)**: Validate server identity and manifest integrity before accepting tools.
5. **[SAFE-M-29: Explicit Privilege Boundaries](../../mitigations/SAFE-M-29/README.md)**: Limit blast radius if a spoofed endpoint is accepted.

### Detective Controls
1. **[SAFE-M-12: Audit Logging](../../mitigations/SAFE-M-12/README.md)**: Log registry changes, server identity decisions, and endpoint shifts.
2. **[SAFE-M-20: Anomaly Detection](../../mitigations/SAFE-M-20/README.md)**: Detect unexpected discovery/connection behavior and resolution drift.
3. **[SAFE-M-11: Behavioral Monitoring](../../mitigations/SAFE-M-11/README.md)**: Correlate unusual tool behavior with identity and routing anomalies.

### Response Procedures
1. **Immediate Actions**:
   - Block malicious or untrusted endpoint IPs/domains.
   - Remove rogue local registry entries and disable affected server registrations.
   - Flush poisoned DNS and ARP caches on impacted hosts.
2. **Investigation Steps**:
   - Reconstruct timeline of DNS/registry/certificate changes.
   - Identify initial poisoning vector (DNS, ARP, DHCP, registry tampering).
   - Scope impacted clients and exposed credentials/tokens.
3. **Remediation**:
   - Rotate exposed credentials, tokens, and certificates.
   - Re-establish trusted server identity material and pinning policy.
   - Add preventive and detective controls for duplicate-name and identity drift.

## Related Techniques
- [SAFE-T1301](../SAFE-T1301/README.md): Cross-Server Tool Shadowing - exploits tool-name collisions in multi-server environments.
- [SAFE-T1407](../SAFE-T1407/README.md): Server Proxy Masquerade - uses intermediary infrastructure to impersonate trusted paths.
- [SAFE-T1005](../SAFE-T1005/README.md): Exposed Endpoint Exploit - broad endpoint exposure can enable impersonation opportunities.
- [SAFE-T1704](../SAFE-T1704/README.md): Compromised-Server Pivot - impersonation can provide a foothold for lateral movement.

## References
- [Model Context Protocol Specification](https://modelcontextprotocol.io/specification)
- [OWASP Top 10 for LLM Applications](https://owasp.org/www-project-top-10-for-large-language-model-applications/)
- [Sea Turtle - ATT&CK Group G1041](https://attack.mitre.org/groups/G1041/)
- [Windows ODR Tool (odr.exe)](https://learn.microsoft.com/en-us/windows/ai/mcp/odr-tool)
- [Internet Society - DNSSEC Deployment Maps](https://www.internetsociety.org/deploy360/dnssec/maps/)
- [APNIC DNSSEC Validation World Map](https://stats.labs.apnic.net/dnssec)
- [European Commission JRC Report on DNSSEC Adoption (2025)](https://publications.jrc.ec.europa.eu/repository/handle/JRC143100)
- [Model Context Protocol Roadmap](https://modelcontextprotocol.io/development/roadmap)

## MITRE ATT&CK Mapping
- [T1557 - Adversary-in-the-Middle](https://attack.mitre.org/techniques/T1557/)
- [T1557.002 - Adversary-in-the-Middle: ARP Cache Poisoning](https://attack.mitre.org/techniques/T1557/002/)
- [T1565.002 - Data Manipulation: DNS Manipulation](https://attack.mitre.org/techniques/T1565/002/)
- [T1071.004 - Application Layer Protocol: DNS](https://attack.mitre.org/techniques/T1071/004/)

## Version History
| Version | Date | Changes | Author |
|---------|------|---------|--------|
| 1.0 | 2025-11-22 | Initial documentation with ODR explanation | Ryan Jennings |
| 1.1 | 2026-02-24 | Replaced placeholder mitigations, corrected related-technique mapping, updated detection rule example, and added clearer ODR scope language | Bishnu Bista |
| 1.2 | 2026-02-24 | Corrected ATT&CK reference for Sea Turtle, aligned DNS EventID 1014 example wording, reduced over-specific ARP event assumptions, and added ODR/APNIC references for source clarity | Bishnu Bista |
