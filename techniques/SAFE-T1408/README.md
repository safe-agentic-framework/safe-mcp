
# SAFE-T1408: OAuth Protocol Downgrade

## Overview
**Tactic**: Credential Access (ATK-TA0006)  
**Technique ID**: SAFE-T1408  
**Severity**: High  
**First Observed**: Documented in OAuth 2.0 Security BCP (2020)  
**Last Updated**: November 2025  
**Author**: Ryan Jennings

## Description
OAuth Protocol Downgrade occurs when an attacker forces an MCP server or client to use a less secure OAuth 2.0 flow (such as the implicit grant) instead of the authorization code flow with PKCE. This bypasses modern protections and exposes tokens in the browser or front channel, making them easier to intercept.

Within MCP or AI-integrated systems, attackers exploit weak client registration or misconfigured authorization servers. By manipulating `response_type` parameters or exploiting legacy compatibility, they downgrade the protocol, causing the MCP server to issue tokens insecurely. This enables session hijacking and unauthorized access to sensitive AI contexts or data.

## Attack Vectors
- **Primary Vector**: Manipulation of OAuth `response_type=token` to force implicit flow  
- **Secondary Vectors**:  
  - Exploiting legacy client configurations that still allow implicit flow  
  - Leveraging misconfigured authorization servers that permit multiple flows

## Technical Details

### Prerequisites
- Authorization server that supports implicit flow  
- Client application registered with insecure or legacy settings

### Attack Flow
1. **Initial Stage**: Attacker identifies MCP server or client supporting multiple OAuth flows.  
2. **Downgrade Negotiation**: Attacker manipulates request parameters (`response_type=token`) to force implicit flow.  
3. **Token Exposure**: Access token is returned in the URL fragment to the browser.  
4. **Exploitation Stage**: Attacker intercepts token via logs, referrer headers, or malicious extensions.  
5. **Post-Exploitation**: Attacker reuses token to impersonate user and access MCP resources.

### Example Scenario
```json
// Example OAuth request forcing implicit flow
{
  "client_id": "mcp-client",
  "redirect_uri": "https://attacker.example/callback",
  "response_type": "token",
  "scope": "read write"
}
```

### Advanced Attack Techniques (2020 Research Published)
According to research from the IETF OAuth 2.0 Security Best Current Practice (RFC 9700) and OWASP OAuth 2.0 Security Cheat Sheet, attackers have developed sophisticated variations:

1. **Forced Downgrade via Client Misregistration**: Exploiting clients registered with both implicit and code flows.  
2. **Token Replay in SPAs**: Using stolen tokens from browser history or logs to impersonate users.

---

### Threat Chain

1. **Downgrade Success**  
   - Attacker forces MCP server/client into implicit flow.  
   - Tokens are exposed in the browser or logs.

2. **Token Theft**  
   - Attacker harvests tokens via referrer headers, browser extensions, or compromised endpoints.  
   - Tokens act as bearer credentials.

3. **Session Hijacking (Local Impact)**  
   - Attacker impersonates the victim within the MCP server.  
   - Gains access to sensitive contexts, prompts, or AI workflows.

4. **Lateral Movement (Across MCP Servers)**  
   - If multiple MCP servers trust the same IdP, attacker reuses tokens.  
   - Exploits federated trust to pivot into adjacent servers.

5. **External Service Abuse**  
   - Tokens may grant access to SaaS integrations (email, storage, calendars).  
   - Attacker exfiltrates data or impersonates the victim in external platforms.

6. **LLM-Specific Exploitation**  
   - Hijacked sessions allow prompt injection or malicious context manipulation.  
   - Attacker can poison data, override instructions, or abuse connectors to external services.  
   - Potential for chained attacks: MCP → LLM → external API.

7. **Persistence & Replay**  
   - Without refresh rotation or audience restriction, attacker reuses tokens until expiry.  
   - May automate replay across multiple services.

flowchart TD
    A[Downgrade Success] --> B[Token Theft]
    B --> C[Session Hijacking (Local Impact)]
    C --> D[Lateral Movement Across MCP Servers]
    D --> E[External Service Abuse]
    E --> F[LLM-Specific Exploitation]
    F --> G[Persistence & Replay]

---

## Impact Assessment
- **Confidentiality**: High – Tokens exposed in front channel can be stolen.  
- **Integrity**: Medium – Attackers can impersonate users and alter MCP context.  
- **Availability**: Low – Attack does not directly affect service uptime.  
- **Scope**: Network-wide – Any client/server supporting implicit flow is vulnerable.

### Current Status (2025)
According to security researchers, organizations are beginning to implement mitigations:  
- OAuth 2.1 formally removes implicit flow (IETF Draft)  
- Major IdPs (Azure AD, Okta, Auth0) now disable implicit grant by default  
- HTTP Message Signatures (RFC 9421) are being adopted to protect request integrity and prevent parameter tampering

---

## Detection Methods

### Indicators of Compromise (IoCs)
- Requests with `response_type=token`  
- Tokens appearing in URL fragments or logs  
- Unexpected access tokens in browser history

### Detection Rules
```yaml
title: OAuth Implicit Flow Downgrade Detection
id: 123e4567-e89b-12d3-a456-426614174000
status: experimental
description: Detects attempts to force OAuth implicit flow in MCP context
author: Ryan Jennings
date: 2025-11-21
references:
  - https://github.com/safe-mcp/techniques/SAFE-T1408
logsource:
  product: mcp
  service: auth
detection:
  selection:
    oauth.response_type:
      - 'token'
      - 'id_token'
  condition: selection
falsepositives:
  - Legacy clients not yet migrated
level: high
tags:
  - attack.credential_access
  - attack.t1408
  - safe.t1408
```

### Behavioral Indicators
- MCP clients requesting tokens directly in redirect URIs  
- Tokens logged in browser or proxy logs

---

## Mitigation Strategies

### Preventive Controls
1. **SAFE-M-101: Disable Implicit Flow**: Configure authorization server to reject `response_type=token`.  
2. **SAFE-M-102: Enforce PKCE**: Require PKCE for all public clients.  
3. **SAFE-M-103: Client Registration Hardening**: Allow only authorization code flow with PKCE.  
4. **SAFE-M-104: HTTP Message Signatures**: Use RFC 9421 to sign requests, preventing parameter tampering and downgrade attempts.  
5. **SAFE-M-105: Audience and Scope Restriction**: Bind tokens to specific resources and minimize privileges.  
6. **SAFE-M-106: Secure Token Storage**: Ensure tokens are never stored in URLs, logs, or insecure browser storage.

### Detective Controls
1. **SAFE-M-201: Log Monitoring**: Detect requests with implicit flow parameters.  
2. **SAFE-M-202: Token Exposure Alerts**: Alert when tokens appear in URL fragments.  
3. **SAFE-M-203: Replay Detection**: Monitor for repeated use of the same token across multiple MCP servers.

### Response Procedures
1. **Immediate Actions**:  
   - Block suspicious client registrations  
   - Invalidate exposed tokens  
2. **Investigation Steps**:  
   - Review logs for downgrade attempts  
   - Identify affected clients  
3. **Remediation**:  
   - Update client configurations to disallow implicit flow  
   - Patch authorization server to enforce OAuth 2.1 compliance  
   - Rotate signing keys and refresh tokens

---

## Related Techniques
- [SAFE-T1007](../SAFE-T1007/README.md): OAuth Authorization Phishing – Exploit OAuth flows to steal access tokens
- [SAFE-T1009](../SAFE-T1009/README.md): Authorization Server Mix-up – Client follows redirect to look-alike server
- [SAFE-T1202](../SAFE-T1202/README.md): OAuth Token Persistence - Theft and reuse of OAuth access/refresh tokens for persistent access
- [SAFE-T1308](../SAFE-T1308/README.md): Token Scope Substitution - Swaps a limited-scope token with one that has broader permissions
- [SAFE-T1507](../SAFE-T1507/README.md): Authorization Code Interception - Man-in-the-browser attack steals OAuth authorization codes during the redirect flow
- [SAFE-T1706](../SAFE-T1706/README.md): OAuth Token Pivot Replay - Reuses OAuth tokens across different services that fail to validate audience claims

---

## References
- [Model Context Protocol Specification](https://modelcontextprotocol.io/specification)  
- [OWASP Top 10 for LLM Applications](https://owasp.org/www-project-top-10-for-large-language-model-applications/)  
- [RFC 9700: OAuth 2.0 Security Best Current Practice – IETF, 2025](https://www.ietf.org/rfc/rfc9700.html)  
- [OAuth 2.1 Authorization Framework – IETF Draft](https://datatracker.ietf.org/doc/draft-ietf-oauth-v2-1/)  
- [OWASP OAuth 2.0 Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/OAuth2_Cheat_Sheet.html)  
- [NIST SP 800‑63B‑4 Digital Identity Guidelines: Authentication and Authenticator Management](https://csrc.nist.gov/pubs/sp/800/63/b/4/final)  
- [RFC 9421: HTTP Message Signatures – IETF, 2023](https://www.rfc-editor.org/rfc/rfc9421.html)

---

## MITRE ATT&CK Mapping
- [T1556.007 - Modify Authentication Process: OAuth Abuse](https://attack.mitre.org/techniques/T1556/007/)  
- [T1078 - Valid Accounts](https://attack.mitre.org/techniques/T1078/)
- [T1550 - Use Alternate Authentication](https://attack.mitre.org/techniques/T1550/)
- [T1566.002 - Phishing: Spearphishing Link](https://attack.mitre.org/techniques/T1566/002/)

---

## Version History
| Version | Date | Changes | Author |
|---------|------|---------|--------|
| 1.0 | 2025-11-21 | Initial documentation | Ryan Jennings |
