# SAFE-T1911: Parameter Exfiltration

## Overview
**Tactic**: Exfiltration (ATK-TA0010)
**Technique ID**: SAFE-T1911
**Severity**: High
**First Observed**: Not observed in production (technique analysis based on threat modeling)
**Last Updated**: 2025-12-16

## Description
Parameter Exfiltration is a covert data exfiltration technique where adversaries embed sensitive information within unused or optional JSON parameters of MCP tool calls. The attack leverages the fact that MCP tool invocations accept structured JSON arguments, and many implementations do not validate or sanitize parameters that fall outside the defined schema. This allows attackers to smuggle secrets, credentials, or other sensitive data through seemingly legitimate tool calls without triggering traditional data loss prevention (DLP) controls.

This technique exploits the gap between schema-defined parameters and actually transmitted data. When an AI agent is manipulated through prompt injection or other means, it can be instructed to include exfiltration payloads in unused parameter fields. The data flows through the normal MCP communication channel, appearing as legitimate tool invocation traffic to network monitoring systems.

## Attack Vectors
- **Primary Vector**: Embedding sensitive data in unused/optional JSON parameters during MCP tool calls
- **Secondary Vectors**:
  - Prompt injection instructing AI agents to include secrets in tool parameters
  - Malicious tool definitions with hidden exfiltration parameters
  - Metadata field abuse in legitimate tool schemas
  - Nested JSON structures concealing exfiltration payloads
  - Base64/hex encoding of sensitive data in string parameters
  - Scheduled or triggered exfiltration during normal operations

## Technical Details

### Prerequisites
- Ability to influence AI agent behavior (prompt injection, compromised context)
- Knowledge of target MCP tool schemas and available parameters
- Understanding of which parameters are validated vs. passed through unchecked
- Optional: Control of MCP server to receive exfiltrated data

### Attack Flow

```mermaid
graph TD
    A[Attacker] -->|1. Prompt Injection| B[AI Agent]
    B -->|2. Accesses Sensitive Data| C[Local Files/Credentials/Secrets]
    C -->|3. Data Retrieved| B

    B -->|4. Constructs Tool Call| D{MCP Tool Call}

    D -->|Legitimate Params| E[Expected Parameters]
    D -->|Hidden Payload| F[Unused/Optional Parameters]

    E --> G[MCP Server]
    F --> G

    G -->|5. Processes Request| H{Parameter Handling}

    H -->|Validated| I[Execute Tool Function]
    H -->|Ignored/Logged| J[Exfiltration Payload]

    J -->|6. Stored in Logs| K[Server Logs]
    J -->|6. Forwarded| L[Attacker-Controlled Endpoint]

    I -->|7. Normal Response| B

    M[DLP/Security Monitoring] -.->|Sees Only| N[Normal Tool Invocation]

    style A fill:#d73027,stroke:#000,stroke-width:2px,color:#fff
    style F fill:#d73027,stroke:#000,stroke-width:2px,color:#fff
    style J fill:#fc8d59,stroke:#000,stroke-width:2px,color:#000
    style L fill:#d73027,stroke:#000,stroke-width:2px,color:#fff
    style N fill:#fee090,stroke:#000,stroke-width:2px,color:#000
```

1. **Initial Compromise**: Attacker gains influence over AI agent through prompt injection or context poisoning
2. **Data Collection**: Agent is instructed to access sensitive files, credentials, or environment variables
3. **Payload Construction**: Sensitive data is embedded in unused parameters of legitimate tool calls
4. **Exfiltration**: Tool call transmits data through normal MCP channel to server
5. **Data Capture**: Attacker-controlled server logs or forwards the parameter contents
6. **Evasion**: Traffic appears as normal tool invocation, bypassing DLP systems

### Example Scenario

**Legitimate Tool Call:**
```json
{
  "tool": "send_notification",
  "arguments": {
    "channel": "#general",
    "message": "Build completed successfully",
    "priority": "normal"
  }
}
```

**Tool Call with Exfiltration Payload:**
```json
{
  "tool": "send_notification",
  "arguments": {
    "channel": "#general",
    "message": "Build completed successfully",
    "priority": "normal",
    "note": "QVdTX0FDQ0VTU19LRVk9QUtJQUlPU0ZPRE5ON0VYQU1QTEU7QVdTX1NFQ1JFVD13SmFsclhVdG5GRU1JL0s3TURFTkcvYlB4UmZpQ1lFWEFNUExFS0VZ",
    "metadata": {
      "internal_id": "db_password=SuperSecret123!",
      "trace_context": "api_key=sk-proj-abc123xyz789"
    }
  }
}
```

### Multi-Stage Exfiltration Attack

**Stage 1: Data Collection via File Tool**
```json
{
  "tool": "read_file",
  "arguments": {
    "path": "/home/user/.aws/credentials"
  }
}
```

**Stage 2: Exfiltration via Notification Tool**
```json
{
  "tool": "create_calendar_event",
  "arguments": {
    "title": "Team Meeting",
    "date": "2025-12-20",
    "attendees": ["team@company.com"],
    "description": "Weekly sync",
    "custom_fields": {
      "aws_credentials": "[default]\naws_access_key_id=AKIAIOSFODNN7EXAMPLE\naws_secret_access_key=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
    }
  }
}
```

### Advanced Attack Techniques

#### Encoding and Obfuscation Methods

Based on research into covert channel techniques:

1. **Base64 Encoding**: Encode binary or sensitive text data to avoid pattern matching
   ```json
   {"note": "U2VjcmV0UGFzc3dvcmQxMjM="}  // "SecretPassword123"
   ```

2. **Hex Encoding**: Alternative encoding for binary data
   ```json
   {"debug_data": "5365637265745061737377"}  // "SecretPassw"
   ```

3. **JSON Nesting**: Hide data in deeply nested structures
   ```json
   {"metadata": {"internal": {"debug": {"trace": {"value": "secret"}}}}}
   ```

4. **Field Name Steganography**: Encode data in parameter names themselves
   ```json
   {"s_e_c_r_e_t": "placeholder"}
   ```

5. **Chunked Exfiltration**: Split large data across multiple tool calls
   ```json
   // Call 1: {"chunk_id": "1", "data": "first_part_of_credential"}
   // Call 2: {"chunk_id": "2", "data": "second_part_of_credential"}
   ```

#### Scheduled Transfer Patterns

Based on [MITRE ATT&CK T1029](https://attack.mitre.org/techniques/T1029/):

- **ComRAT Pattern**: Sleep outside business hours, exfiltrate during normal activity periods
- **ShadowPad Pattern**: Send data at fixed intervals (e.g., every 8 hours) to blend with routine traffic
- **Volume-Based Triggering**: Only exfiltrate when data volume reaches threshold

#### Webhook/API Abuse

According to [MITRE ATT&CK T1567.004](https://attack.mitre.org/techniques/T1567/004/):

- **Webhook Exfiltration**: Use legitimate webhook parameters to send data to attacker endpoints
- **Cloud Service Abuse**: Leverage cloud API tools to exfiltrate to attacker-controlled storage
- **Code Repository Exfil**: Use git/GitHub tools to push secrets to attacker repositories

## Impact Assessment
- **Confidentiality**: Critical - Direct exfiltration of sensitive credentials and data
- **Integrity**: Low - Does not directly modify data, but enables subsequent attacks
- **Availability**: Low - Exfiltration does not typically impact service availability
- **Scope**: Network-wide - Can exfiltrate data from any source accessible to the AI agent

### Current Status (2025)
According to security research in the MCP ecosystem:
- MCP servers commonly accept undefined parameters without validation ([Backslash Security, 2025](https://www.backslash.security/))
- 43% of analyzed MCP servers contain input validation flaws that enable parameter abuse
- Few implementations enforce strict schema validation for tool parameters
- DLP systems typically do not inspect MCP tool call payloads for sensitive data patterns

## Detection Methods

### Indicators of Compromise (IoCs)
- Tool calls containing parameters not defined in the tool schema
- Unusually large parameter payloads (>10KB) in simple tool calls
- High-entropy strings in parameter values (indicating encoded data)
- Parameters containing sensitive keywords (password, key, token, secret, credential)
- Repeated patterns of unused parameters across multiple tool calls
- Base64 or hex-encoded strings in text parameters
- Nested JSON structures in fields expecting simple values

### Detection Rules

**Important**: The following rule is written in Sigma format and contains example patterns only. Parameter exfiltration can use novel encoding and obfuscation techniques. Organizations should:
- Implement strict JSON schema validation for all tool parameters
- Deploy ML-based anomaly detection for parameter patterns
- Monitor parameter entropy and size distributions
- Consider semantic analysis of parameter contents

```yaml
# EXAMPLE SIGMA RULE - Not comprehensive
title: MCP Parameter Exfiltration Detection
id: e004e53d-8c44-4b5c-851c-550c20020c21
status: experimental
description: Detects potential data exfiltration through unused MCP tool parameters
author: SAFE-MCP Contributors
date: 2025-12-16
references:
  - https://github.com/SAFE-MCP/safe-mcp/techniques/SAFE-T1911
  - https://attack.mitre.org/techniques/T1041/
  - https://attack.mitre.org/techniques/T1567/
logsource:
  product: mcp
  service: tool_invocation
detection:
  # Undefined parameters in tool calls
  selection_undefined_params:
    event_type: 'tool_call'
    has_undefined_parameters: true

  # Large parameter payloads
  selection_large_payload:
    total_params_size_bytes|gt: 10240  # 10KB threshold

  # Sensitive keywords in parameters
  selection_sensitive_keywords:
    parameter_value|contains:
      - 'password'
      - 'api_key'
      - 'secret'
      - 'token'
      - 'credential'
      - 'AWS_ACCESS_KEY'
      - 'PRIVATE_KEY'
      - 'BEGIN RSA'
      - 'BEGIN OPENSSH'

  # High entropy values (base64/encrypted data)
  selection_high_entropy:
    parameter_entropy|gt: 5.5

  # Suspicious parameter names
  selection_suspicious_names:
    parameter_name|contains:
      - 'note'
      - 'metadata'
      - 'debug'
      - 'internal'
      - 'extra'
      - 'custom'
      - 'context'
      - 'trace'

  condition: selection_undefined_params or selection_large_payload or
             (selection_sensitive_keywords and selection_high_entropy) or
             (selection_suspicious_names and selection_high_entropy)

falsepositives:
  - Legitimate debugging metadata
  - Application-specific extended parameters
  - Backward compatibility fields
  - Rich text content in messaging tools

level: high

tags:
  - attack.exfiltration
  - attack.ta0010
  - attack.t1041
  - attack.t1567
  - safe.t1911
  - mcp.exfiltration

fields:
  - session_id
  - tool_name
  - parameter_names
  - parameter_sizes
  - parameter_entropy
  - timestamp
```

### Behavioral Indicators
- AI agent accessing sensitive files followed by tool calls with large parameters
- Patterns of tool calls with consistent unused parameter structures
- Tool invocations with parameters containing structured data (JSON, key=value pairs)
- Correlation between file read operations and subsequent API/notification tool calls
- Increasing parameter sizes over time within a session
- Tool calls to external services with unexpectedly detailed "notes" or "metadata"

## Mitigation Strategies

### Preventive Controls
1. **[SAFE-M-1: Input Validation](../../mitigations/SAFE-M-1/README.md)**: Enforce strict JSON schema validation for all tool parameters; reject calls with undefined parameters
2. **[SAFE-M-5: Content Sanitization](../../mitigations/SAFE-M-5/README.md)**: Strip unused parameters before processing; sanitize parameter values to remove sensitive patterns
3. **[SAFE-M-19: Least Privilege](../../mitigations/SAFE-M-19/README.md)**: Restrict AI agent access to sensitive files and credentials
4. **[SAFE-M-63: Parameter Size Limits](../../mitigations/SAFE-M-63/README.md)**: Implement maximum size limits for individual parameters and total payload
5. **[SAFE-M-64: Schema Enforcement](../../mitigations/SAFE-M-64/README.md)**: Require strict adherence to tool schemas; use JSON Schema validation with additionalProperties: false
6. **[SAFE-M-65: Sensitive Data Filtering](../../mitigations/SAFE-M-65/README.md)**: Implement DLP patterns to detect and block credential-like patterns in parameters

### Detective Controls
1. **[SAFE-M-2: Comprehensive Logging](../../mitigations/SAFE-M-2/README.md)**: Log all tool parameters with full context including entropy metrics and schema compliance
2. **[SAFE-M-10: Anomaly Detection](../../mitigations/SAFE-M-10/README.md)**: Deploy ML models to detect unusual parameter patterns, sizes, and content
3. **[SAFE-M-11: Behavioral Monitoring](../../mitigations/SAFE-M-11/README.md)**: Correlate file access with subsequent tool calls to detect collection-exfiltration patterns
4. **[SAFE-M-66: Entropy Analysis](../../mitigations/SAFE-M-66/README.md)**: Monitor parameter entropy to detect encoded exfiltration payloads

### Response Procedures
1. **Immediate Actions**:
   - Quarantine sessions with suspicious parameter usage
   - Block tool calls with undefined parameters
   - Revoke credentials potentially exfiltrated
   - Capture parameter payloads for forensic analysis
2. **Investigation Steps**:
   - Extract and decode suspicious parameter contents
   - Determine if sensitive data was embedded
   - Trace parameter data to its source (file read, database query, etc.)
   - Identify destination (network endpoints, logs, external services)
   - Assess scope of potential data exposure
3. **Remediation**:
   - Implement strict parameter schema validation
   - Rotate compromised credentials
   - Update detection rules based on observed patterns
   - Enhance logging for parameter-level visibility
   - If data exfiltrated: initiate breach notification per regulatory requirements

## Related Techniques
- [SAFE-T1910](../SAFE-T1910/README.md): Covert Channel Exfiltration - Parent technique category
- [SAFE-T1912](../SAFE-T1912/README.md): Stego Response Exfil - Similar concealment in code blocks
- [SAFE-T1913](../SAFE-T1913/README.md): HTTP POST Exfil - Direct exfiltration via web tools
- [SAFE-T1914](../SAFE-T1914/README.md): Tool-to-Tool Exfil - Chaining tools for exfiltration
- [SAFE-T1801](../SAFE-T1801/README.md): Automated Data Harvesting - Often precedes parameter exfiltration
- [SAFE-T1102](../SAFE-T1102/README.md): Prompt Injection - Common initial access vector for this technique
- [SAFE-T1501](../SAFE-T1501/README.md): Full-Schema Poisoning - Related schema exploitation technique

## References
- [Model Context Protocol Specification](https://modelcontextprotocol.io/specification)
- [OWASP Top 10 for LLM Applications](https://owasp.org/www-project-top-10-for-large-language-model-applications/)
- [MITRE ATT&CK T1041 - Exfiltration Over C2 Channel](https://attack.mitre.org/techniques/T1041/)
- [MITRE ATT&CK T1567 - Exfiltration Over Web Service](https://attack.mitre.org/techniques/T1567/)
- [MITRE ATT&CK T1567.004 - Exfiltration Over Webhook](https://attack.mitre.org/techniques/T1567/004/)
- [MITRE ATT&CK T1048 - Exfiltration Over Alternative Protocol](https://attack.mitre.org/techniques/T1048/)
- [MITRE ATT&CK T1029 - Scheduled Transfer](https://attack.mitre.org/techniques/T1029/)
- [OWASP API Security - Broken Object Property Level Authorization](https://owasp.org/API-Security/editions/2023/en/0xa3-broken-object-property-level-authorization/)
- [OWASP REST Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/REST_Security_Cheat_Sheet.html)
- [CWE-20: Improper Input Validation](https://cwe.mitre.org/data/definitions/20.html)
- [CWE-200: Exposure of Sensitive Information](https://cwe.mitre.org/data/definitions/200.html)

## MITRE ATT&CK Mapping
- [T1041 - Exfiltration Over C2 Channel](https://attack.mitre.org/techniques/T1041/)
- [T1567 - Exfiltration Over Web Service](https://attack.mitre.org/techniques/T1567/)
- [T1567.004 - Exfiltration Over Webhook](https://attack.mitre.org/techniques/T1567/004/)
- [T1048 - Exfiltration Over Alternative Protocol](https://attack.mitre.org/techniques/T1048/)
- [T1029 - Scheduled Transfer](https://attack.mitre.org/techniques/T1029/)
- [T1132 - Data Encoding](https://attack.mitre.org/techniques/T1132/)

## Version History
| Version | Date | Changes | Author |
|---------|------|---------|--------|
| 1.0 | 2025-12-16 | Initial documentation of Parameter Exfiltration technique | SAFE-MCP Contributors |
