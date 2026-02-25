# SAFE-M-43: Detective Control – Steganography Scanner

## Overview
**Mitigation ID**: SAFE-M-43  
**Category**: Detective Control  
**Effectiveness**: Medium-High (Detects hidden characters and steganographic payloads in metadata)  
**Implementation Complexity**: Medium  
**First Published**: April 2025

## Description
Steganography Scanner is a detective control that audits MCP tool configurations for hidden instructions embedded via zero-width characters, HTML comments, or obfuscated prompt fragments. It analyzes metadata fields such as `description`, `parameters`, and `examples` to identify invisible or malformed content that could influence LLM behavior.

This mitigation is critical in environments where tool metadata is parsed by models as part of prompt context. Attackers exploit this by embedding payloads that evade human review and basic sanitization. The scanner flags suspicious patterns, enabling security teams to quarantine or sanitize affected tools before they are used in production.  This scanner is particularly effective against Shadow Tools, which embed steganographic payloads in metadata while appearing benign. By flagging hidden characters and markup, it exposes these tools before they are used.

## Mitigates
- [SAFE-T1402](../../techniques/SAFE-T1402/README.md): Instruction Steganography
- [SAFE-T1403](../../techniques/SAFE-T1403/README.md): Context Poisoning
- [SAFE-T1401](../../techniques/SAFE-T1401/README.md): Direct Prompt Injection

## Technical Implementation

### Core Principles
1. **Character Inspection**: Detect zero-width and non-printable Unicode characters in metadata.
2. **Markup Detection**: Identify HTML comments and hidden tags.
3. **Entropy Analysis**: Flag low-entropy or highly repetitive strings that may encode payloads.

### Architecture Components
```
+------------------+       +------------------+       +------------------+
| Tool Registry    | --->  | Steganography Scanner | --->  | Alerting System |
+------------------+       +------------------+       +------------------+
        |                          |                          |
        |                          v                          v
        |                 [Flagged Metadata]         [Security Dashboard]
        v
[Tool Config Database]
```

### Prerequisites
- Access to tool metadata (e.g., via MCP registry API)
- Scanner engine with Unicode and markup parsing capabilities

### Implementation Steps
1. **Design Phase**:
   - Define detection rules for steganographic patterns
   - Specify alert thresholds and quarantine policies

2. **Development Phase**:
   - Build scanner using regex, Unicode inspection, and entropy checks
   - Integrate with MCP registry or CI pipeline

3. **Deployment Phase**:
   - Run scanner on all existing tool configs
   - Set up alerts for flagged entries

## Benefits
- **Early Detection**: Identifies hidden payloads before tools are used by agents
- **Supports Forensics**: Enables investigation of prompt injection attempts
- **Improves Metadata Hygiene**: Encourages clean and reviewable tool descriptions
- **Detects Shadow Tools**: Flags tools with hidden payloads that mimic legitimate configurations

## Limitations
- **False Positives**: May flag legitimate multilingual or formatted content
- **Evasion Risk**: Attackers may develop new encoding schemes
- **Requires Manual Review**: Flagged entries often need human validation

## Implementation Examples

### Example 1: Python Scanner
```python
import re

def scan_metadata(text):
    zero_width = re.findall(r'[\u200B-\u200D\u2060\uFEFF]', text)
    html_comments = re.findall(r'<!--.*?-->', text)
    return {
        "zero_width_count": len(zero_width),
        "html_comment_count": len(html_comments),
        "flagged": bool(zero_width or html_comments)
    }
```

### Example 2: Configuration Policy
```json
{
  "steganography_scanner": {
    "enabled": true,
    "alert_thresholds": {
      "zero_width": 5,
      "html_comments": 1
    },
    "quarantine_on_flag": true
  }
}
```

## Testing and Validation
1. **Security Testing**:
   - Inject known steganographic payloads and verify detection
   - Test HTML comment injection scenarios
   - Validate against MCPTox benchmark samples

2. **Functional Testing**:
   - Ensure scanner does not block valid metadata
   - Confirm alerting and quarantine workflows
   - Measure scan latency

3. **Integration Testing**:
   - Validate compatibility with MCP registry APIs
   - Confirm dashboard integration and alert visibility

## Deployment Considerations

### Resource Requirements
- **CPU**: Moderate (string parsing and entropy analysis)
- **Memory**: Low
- **Storage**: Minimal (scan logs only)
- **Network**: No impact

### Performance Impact
- **Latency**: ~10–20ms per scan
- **Throughput**: Scales with registry size
- **Resource Usage**: Moderate

### Monitoring and Alerting
- Number of flagged tool configs
- Frequency of zero-width character detections
- Alert on repeated violations by same source
- Alert on entropy anomalies

## Current Status (2025)
According to industry reports, organizations are adopting this mitigation:
- MCP-Scan tool released by Invariant Labs is used by 38% of vendors (2025)
- OWASP LLM Top 10 recommends scanning for hidden prompt injection vectors

## References
- [Model Context Protocol Specification](https://modelcontextprotocol.io/specification)
- [OWASP Top 10 for LLM Applications](https://owasp.org/www-project-top-10-for-large-language-model-applications/)
- [Tool Poisoning Attacks – Invariant Labs, 2025](https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks)
- [MCPTox Benchmark – Arxiv, 2025](https://arxiv.org/abs/2508.14925)

## Related Mitigations
- [SAFE-M-37](../SAFE-M-37/README.md): Metadata Sanitization – Removes hidden characters from flagged fields
- [SAFE-M-38](../SAFE-M-38/README.md): Schema Validation – Prevents malformed metadata from entering the system

## Version History
| Version | Date | Changes | Author |
|---------|------|---------|--------|
| 1.0 | 2025-10-25 | Initial documentation | Ryan Jennings |

