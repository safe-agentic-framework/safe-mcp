# SAFE-M-41: Supply Chain Control – Tool and Package Pinning

## Overview  
**Mitigation ID**: SAFE-M-41  
**Category**: Supply Chain Control  
**Effectiveness**: High (Prevents unauthorized tool swaps and metadata tampering)  
**Implementation Complexity**: Medium  
**First Published**: April 2025

## Description  
Tool and Package Pinning is a supply chain integrity control that ensures MCP clients and agents only use trusted versions of tools and server packages. It prevents unauthorized updates, rug-pull server swaps, and Shadow Tool injection by cryptographically verifying the integrity of tool metadata and server-side components before execution.

This mitigation uses version locking, hash verification, and digital signing to ensure that tools and packages remain consistent across deployments. It protects against both external attackers and insider threats by enforcing immutability and traceability of tool configurations. Tools like **Sigstore** enable transparent signing and verification of MCP tool manifests, making it easy to audit and trust the supply chain.

## Mitigates  
- [SAFE-T1402](../../techniques/SAFE-T1402/README.md): Instruction Steganography  
- [SAFE-T1403](../../techniques/SAFE-T1403/README.md): Context Poisoning  
- [SAFE-T1401](../../techniques/SAFE-T1401/README.md): Direct Prompt Injection  
- Rug Pull Server Swapping  
- Shadow Tool Injection  

## Technical Implementation

### Core Principles  
1. **Version Locking**: Pin tool versions and MCP server builds to prevent unauthorized updates.  
2. **Hash Verification**: Use SHA-256 or stronger hashes to verify tool metadata integrity.  
3. **Digital Signing**: Sign tool manifests and registry updates using tools like Sigstore.  
4. **Immutable Registries**: Prevent overwrites or silent updates to registered tools.

### Architecture Components
```
+------------------+       +------------------+       +------------------+
| Tool Registry    | --->  | Integrity Verifier| ---> | Agent Execution |
+------------------+       +------------------+       +------------------+
        |                          |                          |
        |                          v                          v
        |                 [Signed & Pinned Tools]       [Trusted Execution]
        v
[Sigstore Transparency Log]
```

### Prerequisites  
- MCP registry with versioning support  
- Hashing and signing infrastructure (e.g., Sigstore, cosign)  
- Agent-side verification hooks  

### Implementation Steps  
1. **Design Phase**:  
   - Define versioning and hash policies for tools and packages  
   - Select signing infrastructure (e.g., Sigstore, GPG, SLSA-compliant pipeline)  

2. **Development Phase**:  
   - Implement hash verification and signature checks in agent runtime  
   - Integrate Sigstore signing into CI/CD pipeline for tool registration  

3. **Deployment Phase**:  
   - Pin all tool versions in client config  
   - Publish signed manifests to transparency log  
   - Reject unsigned or tampered tools at runtime  

## Benefits  
- **Prevents Tool Swaps**: Blocks rug-pull attacks and unauthorized updates  
- **Protects Against Shadow Tools**: Ensures only audited tools are executed  
- **Improves Supply Chain Trust**: Enables cryptographic verification of tool provenance  
- **Supports Forensic Auditing**: Transparency logs allow post-incident investigation  

## Limitations  
- **Requires Signing Infrastructure**: Needs integration with tools like Sigstore or GPG  
- **Operational Overhead**: Adds complexity to registry updates and CI/CD workflows  
- **Does Not Detect Behavioral Drift**: Must be paired with runtime monitoring for full coverage  

## Implementation Examples

### Example 1: Sigstore Signing and Verification
```bash
# Sign tool manifest
cosign sign --key cosign.pub tool-manifest.json

# Verify signature before execution
cosign verify --key cosign.pub tool-manifest.json
```

### Example 2: Pinned Tool Configuration
```json
{
  "tool_registry": {
    "pinned_versions": {
      "summarizer": "v2.3.1",
      "translator": "v1.9.0"
    },
    "hashes": {
      "summarizer@v2.3.1": "sha256:abc123...",
      "translator@v1.9.0": "sha256:def456..."
    },
    "signature_required": true
  }
}
```

## Testing and Validation

1. **Security Testing**:  
   - Attempt tool swaps and verify rejection  
   - Tamper with metadata and test hash mismatch alerts  
   - Validate signature enforcement using Sigstore  

2. **Functional Testing**:  
   - Confirm agents load only pinned versions  
   - Ensure registry updates require re-signing  
   - Measure latency impact of verification  

3. **Integration Testing**:  
   - Validate compatibility with CI/CD pipelines  
   - Confirm agent-side enforcement across environments  

## Deployment Considerations

### Resource Requirements  
- **CPU**: Low (hash and signature checks)  
- **Memory**: Minimal  
- **Storage**: Transparency logs and signed manifests  
- **Network**: Minimal (log sync and key retrieval)  

### Performance Impact  
- **Latency**: ~5–10ms per verification  
- **Throughput**: No significant impact  
- **Resource Usage**: Lightweight  

### Monitoring and Alerting  
- Alert on hash mismatches  
- Alert on unsigned tool usage  
- Monitor transparency log for unauthorized entries  
- Audit registry update history  

## Current Status (2025)  
According to industry reports:  
- 48% of MCP vendors now implement tool pinning and hash verification  
- Sigstore adoption is growing in LLM supply chains for manifest signing  
- OWASP LLM Top 10 recommends cryptographic integrity checks for tool registries  

## References  
- [Sigstore Project](https://www.sigstore.dev/)  
- [OWASP Top 10 for LLM Applications](https://owasp.org/www-project-top-10-for-large-language-model-applications/)  
- [Model Context Protocol Specification](https://modelcontextprotocol.io/specification)  
- [MCPTox Benchmark – Arxiv, 2025](https://arxiv.org/abs/2508.14925)

## Related Mitigations  
- [SAFE-M-37](../SAFE-M-37/README.md): Metadata Sanitization – Prevents hidden payloads in tool fields  
- [SAFE-M-43](../SAFE-M-43/README.md): Steganography Scanner – Detects tampered or suspicious metadata  
- [SAFE-M-44](../SAFE-M-44/README.md): Behavioral Monitoring – Detects runtime anomalies from compromised tools  

## Version History  
| Version | Date | Changes | Author |  
|---------|------|---------|--------|  
| 1.0 | 2025-10-25 | Initial documentation | Ryan Jennings |

