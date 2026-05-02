# SAFE-M-15: User Warning Systems

## Overview
**Mitigation ID**: SAFE-M-15  
**Type**: Preventive Control  
**Complexity**: Low  
**Effectiveness**: Medium  

## Description
Display clear warnings when sensitive client-mediated flows are initiated, surfacing the requesting MCP server and the full operation being authorized so users can identify phishing or over-scoped requests before approval. Applies to OAuth authorization flows (showing requesting server and target service), `sampling/createMessage` approval UX (showing the complete sampling prompt, requested tools, model constraints, and token budget), and other client-mediated operations where a malicious or compromised server can abuse weak or truncated review.

## Implementation
[To be documented]

## Related Techniques
- [SAFE-T1007](../../techniques/SAFE-T1007/README.md): OAuth Authorization Phishing
- [SAFE-T1006](../../techniques/SAFE-T1006/README.md): User-Social-Engineering Install
- [SAFE-T1112](../../techniques/SAFE-T1112/README.md): Sampling Request Abuse — approval UX must expose the full sampling prompt, `tools` array, `toolChoice`, and `maxTokens` so users can review nested model calls before authorizing them

## References
- [OWASP Top 10 for LLM Applications](https://owasp.org/www-project-top-10-for-large-language-model-applications/)