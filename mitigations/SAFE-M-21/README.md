# SAFE-M-21: Output Context Isolation

## Overview
**Mitigation ID**: SAFE-M-21  
**Category**: Architectural Control  
**Effectiveness**: High  
**Implementation Complexity**: Low  
**First Published**: 2025-01-09

## Description
Output Context Isolation uses special delimiters or structured formatting (such as XML-style tags) to clearly separate tool outputs from system instructions in the LLM context. This architectural pattern ensures that data returned by tools cannot be interpreted as instructions by implementing clear boundaries between different types of content. For example, wrapping tool outputs in `<tool-output>...</tool-output>` tags helps the LLM maintain context awareness.

## Mitigates
- [SAFE-T1102](../../techniques/SAFE-T1102/README.md): Prompt Injection (Multiple Vectors)
- [SAFE-T1103](../../techniques/SAFE-T1103/README.md): Indirect Prompt Injection
- [SAFE-T1112](../../techniques/SAFE-T1112/README.md): Sampling Request Abuse — nested `sampling/createMessage` output must be held logically separate from planner state until reviewed, logged, and policy-checked, so a malicious server's sampling response cannot directly seed subsequent reasoning

## Technical Implementation
[TO BE COMPLETED]

## References
[TO BE COMPLETED]

## Related Mitigations
- [SAFE-M-1](../SAFE-M-1/README.md): Architectural Defense - Control/Data Flow Separation
- [SAFE-M-5](../SAFE-M-5/README.md): Content Sanitization

## Version History
| Version | Date | Changes | Author |
|---------|------|---------|--------|
| 0.1 | 2025-01-09 | Initial documentation | Frederick Kautz |