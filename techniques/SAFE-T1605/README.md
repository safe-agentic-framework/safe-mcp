# SAFE-T1605: Capability Mapping

## Tactic

Discovery (ATK-TA0007)

## Description

Capability Mapping is an adaptation of MITRE ATT&CK’s Discovery tactic (TA0007) to Model Context Protocol (MCP) environments. Instead of scanning networks or enumerating hosts, an adversary coaxes an MCP agent or LLM-based assistant into describing its own tools, workflows, and policy exceptions. Innocuous prompts such as “What can you do?” or “List the automations you have” yield authoritative inventories of high-value capabilities—database writers, cloud-control hooks, file-system operators—without any external probing.

Armed with this intelligence, the attacker quickly prioritizes follow-on actions. Because responses often include parameters, guardrails, and sample payloads, Capability Mapping drastically shortens the path to privilege escalation or data theft compared with traditional trial-and-error reconnaissance.

### Capability Mapping as LLM-Native Reconnaissance

Capability Mapping in MCP environments mirrors traditional reconnaissance techniques, translated into an LLM and agent-tooling context. Rather than scanning hosts or ports, adversaries probe agent behavior, tool invocation paths, and registry exposure to enumerate high-value capabilities.

| Traditional Reconnaissance | MCP / LLM Analog |
| -------------------------- | ---------------- |
| Social engineering | Prompt framing such as “I heard this agent can deploy infrastructure.” |
| Network scanning | Observing which tools are invoked and how failures manifest. |
| Service discovery | Probing available MCP registries, plugins, or tool namespaces. |
| OS fingerprinting | Testing guardrails, sandbox limits, or execution constraints. |
| User / group enumeration | Asking whether different users or roles have access to different tools. |

This reconnaissance phase materially reduces attacker uncertainty and accelerates follow-on exploitation of privileged automations.

## How It Works

1. Ask meta-questions (“summarize your API surface,” “which tools are enabled right now?”) to elicit structured tool manifests.  
2. Iterate on phrasing until the model discloses parameters, prerequisites, and side effects for each tool or workflow.  
3. Correlate disclosed tools with known weaknesses (over-privileged storage access, unrestricted HTTP fetchers, credential rotators).  
4. Launch tailored prompt injections or chained tool invocations targeting the exposed high-value capabilities, often without tripping coarse anomaly detectors.

## Examples

An attacker could join a shared MCP assistant, casually ask ‘Walk me through every action you’re allowed to perform for DevOps,’ receive a list that includes `deploy_kubernetes_cluster`, `rotate_database_credentials`, and `read_secret_store`, and then craft prompt injections that trick the agent into invoking those tools on the attacker’s behalf.

## Impact

- Confidentiality: **High** – Capability inventories expose data-access tools and secret-bearing workflows.  
- Integrity: **Medium** – Precise knowledge of privileged automations enables tampering with configs, pipelines, or prompts.  
- Availability: **Low** – Discovery itself is non-destructive, though mapped tools can later be abused to disrupt services.

**Consequences:** With an accurate capability map, adversaries align social-engineering scripts to real tool names, skip blind experimentation, and focus directly on the most damaging automations.

## Detection

How defenders can identify this attack:

- **Log patterns**: repeated prompts like “list tools,” “describe abilities,” or “what external systems can you reach?”; sessions that request enumerations immediately after authentication.  
- **Behavioral indicators**: sudden interest in policy/system prompts or manifest files, chained requests that mirror tool names just disclosed.  
- **Monitoring strategies**: instrument prompt telemetry for enumeration phrases, correlate with RBAC context, and alert when low-privilege users ask for privileged tool descriptions.
- **Detection assets**: the Sigma-style rule in [detection-rule.yml](./detection-rule.yml) flags early-session capability-enumeration prompts aligned with TA0007/T1592, and the lightweight harness [test_detection_rule.py](./test_detection_rule.py) plus sample logs ([test-logs.json](./test-logs.json)) help validate the rule against both malicious and benign scenarios.

#### Additional Capability Enumeration Scenarios

- **Progressive probing** – a sequence of partial or seemingly benign questions that converge on a complete capability map over multiple interactions.
- **Indirect enumeration** – queries framed as best-practice, limitations, or comparisons rather than explicit requests for tool lists.
- **Registry inference** – prompts that imply prior knowledge of MCP registry structure or naming conventions to elicit confirmation from the agent.

### Note on Detection Assets

The detection rules and executable harness included with SAFE-T1605 are **illustrative reference implementations**, not production-tuned signatures. They are intended to demonstrate *observable patterns* of capability enumeration behavior rather than prescribe fixed thresholds or phrases.

Real-world deployments **should**:

- Tune thresholds based on baseline agent usage.
- Adapt phrase matching to domain-specific language.
- Correlate signals over time rather than rely on single prompts.

## Mitigation

How to prevent or minimize this attack:

1. **Configuration hardening** – Redact verbose tool manifests; disclose only the minimal capabilities per policy.  
2. **Access controls** – Require scoped authorization before describing or invoking sensitive tools; enforce least privilege.  
3. **Input validation** – Filter or refuse prompts seeking system prompts, tool catalogs, or policy internals.  
4. **Monitoring requirements** – Capture “what can you do” style prompts, correlate with user risk, and rate-limit repeated enumeration attempts.

## References

- [MITRE ATT&CK Discovery Tactic (TA0007)](https://attack.mitre.org/tactics/TA0007/)
- [MITRE ATT&CK T1592 – Gather Victim Host Information](https://attack.mitre.org/techniques/T1592/)
- [Model Context Protocol Specification](https://modelcontextprotocol.io/specification)
- [OWASP LLM Top 10 – LLM01 Prompt Injection Mitigations](https://llmtop10.com/llm01-prompt-injection/#mitigations)
- [OWASP ASVS v4.0.3 – Access Control Verification](https://github.com/OWASP/ASVS/blob/master/4.0/en/0x12-V4-Access-Control.md)
- [OWASP Input Validation Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html)
- [NIST SP 800-53 Rev. 5, Update 1 (AU-6, SI-4, AC-6)](https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final)
- [Invariant Labs: MCP Safety Audit Research](https://arxiv.org/abs/2504.03767)

SAFE-T1605 also aligns with reconnaissance concepts from MITRE ATT&CK adversary emulation, adapted for LLM-mediated and agent-orchestrated systems.

## MITRE ATT&CK Mapping

ATT&CK Technique: T1592 – Gather Victim Host Information  
ATT&CK Tactic: Discovery (TA0007)

## Version History
| Version | Date | Changes | Author |
|---------|------|---------|--------|
| 1.0 | 2025-12-25 | Initial documentation of Capability Mapping technique | Umesh Rawat |