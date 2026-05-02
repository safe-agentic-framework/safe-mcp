# SAFE-T1106: Autonomous Loop Exploit

## Overview
**Tactic**: Execution (ATK-TA0002)  
**Technique ID**: SAFE-T1106  
**Severity**: High  
**First Observed**: Not observed in production  
**Last Updated**: 2025-08-10

## Description
An adversary induces an MCP-enabled agent or workflow into a self-reinforcing loop of tool invocations (for example, “re-check,” “try again,” or delegation cycles) to exhaust local compute, hit external service rate limits, or drive quota/cost blowups. The loop can be triggered by attacker-controlled prompts, poisoned intermediate tool outputs, or cyclic multi-agent handoffs. Without convergence checks, iteration caps, or budget guardrails, the system repeatedly invokes tools with little or no progress—resulting in availability impact similar to Endpoint DoS.

This is conceptually related to application/protocol loop DoS, where two components continuously respond to each other (see References), but here the loop is induced via agent planning and MCP tool I/O patterns.

## Attack Vectors
- **Primary Vector**: Prompt or tool-output patterns that suggest non-terminal progress and encourage retries
- **Secondary Vectors**:
  - Cyclic tool chains (A→B→A) caused by orchestration/hand-offs
  - “Transient failure” responses engineered to keep the planner in retry mode

## Technical Details

### Prerequisites
- Agent or workflow capable of autonomous planning/execution
- Tool adapters that allow repeated calls/retries without strict caps

### Attack Flow
1. Seed: adversary injects instructions or output that frames work as “almost done; retry.”
2. Planning: agent selects the same tool(s) again with similar parameters.
3. Response shaping: tool returns partial/inconclusive state (for example, "warming_up," "retry_later").
4. Non-convergence: planner repeats steps 2–3; possibly delegates to another agent that routes back.
5. Exhaustion: CPU/time budget consumed; external APIs emit 429/5xx; user session becomes unresponsive.

### Example Scenario
```json
{
  "session_goal": "Ensure service is healthy; keep checking until it's green.",
  "policy": "If status != 'healthy', try again after delay.",
  "tool_calls": [
    {"tool": "http.get", "args": {"url": "https://api.example.com/health"}},
    {"tool": "wait", "args": {"ms": 5000}}
  ],
  "engineered_responses": ["warming_up", "almost_ready", "warming_up"]
}
```

### Beginner-Friendly Examples

The following examples help beginners understand how autonomous loops work and how to detect them in practice.

#### Example 1: Simple Loop Detection

This Python example demonstrates how to detect when an agent is stuck in a loop by tracking repeated identical tool calls:

```python
from collections import defaultdict
from typing import Dict, List, Tuple
import hashlib
import json

class LoopDetector:
    """Simple detector for autonomous loops in MCP tool invocations"""
    
    def __init__(self, max_repeats: int = 10, time_window_seconds: int = 300):
        self.max_repeats = max_repeats
        self.time_window = time_window_seconds
        self.call_history: Dict[str, List[Tuple[int, str]]] = defaultdict(list)
    
    def _generate_call_hash(self, tool_name: str, args: dict) -> str:
        """Create a unique hash for a tool call based on name and arguments
        
        Note: MD5 is used here for non-cryptographic purposes (content identification).
        For security-sensitive applications, use SHA-256 or another secure hash function.
        """
        call_signature = json.dumps({"tool": tool_name, "args": args}, sort_keys=True)
        return hashlib.md5(call_signature.encode()).hexdigest()
    
    def record_call(self, session_id: str, tool_name: str, args: dict, timestamp: int):
        """Record a tool call and check if it indicates a loop"""
        call_hash = self._generate_call_hash(tool_name, args)
        key = f"{session_id}:{call_hash}"
        
        # Add timestamp to history
        self.call_history[key].append(timestamp)
        
        # Remove old entries outside time window
        cutoff = timestamp - self.time_window
        self.call_history[key] = [t for t in self.call_history[key] if t > cutoff]
        
        # Check if we've exceeded the repeat threshold
        if len(self.call_history[key]) >= self.max_repeats:
            return {
                "is_loop": True,
                "session_id": session_id,
                "tool_name": tool_name,
                "repeat_count": len(self.call_history[key]),
                "call_hash": call_hash
            }
        
        return {"is_loop": False}

# Example usage
detector = LoopDetector(max_repeats=5, time_window_seconds=60)

# Simulate repeated identical calls (potential loop)
for i in range(6):
    result = detector.record_call(
        session_id="session_123",
        tool_name="http.get",
        args={"url": "https://api.example.com/health"},
        timestamp=1000 + i * 10
    )
    if result["is_loop"]:
        print(f"⚠️  Loop detected! Tool '{result['tool_name']}' called {result['repeat_count']} times")
        break
```

#### Example 2: Basic Loop Prevention

This example shows a simple way to prevent loops by adding iteration limits and convergence checks:

```python
class SafeAgentExecutor:
    """Agent executor with basic loop prevention"""
    
    def __init__(self, max_iterations: int = 50, convergence_threshold: float = 0.01):
        self.max_iterations = max_iterations
        self.convergence_threshold = convergence_threshold
        self.iteration_count = 0
        self.previous_results = []
    
    def execute_with_guardrails(self, tool_call_func, *args, **kwargs):
        """Execute a tool call with loop prevention guardrails"""
        if self.iteration_count >= self.max_iterations:
            raise RuntimeError(f"Maximum iterations ({self.max_iterations}) exceeded. Possible loop detected.")
        
        result = tool_call_func(*args, **kwargs)
        self.iteration_count += 1
        
        # Simple convergence check: stop if result hasn't changed significantly
        if len(self.previous_results) > 0:
            if self._is_converged(result, self.previous_results[-1]):
                return result
        
        self.previous_results.append(result)
        return result
    
    def _is_converged(self, current: dict, previous: dict) -> bool:
        """Check if the result has converged (stopped changing)"""
        # Simple check: compare result values
        if current.get("status") == previous.get("status"):
            return True
        return False
    
    def reset(self):
        """Reset the executor state"""
        self.iteration_count = 0
        self.previous_results = []

# Example usage
def check_service_health():
    """Simulated service health check"""
    return {"status": "warming_up", "message": "Service is starting..."}

executor = SafeAgentExecutor(max_iterations=10)

try:
    for i in range(15):  # Try more than max_iterations
        result = executor.execute_with_guardrails(check_service_health)
        print(f"Iteration {i+1}: {result}")
except RuntimeError as e:
    print(f"🛑 Guardrail triggered: {e}")
```

#### Example 3: Recognizing Loop Patterns in Logs

This example shows how to identify loop patterns from log entries:

```python
import re
from collections import Counter
from typing import List

def analyze_logs_for_loops(log_entries: List[str]) -> dict:
    """Analyze log entries to detect potential autonomous loops"""
    
    # Patterns that suggest non-convergence
    loop_indicators = [
        r"retry",
        r"try again",
        r"almost ready",
        r"warming up",
        r"in progress",
        r"checking\.\.\."
    ]
    
    # Count tool call patterns
    tool_call_pattern = r'tool["\']?\s*:\s*["\']([^"\']+)["\']'
    tool_calls = []
    
    for entry in log_entries:
        # Check for loop indicator phrases
        for pattern in loop_indicators:
            if re.search(pattern, entry, re.IGNORECASE):
                # Extract tool name if present
                match = re.search(tool_call_pattern, entry)
                if match:
                    tool_calls.append(match.group(1))
    
    # Analyze frequency
    tool_counter = Counter(tool_calls)
    suspicious_tools = {tool: count for tool, count in tool_counter.items() if count >= 5}
    
    return {
        "total_loop_indicators": len(tool_calls),
        "suspicious_tools": suspicious_tools,
        "is_likely_loop": len(suspicious_tools) > 0
    }

# Example log entries
sample_logs = [
    '{"tool": "http.get", "status": "warming_up", "message": "retry in 5s"}',
    '{"tool": "http.get", "status": "warming_up", "message": "almost ready"}',
    '{"tool": "http.get", "status": "warming_up", "message": "try again"}',
    '{"tool": "http.get", "status": "warming_up", "message": "retry in 5s"}',
    '{"tool": "http.get", "status": "warming_up", "message": "checking..."}',
]

analysis = analyze_logs_for_loops(sample_logs)
if analysis["is_likely_loop"]:
    print("⚠️  Potential loop detected!")
    print(f"   Suspicious tool calls: {analysis['suspicious_tools']}")
```

These examples demonstrate:
- **Detection**: How to identify when an agent is stuck in a loop
- **Prevention**: Basic guardrails to stop loops before they cause damage
- **Analysis**: How to recognize loop patterns in system logs

For production systems, combine these approaches with the more sophisticated mitigations listed in the [Mitigation Strategies](#mitigation-strategies) section.

### Advanced Attack Techniques
- Loop amplification via parallel subtasks re-queuing on partial failure
- Cross-agent cycles where delegation returns to originator after minor mutation

## Impact Assessment
- **Confidentiality**: Low — no direct data exposure
- **Integrity**: Low — no direct tampering
- **Availability**: High — local CPU exhaustion, API rate-limit storms, quota/cost burn
- **Scope**: Local to host; can propagate to external services via repeated API calls

### Current Status (2025)
Many agent stacks rely on simple retry caps or token budgets; robust convergence checks and semantic loop detectors are not universal.

## Detection Methods

### Indicators of Compromise (IoCs)
- High-frequency identical tool invocations per session (same name/args)
- Alternating call pairs or cycles in traces (A,B,A,B,…)
- Bursts of 429 (Too Many Requests) or repeating 5xx from dependencies
- Log strings suggesting non-convergence: "retry", "try again", "almost ready"

### Detection Rules

**Important**: The following rule is written in Sigma format and contains example patterns only. Organizations should:
- Use AI-based anomaly detection to identify novel loop patterns
- Regularly update detection logic based on operational telemetry
- Implement multiple layers of detection beyond pattern matching
- Consider semantic analysis of agent traces to confirm non-convergence
```yaml
title: Repeated Identical MCP Tool Invocations (Possible Loop)
id: REPLACE-WITH-UUID
status: experimental
description: Detects repeated identical tool calls by the same session over a short interval
author: SAFE-MCP Authors
date: 2025-08-10
logsource:
  product: mcp
  service: host
detection:
  selection:
    tool_name|same: ['*']
    session_id|same: true
    args_hash|same: true
  timeframe: 5m
  condition: selection | count() by session_id, tool_name, args_hash >= 10
falsepositives:
  - Legitimate batch/retry jobs with identical parameters
level: high
tags:
  - attack.execution
  - attack.t1499.003
  - safe.t1106
```

### Behavioral Indicators
- Monotonic retry counters without success transitions
- Flatlined “progress” metrics while invocation count grows
- API cost/usage spikes tied to the same session or tool/args hash

## Mitigation Strategies

### Preventive Controls
1. **[SAFE-M-21: Output Context Isolation](../../mitigations/SAFE-M-21/README.md)**: Separate planning and tool-output contexts to reduce self-reinforcement loops.
2. **[SAFE-M-22: Semantic Output Validation](../../mitigations/SAFE-M-22/README.md)**: Gate follow-ups unless outputs show material progress; add convergence criteria.
3. **[SAFE-M-23: Tool Output Truncation](../../mitigations/SAFE-M-23/README.md)**: Limit repetitive cues (“retry”, “in progress”) in model-visible outputs.
4. **[SAFE-M-3: AI-Powered Content Analysis](../../mitigations/SAFE-M-3/README.md)**: Flag loop-inducing language before execution.
5. **[SAFE-M-16: Token Scope Limiting](../../mitigations/SAFE-M-16/README.md)**: Cap downstream blast radius for repeated API calls.

### Detective Controls
1. **[SAFE-M-11: Behavioral Monitoring](../../mitigations/SAFE-M-11/README.md)**: Track per-session identical-call rates and cyclic graphs.
2. **[SAFE-M-20: Anomaly Detection](../../mitigations/SAFE-M-20/README.md)**: Detect non-convergent sequences and abnormal call densities.
3. **[SAFE-M-12: Audit Logging](../../mitigations/SAFE-M-12/README.md)**: Ensure fine-grained logs for reconstructing and auto-stopping loops.

### Response Procedures
1. **Immediate Actions**:
   - Terminate or pause agent sessions exceeding iteration/time thresholds
   - Apply global backoff and cooldown across tool adapters
   - Isolate the affected workspace/session to prevent further API floods
2. **Investigation Steps**:
   - Analyze execution traces for cyclic call graphs and identical-arg repeats
   - Correlate with external API logs (429/5xx bursts) and cost/usage spikes
   - Identify trigger prompts/tool outputs that seeded non-convergence
3. **Remediation**:
   - Enforce max-iterations, budget caps, and convergence checks in planners
   - Introduce per-session quotas and progressive throttling
   - Harden tool adapters with retry jitter, exponential backoff, and idempotency

## Related Techniques
- [SAFE-T1102](../SAFE-T1102/README.md) – Prompt Injection (can induce autonomous loops)
- SAFE-T1703 – Tool-Chaining Pivot (loop-like chaining patterns)

## References
- [OWASP Top 10 for LLM Applications](https://owasp.org/www-project-top-10-for-large-language-model-applications/)
- CISPA Helmholtz Center: Loop DoS (application-layer loops as a DDoS vector), CVE-2024-2169 — https://cispa.de/en/loop-dos
- MITRE ATT&CK: Endpoint DoS (T1499) — https://attack.mitre.org/techniques/T1499/
- MITRE ATT&CK: Application Exhaustion Flood (T1499.003) — https://attack.mitre.org/techniques/T1499/003/

## MITRE ATT&CK Mapping
- [T1499 - Endpoint Denial of Service](https://attack.mitre.org/techniques/T1499/)
- [T1499.003 - Application Exhaustion Flood](https://attack.mitre.org/techniques/T1499/003/)

## Version History
| Version | Date       | Changes               | Author           |
|---------|------------|-----------------------|------------------|
| 1.0     | 2025-08-10 | Initial documentation | Sunil Dhakal |
| 1.1     | 2025-11-16 | Added beginner-friendly examples section with practical code demonstrations for loop detection, prevention, and log analysis | Satbir Singh |


