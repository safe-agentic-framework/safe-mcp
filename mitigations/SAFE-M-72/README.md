# SAFE-M-72: Data Security - Data Loss Prevention on Tool Outputs

## Overview
**Mitigation ID**: SAFE-M-72  
**Category**: Data Security  
**Effectiveness**: Medium-High (inline masking and tokenization are deterministic; policy accuracy is bounded by classification quality and detector recall)  
**Implementation Complexity**: Medium-High  
**First Published**: 2026-04-14

## Description
Data Loss Prevention (DLP) on Tool Outputs applies column-level classification, masking, tokenization, and sensitive-content detection to the results returned by MCP tools **before** those results enter the agent's context window or are surfaced to a user. The control treats every tool response as an untrusted egress point from a protected data store: structured rows from database connectors, semi-structured payloads from API wrappers, and free-text fields from document/knowledge tools are all inspected against a policy that maps sensitivity labels (PII, PCI, PHI, secrets, IP) to actions (allow, mask, tokenize, redact, block, alert).

Unlike prompt-injection defenses that look for instruction-shaped content in model inputs, SAFE-M-72 operates on the **outbound** path of the tool boundary and is specifically tuned to prevent bulk disclosure of sensitive records even when the underlying query is syntactically valid and the agent is behaving as intended. The control composes schema-authoritative filtering (using a data classification catalog that maps columns → labels) with content-based scanners (regex, dedicated validators per identifier class — Luhn / MOD-10 for PAN, MOD-97 for IBAN, format/area checks for US SSN — Named Entity Recognition, ML classifiers, and embedding-based secret detectors) to cover both typed and untyped fields. Every masking or block decision is logged as an audit event, giving defenders a high-signal telemetry source for detecting exfiltration attempts that evade upstream guardrails [1][2][3].

## Mitigates
- [SAFE-T1803](../../techniques/SAFE-T1803/README.md): Database Dump — primary mitigation; even if query-layer guardrails are bypassed, PII/PCI/secret columns are masked or tokenized before the agent sees the rows, capping the blast radius of a bulk `SELECT`.
- [SAFE-T1008](../../techniques/SAFE-T1008/README.md): Credential-in-File — secret scanners in the output path redact tokens, keys, and passwords that would otherwise be returned verbatim by file-read or config-dump tools.
- [SAFE-T1102](../../techniques/SAFE-T1102/README.md): Prompt Injection (Multiple Vectors) — secondary mitigation; bounds the information an injection-hijacked agent can actually exfiltrate through tool results, because sensitive payloads never reach the model context in clear form.

## Technical Implementation

### Core Principles
1. **Classify at the schema layer where possible**: a column-level classification catalog (column → sensitivity label) is authoritative, deterministic, and cheap to enforce. Every field with a label gets its policy action applied without content inspection.
2. **Fall back to content scanning for unclassified or free-text fields**: JSON blobs, document bodies, log lines, and notes columns must be scanned with regex/validator combinations (Luhn / MOD-10 for PAN, MOD-97 for IBAN, format/area checks for US SSN, entropy + structural checks for API keys) and ML classifiers for unstructured PII [4][5].
3. **Default deny for unknown sensitivity**: fields with no classification label and no content-scanner hit are replaced by a summary (length, type) rather than passed through raw, unless an allowlist explicitly marks the column or field as non-sensitive. Newly observed columns inherit this summarization default until a catalog entry is added.
4. **Distinguish masking, redaction, and tokenization**: **masking** (e.g., `****1234` for a PAN) and **redaction** (full removal) are one-way — the clear value cannot be recovered from the output. **Tokenization** replaces the value with an opaque token whose clear form can be retrieved only through an authenticated detokenization channel; it is reversible by design and appropriate where a downstream system must correlate, join, or later re-hydrate the real value [6][7]. The policy **MUST** pick one per label and document the choice; mixing masking and tokenization for the same label breaks referential behavior.
5. **Audit every trigger**: record policy hits (field path, label, action, caller identity, tool name) to an append-only log so bulk-dump attempts show up as spikes in mask/block counts even when the agent returned a "successful" response.

### Architecture Components
```
                 ┌──────────────────────────────────────────────┐
   MCP Tool ─────▶  Connector (DB driver / HTTP client / FS)    │
   request        └──────────────────────────────────────────────┘
                                     │ raw rows / JSON / text
                                     ▼
                 ┌──────────────────────────────────────────────┐
                 │         DLP Pipeline (per response)          │
                 │                                              │
                 │  1. Schema-aware Column Classifier           │
                 │     (lookup against data catalog)            │
                 │  2. Sensitive-Pattern Scanner                │
                 │     (regex + validators + NER + ML)          │
                 │  3. Secret Detector (composes SAFE-M-63)     │
                 │  4. Policy Engine                            │
                 │     label + context -> action                │
                 │  5. Transform (mask/tokenize/redact/block)   │
                 │  6. Audit Emitter (SIEM)                     │
                 └──────────────────────────────────────────────┘
                                     │ sanitized payload
                                     ▼
                 ┌──────────────────────────────────────────────┐
                 │  MCP Tool Handler ──▶ Agent Context / User   │
                 └──────────────────────────────────────────────┘
```

### Prerequisites
- A data classification catalog covering high-value datastores (column → sensitivity label). Discovery tools — AWS Macie, Google Cloud DLP discovery scans, Microsoft Purview — are used **to populate this catalog**, not as inline scanners in the request path [3][8][9].
- A DLP engine capable of inline recognizer composition on each tool response. Common engine choices: Microsoft Presidio (open-source, recognizer-based NLP) [1], Google Cloud DLP / Sensitive Data Protection (API-based inline inspection) [3], Nightfall DLP (API-based inline inspection) [10]. A tokenization service is required when reversibility is needed for any label; common choices include Fortanix Data Security Manager [6] and cloud-native format-preserving encryption [7].
- AWS Macie and Microsoft Purview are catalog/discovery inputs to this pipeline, not inline DLP engines — they do not sit in the per-request critical path.
- A connector-layer hook point inside each MCP server (SQL driver wrapper, HTTP response middleware, filesystem read wrapper) where responses can be intercepted before serialization back to the tool caller.
- Optional: a token vault or format-preserving encryption service if reversible tokenization is required [6][7].
- Audit sink (SIEM, append-only log, or OpenTelemetry pipeline) for DLP events.

### Implementation Steps

1. **Design Phase**:
   - Inventory the datastores reachable via MCP tools and identify the top-N tables by sensitivity.
   - Build (or import) the classification catalog. Prefer declarative sources (DDL comments, dbt `meta`, Purview/Collibra exports) over ad-hoc spreadsheets.
   - Define the label → action policy (e.g., `pii.email` → tokenize, `pci.pan` → mask-last-4, `secret.*` → block+alert, `phi.*` → block unless caller has PHI scope).
   - Decide on reversibility requirements per label (tokenization vault vs one-way hash vs plain redact).

2. **Development Phase**:
   - Implement a DLP pipeline module that accepts a response payload plus a schema/context descriptor and returns a sanitized payload plus an audit record.
   - Integrate Presidio (or chosen engine) with custom recognizers for domain-specific identifiers (internal user IDs, proprietary license keys, customer IDs) [1].
   - For API-key and credential-like content in outputs, plug in an output-side secret scanner. Many deployments adapt the embedding-based semantic similarity approach from SAFE-M-63 (originally scoped to **incoming** credential-seeking queries) by reusing the same similarity engine to score outbound text fragments against known credential patterns. This is a composition pattern, not a direct reuse — the output-side application re-trains or re-threshold-tunes against masked-output fixtures, and SAFE-M-63's ingress scope is unchanged.
   - Wrap each MCP tool's response path: for SQL connectors, iterate rows after fetch and before serialization; for HTTP connectors, parse JSON and traverse by JSON-path; for file/document tools, stream through the scanner with chunking.
   - Emit structured audit events (tool, caller, label, action, match-count) on every non-allow decision.

3. **Deployment Phase**:
   - Roll out in **observe mode** first: run the pipeline, log what *would* have been masked/blocked, but do not transform payloads. Tune thresholds and catalog coverage.
   - Promote to **enforce mode** per label class, starting with the highest-severity labels (secrets, PAN, SSN) where false-positives are operationally acceptable.
   - Add SIEM detections on DLP audit events: spikes in `block` or `mask_count` per tool call, anomalous caller identities, novel label hits.
   - Re-tune quarterly against red-team exercises (synthetic PII/PCI/secret fixtures) and production false-positive reports.

## Benefits
- **Contains bulk disclosure at the tool boundary**: a 3M-row `SELECT *` that would leak customer PII is reduced to 3M masked tokens plus a single loud audit event, even if the query itself was not blocked.
- **Composable with query-layer controls**: stacks cleanly with query shape guardrails (SAFE-M-71), row caps (SAFE-M-23), and least-privilege DB roles (SAFE-M-16) as a defense-in-depth layer.
- **High-signal telemetry**: DLP audit events are dense and rarely benign at scale, making them one of the most reliable detections for SAFE-T1803-style exfiltration.
- **Reversibility preserved for legitimate flows**: tokenization keeps referential integrity for joins and pipelines while removing clear-text exposure from the agent context.

## Limitations
- **Schema-free outputs depend on detector recall**: document stores, blob columns, free-text notes, and agent-authored summaries cannot be classified at the schema layer; content scanners have measurable false-positive and false-negative rates that must be monitored and tuned [1][4].
- **Tokenization adds infrastructure complexity**: a token vault is a high-value target itself and introduces availability and key-management risk; plan for it like any other cryptographic service [6][7].
- **Derived/aggregate leakage**: an attacker or misaligned agent can ask for aggregates, counts, or model-authored summaries that encode sensitive content without triggering word-level scanners (e.g., "describe the 10 highest-paid employees"). DLP on outputs must be paired with query-shape and purpose controls.
- **Performance cost on wide results**: per-row/per-field inspection adds latency proportional to row count and detector count; large result sets benefit from batching, sampling (with guaranteed coverage of classified columns), and native-language scanners.
- **Classification-catalog drift**: schemas evolve; unclassified new columns are summarized (length and type) per principle 3, which can surprise downstream consumers that expected raw values — requires a catalog-freshness SLO and a documented path to add columns to the classification catalog quickly.

## Implementation Examples

### Example 1: DB connector wrapping query results with a Presidio-style scanner
```python
# Simplified; production code should stream rows rather than materialize them.
from typing import Any, Iterable, Mapping
from presidio_analyzer import AnalyzerEngine
from presidio_anonymizer import AnonymizerEngine
from presidio_anonymizer.entities import OperatorConfig

analyzer = AnalyzerEngine()
anonymizer = AnonymizerEngine()

# label -> action config; loaded from policy file at startup
POLICY: Mapping[str, OperatorConfig] = {
    "pci.pan":     OperatorConfig("mask", {"masking_char": "*",
                                           "chars_to_mask": 12,
                                           "from_end": False}),
    "pii.email":   OperatorConfig("replace", {"new_value": "<tokenized:email>"}),
    "pii.ssn":     OperatorConfig("redact", {}),
    "secret.key":  OperatorConfig("redact", {}),  # always strip
}

def sanitize_row(row: Mapping[str, Any],
                 column_labels: Mapping[str, str],
                 tool: str,
                 caller: str) -> Mapping[str, Any]:
    sanitized = {}
    for col, value in row.items():
        label = column_labels.get(col)

        # 1. Schema-authoritative path
        if label and label in POLICY:
            sanitized[col] = _apply(POLICY[label], value)
            _audit(tool, caller, col, label, action=POLICY[label].operator_name)
            continue

        # 2. Content-based fallback for unclassified or free-text
        if isinstance(value, str):
            findings = analyzer.analyze(text=value, language="en")
            if findings:
                sanitized[col] = anonymizer.anonymize(
                    text=value, analyzer_results=findings
                ).text
                for f in findings:
                    _audit(tool, caller, col, f.entity_type, action="mask")
                continue

        # 3. Default: pass through only if explicitly allowlisted
        sanitized[col] = value if col in ALLOWLIST else _summarize(value)
    return sanitized

def sanitize_result_set(rows: Iterable[Mapping[str, Any]],
                        table: str, tool: str, caller: str):
    column_labels = CATALOG.labels_for(table)   # column -> label from data catalog
    for row in rows:
        yield sanitize_row(row, column_labels, tool, caller)
```

### Example 2: Policy configuration mapping labels to actions
```json
{
  "version": "1.0",
  "default_action": "summarize",
  "labels": {
    "pci.pan":      { "action": "mask",     "keep_last": 4,  "validator": "luhn" },
    "pii.email":    { "action": "tokenize", "vault": "email-vault-v1" },
    "pii.ssn":      { "action": "block",    "alert": "high" },
    "pii.phone":    { "action": "mask",     "keep_last": 2 },
    "phi.icd10":    { "action": "block",    "alert": "high",
                      "exceptions": ["role:clinical-analyst"] },
    "secret.key":   { "action": "redact",   "alert": "critical" },
    "secret.jwt":   { "action": "redact",   "alert": "high" },
    "ip.internal":  { "action": "allow" }
  },
  "scanners": {
    "presidio":   { "enabled": true, "recognizers": ["US_SSN","CREDIT_CARD","EMAIL_ADDRESS","PERSON"] },
    "secret_detector_safe_m_63": { "enabled": true, "threshold": 0.85 },
    "custom_regex": {
      "internal_user_id": "^usr_[A-Z0-9]{16}$"
    }
  }
}
```

### Example 3: Observed detector performance (indicative; validate per deployment)
| Detector                           | Corpus                         | Precision | Recall | Notes |
|------------------------------------|--------------------------------|-----------|--------|-------|
| Schema catalog (column label)      | Classified columns             | 1.00      | 1.00   | Authoritative when catalog is current |
| Presidio `CREDIT_CARD` + Luhn      | Mixed JSON payloads            | 0.97      | 0.93   | Luhn post-filter cuts FP substantially [1] |
| Presidio `US_SSN` (regex + context)| Customer service transcripts   | 0.88      | 0.91   | Sensitive to context words [1] |
| Embedding-based secret scanner (output-side adaptation of the SAFE-M-63 approach) | API-key fixtures | 0.94 | 0.96 | Adapts SAFE-M-63's ingress similarity technique to output-side recognition [SAFE-M-63] |
| Cloud DLP `PERSON_NAME` infoType   | Free-text notes                | 0.75      | 0.82   | High FP; pair with label context [3] |

> Values above are illustrative ranges drawn from vendor reports and typical Presidio benchmarks. Every deployment must re-measure these metrics against its own data before promoting any label from observe mode to enforce mode, and must recalibrate after each catalog or detector update.

## Testing and Validation
1. **Security Testing**:
   - Synthetic-fixture test suite covering PAN, SSN, IBAN, JWT, AWS/GCP/OpenAI-style keys, email, phone, and domain-specific IDs; assert every fixture is masked or blocked end-to-end through a representative MCP tool.
   - Red-team drills simulating SAFE-T1803: issue `SELECT *` against a seeded `users` table and confirm no clear-text PII/secret reaches the agent.
   - Evasion tests (homoglyphs, base64-wrapped secrets, split values across adjacent columns) to measure recall of the content scanners.

2. **Functional Testing**:
   - Golden-query regression tests to ensure legitimate analytics queries still return usable, tokenized results.
   - Latency benchmarks at p50/p95/p99 for row-widths 10/100/1000 columns and result sizes 1/1k/100k rows.
   - Catalog-coverage report: percentage of queried columns that hit a classified label vs fall back to content scanning.

3. **Integration Testing**:
   - Verify audit events flow to SIEM with correct caller identity, tool name, and label.
   - Confirm tokenization round-trip through the detokenization service for authorized callers only.
   - Chaos test: disable the DLP engine and confirm the connector fails closed (default deny), not open.

## Deployment Considerations

### Resource Requirements
- **CPU**: scanner-bound; Presidio NER on CPU adds ~2–8 ms per short string, more for long documents [1]. Plan for per-connector worker pools or sidecar processes for high-QPS tools.
- **Memory**: ~500 MB–2 GB per worker when loading Presidio/spaCy models; embedding-based secret scanners (SAFE-M-63) add ~500 MB.
- **Storage**: negligible for policy/catalog; token vault sized to cardinality of tokenized values.
- **Network**: if using cloud inline DLP APIs (Google Cloud DLP, Nightfall), factor egress and per-request quotas [3][10]. (AWS Macie is a discovery service, not a per-request inline engine — it runs offline against object stores to populate the classification catalog rather than sitting in the request path.)

### Performance Impact
- **Latency**: typically +5–30 ms per response for structured rows with a hit catalog; +50–200 ms for free-text scanning of large documents.
- **Throughput**: schema-catalog path is effectively free; content scanning is the bottleneck — mitigate with batching and skipping already-classified columns.
- **Resource Usage**: dominated by NER/embedding models; autoscale on per-tool QPS.

### Monitoring and Alerting
- `dlp.action_count{action=block}` per tool, per caller (primary SAFE-T1803 detection).
- `dlp.mask_count` rate-of-change; sudden spikes indicate bulk dump attempts.
- `dlp.catalog_miss_ratio` per table (drives classification-catalog freshness SLO).
- `dlp.latency_ms` p95/p99 per connector.
- Alert: any `secret.*` block, any `phi.*` block, any caller exceeding N blocks/hour.

## Current Status (2026)
DLP tooling is mature for general workloads: Microsoft Presidio [1], Google Cloud Sensitive Data Protection [3], and Nightfall [10] provide production-ready inline inspection engines; Fortanix Data Security Manager [6] and cloud-native format-preserving encryption [7] provide tokenization. AWS Macie [8] and Microsoft Purview [9] are data-discovery and classification catalog services that feed this pipeline rather than performing per-request inline scanning. Integration with MCP connectors is still largely **custom per deployment**: most MCP server implementations do not ship with a DLP hook point, so teams are wrapping database drivers and HTTP clients themselves. Column-level classification remains the practical bottleneck — organizations with mature data catalogs (dbt metadata, Purview, Collibra, Atlan) can deploy SAFE-M-72 in weeks, while teams without a catalog must first invest in discovery scans (Macie, Cloud DLP) to populate the catalog before enforcement becomes reliable [3][8][9]. Industry guidance from OWASP and NIST increasingly recommends egress-side DLP as a necessary layer for LLM-agent systems that expose tool access to sensitive datastores [2][11][12].

## References
- [1] [Microsoft Presidio — Data Protection and De-identification SDK](https://microsoft.github.io/presidio/)
- [2] [OWASP Top 10 for LLM Applications (2025) — LLM02: Sensitive Information Disclosure](https://genai.owasp.org/llmrisk/llm02-sensitive-information-disclosure/)
- [3] [Google Cloud Sensitive Data Protection (Cloud DLP) documentation](https://cloud.google.com/sensitive-data-protection/docs)
- [4] [Luhn algorithm (ISO/IEC 7812-1) — MOD-10 validation for PAN](https://www.iso.org/standard/70484.html)
- [5] [NIST SP 800-122 — Guide to Protecting the Confidentiality of PII](https://csrc.nist.gov/pubs/sp/800/122/final)
- [6] [Fortanix Data Security Manager — Tokenization](https://www.fortanix.com/platform/data-security-manager/tokenization)
- [7] [NIST SP 800-38G — Format-Preserving Encryption (FF1/FF3-1)](https://csrc.nist.gov/pubs/sp/800/38/g/final)
- [8] [AWS Macie — Sensitive data discovery and classification](https://docs.aws.amazon.com/macie/latest/user/what-is-macie.html)
- [9] [Microsoft Purview — Data classification and sensitivity labels](https://learn.microsoft.com/en-us/purview/data-classification-overview)
- [10] [Nightfall AI — DLP for APIs and SaaS](https://www.nightfall.ai/platform)
- [11] [MITRE ATT&CK M1041 — Data Loss Prevention](https://attack.mitre.org/mitigations/M1041/)
- [12] [NIST AI 600-1 — Generative AI Profile (sensitive-data handling guidance)](https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.600-1.pdf)
- [13] [Model Context Protocol Specification](https://modelcontextprotocol.io/specification)

## Related Mitigations
- [SAFE-M-71](../SAFE-M-71/README.md): Query Guardrails & Result Limits — complementary; SAFE-M-71 blocks malformed or overbroad queries at ingress, SAFE-M-72 sanitizes results at egress when a query slips through.
- [SAFE-M-23](../SAFE-M-23/README.md): Tool Output Size Limits — complementary; row/byte caps reduce the volume DLP must scan and bound the worst-case disclosure.
- [SAFE-M-63](../SAFE-M-63/README.md): Embedding-Based API Key Detection and Filtering — specialization; SAFE-M-63 is one high-recall secret-detection strategy that plugs into SAFE-M-72's scanner stage.
- [SAFE-M-16](../SAFE-M-16/README.md): Least-Privilege Tool Authorization — complementary; tokens scope what data is reachable, DLP scopes what of that data is returned in clear.
- [SAFE-M-5](../SAFE-M-5/README.md): Content Sanitization — distinct control (prompt-injection defense on inbound text); SAFE-M-72 is outbound sensitive-data filtering, not instruction filtering.
- [SAFE-M-22](../SAFE-M-22/README.md): Semantic Output Validation — distinct control; SAFE-M-22 checks outputs for instruction-shaped content that could subvert the model; SAFE-M-72 checks outputs for sensitive content that should not cross the tool boundary regardless of model behavior.

## Version History
| Version | Date       | Changes                | Author       |
|---------|------------|------------------------|--------------|
| 1.0     | 2026-04-14 | Initial documentation  | bishnu bista |
