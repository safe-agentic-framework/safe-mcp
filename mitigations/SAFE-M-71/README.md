# SAFE-M-71: Query Guardrails & Result Limits

## Overview
**Mitigation ID**: SAFE-M-71  
**Category**: Preventive Control  
**Effectiveness**: High (when enforced at the connector/tool layer, not in the model's context)  
**Implementation Complexity**: Medium  
**First Published**: 2026-04-14

## Description
Query Guardrails & Result Limits is a preventive control for MCP tools that execute queries against databases, data warehouses, or other structured stores. A policy engine sits between the model-proposed tool call and the backing datastore, parses the proposed query, inspects its **shape** (not just its text), and either dispatches, rewrites, rejects, or escalates the call. Pre-dispatch guardrails may also inject a hard `LIMIT` into an otherwise-approved query before sending it to the datastore, so the query cannot request an unbounded scan in the first place. Post-execution size capping on the return path is a separate, complementary control (see SAFE-M-23). Because enforcement lives outside the model, the agent cannot talk its way past the gate.

Unlike post-hoc truncation, this control can refuse a query **before** it runs, preventing load on the target database, avoiding memory pressure on the MCP host, and keeping sensitive data from ever being read off disk. Typical rules include: reject `SELECT *` on privileged tables, reject unbounded scans (no `WHERE` clause, no time filter) on large tables, require parameterized or pre-vetted stored procedures for bulk access, cap result rows per tool and per session, and route explicit "bulk export" requests through an exception workflow with human approval and audit logging. Guardrails are the primary defense against SAFE-T1803 (Database Dump) driven via MCP query tools.

## Mitigates
- [SAFE-T1803](../../techniques/SAFE-T1803/README.md): Database Dump (primary)
- [SAFE-T1104](../../techniques/SAFE-T1104/README.md): Over-Privileged Tool Abuse (where the over-privilege is expressed as unbounded query capability)

## Technical Implementation

### Core Principles
1. **Enforcement outside the model**: The policy engine is a separate process or library invoked by the MCP tool handler. The model cannot inspect, disable, or bypass it through prompt content.
2. **Shape-level rules, not string matching**: Parse the proposed query into an AST (sqlparse, sqlglot, or a DB-native `EXPLAIN`/plan inspection) and reason about tables, projected columns, predicates, joins, and estimated scan size. String-matching on `SELECT *` is trivially evaded by whitespace, comments, or column enumeration.
3. **Fail closed**: If the parser errors, the policy engine is unreachable, or estimated scan size cannot be determined, the call is denied. Availability of the gate is a safety property.
4. **Structured exceptions with audit**: Legitimate bulk needs (backups, migrations, analytics exports) route through a named exception with an approver, a TTL, and an immutable audit record — never through a generic "disable guardrails" flag.
5. **Compose with post-execution controls**: Guardrails are the first line; SAFE-M-23 (truncation), SAFE-M-16 (scope-limited credentials), and DLP on outputs remain in place.

### Architecture Components
```text
                                +---------------------------------+
  Model / Agent -- proposes --> |  MCP Tool Handler (db_query)    |
                                |                                 |
                                |   +-------------------------+   |
                                |   | Policy Engine Gate      |   |
                                |   |  1. SQL parser (AST)    |   |
                                |   |  2. Shape rules:        |   |
                                |   |     - privileged tables |   |
                                |   |     - SELECT * deny     |   |
                                |   |     - WHERE required    |   |
                                |   |     - join depth        |   |
                                |   |  3. Quota check         |   |
                                |   |     (row/byte caps)     |   |
                                |   |  4. Exception lookup    |   |
                                |   +-----------+-------------+   |
                                |               |                 |
                                |    deny       | allow (maybe    |
                                |    reject     | with LIMIT      |
                                |    / escalate | injected)       |
                                |               v                 |
                                |     +---------------------+     |
                                |     | DB Driver / Conn    |-----+--> Database / Warehouse
                                |     +----------+----------+     |
                                |                |                |
                                |     +----------v----------+     |
                                |     | Result Cap (rows,   |     |
                                |     | bytes, timeout)     |     |
                                |     +----------+----------+     |
                                +----------------|----------------+
                                                 v
                                          Audit Log / SIEM
                                                 |
                                                 v
                                        Agent / Tool Response
```

### Prerequisites
- A SQL parser for each target dialect (e.g., [sqlparse](https://github.com/andialbrecht/sqlparse), [sqlglot](https://github.com/tobymao/sqlglot)) or access to a DB-native query planner (`EXPLAIN`, `EXPLAIN ANALYZE`, `SHOW PLAN`).
- A policy-expression language or structured config. Off-the-shelf options include [Open Policy Agent (OPA)](https://www.openpolicyagent.org/), [Cerbos](https://cerbos.dev/), or [Permit.io](https://www.permit.io/).
- An MCP connector/tool layer that can inject a pre-dispatch hook — the handler must not talk to the DB directly.
- A list of privileged tables / columns, plus per-tool row and byte caps agreed with data owners.
- An audit sink (SIEM or write-once log) that receives every allow, deny, and exception decision.

### Implementation Steps
1. **Design Phase**:
   - Classify datastores and tables: `privileged` (PII, credentials, payments, auth logs), `internal`, `public`. Record in a version-controlled registry.
   - Define per-tool, per-role row and byte caps (e.g., `analyst_query`: 10k rows / 25 MB; `support_query`: 500 rows / 2 MB).
   - Define shape-level deny rules: no `SELECT *` on privileged tables; every query against large tables must include a bounded predicate on an indexed column; joins that cross privilege classes require approval.
   - Design the exception workflow: who approves, TTL, which tables are eligible, what log format.

2. **Development Phase**:
   - Integrate a SQL parser in the MCP tool handler. Walk the AST to extract referenced tables, projected columns, presence of `WHERE`, join count, and any `LIMIT`.
   - Implement deny rules as policy (OPA Rego, Cerbos policies, or typed Python rules). Load from a signed, versioned config.
   - On allow, inject a hard `LIMIT` if absent and attach a statement-level timeout.
   - On approved queries, inject a hard `LIMIT` before dispatch when none is present in the submitted SQL; attach a statement-level timeout. Post-execution byte caps on the returned payload are out of scope here — they belong to SAFE-M-23.
   - Wire audit logging: every decision is logged with query hash, tool name, caller identity, decision, matched rule, and the `LIMIT` injected (if any).

3. **Deployment Phase**:
   - Roll out in `log-only` mode first; baseline what production queries look like and tune rules to minimize false positives.
   - Flip to `enforce` mode table-by-table, starting with the highest-sensitivity tables.
   - Stand up the exception workflow and dashboards. Monitor deny rates, exception rates, and 95th-percentile guardrail latency.
   - Red-team the gate with evasion attempts (comments, unicode, subqueries, CTEs, prepared statements).

## Benefits
- **Prevents the dump before it happens**: Unlike output truncation, no rows are read off disk and no DB resources are spent on a rejected query.
- **Works even against a fully compromised agent**: Because enforcement is outside the model, prompt injection cannot turn guardrails off.
- **Produces clean audit evidence**: Every denied or escalated query is a high-signal event for detection (SAFE-T1803 IoC feed).
- **Composable**: Layers cleanly with SAFE-M-16 (DB-side least privilege), SAFE-M-23 (post-execution truncation), and DLP controls on outputs.

## Limitations
- **Does not prevent pattern circumvention via many small queries**: A loop of small, well-shaped queries can still exfiltrate a table row-by-row. Rate limiting and per-session cumulative caps are separate controls and must be paired.
- **Parser bugs and dialect drift**: A malformed query, dialect-specific syntax, or exotic constructs (stored procs, dynamic SQL via `EXECUTE`) can slip past an AST-only check. Prefer combining AST inspection with a server-side `EXPLAIN` estimate when available.
- **Per-row sensitivity still needs DLP**: A shape-compliant query can still return sensitive columns. Column-level masking, tokenization, or output DLP — see [SAFE-M-72](../SAFE-M-72/README.md) — is complementary and required for regulated data.
- **Operational tuning cost**: False-positive denies frustrate analysts. Expect 2–6 weeks of log-only tuning before enforcement on busy warehouses.
- **Stored-procedure and ORM blind spots**: Queries generated by ORMs or wrapped in stored procedures may obscure the effective shape; inspect the rendered SQL or the procedure body, not the caller signature.

## Implementation Examples

### Example 1: Python query-shape checker (pseudocode)
```python
import sqlglot
from sqlglot import exp

PRIVILEGED_TABLES = {"users", "auth_logs", "payments", "sessions", "api_tokens"}
DEFAULT_ROW_CAP = 1_000
BYTE_CAP = 2 * 1024 * 1024  # 2 MB

class GuardrailDenied(Exception):
    pass

def check_query(sql: str, dialect: str, tool: str, caller: str, exceptions: set[str]) -> str:
    try:
        tree = sqlglot.parse_one(sql, read=dialect)
    except sqlglot.errors.ParseError as e:
        # Fail closed on parse errors.
        raise GuardrailDenied(f"unparseable SQL: {e}")

    if not isinstance(tree, exp.Select):
        raise GuardrailDenied("only SELECT permitted for this tool")

    tables = {t.name for t in tree.find_all(exp.Table)}
    star = any(isinstance(p, exp.Star) for p in tree.find_all(exp.Star))

    if star and tables & PRIVILEGED_TABLES:
        raise GuardrailDenied(
            f"SELECT * on privileged tables denied: {tables & PRIVILEGED_TABLES}"
        )

    if not tree.find(exp.Where) and tables & PRIVILEGED_TABLES:
        if f"{tool}:unbounded" not in exceptions:
            raise GuardrailDenied("unbounded scan on privileged table denied")

    # Inject row cap if absent.
    if not tree.args.get("limit"):
        tree.set("limit", exp.Limit(expression=exp.Literal.number(DEFAULT_ROW_CAP)))

    return tree.sql(dialect=dialect)
```

### Example 2: OPA-style Rego policy fragment
```rego
package mcp.db_query

default allow := false

# Deny SELECT * on privileged tables.
deny[msg] {
    input.query.has_star
    some t
    input.query.tables[t]
    privileged_tables[t]
    msg := sprintf("SELECT * on privileged table %q denied", [t])
}

# Deny unbounded scans on large tables unless a scoped exception is active.
deny[msg] {
    input.query.missing_where
    some t
    input.query.tables[t]
    large_tables[t]
    not input.exceptions["bulk_export"]
    msg := sprintf("unbounded scan on large table %q denied", [t])
}

allow {
    count(deny) == 0
    input.query.row_estimate <= input.policy.row_cap
}

privileged_tables := {"users", "auth_logs", "payments", "sessions"}
large_tables      := {"users", "events", "sessions", "access_logs"}
```

### Example 3: Per-tool config
```yaml
guardrails:
  enforcement_mode: enforce        # log_only | enforce
  fail_closed: true
  tools:
    analyst_query:
      row_cap: 10000
      byte_cap_mb: 25
      statement_timeout_ms: 15000
      deny_select_star_on: [users, auth_logs, payments]
      require_where_on:    [users, events, access_logs]
    support_query:
      row_cap: 500
      byte_cap_mb: 2
      statement_timeout_ms: 5000
      deny_select_star_on: [users, auth_logs, payments, api_tokens]
  exceptions:
    bulk_export:
      approver_role: data_protection_officer
      ttl_minutes: 60
      audit_required: true
```

## Testing and Validation
1. **Security Testing**:
   - Attempt `SELECT *` on privileged tables via direct text, whitespace variants, comments, unicode look-alikes, subqueries, and CTEs. All must deny.
   - Attempt unbounded scans without `WHERE`, with trivially-true predicates (`WHERE 1=1`), and with predicates on unindexed columns. Unbounded and trivially-true variants must deny.
   - Confirm fail-closed behavior when the policy engine process is killed.
   - Attempt small-query exfiltration loops; confirm cumulative session caps fire (if implemented).
2. **Functional Testing**:
   - Validate that representative analyst, support, and reporting queries still run.
   - Measure added latency at p50/p95/p99 with the parser + policy engine in the path.
3. **Integration Testing**:
   - Confirm audit records land in SIEM with query hash, decision, matched rule, caller, and tool.
   - Exercise the exception workflow end-to-end, including TTL expiry.

## Deployment Considerations

### Resource Requirements
- **CPU**: Parsing and policy evaluation are typically sub-millisecond per query; budget ~1–5% overhead on the MCP host.
- **Memory**: Policy bundles and AST buffers are small; ~tens of MB per worker.
- **Storage**: Audit logs dominate; plan for SIEM ingest proportional to tool call volume.
- **Network**: Negligible unless using a remote OPA / Cerbos server; keep the policy engine local or sidecar for latency.

### Performance Impact
- **Latency**: Expect +1–10 ms per tool call for AST + policy evaluation. DB-native `EXPLAIN` estimates add a round trip.
- **Throughput**: Stateless checks scale horizontally with the tool handler.
- **Resource Usage**: Net positive at the DB layer — denied queries never consume DB CPU, I/O, or buffer pool.

### Monitoring and Alerting
- Guardrail deny rate per tool and per caller (spikes indicate evasion or misconfiguration).
- Exception activation rate and approver identity.
- p95 guardrail latency; alert if parser budget exceeded.
- Fail-closed events (policy engine unreachable).
- Rate at which approved queries required a guardrail-injected `LIMIT`.

## Current Status (2026)
Production MCP deployments with database connectors typically ship with either naive string-matching guardrails ("reject if the string `SELECT *` appears") or none at all. Policy engines such as OPA, Cerbos, and Permit.io are mature for RBAC/ABAC but integration into MCP tool handlers remains custom work, and public reference implementations for SQL-shape rules are sparse. Cloud providers recommend query guardrails and schema-aware DLP as core defenses against bulk database theft from agent-driven workloads ([NSA/CISA Cloud Top 10, 2024](https://media.defense.gov/2024/Mar/07/2003407862/-1/-1/0/CSI-CLOUDTOP10-SECURE-DATA.PDF); [Google Cloud — 4 Steps to Stop Data Exfiltration](https://cloud.google.com/blog/products/identity-security/4-steps-to-stop-data-exfiltration-with-google-cloud)).

## References
- [Model Context Protocol Specification](https://modelcontextprotocol.io/specification)
- [OWASP Top 10 for Large Language Model Applications](https://owasp.org/www-project-top-10-for-large-language-model-applications/)
- [MITRE ATT&CK T1213.006 — Databases](https://attack.mitre.org/techniques/T1213/006/)
- [MITRE ATT&CK M1041 — Data Loss Prevention](https://attack.mitre.org/mitigations/M1041/)
- [NSA & CISA — Top 10 Cloud Security Mitigation Strategies: Secure Data in the Cloud (CSI, March 2024)](https://media.defense.gov/2024/Mar/07/2003407862/-1/-1/0/CSI-CLOUDTOP10-SECURE-DATA.PDF)
- [Google Cloud — 4 Steps to Stop Data Exfiltration with Google Cloud](https://cloud.google.com/blog/products/identity-security/4-steps-to-stop-data-exfiltration-with-google-cloud)
- [Open Policy Agent (OPA)](https://www.openpolicyagent.org/)
- [Cerbos Authorization](https://cerbos.dev/)
- [sqlglot — SQL parser and transpiler](https://github.com/tobymao/sqlglot)
- [sqlparse — non-validating SQL parser](https://github.com/andialbrecht/sqlparse)

## Related Mitigations
- [SAFE-M-23](../SAFE-M-23/README.md): Tool Output Truncation — complementary; applies hard caps **after** execution. SAFE-M-71 rejects dangerous queries before they run; together they provide defense in depth.
- [SAFE-M-16](../SAFE-M-16/README.md): Token Scope Limiting — complementary; reduces the DB-side permission surface so that even a guardrail bypass returns less data.
- [SAFE-M-29](../SAFE-M-29/README.md): Explicit Privilege Boundaries — defines the privilege structure that guardrails enforce at the query layer.
- [SAFE-M-72](../SAFE-M-72/README.md): Data Loss Prevention on Tool Outputs — complementary; SAFE-M-71 blocks overbroad queries at ingress, SAFE-M-72 masks or redacts sensitive columns at egress when a query slips through.

## Version History
| Version | Date       | Changes                 | Author       |
|---------|------------|-------------------------|--------------|
| 1.0     | 2026-04-14 | Initial documentation   | bishnu bista |
