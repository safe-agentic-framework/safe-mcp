# SAFE-M-14: Server Allowlisting

## Overview
**Mitigation ID**: SAFE-M-14  
**Category**: Preventive Control  
**Effectiveness**: High (against the curated set of directly-mapped techniques below; allowlisting alone does not address compromised-but-allowlisted endpoints)  
**Implementation Complexity**: Medium  
**First Published**: 2025-07-05

## Description

Server Allowlisting is a policy-level control that decides, before any payload exchange, whether a given MCP connection target is permitted. The unit of allowlisting is a plain string identifier — a hostname, a domain, or an OAuth Authorization Server issuer URL. The allowlist policy answers one question: "is this endpoint permitted to be a counterparty for this MCP client at all?" Mechanisms that prove an endpoint actually *is* who its identifier claims (mutual TLS, certificate pinning, SAN/SPKI checks, RFC 9207 issuer-claim validation, DNSSEC) are deliberately not part of M-14's surface — they belong to other controls and are described inline as enforcement mechanisms with which M-14 is layered.

This narrow scoping is intentional. An allowlist policy that conflates "endpoint string is permitted" with "the endpoint that answered actually corresponds to that string" overlaps multiple adjacent canonical mitigations (SAFE-M-45 *Tool Manifest Signing & Server Attestation* owns cryptographic attestation and SPIFFE-style workload identity; SAFE-M-13 *OAuth Flow Verification* owns RFC 9207 `iss`-claim validation). M-14's value is that it gives operators a deny-by-default policy decision they can audit and version independently of the transport mechanism that enforces it. Allowlisting is insufficient on its own — a compromised but still-allowlisted endpoint defeats the policy entirely. Pair with payload integrity (SAFE-M-2), audit logging (SAFE-M-12), and OAuth flow verification (SAFE-M-13) as recommended companions for end-to-end coverage.

## Mitigates
- [SAFE-T1004](../../techniques/SAFE-T1004/README.md): Server Impersonation / Name-Collision — allowlisting trusted MCP server domains/endpoints prevents the client from connecting to a name-colliding impersonator
- [SAFE-T1007](../../techniques/SAFE-T1007/README.md): OAuth Authorization Phishing — allowlisting trusted MCP server domains denies OAuth flows that would route through unknown server endpoints
- [SAFE-T1009](../../techniques/SAFE-T1009/README.md): OAuth Authorization Server Spoofing — the AS-domain allowlist portion (M-14 covers the policy decision over which Authorization Server issuer URLs are permitted; SAFE-M-13 covers the protocol-level RFC 9207 `iss`-claim validation that proves a response actually came from that issuer)
- [SAFE-T1303](../../techniques/SAFE-T1303/README.md): Container Runtime Escape via Orchestrator — allowlisting which orchestrator MCP servers may be attached limits exposure to malicious orchestrators
- [SAFE-T1407](../../techniques/SAFE-T1407/README.md): DNS Proxy / Man-in-the-Middle — allowlist policy as one layer of a layered defense; DNS integrity (DNSSEC, DNS-over-HTTPS) at the resolution layer is the complementary mechanism
- [SAFE-T1606](../../techniques/SAFE-T1606/README.md): File System Tool Server Restriction — allowlisting which MCP file-system tool servers are permitted to run

For citing techniques excluded from this curated list, see the `## Out of scope` section below.

## Technical Implementation

### Core Principles

1. **The allowlist unit is a hostname / domain / issuer-URL string.** Allowlist entries are concrete connection-target strings — not cryptographic credentials. M-14 does not specify, store, or validate certificates, SPKI fingerprints, or peer-cert chains; those concerns belong to deployment-layer transport mechanisms (mutual TLS, cert pinning) or to SAFE-M-45.
2. **Three-phase enforcement model — M-14 owns Phase 1 only.**
   - **Phase 1 — pre-connect**: M-14's surface. Resolve the configured target endpoint to a hostname or issuer URL string; consult the allowlist policy; ADMIT or DENY before any payload exchange.
   - **Phase 2 — TLS handshake**: the deployment-chosen mechanism (mutual TLS, cert pinning) enforces transport-layer endpoint authentication for the allowlisted string. M-14 does not specify the mechanism — pair with SAFE-M-45 (manifest attestation / SPIFFE) or operator-deployed transport controls.
   - **Phase 3 — post-handshake**: for OAuth flows, RFC 9207 `iss`-claim validation (SAFE-M-13's mechanism) confirms the response actually came from the allowlisted Authorization Server.
3. **Denial-by-default with explicit governance.** Empty allowlist denies all connections. New entries require human approval, are accompanied by an owner and a review cadence, and emit SAFE-M-12 audit events on add / modify / delete and on every allowlist evaluation that denies.
4. **Layered with companion controls, not load-bearing alone.** The allowlist policy alone does not prove behavior — a compromised but still-allowlisted endpoint passes the gate. Deploy alongside SAFE-M-2 (payload integrity), SAFE-M-12 (audit), and SAFE-M-13 (OAuth flow verification) as recommended companions.
5. **Hostname-only allowlists do not close the DNS gap.** A hostname allowlist that resolves through an attacker-controlled DNS path is bypassed at the resolution layer. Pair with DNSSEC / DNS-over-HTTPS at deployment, or pair with cert-pinning at the transport layer (SAFE-M-45-adjacent), to close that gap. M-14 does not close it on its own.

### Architecture Components

```text
┌──────────────────────┐  ┌──────────────────────┐  ┌─────────────────────────┐
│ Phase 1: pre-connect │  │ Phase 2: TLS         │  │ Phase 3: post-handshake │
│                      │  │ handshake            │  │ (OAuth flows only)      │
│ Policy decision      │  │                      │  │                         │
│ - hostname allowed?  │  │ Deployment mechanism │  │ Protocol mechanism      │
│ - issuer URL         │  │ enforces transport   │  │ validates issuer claim  │
│   allowed?           │  │ for the allowlisted  │  │ (RFC 9207 iss claim)    │
│ → ADMIT or DENY      │  │ endpoint             │  │                         │
│                      │  │                      │  │                         │
│ ★ M-14's surface     │  │ ★ SAFE-M-45-adjacent │  │ ★ SAFE-M-13's surface   │
│   (policy over       │  │   / operator-        │  │   (M-14 does not own)   │
│    strings)          │  │   deployed           │  │                         │
│                      │  │   (M-14 does not own)│  │                         │
└──────────────────────┘  └──────────────────────┘  └─────────────────────────┘
           │                       │                          │
           └───────── on any phase failure → SAFE-M-12 audit event ─┘
```

### Prerequisites

Hard prerequisites — M-14 cannot make policy decisions without these:

- **A registry of permitted endpoint strings** (hostnames, domains, OAuth issuer URLs) with explicit ownership and review cadence per entry. The registry is M-14's own state and must be populated before the policy can ADMIT any connection. The schema separates `servers` (matched by host[:port]) from `oauth_authorization_servers` (matched by scheme+host+port+path per RFC 8414); the two namespaces canonicalize differently and cannot share entries.
- **A connection-establishment hook in the MCP client** where the policy can be evaluated *before* any TCP / TLS handshake or HTTP request to the target endpoint. Without this hook the policy decision cannot precede the network exchange and Phase 1 of the enforcement model is unenforceable.

### Recommended Companions

M-14 is functional standalone — none of the following is a hard prerequisite. The companions below extend M-14's coverage to threat surfaces M-14 does not address.

- An audit substrate to persist allowlist-decision events. SAFE-M-12 *Audit Logging* is the recommended choice; any structured event sink with retention and tamper-evidence equivalent to a security-audit log is acceptable. Without an audit substrate, M-14 still makes ADMIT/DENY decisions but loses the accountability trail.
- For OAuth flows: SAFE-M-13 *OAuth Flow Verification* validates RFC 9207 `iss` claims after M-14 admits the issuer URL. M-14 alone does not protect against a forged token claiming an allowlisted issuer; without M-13, that gap remains open.
- For hostname allowlists in untrusted networks: DNS integrity (DNSSEC, DNS-over-HTTPS) at the resolution layer, or cert-pinning at the transport layer, to close the DNS gap M-14 does not address.
- SAFE-M-2 *Cryptographic Integrity for Tool Descriptions* — verifies the payload that flows over the connection M-14 admits.

### Implementation Steps

1. **Design Phase**:
   - Catalog the connection targets the MCP client must reach: server endpoints (hostnames or domains), Authorization Server issuer URLs, and any other endpoint categories.
   - Decide the allowlist data model: per-environment (dev/staging/prod), per-client-instance, or global. Single-environment global is the simplest starting structure.
   - Define the suppression / exception governance: who can add an entry, who must review, what the maximum lifetime of an "exception" entry is, how exceptions are audited.

2. **Development Phase**:
   - Implement the policy decision as a pure function over the allowlist registry — `is_allowlisted(endpoint_string) → bool`. No transport, certificate, or token concerns inside this function.
   - Wire the policy decision into the connection path: the function is consulted before any TCP / TLS handshake or HTTP request to the target endpoint.
   - Emit SAFE-M-12 audit events on every DENY decision (with endpoint, reason, timestamp, client identifier) and on add/modify/delete of allowlist entries.
   - Implement a shadow-mode flag that logs DENY decisions without enforcing them, for soak testing before enforcement.

3. **Deployment Phase**:
   - Run a shadow-policy soak period (recommended minimum 7 days) where DENY decisions are logged but not enforced. Review the shadow-log for legitimate-but-not-yet-allowlisted endpoints; add them with proper governance before flipping to enforce.
   - Flip to enforce mode. Confirm denied-connection rate stabilizes after the cutover.
   - Configure monitoring per the *Monitoring and Alerting* section below.
   - Establish the review cadence for allowlist entries (suggested quarterly minimum); entries with no traffic in the cadence window are candidates for removal.

## Benefits
- **Deterministic decision**: allowlist evaluation is a pure function over a registry of strings; no model inference, no probabilistic verdict. The decision is reproducible and auditable.
- **Defense-in-depth complement**: M-14 layers cleanly with payload integrity (SAFE-M-2), audit (SAFE-M-12), OAuth flow verification (SAFE-M-13), and transport-layer mechanisms (mutual TLS, cert pinning, DNSSEC). Each layer addresses a different threat surface; M-14 specifically addresses "is this counterparty permitted at all?"
- **Operational signal**: the rate of DENY decisions over time is a useful tampering canary. A sudden spike in denied-connection attempts against a previously-stable client is a strong signal that something in the configuration or environment has shifted.
- **Operator-tunable per environment**: development environments can be permissive or operate in shadow-mode while production environments enforce strictly. The decision is local to the deployment.

## Limitations
- **Insufficient on its own**: an allowlist policy gates only by endpoint string. A compromised-but-still-allowlisted endpoint passes the gate. Pair with payload integrity (SAFE-M-2) and behavioral monitoring (SAFE-M-11) for end-to-end coverage of compromised-counterparty risk.
- **Allowlist drift**: stale entries that no longer correspond to live endpoints accumulate over time. Without active review cadence, the allowlist grows monotonically and the meaningful signal of "denied unknown endpoint" weakens.
- **DNS-only allowlists are bypassed at the resolution layer**: an attacker who controls the DNS path between the client and the resolver can redirect an allowlisted hostname to a malicious endpoint. Pair with DNSSEC / DNS-over-HTTPS at the deployment layer, or pair with cert-pinning at the transport layer.
- **OAuth dynamic-discovery undermines AS allowlists**: if the OAuth client dynamically discovers an Authorization Server endpoint at runtime (rather than using a statically-configured allowlisted issuer URL), the allowlist policy can be circumvented unless the discovery result is itself validated against the allowlist before use. Combine M-14's AS-domain allowlist with SAFE-M-13's RFC 9207 `iss` validation; M-14 alone does not close this gap.
- **Outbound-only in this version**: M-14 currently covers the client-to-server outbound direction. The inverse direction (server-side client allowlisting / pre-authentication metadata concealment) is a distinct surface tracked separately in the corpus catalog and not within M-14's scope as of this revision.

## Out of scope

The following citing techniques are deliberately excluded from M-14's curated `## Mitigates` list above; the rationale and the better-fit canonical mitigation are documented per technique:

**Mislabeled citations (3)** — the technique cites M-14 with a label that does not correspond to M-14's actual control concept:

- `techniques/SAFE-T1002/README.md` cites M-14 as "Dependency Scanning" — wants automated package vulnerability scanning, which is a supply-chain control surface, not connection-identity allowlisting. (T1002 also mislabels SAFE-M-13's title in the same preventive-controls list; that's a separate audit issue.) Better-fit canonical mitigation for the dependency-scanning ask is not currently in the canonical set; flagged for corpus follow-up.
- `techniques/SAFE-T1305/README.md` cites M-14 as "AppArmor/SELinux Policies" — wants host-level mandatory access controls. Different control surface entirely (host-process isolation rather than connection-identity policy). No current canonical mitigation in the corpus is a clean redirect target; flagged for corpus follow-up.
- `techniques/SAFE-T1804/README.md` cites M-14 as "API Access Allowlisting" — wants per-API authorization (which API surface a tool can access), which is a different scope (intra-server resource ACL, not inter-server connection allowlist). Better fit: SAFE-M-29 *Explicit Privilege Boundaries*.

**Partial-fit citations (2)** — the technique cites M-14 with the right concept but the technique's primary ask falls outside M-14's scope:

- `techniques/SAFE-T1204/README.md` cites M-14 for vector-store access control. The primary ask is per-data-store authorization (which MCP servers can read which vector stores), which is a per-resource ACL surface. Better fit: SAFE-M-29 *Explicit Privilege Boundaries*.
- `techniques/SAFE-T1308/README.md` cites M-14 for "strict allowlist of trusted Authorization Server issuers + validate `iss` claim". M-14 covers the issuer-URL allowlist policy decision; the `iss`-claim validation that proves a token actually came from that issuer is SAFE-M-13's RFC 9207 mechanism. T1308's full coverage requires a *dual cite* of M-14 (issuer URL allowlist) + SAFE-M-13 (`iss`-claim validation), not M-14 alone.

**Boundary-deferred citation (1)**:

- `techniques/SAFE-T1604/README.md` cites M-14 for inbound server-side client allowlisting and version-endpoint denial. The primary surface there is *pre-authentication metadata concealment* (the server should not expose `serverInfo` / version metadata to clients that have not yet authenticated). The corpus catalog identifies a separate canonical mitigation for that surface that does not yet have a published README. Once that canonical mitigation is authored, T1604's citation should be redirected there. Subsuming this surface under M-14 in the meantime would conflate two distinct control concepts — outbound endpoint policy (M-14) and inbound metadata concealment (the separate canonical) — so M-14 stays outbound-only in this version.

## Implementation Examples

### Example 1: Outbound MCP server allowlist policy (Python) — vulnerable vs protected

```python
# VULNERABLE: client connects to whatever endpoint the configuration provides.
# An attacker who can influence the configuration (file mutation, environment
# variable injection, supply-chain compromise of the configuration loader)
# redirects the client to a hostile endpoint.
def connect_to_mcp_server_unsafe(config: dict) -> "MCPConnection":
    endpoint = config["mcp_server_endpoint"]  # no policy gate
    return mcp_client.connect(endpoint)
```

```python
# PROTECTED: deny-by-default allowlist gate consulted before any connection.
# Mismatch emits an audit event and refuses the connection. The gate is a
# pure function over a registry of strings — it does not perform any TLS,
# certificate, or token validation; those are delegated to the transport
# adapter (SAFE-M-45-adjacent or operator-deployed mTLS).

import time
from dataclasses import dataclass
from urllib.parse import urlparse

# Allowlist entries are tagged by `kind` because servers and OAuth issuers
# canonicalize differently — see _canonicalize_server vs _canonicalize_oauth_issuer
# below. The YAML schema (Example 2) reflects the same separation.
@dataclass(frozen=True)
class AllowlistEntry:
    endpoint: str           # hostname / domain (kind="server") or full issuer URL (kind="oauth_issuer")
    kind: str               # "server" | "oauth_issuer"
    owner: str
    review_by: str          # ISO-8601 date; entries past review_by are flagged stale
    reason: str

class ServerAllowlistPolicy:
    """Pure policy decision over a registry of permitted endpoint strings.

    M-14 surface only — does NOT perform certificate or token validation.
    Servers and OAuth issuers are stored in separate sets and canonicalize
    differently: server entries reduce to host[:port]; OAuth issuer entries
    preserve scheme + host[:port] + path because RFC 8414 issuers can share
    host[:port] and differ only by path (e.g., per-tenant issuers).
    """

    def __init__(self, entries: list[AllowlistEntry], shadow_mode: bool = False) -> None:
        self._server_allowed = {
            self._canonicalize_server(e.endpoint) for e in entries if e.kind == "server"
        }
        self._oauth_issuer_allowed = {
            self._canonicalize_oauth_issuer(e.endpoint) for e in entries if e.kind == "oauth_issuer"
        }
        self._shadow_mode = shadow_mode

    @staticmethod
    def _canonicalize_server(endpoint: str) -> str:
        # Server entries are matched by host[:port] only.
        parsed = urlparse(endpoint if "://" in endpoint else f"https://{endpoint}")
        host = (parsed.hostname or "").lower()
        return f"{host}:{parsed.port}" if parsed.port else host

    @staticmethod
    def _canonicalize_oauth_issuer(issuer_url: str) -> str:
        # OAuth issuer entries preserve scheme + host + port + path.
        # RFC 8414 §2: an issuer URL can include a path component, and two
        # distinct issuers (e.g., per-tenant) may share host[:port] and
        # differ only by path. Dropping the path here would collapse them
        # into one allowlist key and over-allow.
        parsed = urlparse(issuer_url)
        scheme = (parsed.scheme or "https").lower()
        host = (parsed.hostname or "").lower()
        host_port = f"{host}:{parsed.port}" if parsed.port else host
        path = parsed.path.rstrip("/")  # treat trailing slash as equivalent
        return f"{scheme}://{host_port}{path}"

    def evaluate(self, endpoint: str, kind: str) -> bool:
        if kind == "server":
            return self._canonicalize_server(endpoint) in self._server_allowed
        if kind == "oauth_issuer":
            return self._canonicalize_oauth_issuer(endpoint) in self._oauth_issuer_allowed
        raise ValueError(f"unknown allowlist kind: {kind!r}")

    @property
    def shadow_mode(self) -> bool:
        return self._shadow_mode

def connect_to_mcp_server(
    config: dict,
    policy: ServerAllowlistPolicy,
    audit_emit,           # callable: emit_event(event_type, payload) → None
    client_id: str,       # logical client identifier for the audit trail
) -> "MCPConnection":
    endpoint = config["mcp_server_endpoint"]
    permitted = policy.evaluate(endpoint, kind="server")

    # Audit payload carries the canonical fields M-14's Implementation Steps +
    # Integration Testing sections document (timestamp, endpoint, decision,
    # client_id, reason), plus a `kind` discriminator (server vs oauth_issuer)
    # so analysts can query decisions by allowlist namespace.
    audit_emit(
        "safe_m_14_allowlist_decision",
        {
            "timestamp_utc": time.time(),
            "endpoint": endpoint,
            "kind": "server",
            "decision": "ADMIT" if permitted else "DENY",
            "client_id": client_id,
            "reason": None if permitted else "endpoint not in SAFE-M-14 allowlist",
        },
    )

    if not permitted and not policy.shadow_mode:
        raise ConnectionRefusedError(
            f"endpoint {endpoint!r} is not in the SAFE-M-14 allowlist"
        )
    return mcp_client.connect(endpoint)
```

### Example 2: YAML allowlist policy schema

```yaml
# SAFE-M-14 allowlist policy — outbound endpoint allowlist for MCP clients.
# Schema is intentionally narrow: hostname / issuer-URL strings only.
# No mTLS / cert-pinning / RFC 9207 fields — those belong to other controls.

version: 1
mode: enforce                       # one of: shadow | enforce
audit_sink: safe_m_12               # event-emit target for ADMIT/DENY events

allowlist:
  servers:
    - endpoint: mcp.example.com
      owner: platform-team@example.com
      review_by: 2026-08-01
      reason: production MCP server for tools/finance

    - endpoint: mcp-staging.example.com
      owner: platform-team@example.com
      review_by: 2026-06-01
      reason: staging environment for tools/finance

  oauth_authorization_servers:
    - issuer_url: https://login.example.com
      owner: identity-team@example.com
      review_by: 2026-07-15
      reason: |
        corporate IdP issuer URL — RFC 9207 iss-claim validation
        required (delegated to SAFE-M-13)

# Suppressions: time-bounded exceptions to the deny-by-default policy.
# Owner, expiry, and reason are mandatory; expired suppressions are
# inert and emit a stale-suppression alarm.
suppressions:
  - endpoint: legacy-mcp.example.com
    owner: platform-team@example.com
    expires_at: 2026-06-30
    reason: |
      decommissioning legacy server; allowlisted through migration window.
      remove on or before expires_at.
```

## Testing and Validation

1. **Security Testing**:
   - **Synthetic non-allowlisted-endpoint replay**: attempt connections to a corpus of non-allowlisted hostnames covering name-collision variants (typosquats, IDN homoglyphs, subdomain confusions). All must result in DENY decisions and SAFE-M-12 audit events.
   - **OAuth dynamic-discovery negative test**: simulate an attempt to discover an Authorization Server endpoint at runtime where the discovered endpoint is not in the allowlist. Must result in DENY before any token exchange.
   - **Shadow-mode → enforce transition**: run shadow mode for the planned soak window, then flip to enforce. Confirm the enforce-mode rollout does not deny any legitimate traffic that the shadow log did not previously flag.

2. **Functional Testing**:
   - **Allowlist drift alarm**: entries with no traffic in the configured cadence window (e.g., 90 days) should surface in a stale-entries report. Test by populating the allowlist with a deliberately-stale entry and confirming the report flags it.
   - **Suppression expiry**: a suppression past its `expires_at` should be inert (treated as if absent) and emit a stale-suppression alarm.
   - **Performance impact**: allowlist evaluation is a hash-set membership check; latency overhead per connection is dominated by the surrounding TCP / TLS handshake. Measure in the deployment's connection-establishment hot path before declaring overhead acceptable.

3. **Integration Testing**:
   - **Negative test — M-14 alone does not block forged-`iss` tokens**: present a token whose `iss` claim names an allowlisted issuer URL but whose signature is from a different issuer. M-14's allowlist evaluation will ADMIT the connection (the issuer URL is permitted) — that is M-14 behaving correctly within its surface. To reject the forged token, the deployment should be paired with SAFE-M-13's RFC 9207 `iss`-claim validation. This negative test confirms M-14 is not over-claimed in the deployment and documents the boundary at which a companion control becomes necessary.
   - **Audit-event chain**: every ADMIT and DENY decision produces a SAFE-M-12 audit event with the canonical fields (timestamp, endpoint, decision, client identifier).

## Deployment Considerations

### Resource Requirements
- **CPU**: bounded — allowlist evaluation is a hash-set membership check on a small string set (typically O(1) per evaluation).
- **Memory**: bounded by the size of the allowlist registry; typical deployments keep the registry under a few hundred entries.
- **Storage**: the allowlist registry persists alongside other deployment configuration.
- **Network**: no additional network overhead — the policy decision is local to the client.

### Performance Impact
- **Latency**: allowlist evaluation adds a constant-time hash lookup to the connection-establishment path. The contribution to per-connection latency is dominated by the surrounding TCP / TLS handshake.
- **Throughput**: no measurable throughput impact at typical allowlist sizes.
- **Resource Usage**: no measurable incremental CPU or memory at typical allowlist sizes.

### Monitoring and Alerting
- **DENY decision rate**: track the rate of DENY decisions over time. A sudden increase against a previously-stable client is a tampering or misconfiguration signal.
- **Stale allowlist entries**: entries with no traffic in the configured cadence window should surface in a stale-entries report.
- **Stale suppressions**: suppressions past their `expires_at` should fire an alarm and be excluded from the active policy.
- **Audit-event volume skew**: a sudden drop in SAFE-M-12 emit volume against a previously-stable baseline indicates a possible audit-pipeline failure that breaks M-14's accountability story.

## References
- [Model Context Protocol Specification](https://modelcontextprotocol.io/specification)
- [RFC 9207: OAuth 2.0 Authorization Server Issuer Identification - Meyer zu Selhausen, Mainka, 2022](https://datatracker.ietf.org/doc/html/rfc9207)
- [NIST SP 800-204C: Implementation of DevSecOps for a Microservices-based Application with Service Mesh](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-204C.pdf)
- [OWASP API Security Top 10 (2023)](https://owasp.org/API-Security/editions/2023/en/0x11-t10/)
- [NIST SP 800-207: Zero Trust Architecture](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-207.pdf)

## Related Mitigations
- [SAFE-M-2](../SAFE-M-2/README.md): Cryptographic Integrity for Tool Descriptions — recommended companion at the post-connection payload-verification layer (M-14 admits the connection; M-2 verifies what flows over it).
- [SAFE-M-12](../SAFE-M-12/README.md): Audit Logging — recommended companion as the substrate for allowlist-decision events (ADMIT, DENY, registry-mutation events).
- [SAFE-M-13](../SAFE-M-13/README.md): OAuth Flow Verification — recommended companion for OAuth flows; M-13 owns RFC 9207 `iss`-claim validation, which closes a gap M-14 alone cannot.
- [SAFE-M-29](../SAFE-M-29/README.md): Explicit Privilege Boundaries — orthogonal authorization surface (per-API and per-resource ACLs); M-14 explicitly defers per-API and per-data-store concerns to M-29.
- [SAFE-M-45](../SAFE-M-45/README.md): Tool Manifest Signing & Server Attestation — recommended companion for the cryptographic-attestation layer (SPIFFE-style workload identity, manifest signing, cert pinning are M-45's surface; M-14 references those as enforcement mechanisms but does not own them).

## Version History
| Version | Date | Changes | Author |
|---------|------|---------|--------|
| 1.0 | 2026-05-02 | Initial documentation: 9 missing template sections authored from a prior 19-line stub; outbound-only scope; three-phase enforcement model with M-14 owning Phase 1 (pre-connect policy) only; curated Mitigates list of 6 directly-mapped citers from 12 raw cites; Out of scope section enumerates 3 mislabels, 2 partial-fits, and 1 boundary-deferred citation; canonical schema migration (Type→Category, Complexity→Implementation Complexity) | bishnu bista |
| 1.1 | 2026-05-04 | **Security:** fixed OAuth issuer canonicalization in Example 1 — `_canonicalize` previously dropped the URL path component, collapsing distinct per-tenant issuers (e.g. `https://login.example.com/tenant1` vs `.../tenant2`, RFC 8414 §2) to the same `host[:port]` key and over-allowing across tenants. Split into separate `_canonicalize_server` (host[:port]) and `_canonicalize_oauth_issuer` (scheme + host + port + path with trailing-slash normalization) functions, with `AllowlistEntry.kind` and `evaluate(kind=...)` selecting the right canonicalization; YAML schema in Example 2 already separated `servers` from `oauth_authorization_servers` so the data model is unchanged. Extended Example 1's audit payload to carry the canonical fields M-14's own Implementation Steps + Integration Testing sections require (`timestamp_utc`, `client_id`, `reason`) plus an additional `kind` discriminator so analysts can query decisions by allowlist namespace; previously only `endpoint` and `decision` were emitted. **Template parity:** restored `### Prerequisites` subsection (template-required) with M-14's actual hard prerequisites (the endpoint registry; the connection-establishment hook); kept `### Recommended Companions` for genuine soft-companion items (audit substrate, SAFE-M-13, DNS integrity, SAFE-M-2). The fixup commit a88a963 had renamed Prerequisites→Recommended Companions on a verifier suggestion that conflated hard prereqs with soft companions; this v1.1 restores the template-required header while preserving the soft-companion framing for the items that actually were soft. | bishnu bista |
