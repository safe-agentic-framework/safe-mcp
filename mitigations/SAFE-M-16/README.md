# SAFE-M-16: Token Scope Limiting

## Overview

**Mitigation ID**: SAFE-M-16
**Category**: Preventive Control
**Effectiveness**: High (Defense-in-Depth with sender-constrained tokens)
**Implementation Complexity**: Medium
**First Published**: 2025-01-05

## Description

Token Scope Limiting is a preventive control that enforces comprehensive validation of OAuth 2.0 token scopes at every API endpoint, ensuring that tokens presented for authorization contain the specific scopes required for the requested operation. This mitigation implements the principle of least privilege for token issuance and validates scope requirements server-side, preventing attackers from substituting limited-scope tokens with elevated-scope tokens to perform unauthorized operations.

In MCP environments, where multiple tools and servers share authentication contexts, Token Scope Limiting protects against privilege escalation by enforcing scope hierarchies (where broader scopes like `admin` include narrower scopes like `read`), implementing per-endpoint scope requirements, and optionally binding tokens to specific senders using mechanisms like mTLS ([RFC 8705](https://datatracker.ietf.org/doc/html/rfc8705)) or DPoP ([RFC 9449](https://www.rfc-editor.org/rfc/rfc9449.html)). This defense-in-depth approach ensures that even if an attacker obtains a valid token, they cannot use it to access operations beyond the token's explicitly granted permissions, and stolen tokens cannot be replayed from different clients.

## Mitigates

- [SAFE-T1308](../../techniques/SAFE-T1308/README.md): Token Scope Substitution - Primary mitigation. Directly prevents attackers from substituting limited-scope tokens with elevated-scope tokens by validating scopes server-side at every endpoint.
- [SAFE-T1007](../../techniques/SAFE-T1007/README.md): OAuth Authorization Phishing - Limits impact. When combined with minimal scope issuance and user warnings for broad permissions, reduces the damage from phished tokens.
- [SAFE-T1202](../../techniques/SAFE-T1202/README.md): OAuth Token Persistence - Reduces impact. Minimal scope tokens limit what persistent unauthorized access can achieve; scope validation prevents lateral movement to higher-privilege operations.

## Technical Implementation

### Core Principles

1. **Server-Side Scope Validation at Every Endpoint**: Never trust client-side scope checks. Validate that the presented token's scopes are sufficient for the requested operation at the Resource Server level before processing any request. This is the primary defense against Token Scope Substitution attacks.

2. **Least Privilege Token Issuance**: Issue tokens with the minimal scopes necessary for each use case. Avoid over-scoping tokens "just in case" and implement granular scope definitions for fine-grained access control. This reduces the blast radius of token compromise.

3. **Scope Hierarchy Enforcement**: Implement hierarchical scope models where higher-level scopes imply lower-level permissions (e.g., `admin` > `write` > `read`), but always validate explicitly rather than assuming inheritance. Document the hierarchy clearly.

4. **Sender-Constrained Token Binding**: Bind tokens to specific clients using cryptographic mechanisms (mTLS per [RFC 8705](https://datatracker.ietf.org/doc/html/rfc8705), DPoP per [RFC 9449](https://www.rfc-editor.org/rfc/rfc9449.html)) to prevent token theft and substitution from unauthorized clients.

5. **Comprehensive Scope Logging and Monitoring**: Log all scope validation decisions (granted/denied) with full context, implement alerting on scope mismatches, and track scope usage patterns for anomaly detection to identify potential token scope substitution attempts.

### Architecture Components

```
+------------------------------------------------------------------------------+
|                   OAuth Token Flow with Scope Validation                      |
+------------------------------------------------------------------------------+

+----------------+     +------------------------+     +------------------------+
|    Client      |     |    Authorization       |     |    Resource Server     |
|  (MCP Host)    |     |       Server           |     |    (MCP Server)        |
+-------+--------+     +-----------+------------+     +-----------+------------+
        |                          |                              |
        | 1. Request Token         |                              |
        |   (minimal scopes)       |                              |
        |------------------------->|                              |
        |                          |                              |
        | 2. Issue Token           |                              |
        |   scope: "read list"     |                              |
        |   [+DPoP/mTLS binding]   |                              |
        |<-------------------------|                              |
        |                          |                              |
        |                          |  3. API Request              |
        |                          |    Authorization: Bearer ... |
        |                          |    DPoP: ... (if DPoP)       |
        |-------------------------------------------------------->|
        |                          |                              |
        |                          |      +------------------------+
        |                          |      | SCOPE VALIDATION       |
        |                          |      | PIPELINE               |
        |                          |      +------------------------+
        |                          |      | 1. Verify signature    |
        |                          |      | 2. Validate audience   |
        |                          |      | 3. Check expiration    |
        |                          |      | 4. Verify sender bind  |
        |                          |      |    (DPoP/mTLS)         |
        |                          |      | 5. VALIDATE SCOPES     |
        |                          |      |    - Get endpoint req  |
        |                          |      |    - Check granted     |
        |                          |      |    - Apply hierarchy   |
        |                          |      |    - Log decision      |
        |                          |      +------------------------+
        |                          |                              |
        | 4. Response              |                              |
        |   (200 OK or 403)        |                              |
        |<--------------------------------------------------------|
        |                          |                              |


+------------------------------------------------------------------------------+
|                          SCOPE HIERARCHY MODEL                                |
+------------------------------------------------------------------------------+

                                  admin
                                    |
           +------------+-----------+-----------+------------+
           |            |           |           |            |
           v            v           v           v            v
       write:all    delete:all  config:all  audit:all   user:manage
           |            |           |
           v            v           v
         write        delete      config
           |
           v
          read
           |
           v
          list


+------------------------------------------------------------------------------+
|                    MCP CROSS-TOOL SCOPE ENFORCEMENT                           |
+------------------------------------------------------------------------------+

  +------------------+  +------------------+  +------------------+
  |     Tool A       |  |     Tool B       |  |     Tool C       |
  |  (files:read)    |  |  (files:write)   |  |  (admin)         |
  +--------+---------+  +--------+---------+  +--------+---------+
           |                     |                     |
           +----------+----------+----------+----------+
                      |                     |
                      v                     v
           +---------------------------------------------+
           |           Scope Policy Engine               |
           +---------------------------------------------+
           |  - Per-tool scope requirements map          |
           |  - Cross-tool scope isolation rules         |
           |  - Privilege elevation detection & alerts   |
           |  - Scope usage anomaly detection            |
           +---------------------------------------------+
```

### Prerequisites

- OAuth 2.0 Authorization Server with scope support ([RFC 6749](https://datatracker.ietf.org/doc/html/rfc6749))
- Token introspection endpoint ([RFC 7662](https://datatracker.ietf.org/doc/html/rfc7662)) or JWT validation capability
- Defined scope vocabulary and hierarchy model for the application
- TLS/HTTPS for all OAuth communications
- (Recommended) mTLS support ([RFC 8705](https://datatracker.ietf.org/doc/html/rfc8705)) or DPoP implementation ([RFC 9449](https://www.rfc-editor.org/rfc/rfc9449.html))
- Logging infrastructure for scope validation events
- Per-endpoint scope requirement documentation/configuration

### Implementation Steps

1. **Design Phase**:
   - **Define Scope Vocabulary**: Create a comprehensive list of scopes for all operations (e.g., `mcp:read`, `mcp:write`, `mcp:delete`, `mcp:admin`, `tool:invoke`, `resource:access`)
   - **Design Scope Hierarchy**: Define hierarchical relationships between scopes, documenting which scopes imply others
   - **Map Endpoints to Scopes**: Create a scope-to-endpoint mapping document specifying required scopes for each API endpoint
   - **Choose Sender-Constrained Mechanism**: Decide between mTLS ([RFC 8705](https://datatracker.ietf.org/doc/html/rfc8705)) or DPoP ([RFC 9449](https://www.rfc-editor.org/rfc/rfc9449.html)) based on deployment constraints
   - **Design Monitoring Strategy**: Plan scope validation logging, alerting thresholds, and anomaly detection rules

2. **Development Phase**:
   - **Implement Scope Validation Middleware**: Create a centralized scope validation function/middleware that intercepts all API requests
   - **Build Scope Hierarchy Engine**: Implement scope hierarchy checking logic that correctly resolves hierarchical permissions
   - **Integrate Sender Binding Verification**: Implement mTLS certificate binding or DPoP proof verification
   - **Create Scope Configuration System**: Build configuration system for per-endpoint scope requirements
   - **Implement Logging Integration**: Add comprehensive logging for all scope validation decisions
   - **Develop User Warning System**: Create UI/UX for warning users when applications request overly broad scopes
   - **Write Unit and Integration Tests**: Comprehensive test coverage for scope validation logic

3. **Deployment Phase**:
   - **Configure Scope Requirements**: Deploy scope-to-endpoint mappings to production
   - **Enable Monitoring and Alerting**: Configure scope validation alerts and dashboards
   - **Gradual Rollout**: Consider shadow mode (log but don't enforce) initially, then enforce
   - **Update Client Applications**: Ensure all client applications request minimal required scopes
   - **Train Operations Team**: Educate operations on scope validation monitoring and incident response
   - **Document Scope Vocabulary**: Publish scope vocabulary documentation for API consumers

## Benefits

- **Prevents Privilege Escalation**: Server-side scope validation directly blocks token scope substitution attacks ([SAFE-T1308](../../techniques/SAFE-T1308/README.md)), ensuring attackers cannot use elevated-scope tokens to access operations beyond their authorization level.

- **Defense-in-Depth**: When combined with sender-constrained tokens (mTLS/DPoP), provides multiple layers of protection. Even if an attacker obtains a valid token, they cannot use it from an unauthorized client.

- **Limits Breach Impact**: Minimal scope token issuance reduces the blast radius of compromised tokens. A stolen read-only token cannot be used for write or delete operations.

- **Compliance Alignment**: Supports compliance with security standards (OAuth 2.0 Security BCP, OWASP API Security Top 10 API5:2023) and regulatory requirements for access control.

- **Auditability**: Comprehensive scope validation logging enables forensic analysis, anomaly detection, and compliance auditing of authorization decisions.

- **Transparent to Users**: Properly implemented scope limiting operates transparently, only affecting users when attempting unauthorized operations.

## Limitations

- **Requires Comprehensive Implementation**: Scope validation must be implemented at every endpoint. A single unprotected endpoint creates a vulnerability. This requires discipline and thorough code review.

- **Scope Vocabulary Complexity**: Designing and maintaining a comprehensive scope vocabulary requires upfront effort and ongoing governance, especially as APIs evolve.

- **Performance Overhead**: Scope validation adds latency to every API request. While typically minimal (1-5ms), high-throughput systems should benchmark impact. Token introspection adds additional network calls if not using JWT.

- **Not Protection Against All Token Attacks**: Scope limiting does not prevent attacks using tokens with legitimately granted scopes. If an attacker obtains a token with `admin` scope through phishing, scope validation will grant access.

- **Legacy System Integration**: Retrofitting scope validation into existing systems may require significant refactoring, especially if authorization was previously handled inconsistently.

- **Sender-Constrained Token Complexity**: mTLS and DPoP add deployment complexity, requiring certificate management (mTLS) or cryptographic key handling (DPoP) on clients.

## Implementation Examples

### Example 1: Python (Flask) - Vulnerable vs Protected

```python
# ==========================================
# VULNERABLE APPROACH - NO SCOPE VALIDATION
# ==========================================
from flask import Flask, request, jsonify
import jwt

app = Flask(__name__)
PUBLIC_KEY = "..."  # Your public key
SERVER_AUDIENCE = "https://mcp-server.example.com"

def verify_token(token):
    """Only validates signature, audience, expiration - NOT SCOPES"""
    try:
        payload = jwt.decode(token, PUBLIC_KEY, algorithms=['RS256'],
                           audience=SERVER_AUDIENCE)
        return payload
    except jwt.InvalidTokenError:
        return None

@app.route('/mcp/tools/<tool_id>', methods=['DELETE'])
def delete_tool(tool_id):
    token = request.headers.get('Authorization', '').replace('Bearer ', '')
    payload = verify_token(token)

    if not payload:
        return jsonify({'error': 'Invalid token'}), 401

    # VULNERABLE: No scope validation!
    # Attacker can use any valid token to delete tools
    delete_mcp_tool(tool_id)
    return jsonify({'status': 'deleted'}), 200


# ==========================================
# PROTECTED APPROACH - WITH SCOPE VALIDATION
# ==========================================
from flask import Flask, request, jsonify
from functools import wraps
import jwt
import logging

app = Flask(__name__)
security_logger = logging.getLogger('security.scope')

PUBLIC_KEY = "..."  # Your public key
SERVER_AUDIENCE = "https://mcp-server.example.com"

# Scope hierarchy definition
SCOPE_HIERARCHY = {
    'mcp:admin': ['mcp:write', 'mcp:delete', 'mcp:read', 'mcp:list'],
    'mcp:write': ['mcp:read', 'mcp:list'],
    'mcp:delete': ['mcp:read', 'mcp:list'],
    'mcp:read': ['mcp:list'],
    'mcp:list': []
}

def get_all_implied_scopes(granted_scopes: set) -> set:
    """Expand scopes to include all implied scopes via hierarchy."""
    all_scopes = set(granted_scopes)
    for scope in granted_scopes:
        if scope in SCOPE_HIERARCHY:
            all_scopes.update(SCOPE_HIERARCHY[scope])
    return all_scopes

def verify_token_with_scope(token: str, required_scope: str) -> tuple:
    """Validates token signature, audience, expiration, AND scopes."""
    try:
        # Step 1: Verify signature and standard claims
        payload = jwt.decode(token, PUBLIC_KEY, algorithms=['RS256'],
                           audience=SERVER_AUDIENCE)

        # Step 2: Extract granted scopes
        granted_scopes = set(payload.get('scope', '').split())

        # Step 3: Expand with hierarchy
        effective_scopes = get_all_implied_scopes(granted_scopes)

        # Step 4: Check if required scope is present
        if required_scope not in effective_scopes:
            security_logger.warning(
                f"Scope validation failed: "
                f"sub={payload.get('sub')}, "
                f"required={required_scope}, "
                f"granted={granted_scopes}, "
                f"effective={effective_scopes}"
            )
            return None, 'insufficient_scope'

        security_logger.info(
            f"Scope validation passed: "
            f"sub={payload.get('sub')}, "
            f"required={required_scope}"
        )
        return payload, None

    except jwt.ExpiredSignatureError:
        return None, 'token_expired'
    except jwt.InvalidAudienceError:
        return None, 'invalid_audience'
    except jwt.InvalidTokenError:
        return None, 'invalid_token'

def require_scope(required_scope: str):
    """Decorator to enforce scope requirements on endpoints."""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            token = request.headers.get('Authorization', '').replace('Bearer ', '')

            if not token:
                return jsonify({'error': 'Missing authorization'}), 401

            payload, error = verify_token_with_scope(token, required_scope)

            if error == 'insufficient_scope':
                return jsonify({
                    'error': 'insufficient_scope',
                    'error_description': f'Required scope: {required_scope}',
                    'scope': required_scope
                }), 403
            elif error:
                return jsonify({'error': error}), 401

            # Attach payload to request for use in handler
            request.token_payload = payload
            return f(*args, **kwargs)
        return decorated_function
    return decorator

# Protected endpoints with scope enforcement
@app.route('/mcp/tools/<tool_id>', methods=['DELETE'])
@require_scope('mcp:delete')
def delete_tool(tool_id):
    # Token is validated AND scope is verified
    delete_mcp_tool(tool_id)
    return jsonify({'status': 'deleted'}), 200

@app.route('/mcp/tools', methods=['GET'])
@require_scope('mcp:list')
def list_tools():
    return jsonify(get_all_tools())

@app.route('/mcp/tools/<tool_id>', methods=['GET'])
@require_scope('mcp:read')
def get_tool(tool_id):
    return jsonify(get_tool_by_id(tool_id))

@app.route('/mcp/tools/<tool_id>', methods=['PUT'])
@require_scope('mcp:write')
def update_tool(tool_id):
    return jsonify(update_tool_data(tool_id, request.json))
```

### Example 2: JavaScript/Node.js with DPoP (RFC 9449)

```javascript
// ==========================================
// PROTECTED APPROACH WITH DPoP BINDING
// ==========================================
const express = require('express');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');

const app = express();

const PUBLIC_KEY = process.env.OAUTH_PUBLIC_KEY;
const SERVER_AUDIENCE = 'https://mcp-server.example.com';

// Scope hierarchy
const SCOPE_HIERARCHY = {
  'mcp:admin': ['mcp:write', 'mcp:delete', 'mcp:read', 'mcp:list'],
  'mcp:write': ['mcp:read', 'mcp:list'],
  'mcp:delete': ['mcp:read', 'mcp:list'],
  'mcp:read': ['mcp:list'],
  'mcp:list': []
};

// Security logger
const securityLogger = {
  warn: (msg, data) => console.warn(`[SECURITY] ${msg}`, JSON.stringify(data)),
  info: (msg, data) => console.info(`[SECURITY] ${msg}`, JSON.stringify(data))
};

/**
 * Calculate JWK thumbprint per RFC 7638
 */
function calculateJwkThumbprint(jwk) {
  const ordered = JSON.stringify({
    crv: jwk.crv,
    kty: jwk.kty,
    x: jwk.x,
    y: jwk.y
  });
  return crypto.createHash('sha256').update(ordered).digest('base64url');
}

/**
 * Verify DPoP proof per RFC 9449
 */
function verifyDPoPProof(dpopProof, accessToken, httpMethod, httpUri) {
  try {
    // Decode DPoP header to get the public key
    const dpopHeader = JSON.parse(
      Buffer.from(dpopProof.split('.')[0], 'base64url').toString()
    );

    // Verify DPoP proof signature using the embedded JWK
    const dpopPayload = jwt.verify(dpopProof,
      crypto.createPublicKey({ key: dpopHeader.jwk, format: 'jwk' }),
      { algorithms: ['ES256', 'RS256'] }
    );

    // Verify DPoP claims per RFC 9449
    if (dpopPayload.htm !== httpMethod) {
      return { valid: false, error: 'HTTP method mismatch' };
    }
    if (dpopPayload.htu !== httpUri) {
      return { valid: false, error: 'HTTP URI mismatch' };
    }

    // Verify access token hash (ath) if present
    if (dpopPayload.ath) {
      const expectedAth = crypto
        .createHash('sha256')
        .update(accessToken)
        .digest('base64url');
      if (dpopPayload.ath !== expectedAth) {
        return { valid: false, error: 'Access token hash mismatch' };
      }
    }

    // Calculate JWK thumbprint for binding verification
    const thumbprint = calculateJwkThumbprint(dpopHeader.jwk);

    return { valid: true, thumbprint };
  } catch (error) {
    return { valid: false, error: error.message };
  }
}

/**
 * Expand scopes according to hierarchy
 */
function expandScopeHierarchy(grantedScopes) {
  const effectiveScopes = new Set(grantedScopes);
  for (const scope of grantedScopes) {
    if (SCOPE_HIERARCHY[scope]) {
      SCOPE_HIERARCHY[scope].forEach(s => effectiveScopes.add(s));
    }
  }
  return effectiveScopes;
}

/**
 * Scope validation middleware with DPoP binding
 */
function requireScope(requiredScope) {
  return async (req, res, next) => {
    const authHeader = req.headers.authorization || '';
    const dpopProof = req.headers.dpop;

    // Check for authorization header
    if (!authHeader.startsWith('DPoP ') && !authHeader.startsWith('Bearer ')) {
      return res.status(401).json({ error: 'missing_authorization' });
    }

    const accessToken = authHeader.replace(/^(DPoP|Bearer)\s+/i, '');

    try {
      // Step 1: Verify access token signature and claims
      const tokenPayload = jwt.verify(accessToken, PUBLIC_KEY, {
        audience: SERVER_AUDIENCE,
        algorithms: ['RS256']
      });

      // Step 2: Verify DPoP binding if token is DPoP-bound (cnf.jkt claim)
      if (tokenPayload.cnf && tokenPayload.cnf.jkt) {
        if (!dpopProof) {
          securityLogger.warn('Missing DPoP proof for bound token', {
            sub: tokenPayload.sub,
            jti: tokenPayload.jti
          });
          return res.status(401).json({
            error: 'invalid_token',
            error_description: 'DPoP proof required for sender-constrained token'
          });
        }

        const httpUri = `${req.protocol}://${req.get('host')}${req.originalUrl.split('?')[0]}`;
        const dpopResult = verifyDPoPProof(dpopProof, accessToken, req.method, httpUri);

        if (!dpopResult.valid) {
          securityLogger.warn('DPoP verification failed', {
            sub: tokenPayload.sub,
            error: dpopResult.error
          });
          return res.status(401).json({
            error: 'invalid_dpop_proof',
            error_description: dpopResult.error
          });
        }

        // Verify thumbprint matches token binding
        if (dpopResult.thumbprint !== tokenPayload.cnf.jkt) {
          securityLogger.warn('DPoP thumbprint mismatch - possible token theft', {
            sub: tokenPayload.sub,
            expected: tokenPayload.cnf.jkt,
            received: dpopResult.thumbprint
          });
          return res.status(401).json({
            error: 'invalid_token',
            error_description: 'Token binding mismatch'
          });
        }
      }

      // Step 3: Validate scopes (CRITICAL for preventing SAFE-T1308)
      const grantedScopes = new Set((tokenPayload.scope || '').split(' ').filter(s => s));
      const effectiveScopes = expandScopeHierarchy(grantedScopes);

      if (!effectiveScopes.has(requiredScope)) {
        securityLogger.warn('Scope validation failed', {
          sub: tokenPayload.sub,
          jti: tokenPayload.jti,
          required: requiredScope,
          granted: Array.from(grantedScopes),
          effective: Array.from(effectiveScopes)
        });

        return res.status(403).json({
          error: 'insufficient_scope',
          error_description: `Required scope: ${requiredScope}`,
          scope: requiredScope
        });
      }

      // Log successful validation
      securityLogger.info('Scope validation passed', {
        sub: tokenPayload.sub,
        required: requiredScope,
        endpoint: `${req.method} ${req.path}`
      });

      // Attach validated payload for use in handler
      req.tokenPayload = tokenPayload;
      next();

    } catch (error) {
      if (error.name === 'TokenExpiredError') {
        return res.status(401).json({ error: 'token_expired' });
      }
      if (error.name === 'JsonWebTokenError') {
        return res.status(401).json({ error: 'invalid_token' });
      }
      return res.status(401).json({ error: 'invalid_token', message: error.message });
    }
  };
}

// Protected endpoints with scope enforcement
app.delete('/mcp/tools/:toolId', requireScope('mcp:delete'), (req, res) => {
  // Token validated, DPoP verified (if applicable), scope confirmed
  deleteTool(req.params.toolId);
  res.json({ status: 'deleted' });
});

app.get('/mcp/tools', requireScope('mcp:list'), (req, res) => {
  res.json(getAllTools());
});

app.get('/mcp/tools/:toolId', requireScope('mcp:read'), (req, res) => {
  res.json(getToolById(req.params.toolId));
});

app.put('/mcp/tools/:toolId', requireScope('mcp:write'), (req, res) => {
  res.json(updateTool(req.params.toolId, req.body));
});

app.listen(3000);
```

### Example 3: Scope Policy Configuration (YAML)

```yaml
# scope-policy.yaml - Per-endpoint scope requirements for MCP Server

# Scope definitions with hierarchy
scope_definitions:
  mcp:list:
    description: "List available tools and resources"
    level: 1
    implies: []

  mcp:read:
    description: "Read tool details and resource contents"
    level: 2
    implies:
      - mcp:list

  mcp:write:
    description: "Create and update tools and resources"
    level: 3
    implies:
      - mcp:read
      - mcp:list

  mcp:delete:
    description: "Delete tools and resources"
    level: 3
    implies:
      - mcp:read
      - mcp:list

  mcp:admin:
    description: "Full administrative access"
    level: 4
    implies:
      - mcp:write
      - mcp:delete
      - mcp:read
      - mcp:list

# Endpoint to scope mappings
endpoints:
  # Tool management endpoints
  "GET /mcp/tools":
    required_scope: mcp:list
    description: "List all available tools"
    rate_limit: 100/minute

  "GET /mcp/tools/{id}":
    required_scope: mcp:read
    description: "Get tool details"
    rate_limit: 100/minute

  "POST /mcp/tools":
    required_scope: mcp:write
    description: "Create new tool"
    rate_limit: 10/minute

  "PUT /mcp/tools/{id}":
    required_scope: mcp:write
    description: "Update existing tool"
    rate_limit: 20/minute

  "DELETE /mcp/tools/{id}":
    required_scope: mcp:delete
    description: "Delete tool"
    rate_limit: 5/minute
    audit_log: true

  # Resource endpoints
  "GET /mcp/resources":
    required_scope: mcp:list
    description: "List available resources"

  "GET /mcp/resources/{id}":
    required_scope: mcp:read
    description: "Read resource content"

  "PUT /mcp/resources/{id}":
    required_scope: mcp:write
    description: "Update resource"

  # Administrative endpoints
  "POST /mcp/admin/config":
    required_scope: mcp:admin
    description: "Update server configuration"
    audit_log: true
    require_mfa: true

  "GET /mcp/admin/audit":
    required_scope: mcp:admin
    description: "View audit logs"
    audit_log: true

# Token binding requirements
token_binding:
  # Require DPoP for write/delete operations
  require_dpop_for:
    - mcp:write
    - mcp:delete
    - mcp:admin

  # Allow plain bearer tokens for read-only operations
  allow_bearer_for:
    - mcp:list
    - mcp:read

# Monitoring and alerting configuration
monitoring:
  log_all_scope_decisions: true
  alert_on_scope_failures: true
  alert_threshold: 10  # failures per 5 minutes

  # Anomaly detection rules
  anomaly_detection:
    enabled: true
    rules:
      - name: "scope_elevation_pattern"
        description: "Detect rapid scope elevation attempts"
        condition: "scope_failures > 5 AND different_scopes_attempted > 3"
        window: "5m"
        severity: "high"

      - name: "unusual_admin_access"
        description: "Admin scope used from unusual location"
        condition: "scope == 'mcp:admin' AND geo_location != usual_location"
        severity: "medium"
```

## Testing and Validation

### 1. Security Testing

#### Scope Substitution Attack Tests (SAFE-T1308)
- **Test Case S1**: Attempt DELETE operation with read-only scope token
  - Input: Token with `scope: "mcp:read mcp:list"` calling `DELETE /mcp/tools/123`
  - Expected: 403 Forbidden with `insufficient_scope` error
  - Verify: Error response includes `"scope": "mcp:delete"` requirement

- **Test Case S2**: Attempt to use elevated-scope token from different client
  - Input: DPoP-bound admin token with wrong DPoP proof
  - Expected: 401 Unauthorized with binding mismatch error
  - Verify: Security log captures attempted token replay/theft

- **Test Case S3**: Test scope hierarchy bypass attempts
  - Input: Token with `mcp:read` attempting `mcp:write` operation
  - Expected: 403 Forbidden
  - Verify: Hierarchy expansion does not grant unintended permissions

- **Test Case S4**: Cross-tool scope isolation
  - Input: Token with `tool-a:read` attempting access to Tool B
  - Expected: 403 Forbidden
  - Verify: Tool-specific scopes are properly isolated

#### Boundary Testing
- **Test Case B1**: Token with empty scope string → 403 for all protected endpoints
- **Test Case B2**: Token with malformed scope claim → Handle gracefully, treat as no scopes
- **Test Case B3**: Token with duplicate scopes → Deduplicate and validate correctly
- **Test Case B4**: Token with unknown scope values → Ignore unknown, validate known

### 2. Functional Testing

#### Positive Test Cases
- **Test Case F1**: Valid token with exact required scope
  - Input: Token with `mcp:delete` for `DELETE /mcp/tools/123`
  - Expected: 200 OK, operation succeeds

- **Test Case F2**: Valid token with hierarchically higher scope
  - Input: Token with `mcp:admin` for `GET /mcp/tools`
  - Expected: 200 OK (hierarchy grants `mcp:list` access)

- **Test Case F3**: Multiple scopes in token
  - Input: Token with `mcp:read mcp:write`
  - Expected: Both read and write operations succeed

#### Performance Testing
- **Test Case P1**: Measure scope validation latency
  - Target: < 5ms additional latency per request
  - Method: Load test with 1000 RPS, measure p99 latency

- **Test Case P2**: Token introspection caching effectiveness
  - Measure: Cache hit ratio, introspection endpoint load
  - Target: > 90% cache hit ratio

### 3. Integration Testing

#### MCP Environment Tests
- **Test Case I1**: AI agent scope validation
  - Scenario: LLM attempts tool invocation with insufficient scope
  - Expected: Clear error message suitable for LLM interpretation
  - Verify: Agent can understand and report scope requirements

- **Test Case I2**: Scope validation under concurrent load
  - Scenario: 100 concurrent requests with mixed valid/invalid scopes
  - Expected: All validations correct, no race conditions

- **Test Case I3**: Scope policy hot reload
  - Scenario: Update scope-policy.yaml without restart
  - Expected: New policy takes effect within 30 seconds

#### Audit Log Integration
- **Test Case I4**: Verify all scope decisions logged
  - Fields: timestamp, subject, jti, scope_required, scopes_granted, decision, endpoint, client_ip

## Deployment Considerations

### Resource Requirements

- **CPU**: Minimal additional CPU for scope string parsing and comparison. DPoP verification adds ~1-2ms CPU time per request for cryptographic operations.
- **Memory**: ~10KB per cached token introspection result (if using token introspection with caching). Scope policy configuration typically < 100KB.
- **Storage**: Audit logs at ~500 bytes per request. Plan for retention policy (recommend 90 days minimum for security incidents).
- **Network**: Token introspection adds one HTTP call per unique token (mitigate with caching, TTL matching token lifetime). DPoP adds ~200 bytes to request headers.

### Performance Impact

- **Latency Breakdown**:
  - Scope string parsing: < 0.1ms
  - Hierarchy expansion: < 0.5ms
  - JWT validation (local): 1-2ms
  - Token introspection (uncached): 10-50ms (network dependent)
  - Token introspection (cached): < 1ms
  - DPoP proof verification: 1-3ms
  - **Total overhead**: 2-5ms (JWT with caching), 15-55ms (introspection without caching)

- **Throughput**: Minimal impact. Scope validation is CPU-light. Token introspection caching is critical for high-throughput deployments.

- **Optimization Recommendations**:
  - Use JWT tokens to avoid introspection network calls
  - Implement token validation result caching with TTL
  - Pre-compile scope hierarchy for O(1) lookup

### Monitoring and Alerting

#### Metrics to Monitor
- `scope_validation_success_total{endpoint, scope}` - Counter of successful validations
- `scope_validation_failure_total{endpoint, scope, reason}` - Counter of failures
- `scope_validation_latency_ms{endpoint}` - Histogram of validation latency
- `dpop_verification_failure_total{reason}` - Counter of DPoP proof failures
- `token_introspection_cache_hit_ratio` - Cache effectiveness metric

#### Alert Conditions
| Severity | Condition | Description |
|----------|-----------|-------------|
| Critical | DPoP thumbprint mismatch | Token theft attempt detected |
| High | > 10 scope failures from same subject in 5 minutes | Possible privilege escalation attack |
| High | Scope validation failure rate > 5% | Misconfiguration or attack |
| Medium | Token introspection cache hit ratio < 80% | Performance degradation |
| Info | New scope pattern detected | Configuration drift monitoring |

#### Dashboard Recommendations
- Scope validation success/failure rates by endpoint (time series)
- Top subjects with validation failures (leaderboard)
- Scope usage distribution heatmap
- Latency percentiles for scope validation (p50, p95, p99)
- Geographic distribution of scope failures

## Current Status (2025)

According to industry standards and security research, OAuth scope validation has evolved significantly:

- **[RFC 6819](https://datatracker.ietf.org/doc/html/rfc6819) (OAuth 2.0 Threat Model)** explicitly identifies insufficient scope validation as a critical vulnerability in Section 5.1.5, recommending that Resource Servers MUST verify scope requirements for each protected resource.

- **[OAuth 2.0 Security Best Current Practice](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-security-topics)** (IETF Draft, actively updated) emphasizes comprehensive scope validation at Resource Servers and recommends sender-constrained tokens as the preferred mechanism for high-security deployments.

- **[RFC 9449](https://www.rfc-editor.org/rfc/rfc9449.html) (DPoP)**, published in 2023, provides a standardized mechanism for sender-constrained tokens that is seeing increasing adoption in production OAuth deployments, particularly in financial services and healthcare.

- **[OWASP API Security Top 10](https://owasp.org/www-project-api-security/)** lists Broken Function Level Authorization (API5:2023) as a critical risk, directly related to insufficient scope validation.

- **MCP ecosystem implementations** are increasingly adopting OAuth 2.0 for authentication, but many early implementations focus on signature and audience validation while neglecting comprehensive scope enforcement, creating vulnerability to token scope substitution attacks ([SAFE-T1308](../../techniques/SAFE-T1308/README.md)).

- **Major cloud providers** (AWS, Google Cloud, Microsoft Azure) have implemented comprehensive scope validation in their OAuth Resource Servers, providing reference implementations for MCP deployments.

## References

### RFC Standards
- [RFC 6749 - The OAuth 2.0 Authorization Framework](https://datatracker.ietf.org/doc/html/rfc6749)
- [RFC 6750 - The OAuth 2.0 Authorization Framework: Bearer Token Usage](https://datatracker.ietf.org/doc/html/rfc6750)
- [RFC 6819 - OAuth 2.0 Threat Model and Security Considerations](https://datatracker.ietf.org/doc/html/rfc6819) - Section 5.1.5 explicitly covers scope validation
- [RFC 7662 - OAuth 2.0 Token Introspection](https://datatracker.ietf.org/doc/html/rfc7662)
- [RFC 8705 - OAuth 2.0 Mutual-TLS Client Authentication and Certificate-Bound Access Tokens](https://datatracker.ietf.org/doc/html/rfc8705)
- [RFC 9449 - OAuth 2.0 Demonstrating Proof-of-Possession (DPoP)](https://www.rfc-editor.org/rfc/rfc9449.html)
- [OAuth 2.0 Security Best Current Practice - IETF Draft](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-security-topics)

### Industry Standards
- [OWASP API Security Top 10 - API5:2023 Broken Function Level Authorization](https://owasp.org/www-project-api-security/)
- [OWASP Top 10 for LLM Applications](https://owasp.org/www-project-top-10-for-large-language-model-applications/)
- [Model Context Protocol Specification](https://modelcontextprotocol.io/specification)
- [MCP Security Best Practices](https://modelcontextprotocol.io/specification/draft/basic/security_best_practices)

### Academic Research
- [A Comprehensive Formal Security Analysis of OAuth 2.0 - Fett, Küsters, Schmitz (ACM CCS 2016)](https://publ.sec.uni-stuttgart.de/fettkuestersschmitz-ccs-2016.pdf)

### Additional Resources
- [NIST SP 800-63B - Digital Identity Guidelines](https://pages.nist.gov/800-63-3/sp800-63b.html)
- [OWASP Authorization Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html)

## Related Mitigations

- [SAFE-M-13](../SAFE-M-13/README.md): OAuth Flow Verification - Validates OAuth authorization server legitimacy, complementing scope validation
- [SAFE-M-14](../SAFE-M-14/README.md): Server Allowlisting - Restricts trusted MCP servers, reducing attack surface for token-based attacks
- [SAFE-M-17](../SAFE-M-17/README.md): Callback URL Restrictions - Prevents token redirection, works with scope limiting to protect token lifecycle
- [SAFE-M-19](../SAFE-M-19/README.md): Token Usage Tracking - Monitors token usage patterns, enables detection of scope abuse
- [SAFE-M-20](../SAFE-M-20/README.md): Anomaly Detection - Identifies unusual scope usage patterns that may indicate token compromise
- [SAFE-M-12](../SAFE-M-12/README.md): Audit Logging - Logs scope validation decisions for forensic analysis and compliance

## Version History

| Version | Date | Changes | Author |
|---------|------|---------|--------|
| 1.0 | 2025-01-05 | Initial comprehensive documentation of Token Scope Limiting mitigation, including server-side scope validation, scope hierarchy enforcement, sender-constrained tokens (mTLS/DPoP), and MCP-specific considerations for preventing Token Scope Substitution attacks (SAFE-T1308) | Raju Kumar Yadav |
