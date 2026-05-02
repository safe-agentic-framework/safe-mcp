# SAFE-M-31: Proof of Possession (PoP) Tokens

## Overview
**Mitigation ID**: SAFE-M-31  
**Category**: Cryptographic Control  
**Effectiveness**: High  
**Implementation Complexity**: Medium  
**First Published**: 2025-08-23

## Description
Proof of Possession (PoP) Tokens implement RFC 7800 to bind OAuth tokens to specific clients using cryptographic proof, preventing token replay attacks even if tokens are stolen. This mitigation ensures that only the legitimate client that possesses the required cryptographic material can use the token, significantly reducing the risk of OAuth Token Persistence attacks.

PoP tokens work by requiring clients to demonstrate possession of a private key or other cryptographic material when using access tokens. This prevents attackers from replaying stolen tokens on different clients or systems, as they cannot provide the required cryptographic proof.

## Mitigates
- [SAFE-T1202](../../techniques/SAFE-T1202/README.md): OAuth Token Persistence
- [SAFE-T1506](../../techniques/SAFE-T1506/README.md): Infrastructure Token Theft
- [SAFE-T1706](../../techniques/SAFE-T1706/README.md): OAuth Token Pivot Replay

## Technical Implementation

### Core Principles
1. **Cryptographic Binding**: Tokens are cryptographically bound to specific client identities
2. **Proof Verification**: Each token usage requires cryptographic proof of possession
3. **Client Authentication**: Tokens cannot be used without proper client authentication

### Architecture Components

**PoP Token Flow Architecture:**

```
┌─────────────┐    ┌─────────────────────┐    ┌─────────────────┐
│   Client    │───▶│ Authorization       │───▶│ Resource        │
│             │    │ Server              │    │ Server          │
│ • Private   │    │ • Validates PoP     │    │ • Verifies PoP  │
│   Key       │    │   Token             │    │   Token        │
│ • Generates │    │ • Issues Access     │    │ • Grants Access │
│   PoP Token│    │   Token             │    │   if Valid      │
└─────────────┘    └─────────────────────┘    └─────────────────┘
       │                       │                       │
       │                       │                       │
       ▼                       ▼                       ▼
┌─────────────┐    ┌─────────────────────┐    ┌─────────────────┐
│ PoP Token   │    │ Access Token +      │    │ Resource        │
│ Request     │    │ PoP Validation      │    │ Access          │
│ • Signed    │    │ • Cryptographic     │    │ • Client-       │
│ • Timestamp │    │   Signature Check   │    │   Specific      │
│ • Nonce     │    │ • Binding Verify    │    │ • Secure        │
└─────────────┘    └─────────────────────┘    └─────────────────┘
```

**Flow Description:**
1. **Client** generates PoP token using private key
2. **Authorization Server** validates PoP token and issues access token
3. **Resource Server** verifies PoP token before granting access
4. **Security** is maintained through cryptographic binding at each step

### Prerequisites
- OAuth 2.0 infrastructure supporting PoP tokens
- Client-side cryptographic capabilities (hardware security modules, secure key storage)
- Authorization server support for PoP token issuance
- Resource server implementation of PoP validation

### Implementation Steps
1. **Design Phase**:
   - Define PoP token requirements and cryptographic algorithms
   - Design client key management and storage
   - Plan token validation workflows

2. **Development Phase**:
   - Implement PoP token issuance in authorization server
   - Develop client-side cryptographic operations
   - Create PoP validation in resource servers

3. **Deployment Phase**:
   - Deploy PoP-enabled authorization server
   - Update client applications with PoP support
   - Configure resource servers for PoP validation

## Benefits
- **High Security**: Prevents token replay attacks even if tokens are compromised
- **Client Isolation**: Ensures tokens can only be used by the intended client
- **Standards Compliance**: Implements RFC 7800 OAuth 2.0 PoP extension
- **Backward Compatibility**: Can be implemented alongside existing OAuth flows

## Limitations
- **Implementation Complexity**: Requires changes to both client and server infrastructure
- **Performance Impact**: Additional cryptographic operations increase request latency
- **Key Management**: Requires secure client-side key storage and management
- **Deployment Effort**: Significant changes needed across OAuth ecosystem

## Implementation Examples

### Example 1: PoP Token Request
```python
import base64
import hashlib
import secrets
import time

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa


def generate_nonce(length: int = 16) -> str:
    """Generate a cryptographically strong nonce."""
    return base64.urlsafe_b64encode(secrets.token_bytes(length)).decode("utf-8").rstrip("=")


def hash_access_token(access_token: str) -> str:
    """Create a deterministic hash of the access token for PoP binding."""
    digest = hashlib.sha256(access_token.encode("utf-8")).digest()
    return base64.urlsafe_b64encode(digest).decode("utf-8").rstrip("=")


def create_pop_token_request(client_private_key, access_token: str) -> str:
    """Create a PoP token request with cryptographic proof."""

    header = {
        "alg": "RS256",
        "typ": "JWT",
        "kid": "client-key-id",
    }

    payload = {
        "at": hash_access_token(access_token),
        "ts": int(time.time()),
        "m": "POST",
        "u": "https://api.example.com/resource",
        "nonce": generate_nonce(),
    }

    pop_token = jwt.encode(payload, client_private_key, algorithm="RS256", headers=header)
    return pop_token
```

### Example 2: PoP Token Validation
```python
import logging
import time

import jwt

TOKEN_SKEW_SECONDS = 300  # Accept tokens within ±5 minutes

logger = logging.getLogger(__name__)


def validate_pop_token(pop_token: str, access_token: str, client_public_key, http_method: str, request_url: str) -> bool:
    """Validate a PoP token on the resource server."""

    try:
        payload = jwt.decode(pop_token, client_public_key, algorithms=["RS256"])

        if payload["at"] != hash_access_token(access_token):
            raise ValueError("Access token mismatch")

        if abs(payload["ts"] - time.time()) > TOKEN_SKEW_SECONDS:
            raise ValueError("Token expired")

        if payload.get("m", "").upper() != http_method.upper():
            raise ValueError("HTTP method mismatch")

        if payload.get("u") and payload["u"] != request_url:
            raise ValueError("Request URL mismatch")

        return True

    except (jwt.InvalidTokenError, KeyError, ValueError) as e:
        logger.warning(f"PoP validation failed: {e}")
        return False
```

## Testing and Validation
1. **Security Testing**:
   - Test token replay prevention with stolen tokens
   - Verify cryptographic binding integrity
   - Test client impersonation attempts
   - Validate nonce replay protection

2. **Functional Testing**:
   - Verify PoP token issuance and validation
   - Test client key rotation scenarios
   - Validate performance impact measurements
   - Test error handling and edge cases

3. **Integration Testing**:
   - Test end-to-end OAuth flows with PoP
   - Validate client-server interoperability
   - Test fallback mechanisms for non-PoP clients

## Deployment Considerations

### Resource Requirements
- **CPU**: Additional cryptographic operations increase CPU usage by 10-20%
- **Memory**: Minimal additional memory overhead for PoP validation
- **Network**: Slightly larger token sizes due to PoP payload

### Security Considerations
- **Key Storage**: Client private keys must be stored securely (HSM recommended)
- **Key Rotation**: Implement regular key rotation procedures
- **Audit Logging**: Log all PoP validation attempts and failures
- **Fallback Mechanisms**: Plan for scenarios where PoP validation fails

### Monitoring and Alerting
- PoP validation failure rates
- Client key usage patterns
- Token binding verification success rates
- Performance impact metrics

## Related Mitigations
- [SAFE-M-16](../SAFE-M-16/README.md): Token Scope Limiting
- [SAFE-M-17](../SAFE-M-17/README.md): Callback URL Restrictions
- [SAFE-M-19](../SAFE-M-19/README.md): Token Usage Tracking

## References
- [RFC 7800 - Proof of Possession for OAuth 2.0 Access Tokens](https://datatracker.ietf.org/doc/html/rfc7800)
- [OAuth 2.0 Security Best Current Practices](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-security-topics)
- [Model Context Protocol Specification](https://modelcontextprotocol.io/specification)

## Version History
| Version | Date | Changes | Author |
|---------|------|---------|--------|
| 1.0 | 2025-08-23 | Initial documentation of PoP Tokens mitigation | bishnubista |
