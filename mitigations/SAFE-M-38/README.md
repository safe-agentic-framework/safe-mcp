# SAFE-M-38: PKCE Enforcement

## Overview
**Mitigation ID**: SAFE-M-38  
**Category**: Preventive Control  
**Effectiveness**: High  
**Implementation Complexity**: Low  
**First Published**: 2025-08-23

## Description
PKCE (Proof Key for Code Exchange) Enforcement mandates the use of PKCE for all OAuth flows to prevent authorization code interception attacks. This mitigation implements RFC 7636 to protect against authorization code theft and replay attacks, particularly in public clients and mobile applications where client secrets cannot be securely stored.

PKCE works by requiring clients to generate a code verifier and code challenge pair. The code challenge is sent during the authorization request, and the code verifier must be provided when exchanging the authorization code for tokens. This prevents attackers from intercepting and reusing authorization codes.

## Mitigates
- [SAFE-T1202](../../techniques/SAFE-T1202/README.md): OAuth Token Persistence
- [SAFE-T1007](../../techniques/SAFE-T1007/README.md): OAuth Authorization Phishing
- [SAFE-T1507](../../techniques/SAFE-T1507/README.md): Authorization Code Interception
- [SAFE-T1408](../../techniques/SAFE-T1408/README.md): OAuth Protocol Downgrade

## Technical Implementation

### Core Principles
1. **Mandatory PKCE**: All OAuth flows must use PKCE regardless of client type
2. **Code Verifier Generation**: Clients generate cryptographically random code verifiers
3. **Code Challenge Creation**: SHA256 hash of code verifier creates the challenge
4. **Verification Enforcement**: Authorization server validates code verifier against challenge

### Architecture Components

**PKCE (Proof Key for Code Exchange) Architecture:**

```
┌─────────────┐    ┌─────────────────────┐    ┌─────────────────┐
│   Client    │───▶│ Authorization       │───▶│ Token          │
│             │    │ Server              │    │ Endpoint       │
│ • Generates │    │ • Stores Code       │    │ • Validates    │
│   Code      │    │   Challenge         │    │   Code         │
│   Verifier  │    │ • Issues Auth       │    │   Verifier     │
│ • Creates   │    │   Code              │    │ • Issues       │
│   Challenge │    │ • Binds Challenge   │    │   Access Token │
└─────────────┘    └─────────────────────┘    └─────────────────┘
       │                       │                       │
       │                       │                       │
       ▼                       ▼                       ▼
┌─────────────┐    ┌─────────────────────┐    ┌─────────────────┐
│ Code        │    │ Authorization       │    │ PKCE           │
│ Verifier    │    │ Response            │    │ Validation     │
│ • Random    │    │ • Auth Code         │    │ • Hash         │
│ • Secure    │    │ • Redirect URI      │    │   Comparison   │
│ • Stored    │    │ • State Parameter   │    │ • Security     │
│   Locally   │    │                     │    │   Enforcement  │
└─────────────┘    └─────────────────────┘    └─────────────────┘
```

**Flow Description:**
1. **Client** generates code verifier and creates code challenge
2. **Authorization Server** stores challenge and issues authorization code
3. **Token Endpoint** validates code verifier against stored challenge
4. **Security** is enforced through cryptographic proof of code possession

### Prerequisites
- OAuth 2.0 authorization server with PKCE support
- Client applications capable of generating cryptographically secure random values
- SHA256 hashing capabilities on both client and server
- PKCE validation logic in token endpoint

### Implementation Steps
1. **Design Phase**:
   - Define PKCE requirements for all OAuth flows
   - Design code verifier generation and storage
   - Plan PKCE validation workflows

2. **Development Phase**:
   - Implement PKCE in authorization server
   - Develop client-side PKCE generation
   - Create PKCE validation in token endpoint

3. **Deployment Phase**:
   - Deploy PKCE-enabled authorization server
   - Update client applications with PKCE support
   - Test PKCE enforcement across all flows

## Benefits
- **High Security**: Prevents authorization code interception and replay attacks
- **Client Protection**: Protects public clients without client secrets
- **Standards Compliance**: Implements RFC 7636 OAuth 2.0 PKCE extension
- **Mandatory Enforcement**: Ensures all OAuth flows use PKCE by default

## Limitations
- **Client Requirements**: All clients must support PKCE generation
- **Backward Compatibility**: May break older clients without PKCE support
- **Implementation Complexity**: Requires changes to both client and server
- **Performance Impact**: Minimal additional cryptographic operations

## Implementation Examples

### Example 1: Client-Side PKCE Generation
```python
import secrets
import hashlib
import base64
import urllib.parse
import string

class PKCEGenerator:
    def __init__(self):
        self.code_verifier = None
        self.code_challenge = None
    
    def generate_code_verifier(self, length=64):
        """Generate a cryptographically random code verifier (RFC 7636: 43-128 chars)."""
        # Enforce RFC length bounds
        length = max(43, min(128, int(length)))
        # Use RFC-allowed characters: ALPHA / DIGIT / "-" / "." / "_" / "~"
        allowed = string.ascii_letters + string.digits + "-._~"
        self.code_verifier = ''.join(secrets.choice(allowed) for _ in range(length))
        return self.code_verifier
    
    def generate_code_challenge(self):
        """Generate code challenge from code verifier"""
        if not self.code_verifier:
            raise ValueError("Code verifier must be generated first")
        
        # Create SHA256 hash of code verifier
        sha256_hash = hashlib.sha256(self.code_verifier.encode('utf-8')).digest()
        
        # Encode as base64url
        self.code_challenge = base64.urlsafe_b64encode(sha256_hash).decode('utf-8')
        
        # Remove padding characters
        self.code_challenge = self.code_challenge.rstrip('=')
        
        return self.code_challenge
    
    def create_authorization_url(self, base_url, client_id, redirect_uri, scope):
        """Create authorization URL with PKCE parameters"""
        params = {
            'response_type': 'code',
            'client_id': client_id,
            'redirect_uri': redirect_uri,
            'scope': scope,
            'code_challenge': self.code_challenge,
            'code_challenge_method': 'S256'
        }
        
        query_string = urllib.parse.urlencode(params)
        return f"{base_url}?{query_string}"
    
    def create_token_request_data(self, authorization_code, client_id, redirect_uri):
        """Create token request data with PKCE verification"""
        return {
            'grant_type': 'authorization_code',
            'code': authorization_code,
            'client_id': client_id,
            'redirect_uri': redirect_uri,
            'code_verifier': self.code_verifier
        }
```

### Example 2: Server-Side PKCE Validation
```python
import base64
import hashlib
from typing import Dict, Union

from oauthlib.oauth2 import RequestValidator


class PKCEValidator(RequestValidator):
    def __init__(self):
        # PRODUCTION WARNING: Use Redis or similar distributed cache instead of in-memory storage
        self.stored_challenges: Dict[str, Dict[str, str]] = {}

    def _store_code_challenge(self, authorization_code: str, code_challenge: str, code_challenge_method: str):
        """Store PKCE challenge for later validation. Always defaults to S256 for security."""
        self.stored_challenges[authorization_code] = {
            "challenge": code_challenge,
            "method": code_challenge_method or "S256",
        }

    def save_authorization_code(self, client_id: str, code: Union[str, Dict[str, str]], request):
        """
        Persist PKCE challenge alongside the authorization code.

        Args:
            client_id: OAuth client identifier
            code: Either a string (authorization code) or dict with 'code' key (oauthlib format)
            request: OAuth request object containing code_challenge and code_challenge_method
        """
        if not request.code_challenge:
            raise ValueError("PKCE code_challenge is required")

        # Default to S256, reject 'plain' for security
        method = request.code_challenge_method or "S256"
        if method not in ("S256",):
            raise ValueError(f"Unsupported PKCE method '{method}'. Only S256 is allowed for security.")

        # Handle both oauthlib dict format and plain string
        auth_code = code["code"] if isinstance(code, dict) else code
        self._store_code_challenge(auth_code, request.code_challenge, method)

    def validate_code_verifier(self, authorization_code: str, code_verifier: str) -> bool:
        """Validate code verifier against stored challenge."""
        challenge_data = self.stored_challenges.get(authorization_code)
        if not challenge_data:
            return False

        if challenge_data["method"] != "S256":
            return False  # Enforce S256 for maximum security

        sha256_hash = hashlib.sha256(code_verifier.encode("utf-8")).digest()
        generated_challenge = base64.urlsafe_b64encode(sha256_hash).decode("utf-8").rstrip("=")

        if generated_challenge != challenge_data["challenge"]:
            return False

        # Clean up to prevent reuse
        self.stored_challenges.pop(authorization_code, None)
        return True

    def validate_token_request(self, request):
        """Validate token request includes PKCE verification."""
        if request.grant_type == "authorization_code":
            if not request.code_verifier:
                raise ValueError("PKCE code_verifier is required for authorization code flow")

            if not self.validate_code_verifier(request.code, request.code_verifier):
                raise ValueError("Invalid PKCE code_verifier")

        return True
```

## Testing and Validation
1. **Security Testing**:
   - Test PKCE enforcement in authorization requests
   - Verify code verifier validation in token requests
   - Test rejection of requests without PKCE
   - Validate challenge method enforcement

2. **Functional Testing**:
   - Verify PKCE generation and validation workflows
   - Test PKCE with different client types
   - Validate error handling for invalid PKCE
   - Test PKCE cleanup and storage management

3. **Integration Testing**:
   - Test end-to-end OAuth flows with PKCE
   - Validate PKCE across different OAuth grant types
   - Test PKCE with mobile and web clients
   - Verify PKCE compliance with OAuth 2.1 requirements

## Deployment Considerations

### Resource Requirements
- **CPU**: Minimal additional overhead for PKCE validation
- **Memory**: Storage for code challenges during authorization flow
- **Network**: No additional network overhead

### Security Considerations
- **Secure Storage**: Code challenges must be stored securely
- **Challenge Cleanup**: Implement proper cleanup of expired challenges
- **Method Enforcement**: Enforce S256 method for enhanced security
- **Audit Logging**: Log PKCE validation attempts and failures

### Performance Considerations
- **Challenge Storage**: Use efficient storage for code challenges
- **Cleanup Scheduling**: Implement background cleanup of expired challenges
- **Caching**: Cache PKCE validation results where appropriate

## Related Mitigations
- [SAFE-M-13](../SAFE-M-13/README.md): OAuth Flow Verification
- [SAFE-M-17](../SAFE-M-17/README.md): Callback URL Restrictions
- [SAFE-M-31](../SAFE-M-31/README.md): Proof of Possession (PoP) Tokens

## References
- [RFC 7636 - Proof Key for Code Exchange by OAuth Public Clients](https://datatracker.ietf.org/doc/html/rfc7636)
- [OAuth 2.1 Security Best Current Practices](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-security-topics)
- [OAuth 2.0 for Native Apps - Best Practices](https://tools.ietf.org/html/rfc8252)
- [Model Context Protocol Specification](https://modelcontextprotocol.io/specification)

## Version History
| Version | Date | Changes | Author |
|---------|------|---------|--------|
| 1.0 | 2025-08-23 | Initial documentation of PKCE Enforcement mitigation | bishnubista |
