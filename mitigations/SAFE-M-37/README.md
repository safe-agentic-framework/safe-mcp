# SAFE-M-37: Token Rotation and Invalidation

## Overview
**Mitigation ID**: SAFE-M-37  
**Category**: Preventive Control  
**Effectiveness**: High  
**Implementation Complexity**: Medium  
**First Published**: 2025-08-23

## Description
Token Rotation and Invalidation implements automatic token refresh cycles and immediate invalidation of compromised tokens to limit the window of opportunity for OAuth Token Persistence attacks. This mitigation reduces the impact of stolen tokens by ensuring they have short lifespans and can be quickly revoked when compromise is detected.

The approach combines proactive token rotation (replacing tokens before expiration) with reactive invalidation (immediately revoking compromised tokens). This dual strategy minimizes the time window during which stolen tokens can be used, significantly reducing the effectiveness of token persistence attacks.

## Mitigates
- [SAFE-T1202](../../techniques/SAFE-T1202/README.md): OAuth Token Persistence
- [SAFE-T1506](../../techniques/SAFE-T1506/README.md): Infrastructure Token Theft
- [SAFE-T1706](../../techniques/SAFE-T1706/README.md): OAuth Token Pivot Replay

## Technical Implementation

### Core Principles
1. **Proactive Rotation**: Tokens are automatically refreshed before expiration
2. **Immediate Invalidation**: Compromised tokens are revoked instantly
3. **Short Lifespans**: Access tokens have minimal validity periods
4. **Secure Refresh**: Refresh tokens are rotated with each access token renewal

### Architecture Components

**Token Rotation and Invalidation Architecture:**

```
┌─────────────┐    ┌─────────────────────┐    ┌─────────────────┐
│   Client    │───▶│ Resource Server     │    │ Security       │
│             │    │                     │    │ Monitor        │
│ • Uses      │    │ • Validates Access  │    │ • Detects      │
│   Access    │    │   Token             │    │   Suspicious   │
│   Token     │    │ • Grants Resource   │    │   Activity     │
│             │    │   Access            │    │ • Triggers     │
└─────────────┘    └─────────────────────┘    │   Alerts       │
       │                       │              └─────────────────┘
       │                       │                       │
       ▼                       ▼                       ▼
┌─────────────┐    ┌─────────────────────┐    ┌─────────────────┐
│ Refresh     │    │ Authorization       │    │ Token           │
│ Request     │───▶│ Server              │◀───│ Revocation     │
│ • Automatic │    │ • Issues New        │    │ Service         │
│ • Proactive │    │   Access Token      │    │ • Blacklists    │
│ • Secure    │    │ • Rotates Refresh   │    │   Compromised   │
│             │    │   Token             │    │   Tokens        │
└─────────────┘    └─────────────────────┘    └─────────────────┘
```

**Flow Description:**
1. **Client** uses access token to access resources
2. **Token Rotation** automatically refreshes tokens before expiry
3. **Security Monitor** detects suspicious activity and triggers alerts
4. **Revocation Service** immediately invalidates compromised tokens

### Prerequisites
- OAuth 2.0 infrastructure with refresh token support
- Token lifecycle management system
- Real-time token revocation capabilities
- Monitoring and alerting for suspicious token usage
- Secure communication channels for token operations

### Implementation Steps
1. **Design Phase**:
   - Define token rotation policies and intervals
   - Design token invalidation workflows
   - Plan monitoring and alerting systems

2. **Development Phase**:
   - Implement automatic token rotation logic
   - Develop token revocation and blacklisting
   - Create monitoring for suspicious token patterns

3. **Deployment Phase**:
   - Deploy token rotation services
   - Configure monitoring and alerting
   - Test token invalidation workflows

## Benefits
- **Reduced Attack Window**: Short-lived tokens minimize persistence opportunities
- **Immediate Response**: Compromised tokens can be revoked instantly
- **Automated Security**: Token rotation happens automatically without user intervention
- **Compliance**: Meets security requirements for token lifecycle management

## Limitations
- **Increased Complexity**: More complex token management infrastructure
- **Performance Impact**: Additional token refresh operations increase latency
- **User Experience**: Potential for session interruptions during rotation
- **Infrastructure Requirements**: Requires robust token management systems

## Implementation Examples

### Example 1: Automatic Token Rotation
```python
import logging
import time
from typing import Any, Callable, Dict, Optional, Protocol

logger = logging.getLogger(__name__)


class OAuthClient(Protocol):
    """Protocol for OAuth client that can refresh tokens."""
    def refresh_token(self, refresh_token: str) -> Dict[str, Any]: ...


class SecurityMonitor(Protocol):
    """Protocol for security monitoring service."""
    def alert_token_rotation_failure(self, client_id: str, error: str) -> None: ...


class TokenRotationService:
    def __init__(
        self,
        oauth_client: OAuthClient,
        revoke_callback: Callable[[str, str], None],
        security_monitor: SecurityMonitor,
        rotation_threshold: int = 300,
    ):
        """
        oauth_client: object that can refresh tokens (e.g., wraps the authorization server)
        revoke_callback: function invoked with (access_token, reason) when an old token must be revoked
        security_monitor: object with alert_token_rotation_failure(client_id, error) method
        rotation_threshold: number of seconds before expiry to trigger proactive rotation
        """
        self.oauth_client = oauth_client
        self.revoke_callback = revoke_callback
        self.security_monitor = security_monitor
        self.rotation_threshold = rotation_threshold
        # PRODUCTION WARNING: Use Redis or similar distributed cache instead of in-memory storage
        self.active_tokens: Dict[str, Dict[str, Optional[float]]] = {}

    def should_rotate_token(self, expires_at: float) -> bool:
        """Check if token should be rotated."""
        time_until_expiry = expires_at - time.time()
        return time_until_expiry <= self.rotation_threshold

    def rotate_token(self, client_id: str, refresh_token: str):
        """Rotate access token using refresh token."""
        try:
            previous_session = self.active_tokens.get(client_id, {})
            old_access_token = previous_session.get("access_token")

            new_token_response = self.oauth_client.refresh_token(refresh_token)

            # Update active tokens BEFORE revocation to ensure new token is available
            self.active_tokens[client_id] = {
                "access_token": new_token_response["access_token"],
                "refresh_token": new_token_response["refresh_token"],
                "expires_at": time.time() + new_token_response["expires_in"],
            }

            # Attempt to revoke old token, but don't fail rotation if revocation fails
            if old_access_token:
                try:
                    self.revoke_callback(old_access_token, reason="rotation")
                except Exception as revoke_exc:
                    logger.warning(f"Failed to revoke old token for {client_id}: {revoke_exc}")
                    # Continue - new token is already active

            return new_token_response

        except Exception as exc:
            self.security_monitor.alert_token_rotation_failure(client_id, str(exc))
            raise
```

### Example 2: Token Invalidation Service
```python
import logging

logger = logging.getLogger(__name__)


class ResourceNotifier(Protocol):
    """Protocol for notifying resource servers of token revocation."""
    def broadcast_revocation(self, access_token: str) -> None: ...


class AuditLogger(Protocol):
    """Protocol for audit logging."""
    def log_token_revocation(self, access_token: str, reason: str) -> None: ...


class TokenInvalidationService:
    def __init__(
        self,
        resource_notifier: ResourceNotifier,
        audit_logger: AuditLogger,
        security_monitor: SecurityMonitor,
    ):
        self.resource_notifier = resource_notifier
        self.audit_logger = audit_logger
        self.security_monitor = security_monitor
        # PRODUCTION WARNING: Use Redis or similar distributed cache instead of in-memory storage
        self.revoked_tokens = set()
        self.token_blacklist: Dict[str, Dict[str, str]] = {}

    def revoke_token(self, access_token: str, reason: str = "security_compromise") -> bool:
        """Immediately revoke a compromised token."""
        try:
            # Log FIRST to ensure audit trail even if broadcast fails
            self.audit_logger.log_token_revocation(access_token, reason)

            self.revoked_tokens.add(access_token)
            self.token_blacklist[access_token] = {
                "revoked_at": time.time(),
                "reason": reason,
                "revoked_by": "security_system",
            }

            # Attempt broadcast, but don't fail revocation if it fails
            try:
                self.resource_notifier.broadcast_revocation(access_token)
            except Exception as broadcast_exc:
                logger.error(f"Failed to broadcast revocation: {broadcast_exc}")
                # Token is still revoked locally

            return True

        except Exception as exc:
            self.security_monitor.alert_invalidation_failure(access_token, str(exc))
            return False

    def is_token_revoked(self, access_token: str) -> bool:
        """Check if token is in revocation list."""
        return access_token in self.revoked_tokens

    def cleanup_expired_revocations(self, max_age: int = 86_400) -> None:
        """Clean up old revocation records."""
        current_time = time.time()
        expired_tokens = [
            token
            for token, metadata in self.token_blacklist.items()
            if current_time - metadata["revoked_at"] > max_age
        ]

        for token in expired_tokens:
            self.revoked_tokens.discard(token)
            self.token_blacklist.pop(token, None)
```

## Testing and Validation
1. **Security Testing**:
   - Test token rotation timing and frequency
   - Verify immediate token invalidation
   - Test blacklist enforcement across services
   - Validate refresh token rotation security

2. **Functional Testing**:
   - Verify automatic token rotation workflows
   - Test token invalidation and blacklisting
   - Validate monitoring and alerting systems
   - Test performance impact of rotation cycles

3. **Integration Testing**:
   - Test end-to-end token lifecycle management
   - Validate cross-service token invalidation
   - Test fallback mechanisms during rotation failures
   - Verify audit logging and compliance

## Deployment Considerations

### Resource Requirements
- **CPU**: Additional overhead for token rotation operations
- **Memory**: Storage for token blacklists and rotation state
- **Network**: Increased communication for token refresh operations

### Security Considerations
- **Secure Storage**: Token blacklists must be stored securely
- **Access Control**: Strict access controls for token management operations
- **Audit Logging**: Comprehensive logging of all token operations
- **Monitoring**: Real-time monitoring for rotation failures and security events

### Performance Considerations
- **Rotation Frequency**: Balance security with performance impact
- **Caching**: Implement efficient caching for token validation
- **Batch Operations**: Batch token operations where possible
- **Async Processing**: Use asynchronous processing for non-critical operations

## Related Mitigations
- [SAFE-M-16](../SAFE-M-16/README.md): Token Scope Limiting
- [SAFE-M-19](../SAFE-M-19/README.md): Token Usage Tracking
- [SAFE-M-31](../SAFE-M-31/README.md): Proof of Possession (PoP) Tokens

## References
- [OAuth 2.0 Security Best Current Practices](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-security-topics)
- [RFC 6819 - OAuth 2.0 Threat Model and Security Considerations](https://datatracker.ietf.org/doc/html/rfc6819)
- [Model Context Protocol Specification](https://modelcontextprotocol.io/specification)

## Version History
| Version | Date | Changes | Author |
|---------|------|---------|--------|
| 1.0 | 2025-08-23 | Initial documentation of Token Rotation and Invalidation mitigation | bishnubista |
