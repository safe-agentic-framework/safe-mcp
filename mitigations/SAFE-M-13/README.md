# SAFE-M-13: OAuth Flow Verification

## Overview

**Mitigation ID**: SAFE-M-13
**Category**: Preventive Control
**Effectiveness**: High (Protocol-level defense per RFC 9207)
**Implementation Complexity**: Medium
**First Published**: 2025-01-05

## Description

OAuth Flow Verification is a preventive control that implements protocol-level verification of OAuth 2.0 authorization servers to prevent Authorization Server Mix-up attacks and OAuth phishing through malicious MCP servers. This mitigation enforces strict validation of the Authorization Server's identity at every stage of the OAuth flow, from initial configuration through token exchange.

The core defense mechanism is implementing [RFC 9207 (OAuth 2.0 Authorization Server Issuer Identification)](https://datatracker.ietf.org/doc/html/rfc9207), which mandates the inclusion of an `iss` (issuer) parameter in authorization responses. By validating this parameter against expected values before processing authorization codes, clients can detect and reject responses from rogue or impersonated Authorization Servers. This mitigation also incorporates domain similarity detection to identify typosquatted and homograph domains, certificate validation to prevent man-in-the-middle attacks, and static AS configuration to reduce the attack surface from dynamic OAuth discovery manipulation.

## Mitigates

- [SAFE-T1009](../../techniques/SAFE-T1009/README.md): Authorization Server Mix-up - Primary mitigation. RFC 9207 issuer validation directly prevents attackers from redirecting OAuth flows to lookalike or attacker-controlled Authorization Servers.
- [SAFE-T1007](../../techniques/SAFE-T1007/README.md): OAuth Authorization Phishing - Prevents phishing through domain validation, certificate pinning, and user warnings for unfamiliar AS domains.
- [SAFE-T1306](../../techniques/SAFE-T1306/README.md): Rogue Authorization Server - Detects and blocks tokens from malicious AS that ignore audience restrictions or proof-of-possession requirements.

## Technical Implementation

### Core Principles

1. **RFC 9207 Issuer Identification**: Validate the `iss` parameter in every authorization response against the expected Authorization Server issuer URL. Reject any authorization code from responses missing the `iss` parameter or containing a mismatched issuer, as this indicates a potential Mix-up attack.

2. **Authorization Server Allowlisting**: Maintain a strict allowlist of verified Authorization Server domains. Reject OAuth flows to any AS not on the allowlist, regardless of configuration. This prevents dynamic discovery manipulation attacks.

3. **Domain Similarity Detection**: Implement algorithmic detection of typosquatted, homograph, and IDN-based impersonation domains using Levenshtein distance, Unicode confusables detection, and TLD validation to identify suspicious AS domains before OAuth flows begin.

4. **Certificate Pinning and Validation**: Pin TLS certificates or public keys for critical Authorization Servers. Validate certificate chains and alert on unexpected certificate changes that may indicate domain takeover or man-in-the-middle attacks.

5. **Static AS Configuration**: Prefer static, pre-verified AS endpoint configuration over dynamic OAuth discovery (OpenID Connect Discovery). When dynamic discovery is required, validate discovered endpoints against known-good values and require explicit approval for changes.

### Architecture Components

```
+------------------------------------------------------------------------------+
|                    OAuth Flow Verification Architecture                       |
+------------------------------------------------------------------------------+

+------------------+     +------------------------+     +----------------------+
|    MCP Client    |     |   Authorization        |     |    Resource Server   |
|    (OAuth RP)    |     |      Server            |     |                      |
+--------+---------+     +-----------+------------+     +-----------+----------+
         |                           |                              |
         | 1. Initiate OAuth         |                              |
         |    (with state param)     |                              |
         |-------------------------->|                              |
         |                           |                              |
         |        +------------------+------------------+           |
         |        |  PRE-FLOW VALIDATION               |           |
         |        +------------------------------------+           |
         |        | 1. Check AS domain against        |           |
         |        |    allowlist                       |           |
         |        | 2. Validate domain similarity     |           |
         |        |    (Levenshtein, homograph)       |           |
         |        | 3. Verify TLS certificate         |           |
         |        | 4. Check certificate pinning      |           |
         |        +------------------+-----------------+           |
         |                           |                              |
         | 2. Authorization Response |                              |
         |    (code + iss + state)   |                              |
         |<--------------------------|                              |
         |                           |                              |
+--------+---------------------------+------------------+           |
| AUTHORIZATION RESPONSE VALIDATION (RFC 9207)         |           |
+------------------------------------------------------+           |
| 1. Verify 'state' parameter matches                  |           |
| 2. CRITICAL: Validate 'iss' parameter                |           |
|    - Must be present (reject if missing)             |           |
|    - Must match expected issuer exactly              |           |
|    - Must be on AS allowlist                         |           |
| 3. Validate redirect_uri matches configuration       |           |
| 4. Log validation decision                           |           |
+------------------------------------------------------+           |
         |                           |                              |
         | 3. Token Exchange         |                              |
         |    (code + PKCE verifier) |                              |
         |-------------------------->|                              |
         |                           |                              |
         | 4. Access Token           |                              |
         |    (validate issuer)      |                              |
         |<--------------------------|                              |
         |                           |                              |
         | 5. API Request            |                              |
         |--------------------------------------------------------->|
         |                           |                              |


+------------------------------------------------------------------------------+
|                    DOMAIN VALIDATION PIPELINE                                 |
+------------------------------------------------------------------------------+

                          Input: Authorization Endpoint URL
                                         |
                                         v
                    +------------------------------------+
                    |     1. ALLOWLIST CHECK             |
                    |     Is domain in trusted AS list?  |
                    +------------------+-----------------+
                                       |
                         +-------------+-------------+
                         |                           |
                        YES                          NO
                         |                           |
                         v                           v
              +------------------+     +---------------------------+
              | PASS: Continue   |     | 2. SIMILARITY DETECTION   |
              +------------------+     +---------------------------+
                                       |
                    +------------------+------------------+
                    |                  |                  |
                    v                  v                  v
          +----------------+  +----------------+  +----------------+
          | Levenshtein    |  | Unicode        |  | TLD            |
          | Distance Check |  | Confusables    |  | Substitution   |
          | (< 3 = suspect)|  | (Cyrillic a,   |  | (.co vs .com)  |
          +-------+--------+  | Greek o, etc.) |  +-------+--------+
                  |           +-------+--------+          |
                  |                   |                   |
                  +-------------------+-------------------+
                                      |
                                      v
                    +------------------------------------+
                    |     3. IDN/PUNYCODE CHECK          |
                    |     Contains 'xn--' prefix?        |
                    +------------------+-----------------+
                                       |
                                       v
                    +------------------------------------+
                    |     4. SUBDOMAIN CONFUSION         |
                    |     accounts.google.com.evil.com?  |
                    +------------------+-----------------+
                                       |
                         +-------------+-------------+
                         |                           |
                    ALL PASS                    ANY FAIL
                         |                           |
                         v                           v
              +------------------+     +---------------------------+
              | ALLOW with       |     | BLOCK + Alert             |
              | Warning/Logging  |     | Log security event        |
              +------------------+     +---------------------------+


+------------------------------------------------------------------------------+
|                    CERTIFICATE VALIDATION FLOW                                |
+------------------------------------------------------------------------------+

  +------------------+
  | TLS Connection   |
  | to AS Endpoint   |
  +--------+---------+
           |
           v
  +------------------+      +----------------------+
  | Extract Server   |----->| Certificate Pinning  |
  | Certificate      |      | Database             |
  +--------+---------+      +----------+-----------+
           |                           |
           v                           v
  +------------------+      +----------------------+
  | Validate Chain   |      | Compare SPKI Hash    |
  | (CA verification)|      | or Certificate Hash  |
  +--------+---------+      +----------+-----------+
           |                           |
           +-------------+-------------+
                         |
           +-------------+-------------+
           |                           |
       VALID                      MISMATCH
           |                           |
           v                           v
  +------------------+      +----------------------+
  | Continue OAuth   |      | BLOCK Connection     |
  | Flow             |      | Alert: Possible MitM |
  +------------------+      | or Domain Takeover   |
                            +----------------------+
```

### Prerequisites

- OAuth 2.0 client implementation with support for state and PKCE ([RFC 7636](https://datatracker.ietf.org/doc/html/rfc7636))
- Authorization Server that supports RFC 9207 issuer identification (or ability to enforce this requirement)
- TLS/HTTPS for all OAuth communications
- Domain validation library or implementation (Levenshtein distance, Unicode normalization)
- Certificate pinning infrastructure or configuration capability
- Logging infrastructure for security events

### Implementation Steps

1. **Design Phase**:
   - **Define AS Allowlist**: Create a comprehensive list of trusted Authorization Server domains for all integrated OAuth providers (Google, Microsoft, GitHub, etc.)
   - **Map Expected Issuers**: Document the expected `iss` value for each AS (e.g., `https://accounts.google.com` for Google)
   - **Design Validation Rules**: Define thresholds for domain similarity (Levenshtein distance), confusable character sets, and TLD substitution patterns
   - **Plan Certificate Pinning**: Identify critical AS endpoints requiring certificate pinning; obtain current certificate hashes
   - **Design Alerting Strategy**: Define alert conditions for validation failures, suspicious domains, and certificate mismatches

2. **Development Phase**:
   - **Implement RFC 9207 Validation**: Add issuer parameter validation to authorization response handling; reject responses without valid `iss`
   - **Build Domain Validation Library**: Implement Levenshtein distance calculator, Unicode confusables detector, IDN/Punycode checker
   - **Create Allowlist Enforcement**: Implement AS domain allowlist with strict matching
   - **Add Certificate Pinning**: Implement certificate or public key pinning for AS endpoints
   - **Implement User Warnings**: Display clear warnings when OAuth flows target unfamiliar domains
   - **Add Comprehensive Logging**: Log all validation decisions with full context for forensic analysis
   - **Write Tests**: Create test cases for Mix-up attacks, typosquatted domains, homograph attacks

3. **Deployment Phase**:
   - **Configure AS Allowlist**: Deploy allowlist to production; ensure all legitimate AS are included
   - **Enable Validation**: Activate RFC 9207 and domain validation in production
   - **Deploy Certificate Pins**: Configure certificate pinning for major AS providers
   - **Enable Monitoring**: Activate alerts for validation failures and suspicious patterns
   - **Document Procedures**: Create runbooks for allowlist updates and certificate pin rotation

## Benefits

- **Prevents Authorization Server Mix-up**: RFC 9207 issuer validation directly addresses the attack vector documented in [SAFE-T1009](../../techniques/SAFE-T1009/README.md), ensuring clients can detect when authorization codes originate from unexpected servers.

- **Detects Domain Impersonation**: Multi-layered domain validation catches typosquatting (`accounts-google.com`), homograph attacks (`аccounts.google.com` with Cyrillic), and subdomain confusion (`accounts.google.com.attacker.com`).

- **Protocol-Level Security**: RFC 9207 is an IETF standard adopted by major OAuth providers, ensuring interoperability and vendor support.

- **Defense in Depth**: Combines protocol validation (RFC 9207), domain validation, certificate pinning, and user warnings for multiple layers of protection.

- **Audit Trail**: Comprehensive logging of validation decisions enables forensic analysis and compliance reporting.

- **Early Detection**: Domain similarity and certificate validation can detect attacks before user credentials are exposed.

## Limitations

- **RFC 9207 Adoption**: Not all Authorization Servers support RFC 9207 yet. Legacy systems and custom OAuth implementations may not include the `iss` parameter, requiring fallback validation strategies.

- **Allowlist Maintenance**: AS allowlists require ongoing maintenance as new OAuth integrations are added. Overly restrictive allowlists can break legitimate functionality.

- **False Positives in Domain Validation**: Legitimate international domains may trigger IDN/homograph alerts. Levenshtein distance can flag legitimate similar domains (e.g., `auth.example.com` vs `auth.example.org`).

- **Certificate Pinning Complexity**: Certificate pinning requires pin rotation procedures and can cause outages if pins expire or are misconfigured. Some AS providers rotate certificates frequently.

- **Performance Overhead**: Domain similarity detection adds computational overhead, especially for Levenshtein distance on long domain names. Caching and optimization may be required.

- **User Warning Fatigue**: Excessive warnings for unfamiliar (but legitimate) AS domains can lead to users ignoring all warnings, reducing effectiveness.

## Implementation Examples

### Example 1: Python - RFC 9207 Issuer Validation with Domain Similarity Detection

```python
"""
OAuth Flow Verification Implementation
Mitigates: SAFE-T1009 (Authorization Server Mix-up)
"""
import re
import unicodedata
from urllib.parse import urlparse
from typing import Optional, Tuple, Set
import logging

security_logger = logging.getLogger('security.oauth')

# Trusted Authorization Server allowlist with expected issuers
TRUSTED_AS_CONFIG = {
    'google': {
        'domains': ['accounts.google.com', 'oauth2.googleapis.com'],
        'issuer': 'https://accounts.google.com',
        'authorization_endpoint': 'https://accounts.google.com/o/oauth2/v2/auth',
        'token_endpoint': 'https://oauth2.googleapis.com/token',
    },
    'microsoft': {
        'domains': ['login.microsoftonline.com', 'login.microsoft.com'],
        'issuer': 'https://login.microsoftonline.com/{tenant}/v2.0',
        'authorization_endpoint': 'https://login.microsoftonline.com/{tenant}/oauth2/v2.0/authorize',
        'token_endpoint': 'https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token',
    },
    'github': {
        'domains': ['github.com'],
        'issuer': 'https://github.com',
        'authorization_endpoint': 'https://github.com/login/oauth/authorize',
        'token_endpoint': 'https://github.com/login/oauth/access_token',
    },
}

# Unicode confusables mapping (subset - full list from Unicode TR#39)
CONFUSABLES = {
    'а': 'a',  # Cyrillic Small Letter A (U+0430)
    'е': 'e',  # Cyrillic Small Letter Ie (U+0435)
    'о': 'o',  # Cyrillic Small Letter O (U+043E)
    'р': 'p',  # Cyrillic Small Letter Er (U+0440)
    'с': 'c',  # Cyrillic Small Letter Es (U+0441)
    'у': 'y',  # Cyrillic Small Letter U (U+0443)
    'х': 'x',  # Cyrillic Small Letter Ha (U+0445)
    'ο': 'o',  # Greek Small Letter Omicron (U+03BF)
    'α': 'a',  # Greek Small Letter Alpha (U+03B1)
    'ν': 'v',  # Greek Small Letter Nu (U+03BD)
    'ι': 'i',  # Greek Small Letter Iota (U+03B9)
    'ɡ': 'g',  # Latin Small Letter Script G (U+0261)
    'ǥ': 'g',  # Latin Small Letter G with Stroke (U+01E5)
}


def levenshtein_distance(s1: str, s2: str) -> int:
    """Calculate Levenshtein distance between two strings."""
    if len(s1) < len(s2):
        return levenshtein_distance(s2, s1)

    if len(s2) == 0:
        return len(s1)

    previous_row = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row

    return previous_row[-1]


def normalize_confusables(domain: str) -> str:
    """Normalize Unicode confusables to ASCII equivalents."""
    normalized = []
    for char in domain.lower():
        normalized.append(CONFUSABLES.get(char, char))
    return ''.join(normalized)


def detect_homograph(domain: str) -> Tuple[bool, Optional[str]]:
    """Detect IDN homograph attacks."""
    # Check for Punycode (IDN) encoding
    if domain.startswith('xn--') or '.xn--' in domain:
        return True, f"IDN/Punycode domain detected: {domain}"

    # Check for mixed scripts
    normalized = normalize_confusables(domain)
    if normalized != domain.lower():
        return True, f"Homograph detected: '{domain}' normalizes to '{normalized}'"

    # Check for non-ASCII characters
    try:
        domain.encode('ascii')
    except UnicodeEncodeError:
        return True, f"Non-ASCII characters in domain: {domain}"

    return False, None


def detect_typosquatting(domain: str, trusted_domains: Set[str], threshold: int = 3) -> Tuple[bool, Optional[str]]:
    """Detect typosquatting using Levenshtein distance."""
    for trusted in trusted_domains:
        distance = levenshtein_distance(domain.lower(), trusted.lower())
        if 0 < distance <= threshold:
            return True, f"Typosquatting suspected: '{domain}' is {distance} edits from '{trusted}'"
    return False, None


def detect_subdomain_confusion(domain: str, trusted_domains: Set[str]) -> Tuple[bool, Optional[str]]:
    """Detect subdomain confusion attacks like 'accounts.google.com.attacker.com'."""
    for trusted in trusted_domains:
        # Check if trusted domain appears as subdomain of another domain
        if f".{trusted}." in f".{domain}." and domain != trusted:
            if not domain.endswith(f".{trusted}"):
                return True, f"Subdomain confusion: '{domain}' contains '{trusted}' but is not a subdomain"
    return False, None


def validate_as_domain(authorization_endpoint: str) -> Tuple[bool, str, list]:
    """
    Validate Authorization Server domain against security checks.

    Returns: (is_valid, message, warnings)
    """
    warnings = []

    try:
        parsed = urlparse(authorization_endpoint)
        domain = parsed.netloc.lower()
    except Exception as e:
        return False, f"Invalid URL: {e}", []

    # Check HTTPS
    if parsed.scheme != 'https':
        return False, "Authorization endpoint must use HTTPS", []

    # Collect all trusted domains
    all_trusted_domains = set()
    for provider_config in TRUSTED_AS_CONFIG.values():
        all_trusted_domains.update(provider_config['domains'])

    # Check allowlist
    if domain in all_trusted_domains:
        security_logger.info(f"AS domain validated against allowlist: {domain}")
        return True, "Domain in trusted allowlist", []

    # Run security checks for unknown domains
    checks_failed = []

    # 1. Homograph detection
    is_homograph, homograph_msg = detect_homograph(domain)
    if is_homograph:
        checks_failed.append(homograph_msg)

    # 2. Typosquatting detection
    is_typosquatting, typo_msg = detect_typosquatting(domain, all_trusted_domains)
    if is_typosquatting:
        checks_failed.append(typo_msg)

    # 3. Subdomain confusion
    is_subdomain_confusion, subdomain_msg = detect_subdomain_confusion(domain, all_trusted_domains)
    if is_subdomain_confusion:
        checks_failed.append(subdomain_msg)

    # 4. Check for hyphens in brand names (common typosquatting pattern)
    hyphen_pattern = re.compile(r'(accounts|login|auth|oauth|signin)[-]?(google|microsoft|github|amazon|apple)', re.I)
    if hyphen_pattern.search(domain):
        if domain not in all_trusted_domains:
            checks_failed.append(f"Suspicious hyphenated brand name in domain: {domain}")

    if checks_failed:
        security_logger.warning(f"AS domain validation FAILED: {domain} - {checks_failed}")
        return False, f"Domain validation failed: {'; '.join(checks_failed)}", []

    # Unknown domain - allow with warning
    warnings.append(f"Unknown AS domain '{domain}' - not in trusted allowlist")
    security_logger.warning(f"Unknown AS domain allowed with warning: {domain}")
    return True, "Domain not in allowlist but passed security checks", warnings


def validate_authorization_response(
    response_params: dict,
    expected_issuer: str,
    expected_state: str
) -> Tuple[bool, str]:
    """
    Validate OAuth authorization response per RFC 9207.

    This is the PRIMARY defense against Authorization Server Mix-up (SAFE-T1009).

    Args:
        response_params: Query parameters from authorization response
        expected_issuer: The issuer URL we expected (from initial AS config)
        expected_state: The state parameter we sent in authorization request

    Returns: (is_valid, message)
    """

    # 1. Validate state parameter (CSRF protection)
    response_state = response_params.get('state')
    if not response_state:
        security_logger.warning("Authorization response missing 'state' parameter")
        return False, "Missing state parameter - possible CSRF attack"

    if response_state != expected_state:
        security_logger.warning(f"State mismatch: expected={expected_state}, got={response_state}")
        return False, "State parameter mismatch - possible CSRF attack"

    # 2. Check for error response
    if 'error' in response_params:
        error = response_params.get('error')
        error_description = response_params.get('error_description', 'No description')
        return False, f"Authorization error: {error} - {error_description}"

    # 3. Validate authorization code presence
    code = response_params.get('code')
    if not code:
        return False, "Missing authorization code in response"

    # 4. RFC 9207: Validate issuer parameter (CRITICAL for SAFE-T1009 mitigation)
    response_issuer = response_params.get('iss')

    if not response_issuer:
        # RFC 9207 requires 'iss' parameter
        security_logger.error(
            f"SECURITY ALERT: Authorization response missing 'iss' parameter. "
            f"Expected issuer: {expected_issuer}. "
            f"This may indicate an Authorization Server Mix-up attack (SAFE-T1009)."
        )
        return False, (
            "Authorization response missing 'iss' parameter (RFC 9207 violation). "
            "Cannot verify Authorization Server identity - possible Mix-up attack."
        )

    # 5. Compare issuer against expected value
    if response_issuer != expected_issuer:
        security_logger.error(
            f"SECURITY ALERT: Issuer mismatch detected! "
            f"Expected: {expected_issuer}, Received: {response_issuer}. "
            f"This is a potential Authorization Server Mix-up attack (SAFE-T1009)."
        )
        return False, (
            f"Issuer mismatch: expected '{expected_issuer}', received '{response_issuer}'. "
            f"Possible Authorization Server Mix-up attack detected."
        )

    security_logger.info(f"Authorization response validated successfully. Issuer: {response_issuer}")
    return True, "Authorization response validated successfully"


class OAuthFlowVerifier:
    """
    Complete OAuth Flow Verification implementation.
    Mitigates SAFE-T1009, SAFE-T1007, SAFE-T1306.
    """

    def __init__(self, config: dict = None):
        self.config = config or TRUSTED_AS_CONFIG
        self.pending_flows = {}  # state -> flow_context

    def start_authorization(
        self,
        provider: str,
        client_id: str,
        redirect_uri: str,
        scope: str,
        state: str
    ) -> Tuple[bool, str, Optional[str]]:
        """
        Start OAuth authorization flow with pre-flight validation.

        Returns: (success, message, authorization_url)
        """
        if provider not in self.config:
            return False, f"Unknown OAuth provider: {provider}", None

        provider_config = self.config[provider]
        auth_endpoint = provider_config['authorization_endpoint']

        # Validate AS domain before starting flow
        is_valid, message, warnings = validate_as_domain(auth_endpoint)
        if not is_valid:
            security_logger.error(f"AS domain validation failed for {provider}: {message}")
            return False, message, None

        for warning in warnings:
            security_logger.warning(warning)

        # Store flow context for response validation
        self.pending_flows[state] = {
            'provider': provider,
            'expected_issuer': provider_config['issuer'],
            'redirect_uri': redirect_uri,
        }

        # Build authorization URL
        auth_url = (
            f"{auth_endpoint}?"
            f"response_type=code&"
            f"client_id={client_id}&"
            f"redirect_uri={redirect_uri}&"
            f"scope={scope}&"
            f"state={state}"
        )

        return True, "Authorization flow initiated", auth_url

    def validate_callback(self, callback_params: dict) -> Tuple[bool, str, Optional[str]]:
        """
        Validate OAuth callback with RFC 9207 issuer verification.

        Returns: (success, message, authorization_code)
        """
        state = callback_params.get('state')

        if not state or state not in self.pending_flows:
            return False, "Unknown or missing state parameter", None

        flow_context = self.pending_flows[state]

        # RFC 9207 validation
        is_valid, message = validate_authorization_response(
            callback_params,
            flow_context['expected_issuer'],
            state
        )

        if not is_valid:
            del self.pending_flows[state]
            return False, message, None

        code = callback_params.get('code')
        del self.pending_flows[state]

        return True, "Callback validated successfully", code


# Example usage
if __name__ == "__main__":
    # Test domain validation
    test_domains = [
        "https://accounts.google.com/o/oauth2/v2/auth",  # Valid
        "https://accounts-google.com/o/oauth2/v2/auth",  # Typosquatting
        "https://аccounts.google.com/o/oauth2/v2/auth",  # Homograph (Cyrillic 'а')
        "https://accounts.google.com.attacker.com/auth",  # Subdomain confusion
        "https://xn--ccounts-9wa.google.com/auth",  # IDN/Punycode
    ]

    print("Domain Validation Tests:")
    print("-" * 60)
    for url in test_domains:
        is_valid, msg, warnings = validate_as_domain(url)
        status = "PASS" if is_valid else "BLOCK"
        print(f"{status}: {url}")
        print(f"       {msg}")
        if warnings:
            for w in warnings:
                print(f"       WARNING: {w}")
        print()
```

### Example 2: JavaScript/Node.js - AS Allowlist with Homograph Detection

```javascript
/**
 * OAuth Flow Verification Implementation
 * Mitigates: SAFE-T1009 (Authorization Server Mix-up)
 */

const crypto = require('crypto');

// Trusted Authorization Server configuration
const TRUSTED_AS_CONFIG = {
  google: {
    domains: ['accounts.google.com', 'oauth2.googleapis.com'],
    issuer: 'https://accounts.google.com',
    // Certificate pin (SPKI hash) for additional security
    certificatePins: [
      'sha256/XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX=',
    ],
  },
  microsoft: {
    domains: ['login.microsoftonline.com', 'login.microsoft.com'],
    issuer: 'https://login.microsoftonline.com/{tenant}/v2.0',
    certificatePins: [],
  },
  github: {
    domains: ['github.com'],
    issuer: 'https://github.com',
    certificatePins: [],
  },
};

// Unicode confusables (subset)
const CONFUSABLES = new Map([
  ['\u0430', 'a'], // Cyrillic а
  ['\u0435', 'e'], // Cyrillic е
  ['\u043E', 'o'], // Cyrillic о
  ['\u0440', 'p'], // Cyrillic р
  ['\u0441', 'c'], // Cyrillic с
  ['\u03BF', 'o'], // Greek ο
  ['\u03B1', 'a'], // Greek α
]);

/**
 * Security logger
 */
const securityLogger = {
  info: (msg, data) => console.log(`[SECURITY INFO] ${msg}`, data ? JSON.stringify(data) : ''),
  warn: (msg, data) => console.warn(`[SECURITY WARN] ${msg}`, data ? JSON.stringify(data) : ''),
  error: (msg, data) => console.error(`[SECURITY ERROR] ${msg}`, data ? JSON.stringify(data) : ''),
};

/**
 * Calculate Levenshtein distance
 */
function levenshteinDistance(str1, str2) {
  const m = str1.length;
  const n = str2.length;
  const dp = Array(m + 1).fill(null).map(() => Array(n + 1).fill(0));

  for (let i = 0; i <= m; i++) dp[i][0] = i;
  for (let j = 0; j <= n; j++) dp[0][j] = j;

  for (let i = 1; i <= m; i++) {
    for (let j = 1; j <= n; j++) {
      if (str1[i - 1] === str2[j - 1]) {
        dp[i][j] = dp[i - 1][j - 1];
      } else {
        dp[i][j] = 1 + Math.min(dp[i - 1][j], dp[i][j - 1], dp[i - 1][j - 1]);
      }
    }
  }
  return dp[m][n];
}

/**
 * Normalize Unicode confusables to ASCII
 */
function normalizeConfusables(domain) {
  let normalized = '';
  for (const char of domain.toLowerCase()) {
    normalized += CONFUSABLES.get(char) || char;
  }
  return normalized;
}

/**
 * Detect homograph attacks
 */
function detectHomograph(domain) {
  // Check for Punycode
  if (domain.startsWith('xn--') || domain.includes('.xn--')) {
    return { detected: true, reason: `IDN/Punycode domain: ${domain}` };
  }

  // Check for confusables
  const normalized = normalizeConfusables(domain);
  if (normalized !== domain.toLowerCase()) {
    return {
      detected: true,
      reason: `Homograph detected: '${domain}' normalizes to '${normalized}'`,
    };
  }

  // Check for non-ASCII
  if (!/^[\x00-\x7F]*$/.test(domain)) {
    return { detected: true, reason: `Non-ASCII characters in domain: ${domain}` };
  }

  return { detected: false };
}

/**
 * Detect typosquatting
 */
function detectTyposquatting(domain, trustedDomains, threshold = 3) {
  for (const trusted of trustedDomains) {
    const distance = levenshteinDistance(domain.toLowerCase(), trusted.toLowerCase());
    if (distance > 0 && distance <= threshold) {
      return {
        detected: true,
        reason: `Typosquatting suspected: '${domain}' is ${distance} edits from '${trusted}'`,
      };
    }
  }
  return { detected: false };
}

/**
 * Get all trusted domains from config
 */
function getAllTrustedDomains() {
  const domains = new Set();
  for (const config of Object.values(TRUSTED_AS_CONFIG)) {
    config.domains.forEach(d => domains.add(d));
  }
  return domains;
}

/**
 * Validate Authorization Server domain
 */
function validateASDomain(authorizationEndpoint) {
  let url;
  try {
    url = new URL(authorizationEndpoint);
  } catch (e) {
    return { valid: false, message: `Invalid URL: ${e.message}`, warnings: [] };
  }

  const domain = url.hostname.toLowerCase();
  const warnings = [];

  // Must be HTTPS
  if (url.protocol !== 'https:') {
    return { valid: false, message: 'Authorization endpoint must use HTTPS', warnings: [] };
  }

  const trustedDomains = getAllTrustedDomains();

  // Check allowlist
  if (trustedDomains.has(domain)) {
    securityLogger.info(`AS domain validated: ${domain}`);
    return { valid: true, message: 'Domain in trusted allowlist', warnings: [] };
  }

  // Security checks for unknown domains
  const failures = [];

  // Homograph detection
  const homograph = detectHomograph(domain);
  if (homograph.detected) {
    failures.push(homograph.reason);
  }

  // Typosquatting detection
  const typosquatting = detectTyposquatting(domain, trustedDomains);
  if (typosquatting.detected) {
    failures.push(typosquatting.reason);
  }

  // Hyphenated brand names
  const hyphenPattern = /(accounts|login|auth|oauth|signin)[-]?(google|microsoft|github|amazon|apple)/i;
  if (hyphenPattern.test(domain) && !trustedDomains.has(domain)) {
    failures.push(`Suspicious hyphenated brand name: ${domain}`);
  }

  if (failures.length > 0) {
    securityLogger.error('AS domain validation FAILED', { domain, failures });
    return { valid: false, message: `Domain validation failed: ${failures.join('; ')}`, warnings: [] };
  }

  warnings.push(`Unknown AS domain '${domain}' - not in trusted allowlist`);
  return { valid: true, message: 'Passed security checks but not in allowlist', warnings };
}

/**
 * Validate authorization response per RFC 9207
 * PRIMARY defense against SAFE-T1009
 */
function validateAuthorizationResponse(responseParams, expectedIssuer, expectedState) {
  // 1. Validate state
  if (!responseParams.state) {
    securityLogger.warn('Missing state parameter in authorization response');
    return { valid: false, message: 'Missing state parameter - possible CSRF' };
  }

  if (responseParams.state !== expectedState) {
    securityLogger.warn('State mismatch', {
      expected: expectedState,
      received: responseParams.state,
    });
    return { valid: false, message: 'State mismatch - possible CSRF' };
  }

  // 2. Check for errors
  if (responseParams.error) {
    return {
      valid: false,
      message: `Authorization error: ${responseParams.error} - ${responseParams.error_description || ''}`,
    };
  }

  // 3. Check for code
  if (!responseParams.code) {
    return { valid: false, message: 'Missing authorization code' };
  }

  // 4. RFC 9207: Validate issuer (CRITICAL)
  if (!responseParams.iss) {
    securityLogger.error('SECURITY ALERT: Missing iss parameter', {
      expected: expectedIssuer,
      attack: 'SAFE-T1009 Authorization Server Mix-up',
    });
    return {
      valid: false,
      message: 'Missing iss parameter (RFC 9207) - possible Mix-up attack',
    };
  }

  // 5. Compare issuer
  if (responseParams.iss !== expectedIssuer) {
    securityLogger.error('SECURITY ALERT: Issuer mismatch', {
      expected: expectedIssuer,
      received: responseParams.iss,
      attack: 'SAFE-T1009 Authorization Server Mix-up',
    });
    return {
      valid: false,
      message: `Issuer mismatch: expected '${expectedIssuer}', got '${responseParams.iss}'`,
    };
  }

  securityLogger.info('Authorization response validated', { issuer: responseParams.iss });
  return { valid: true, message: 'Validated successfully', code: responseParams.code };
}

/**
 * OAuth Flow Verifier class
 */
class OAuthFlowVerifier {
  constructor(config = TRUSTED_AS_CONFIG) {
    this.config = config;
    this.pendingFlows = new Map();
  }

  startAuthorization(provider, clientId, redirectUri, scope) {
    if (!this.config[provider]) {
      return { success: false, message: `Unknown provider: ${provider}` };
    }

    const providerConfig = this.config[provider];
    const authEndpoint = providerConfig.authorization_endpoint ||
      `https://${providerConfig.domains[0]}/oauth/authorize`;

    // Validate AS domain
    const validation = validateASDomain(authEndpoint);
    if (!validation.valid) {
      return { success: false, message: validation.message };
    }

    // Generate state
    const state = crypto.randomBytes(32).toString('hex');

    // Store flow context
    this.pendingFlows.set(state, {
      provider,
      expectedIssuer: providerConfig.issuer,
      redirectUri,
    });

    const authUrl = new URL(authEndpoint);
    authUrl.searchParams.set('response_type', 'code');
    authUrl.searchParams.set('client_id', clientId);
    authUrl.searchParams.set('redirect_uri', redirectUri);
    authUrl.searchParams.set('scope', scope);
    authUrl.searchParams.set('state', state);

    return {
      success: true,
      authorizationUrl: authUrl.toString(),
      state,
      warnings: validation.warnings,
    };
  }

  validateCallback(callbackParams) {
    const { state } = callbackParams;

    if (!state || !this.pendingFlows.has(state)) {
      return { success: false, message: 'Unknown or missing state' };
    }

    const flowContext = this.pendingFlows.get(state);
    const result = validateAuthorizationResponse(
      callbackParams,
      flowContext.expectedIssuer,
      state
    );

    this.pendingFlows.delete(state);

    return {
      success: result.valid,
      message: result.message,
      code: result.code,
    };
  }
}

module.exports = {
  OAuthFlowVerifier,
  validateASDomain,
  validateAuthorizationResponse,
  detectHomograph,
  detectTyposquatting,
};
```

### Example 3: Authorization Server Allowlist Configuration (YAML)

```yaml
# oauth-flow-verification-config.yaml
# Configuration for SAFE-M-13: OAuth Flow Verification

# Global settings
settings:
  # Require RFC 9207 issuer parameter in all authorization responses
  require_rfc9207_issuer: true

  # Block OAuth flows to domains not in allowlist
  strict_allowlist_mode: true

  # Domain similarity detection threshold (Levenshtein distance)
  typosquatting_threshold: 3

  # Enable Unicode confusables detection
  homograph_detection: true

  # Enable certificate pinning
  certificate_pinning: true

  # Log all validation decisions
  comprehensive_logging: true

# Trusted Authorization Server allowlist
authorization_servers:
  google:
    name: "Google OAuth"
    domains:
      - accounts.google.com
      - oauth2.googleapis.com
    issuer: "https://accounts.google.com"
    authorization_endpoint: "https://accounts.google.com/o/oauth2/v2/auth"
    token_endpoint: "https://oauth2.googleapis.com/token"
    discovery_url: "https://accounts.google.com/.well-known/openid-configuration"
    # Certificate pins (SPKI SHA-256 hashes)
    certificate_pins:
      - "sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
    # Expected certificate issuer
    certificate_issuer: "CN=GTS CA 1C3, O=Google Trust Services LLC, C=US"

  microsoft:
    name: "Microsoft Entra ID"
    domains:
      - login.microsoftonline.com
      - login.microsoft.com
      - login.windows.net
    issuer_pattern: "https://login.microsoftonline.com/{tenant}/v2.0"
    authorization_endpoint: "https://login.microsoftonline.com/{tenant}/oauth2/v2.0/authorize"
    token_endpoint: "https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token"
    # Allow tenant placeholder in issuer comparison
    issuer_regex: "^https://login\\.microsoftonline\\.com/[a-f0-9-]+/v2\\.0$"

  github:
    name: "GitHub OAuth"
    domains:
      - github.com
    issuer: "https://github.com"
    authorization_endpoint: "https://github.com/login/oauth/authorize"
    token_endpoint: "https://github.com/login/oauth/access_token"
    # GitHub doesn't support RFC 9207 yet - use domain validation only
    rfc9207_required: false

  aws_cognito:
    name: "AWS Cognito"
    domains:
      - cognito-idp.{region}.amazonaws.com
    issuer_pattern: "https://cognito-idp.{region}.amazonaws.com/{userPoolId}"
    # Dynamic domains - validate against pattern
    domain_pattern: "^cognito-idp\\.[a-z]{2}-[a-z]+-\\d\\.amazonaws\\.com$"

# Domain validation rules
domain_validation:
  # Known typosquatting patterns to block
  blocked_patterns:
    - "accounts-google"
    - "login-microsoft"
    - "github-login"
    - "signin-apple"

  # TLD substitutions to flag
  suspicious_tld_substitutions:
    - original: ".com"
      suspicious: [".co", ".cm", ".om", ".corn"]
    - original: ".org"
      suspicious: [".og", ".orgg"]

  # Unicode script mixing rules
  script_mixing:
    # Block domains mixing Latin with these scripts
    blocked_scripts:
      - Cyrillic
      - Greek
      - Armenian

# Alert configuration
alerting:
  # High severity - immediate action required
  high:
    - "issuer_mismatch"
    - "homograph_detected"
    - "certificate_pin_mismatch"
  # Medium severity - investigate
  medium:
    - "typosquatting_suspected"
    - "unknown_as_domain"
    - "rfc9207_missing"
  # Low severity - informational
  low:
    - "certificate_rotation_detected"
    - "new_as_domain_seen"

# Monitoring metrics
metrics:
  - name: "oauth_validation_success_total"
    type: counter
    labels: ["provider", "validation_type"]

  - name: "oauth_validation_failure_total"
    type: counter
    labels: ["provider", "failure_reason"]

  - name: "domain_similarity_alerts_total"
    type: counter
    labels: ["alert_type", "suspected_target"]
```

## Testing and Validation

### 1. Security Testing

#### Authorization Server Mix-up Tests (SAFE-T1009)
- **Test Case S1**: Missing `iss` parameter in authorization response
  - Input: Authorization response without `iss` parameter
  - Expected: REJECT with "RFC 9207 violation" error
  - Verify: Security log captures Mix-up attack attempt

- **Test Case S2**: Mismatched `iss` parameter
  - Input: Response with `iss: https://attacker.com` when expecting `https://accounts.google.com`
  - Expected: REJECT with "Issuer mismatch" error
  - Verify: Alert generated for potential Mix-up attack

- **Test Case S3**: Typosquatted Authorization Server domain
  - Input: Authorization endpoint `https://accounts-google.com/oauth`
  - Expected: REJECT with typosquatting detection
  - Verify: Levenshtein distance alert triggered

- **Test Case S4**: Homograph domain attack
  - Input: `https://аccounts.google.com` (Cyrillic 'а')
  - Expected: REJECT with homograph detection
  - Verify: Unicode confusables alert triggered

- **Test Case S5**: Subdomain confusion attack
  - Input: `https://accounts.google.com.attacker.com/oauth`
  - Expected: REJECT with subdomain confusion detection
  - Verify: Domain structure validation catches attack

#### Certificate Validation Tests
- **Test Case C1**: Certificate pin mismatch
  - Expected: REJECT connection, alert for possible MitM

- **Test Case C2**: Valid certificate rotation
  - Expected: ALLOW with warning, update pin database

### 2. Functional Testing

#### Positive Test Cases
- **Test Case F1**: Valid Google OAuth flow
  - Input: Proper authorization response with `iss: https://accounts.google.com`
  - Expected: ACCEPT, continue to token exchange

- **Test Case F2**: Valid Microsoft OAuth flow with tenant
  - Input: `iss: https://login.microsoftonline.com/tenant-id/v2.0`
  - Expected: ACCEPT (matches tenant pattern)

- **Test Case F3**: AS allowlist lookup
  - Input: Domain in trusted allowlist
  - Expected: Fast path acceptance without similarity checks

#### Performance Testing
- **Test Case P1**: Domain validation latency
  - Target: < 10ms for allowlist check, < 50ms with similarity analysis
  - Method: Benchmark 10,000 domain validations

### 3. Integration Testing

#### MCP Environment Tests
- **Test Case I1**: Multi-provider OAuth validation
  - Scenario: MCP server with Google, Microsoft, GitHub integrations
  - Expected: Each provider validated with correct issuer

- **Test Case I2**: Dynamic OAuth discovery validation
  - Scenario: OIDC discovery document points to unexpected endpoints
  - Expected: REJECT if discovered endpoints differ from configured

## Deployment Considerations

### Resource Requirements

- **CPU**: Domain similarity calculations (Levenshtein) are O(n*m) - cache results for repeated domains. Unicode normalization is lightweight.
- **Memory**: Allowlist and certificate pin storage ~10KB. Pending flow state ~1KB per active OAuth flow.
- **Storage**: Security audit logs at ~1KB per validation event. Recommend 90-day retention.
- **Network**: No additional network calls for allowlist/similarity checks. Certificate pinning validation uses existing TLS handshake.

### Performance Impact

- **Latency Breakdown**:
  - Allowlist lookup: < 1ms (hash table)
  - Levenshtein distance (per domain): 1-5ms depending on domain length
  - Unicode normalization: < 1ms
  - RFC 9207 issuer comparison: < 0.1ms
  - Certificate pin verification: Part of TLS handshake
  - **Total overhead**: 2-10ms for unknown domains, < 1ms for allowlisted domains

- **Optimization Recommendations**:
  - Cache domain validation results with TTL
  - Use allowlist as fast-path (skip similarity checks for known domains)
  - Pre-compute Levenshtein distance for common typosquatting patterns

### Monitoring and Alerting

#### Metrics to Monitor
- `oauth_flow_validation_total{result, provider}` - Validation outcomes
- `oauth_issuer_mismatch_total{expected, received}` - Mix-up attempts
- `domain_similarity_alert_total{type, domain}` - Typosquatting/homograph alerts
- `certificate_pin_validation_total{result, domain}` - Pin verification results

#### Alert Conditions
| Severity | Condition | Description |
|----------|-----------|-------------|
| Critical | Issuer mismatch detected | Active Mix-up attack (SAFE-T1009) |
| Critical | Certificate pin mismatch | Possible MitM or domain takeover |
| High | Homograph domain detected | IDN-based impersonation attempt |
| High | Typosquatting domain (distance 1-2) | Close impersonation attempt |
| Medium | Missing RFC 9207 issuer | Legacy AS or misconfiguration |
| Medium | Unknown AS domain used | New OAuth provider or attack |
| Low | Certificate rotation detected | Pin update may be needed |

## Current Status (2025)

According to industry standards and security research:

- **[RFC 9207](https://datatracker.ietf.org/doc/html/rfc9207) (OAuth 2.0 Authorization Server Issuer Identification)**, published March 2022, is now the standard defense against Authorization Server Mix-up attacks. Major providers (Google, Microsoft, Okta) have implemented support.

- **Research by [Mainka et al. (USENIX Security 2016)](https://www.usenix.org/conference/usenixsecurity16/technical-sessions/presentation/mainka)** first formally documented OAuth Mix-up attacks, demonstrating practical exploitation against major OAuth implementations.

- **[Fett et al. (2016)](https://arxiv.org/abs/1601.01229)** provided comprehensive formal security analysis of OAuth 2.0, identifying the Mix-up vulnerability as a fundamental protocol weakness addressed by issuer identification.

- **[OAuth 2.0 Security Best Current Practice](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-security-topics)** recommends strict AS endpoint verification, PKCE usage, and issuer validation as essential security measures.

- **MCP implementations** integrating with multiple OAuth providers face increased Mix-up attack surface. The [SAFE-T1009](../../techniques/SAFE-T1009/README.md) technique documents specific MCP attack vectors addressed by this mitigation.

- **[PortSwigger Research](https://portswigger.net/research/hidden-oauth-attack-vectors)** continues to identify new OAuth attack vectors, emphasizing the importance of comprehensive flow verification.

## References

### RFC Standards
- [RFC 9207 - OAuth 2.0 Authorization Server Issuer Identification](https://datatracker.ietf.org/doc/html/rfc9207) - Primary defense against Mix-up attacks
- [RFC 6749 - The OAuth 2.0 Authorization Framework](https://datatracker.ietf.org/doc/html/rfc6749)
- [RFC 6819 - OAuth 2.0 Threat Model and Security Considerations](https://datatracker.ietf.org/doc/html/rfc6819)
- [RFC 7636 - Proof Key for Code Exchange (PKCE)](https://datatracker.ietf.org/doc/html/rfc7636)
- [RFC 8252 - OAuth 2.0 for Native Apps](https://datatracker.ietf.org/doc/html/rfc8252)
- [OAuth 2.0 Security Best Current Practice - IETF Draft](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-security-topics)

### Academic Research
- [On the Security of Modern Single Sign-On Protocols: Second-Order Vulnerabilities in OpenID Connect - Mainka, Mladenov, Schwenk (2015)](https://arxiv.org/abs/1508.04324)
- [A Comprehensive Formal Security Analysis of OAuth 2.0 - Fett, Küsters, Schmitz (ACM CCS 2016)](https://arxiv.org/abs/1601.01229)

### Industry Standards
- [OWASP Top 10 for LLM Applications](https://owasp.org/www-project-top-10-for-large-language-model-applications/)
- [Model Context Protocol Specification](https://modelcontextprotocol.io/specification)
- [Unicode Security Considerations - Unicode Technical Report #39](https://www.unicode.org/reports/tr39/)

### Additional Resources
- [Hidden OAuth Attack Vectors - PortSwigger Research](https://portswigger.net/research/hidden-oauth-attack-vectors)
- [OWASP OAuth 2.0 Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/OAuth2_Cheat_Sheet.html)

## Related Mitigations

- [SAFE-M-14](../SAFE-M-14/README.md): Server Allowlisting - Complementary AS domain allowlisting
- [SAFE-M-15](../SAFE-M-15/README.md): User Warning Systems - User-facing warnings for suspicious OAuth flows
- [SAFE-M-16](../SAFE-M-16/README.md): Token Scope Limiting - Post-authorization scope validation
- [SAFE-M-18](../SAFE-M-18/README.md): OAuth Flow Monitoring - Detective monitoring of OAuth patterns
- [SAFE-M-19](../SAFE-M-19/README.md): Token Usage Tracking - Token lifecycle monitoring
- [SAFE-M-20](../SAFE-M-20/README.md): Anomaly Detection - Behavioral analysis of OAuth usage

## Version History

| Version | Date | Changes | Author |
|---------|------|---------|--------|
| 1.0 | 2025-01-05 | Initial comprehensive documentation of OAuth Flow Verification mitigation, including RFC 9207 issuer validation, domain similarity detection (typosquatting, homograph, IDN), certificate pinning, and AS allowlisting for preventing Authorization Server Mix-up attacks (SAFE-T1009) | Raju Kumar Yadav |
