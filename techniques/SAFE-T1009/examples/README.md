# OAuth Authorization Server Mix-up Attack Examples

## Educational Purpose Only

⚠️ **WARNING**: These examples are for educational and defensive security purposes only. Implementing these techniques against systems you do not own or have explicit permission to test is illegal and unethical.

## Overview

This directory contains educational examples demonstrating Authorization Server Mix-up attack vectors and detection methods.

## Example 1: Domain Similarity Detector

A tool to detect lookalike domains that could be used in AS Mix-up attacks.

```python
#!/usr/bin/env python3
"""
Domain Similarity Detector for OAuth Authorization Servers

Educational tool for detecting potential typosquatting and homograph attacks
against OAuth Authorization Server domains.
"""

import re
from typing import List, Tuple

def levenshtein_distance(s1: str, s2: str) -> int:
    """Calculate Levenshtein distance between two strings"""
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

def calculate_similarity(domain1: str, domain2: str) -> float:
    """Calculate similarity score between two domains (0-1, higher is more similar)"""
    distance = levenshtein_distance(domain1, domain2)
    max_len = max(len(domain1), len(domain2))
    return 1.0 - (distance / max_len) if max_len > 0 else 0.0

def contains_unicode_confusables(domain: str) -> List[Tuple[str, str, int]]:
    """Detect Unicode confusable characters in domain"""
    confusables = []

    # Common confusables (character, lookalike, unicode codepoint)
    confusable_chars = {
        '\u0430': ('а', 'a', 'Cyrillic'),  # Cyrillic 'а' looks like Latin 'a'
        '\u0435': ('е', 'e', 'Cyrillic'),  # Cyrillic 'е' looks like Latin 'e'
        '\u043E': ('о', 'o', 'Cyrillic'),  # Cyrillic 'о' looks like Latin 'o'
        '\u0440': ('р', 'p', 'Cyrillic'),  # Cyrillic 'р' looks like Latin 'p'
        '\u0441': ('с', 'c', 'Cyrillic'),  # Cyrillic 'с' looks like Latin 'c'
        '\u03BF': ('ο', 'o', 'Greek'),     # Greek omicron looks like Latin 'o'
        '\u03C1': ('ρ', 'p', 'Greek'),     # Greek rho looks like Latin 'p'
    }

    for i, char in enumerate(domain):
        if char in confusable_chars:
            confusable, lookalike, script = confusable_chars[char]
            confusables.append((confusable, lookalike, i))

    return confusables

def detect_typosquatting_patterns(domain: str, legitimate_domain: str) -> List[str]:
    """Detect common typosquatting patterns"""
    patterns = []

    # Hyphenation
    if '-' in domain and '-' not in legitimate_domain:
        patterns.append("Hyphenation: Adds hyphens to legitimate domain")

    # Character omission
    if len(domain) < len(legitimate_domain):
        patterns.append(f"Character Omission: {len(legitimate_domain) - len(domain)} characters removed")

    # Character addition
    if len(domain) > len(legitimate_domain):
        patterns.append(f"Character Addition: {len(domain) - len(legitimate_domain)} characters added")

    # TLD substitution
    domain_parts = domain.split('.')
    legit_parts = legitimate_domain.split('.')
    if len(domain_parts) == len(legit_parts) >= 2:
        if domain_parts[-1] != legit_parts[-1]:
            patterns.append(f"TLD Substitution: .{legit_parts[-1]} → .{domain_parts[-1]}")

    # Punycode/IDN
    if 'xn--' in domain:
        patterns.append("Punycode: Uses internationalized domain name encoding")

    return patterns

# Example usage
if __name__ == "__main__":
    # Legitimate OAuth Authorization Server domains
    legitimate_domains = [
        "accounts.google.com",
        "login.microsoftonline.com",
        "github.com",
        "signin.aws.amazon.com"
    ]

    # Suspicious domains to check
    suspicious_domains = [
        "accounts-google.com",
        "аccounts.google.com",  # Cyrillic 'а'
        "goοgle.com",           # Greek omicron
        "accounts.google.co",
        "xn--ccount-9ua.google.com"
    ]

    print("=" * 80)
    print("OAuth Authorization Server Mix-up Detection")
    print("=" * 80)

    for suspicious in suspicious_domains:
        print(f"\nAnalyzing: {suspicious}")
        print("-" * 80)

        for legitimate in legitimate_domains:
            similarity = calculate_similarity(suspicious, legitimate)

            if similarity > 0.7:  # High similarity threshold
                print(f"⚠️  HIGH SIMILARITY to {legitimate}")
                print(f"   Similarity Score: {similarity:.2%}")

                # Check for confusables
                confusables = contains_unicode_confusables(suspicious)
                if confusables:
                    print(f"   Unicode Confusables Detected:")
                    for char, lookalike, pos in confusables:
                        print(f"     - Position {pos}: '{char}' looks like '{lookalike}'")

                # Check for typosquatting patterns
                patterns = detect_typosquatting_patterns(suspicious, legitimate)
                if patterns:
                    print(f"   Typosquatting Patterns:")
                    for pattern in patterns:
                        print(f"     - {pattern}")
```

## Example 2: RFC 9207 Issuer Validation

Demonstrates proper issuer validation according to RFC 9207.

```python
def validate_oauth_authorization_response(
    authorization_response: dict,
    expected_issuer: str,
    state: str
) -> Tuple[bool, str]:
    """
    Validate OAuth 2.0 authorization response per RFC 9207

    Args:
        authorization_response: The authorization response from AS
        expected_issuer: The expected issuer identifier
        state: The state parameter sent in authorization request

    Returns:
        Tuple of (is_valid, error_message)
    """
    # Check for required iss parameter (RFC 9207)
    if 'iss' not in authorization_response:
        return False, "Missing issuer (iss) parameter - RFC 9207 violation"

    # Validate issuer matches expected value
    actual_issuer = authorization_response['iss']
    if actual_issuer != expected_issuer:
        return False, f"Issuer mismatch: expected '{expected_issuer}', got '{actual_issuer}'"

    # Validate state parameter
    if 'state' not in authorization_response:
        return False, "Missing state parameter"

    if authorization_response['state'] != state:
        return False, "State parameter mismatch - possible CSRF attack"

    # Check for authorization code
    if 'code' not in authorization_response:
        return False, "Missing authorization code"

    return True, "Authorization response valid"

# Example usage
authorization_response = {
    'code': 'auth_code_xyz123',
    'state': 'random_state_value',
    'iss': 'https://accounts.google.com'  # RFC 9207 issuer parameter
}

is_valid, message = validate_oauth_authorization_response(
    authorization_response,
    expected_issuer='https://accounts.google.com',
    state='random_state_value'
)

print(f"Valid: {is_valid}")
print(f"Message: {message}")
```

## Example 3: Static Authorization Server Allowlist

Configuration example for preventing AS Mix-up through allowlisting.

```json
{
  "oauth_authorization_servers": {
    "allowlist": [
      {
        "name": "Google",
        "issuer": "https://accounts.google.com",
        "authorization_endpoint": "https://accounts.google.com/o/oauth2/v2/auth",
        "token_endpoint": "https://oauth2.googleapis.com/token",
        "jwks_uri": "https://www.googleapis.com/oauth2/v3/certs",
        "certificate_pins": [
          "sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
        ]
      },
      {
        "name": "Microsoft",
        "issuer": "https://login.microsoftonline.com",
        "authorization_endpoint": "https://login.microsoftonline.com/common/oauth2/v2.0/authorize",
        "token_endpoint": "https://login.microsoftonline.com/common/oauth2/v2.0/token",
        "jwks_uri": "https://login.microsoftonline.com/common/discovery/v2.0/keys"
      }
    ],
    "validation_rules": {
      "require_issuer_parameter": true,
      "enforce_certificate_pinning": true,
      "reject_non_allowlisted_domains": true,
      "check_domain_similarity": true,
      "similarity_threshold": 0.85
    }
  }
}
```

## Detection Best Practices

1. **Implement RFC 9207**: Always validate the `iss` parameter
2. **Use Allowlists**: Maintain strict lists of approved AS domains
3. **Certificate Pinning**: Pin certificates for critical authorization servers
4. **Domain Similarity Checking**: Flag domains too similar to legitimate ASs
5. **Unicode Normalization**: Detect and flag Unicode confusables
6. **User Warnings**: Display full URLs prominently during OAuth flows
7. **Behavioral Monitoring**: Alert on first-seen domains or configuration changes

## References

- [RFC 9207 - OAuth 2.0 Authorization Server Issuer Identification](https://datatracker.ietf.org/doc/html/rfc9207)
- [RFC 6819 - OAuth 2.0 Threat Model](https://datatracker.ietf.org/doc/html/rfc6819)
- [Unicode Technical Report #39: Security Mechanisms](https://www.unicode.org/reports/tr39/)

## Legal and Ethical Considerations

These examples are provided solely for:

- Educational purposes
- Defensive security research
- Implementing proper detection mechanisms
- Understanding attack vectors to defend against them

**Do NOT use these techniques for:**

- Attacking systems without authorization
- Creating malicious infrastructure
- Phishing or social engineering
- Any illegal activities

Unauthorized testing of security systems is illegal in most jurisdictions.
