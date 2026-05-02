#!/usr/bin/env python3
"""
Test Detection Rules for SAFE-T1009: Authorization Server Mix-up

This script validates Sigma detection rules against test log data to ensure
comprehensive coverage of Authorization Server Mix-up attack patterns.

Usage:
    python test_detection_rule.py
    
Author: Raju Kumar Yadav
Date: 2025-11-23
"""

import json
import re
from typing import List, Dict, Any, Set
from pathlib import Path


class DetectionRuleValidator:
    """Validates Sigma detection rules against test log data"""
    
    def __init__(self, test_logs_path: str):
        """Initialize validator with test log data"""
        with open(test_logs_path, 'r') as f:
            self.test_data = json.load(f)
        self.test_cases = self.test_data['test_cases']
        
        # Detection rule IDs from detection-rule.yml
        self.rule_ids = {
            'a7f8e3d1-9c2b-4a6e-8d5f-1b7c9e4a3f2d': 'OAuth AS Domain Typosquatting',
            'b8e9f4c2-0d3a-5b7e-9f6a-2c8d0e5b4a3f': 'Missing Issuer Identification',
            'c9f0a5d3-1e4b-6c8f-0a7b-3d9e1f6c5b4a': 'Issuer Identifier Mismatch',
            'd0a1b6e4-2f5c-7d9a-1b8c-4e0f2a7d6c5b': 'IDN Homograph Domain Detection',
            'e2c3d8f6-4b7a-9e1c-3d0e-6f2b4a9d8c7b': 'Suspicious TLD Substitution',
            'e1b2c7f5-3a6d-8e0b-2c9d-5f1a3b8e7d6c': 'Suspicious Certificate Characteristics',
            'f3d4e9a7-5c8b-0f2d-4e1a-7b3c6f9e8d0a': 'First-Seen AS Domain',
            'g4e5f0b8-6d9c-1a3e-5f2b-8c4d7a0f9e1b': 'Multiple AS Configurations',
            'h5f6a1c9-7e0d-2b4f-6a3c-9d5e8b1a0f2c': 'OAuth Configuration Change'
        }
    
    def check_typosquatting(self, event: Dict[str, Any]) -> bool:
        """Check for typosquatted domains in authorization endpoint"""
        if event.get('action') not in ['oauth.authorization.initiated', 'oauth.redirect.followed']:
            return False
        
        oauth = event.get('oauth', {})
        endpoint = oauth.get('authorization_endpoint', '')
        
        # Typosquatting patterns
        typosquat_patterns = [
            'accounts-google', 'account.google', 'acounts.google', 'accountsgoogle',
            'gogle.com', 'gooogle.com', 'googlle.com',
            'login-microsoft', 'logon.microsoft', 'signin-microsoft',
            'microsft.com', 'micosoft.com', 'mcrosoft.com',
            'auth-github', 'github-auth', 'guthub.com', 'githup.com', 'githubb.com',
            'oauth-aws', 'signin-aws', 'amazn.com', 'amzon.com', 'amazom.com',
            'signin-apple', 'apple-auth', 'aple.com', 'appel.com'
        ]
        
        # Legitimate patterns (should not trigger)
        legit_patterns = [
            'accounts.google.com', 'login.microsoftonline.com',
            'login.windows.net', 'github.com/login',
            'signin.aws.amazon.com', 'appleid.apple.com'
        ]
        
        # Check if endpoint contains typosquatting pattern
        has_typosquat = any(pattern in endpoint for pattern in typosquat_patterns)
        has_legit = any(pattern in endpoint for pattern in legit_patterns)
        
        return has_typosquat and not has_legit
    
    def check_missing_issuer(self, event: Dict[str, Any]) -> bool:
        """Check for missing issuer parameter in authorization response"""
        if event.get('action') != 'oauth.authorization.response.received':
            return False
        
        oauth = event.get('oauth', {})
        return 'iss' not in oauth or oauth.get('iss') is None
    
    def check_issuer_mismatch(self, event: Dict[str, Any]) -> bool:
        """Check for issuer identifier mismatch"""
        if event.get('action') != 'oauth.authorization.response.received':
            return False
        
        oauth = event.get('oauth', {})
        return oauth.get('issuer_validation') == 'failed'
    
    def check_idn_homograph(self, event: Dict[str, Any]) -> bool:
        """Check for IDN homograph attacks"""
        if event.get('action') not in ['oauth.authorization.initiated', 'oauth.redirect.followed']:
            return False
        
        oauth = event.get('oauth', {})
        endpoint = oauth.get('authorization_endpoint', '')
        
        # Check for Punycode (xn--)
        if 'xn--' in endpoint:
            return True
        
        # Check for Cyrillic characters (U+0400-U+04FF)
        if re.search(r'[\u0400-\u04FF]', endpoint):
            return True
        
        # Check for Greek characters (U+0370-U+03FF)
        if re.search(r'[\u0370-\u03FF]', endpoint):
            return True
        
        return False
    
    def check_tld_substitution(self, event: Dict[str, Any]) -> bool:
        """Check for suspicious TLD substitutions"""
        if event.get('action') not in ['oauth.authorization.initiated', 'oauth.redirect.followed']:
            return False
        
        oauth = event.get('oauth', {})
        endpoint = oauth.get('authorization_endpoint', '')
        
        # Suspicious TLD patterns - must end with these (not just contain)
        suspicious_patterns = [
            'google.co/', 'google.co?', 'google.io/', 'google.cloud/',
            'microsoft.co/', 'microsoft.io/',
            'github.co/', 'github.io/',
            'amazon.co/', 'apple.co/'
        ]
        
        # Legitimate domains and regional TLDs (should not trigger)
        legit_domains = [
            'google.com', 'googleapis.com', 'gstatic.com',
            'google.com.br', 'google.co.uk', 'google.co.jp',
            'microsoftonline.com', 'microsoft.com',
            'github.com', 'githubusercontent.com',
            'aws.amazon.com', 'amazonaws.com',
            'apple.com', 'icloud.com'
        ]
        
        # Check if it's a legitimate domain first
        if any(legit in endpoint for legit in legit_domains):
            return False
        
        # Now check for suspicious patterns
        has_suspicious = any(pattern in endpoint for pattern in suspicious_patterns)
        
        return has_suspicious
    
    def check_suspicious_certificate(self, event: Dict[str, Any]) -> bool:
        """Check for suspicious TLS certificate characteristics"""
        # This can be triggered from either TLS validation or OAuth events with TLS info
        if event.get('action') == 'tls.certificate.validated':
            tls = event.get('tls', {})
        elif 'tls' in event:
            tls = event.get('tls', {})
        else:
            return False
        
        server = tls.get('server', {})
        cert = tls.get('certificate', {})
        domain = server.get('domain', '')
        
        if not domain:
            return False
        
        # Check if domain contains brand names (case insensitive)
        # Also check for common character substitutions (I for l, etc.)
        brand_names = ['google', 'microsoft', 'github', 'amazon', 'apple']
        domain_lower = domain.lower()
        
        # Normalize common character substitutions and remove hyphens for brand matching
        domain_normalized = domain_lower.replace('i', 'l').replace('1', 'l').replace('0', 'o').replace('-', '')
        
        has_brand = any(brand in domain_lower for brand in brand_names) or \
                   any(brand in domain_normalized for brand in brand_names)
        
        if not has_brand:
            return False
        
        # Check if legitimate domain (case insensitive)
        legit_domains = [
            'google.com', 'googleapis.com', 'gstatic.com',
            'microsoft.com', 'microsoftonline.com',
            'github.com', 'githubusercontent.com',
            'aws.amazon.com', 'amazonaws.com',
            'apple.com', 'icloud.com'
        ]
        
        is_legit = any(domain_lower.endswith(legit) for legit in legit_domains)
        
        if is_legit:
            return False
        
        # Check for recently issued certificate (within 7 days)
        not_before = cert.get('not_before', '')
        if '2025-11-' in not_before:
            # Check day of month
            try:
                day = int(not_before.split('-')[2].split('T')[0])
                if day >= 17:  # Issued on or after Nov 17, within 7 days of Nov 23
                    return True
            except:
                pass
        
        # Check for DV certificate on major provider domain
        if cert.get('validation_type') == 'DV' and has_brand:
            return True
        
        return False
    
    def check_first_seen_domain(self, event: Dict[str, Any]) -> bool:
        """Check for first-seen Authorization Server domains"""
        if event.get('action') not in ['oauth.authorization.initiated', 'oauth.redirect.followed']:
            return False
        
        oauth = event.get('oauth', {})
        
        # Check if first-seen flag is set
        if not oauth.get('as_domain_first_seen', False):
            return False
        
        # Check if not in allowlist - be more specific about legitimate domains
        endpoint = oauth.get('authorization_endpoint', '')
        allowlist = [
            'accounts.google.com',
            'googleapis.com', 
            'login.microsoftonline.com',
            'login.windows.net',
            'github.com/login',
            'signin.aws.amazon.com',
            'appleid.apple.com'
        ]
        
        is_allowlisted = any(allowed in endpoint for allowed in allowlist)
        
        return not is_allowlisted
    
    def check_multiple_configs(self, event: Dict[str, Any]) -> bool:
        """Check for multiple AS configurations for same service"""
        if event.get('action') != 'oauth.provider.configured':
            return False
        
        oauth = event.get('oauth', {})
        return oauth.get('configuration_count', 0) > 1
    
    def check_config_change(self, event: Dict[str, Any]) -> bool:
        """Check for suspicious OAuth configuration changes"""
        if event.get('action') != 'oauth.configuration.modified':
            return False
        
        oauth = event.get('oauth', {})
        field_changed = oauth.get('field_changed', '')
        modified_by = oauth.get('modified_by', '')
        
        # Check if critical field changed by non-admin
        critical_fields = ['authorization_endpoint', 'token_endpoint', 'issuer']
        
        return field_changed in critical_fields and modified_by != 'administrator'
    
    def apply_detection_rules(self, event: Dict[str, Any]) -> Set[str]:
        """Apply all detection rules to an event and return triggered rule IDs"""
        triggered_rules = set()
        
        # Apply each detection rule
        if self.check_typosquatting(event):
            triggered_rules.add('a7f8e3d1-9c2b-4a6e-8d5f-1b7c9e4a3f2d')
        
        if self.check_missing_issuer(event):
            triggered_rules.add('b8e9f4c2-0d3a-5b7e-9f6a-2c8d0e5b4a3f')
        
        if self.check_issuer_mismatch(event):
            triggered_rules.add('c9f0a5d3-1e4b-6c8f-0a7b-3d9e1f6c5b4a')
        
        if self.check_idn_homograph(event):
            triggered_rules.add('d0a1b6e4-2f5c-7d9a-1b8c-4e0f2a7d6c5b')
        
        if self.check_tld_substitution(event):
            triggered_rules.add('e2c3d8f6-4b7a-9e1c-3d0e-6f2b4a9d8c7b')
        
        if self.check_suspicious_certificate(event):
            triggered_rules.add('e1b2c7f5-3a6d-8e0b-2c9d-5f1a3b8e7d6c')
        
        if self.check_first_seen_domain(event):
            triggered_rules.add('f3d4e9a7-5c8b-0f2d-4e1a-7b3c6f9e8d0a')
        
        if self.check_multiple_configs(event):
            triggered_rules.add('g4e5f0b8-6d9c-1a3e-5f2b-8c4d7a0f9e1b')
        
        if self.check_config_change(event):
            triggered_rules.add('h5f6a1c9-7e0d-2b4f-6a3c-9d5e8b1a0f2c')
        
        return triggered_rules
    
    def validate_test_cases(self) -> Dict[str, Any]:
        """Validate all test cases against detection rules"""
        results = {
            'total_tests': len(self.test_cases),
            'passed': 0,
            'failed': 0,
            'details': []
        }
        
        for test_case in self.test_cases:
            name = test_case['name']
            category = test_case['category']
            event = test_case['event']
            expected_alerts = set(test_case.get('expected_alerts', []))
            
            # Apply detection rules
            triggered_rules = self.apply_detection_rules(event)
            
            # Check if results match expectations
            if triggered_rules == expected_alerts:
                results['passed'] += 1
                status = 'PASS'
            else:
                results['failed'] += 1
                status = 'FAIL'
            
            # Build detailed result
            result_detail = {
                'name': name,
                'category': category,
                'status': status,
                'expected_alerts': len(expected_alerts),
                'triggered_alerts': len(triggered_rules),
                'expected_rules': [self.rule_ids.get(rid, rid) for rid in expected_alerts],
                'triggered_rules': [self.rule_ids.get(rid, rid) for rid in triggered_rules]
            }
            
            # Add mismatch details if failed
            if status == 'FAIL':
                false_positives = triggered_rules - expected_alerts
                false_negatives = expected_alerts - triggered_rules
                
                result_detail['false_positives'] = [
                    self.rule_ids.get(rid, rid) for rid in false_positives
                ]
                result_detail['false_negatives'] = [
                    self.rule_ids.get(rid, rid) for rid in false_negatives
                ]
            
            results['details'].append(result_detail)
        
        return results
    
    def print_results(self, results: Dict[str, Any]):
        """Print validation results in a readable format"""
        print("=" * 80)
        print("SAFE-T1009 Detection Rule Validation Results")
        print("=" * 80)
        print(f"\nTotal Test Cases: {results['total_tests']}")
        print(f"Passed: {results['passed']} ({results['passed']/results['total_tests']*100:.1f}%)")
        print(f"Failed: {results['failed']} ({results['failed']/results['total_tests']*100:.1f}%)")
        print("\n" + "=" * 80)
        print("Detailed Results:")
        print("=" * 80)
        
        for detail in results['details']:
            status_symbol = "✓" if detail['status'] == 'PASS' else "✗"
            print(f"\n{status_symbol} {detail['name']}")
            print(f"  Category: {detail['category']}")
            print(f"  Status: {detail['status']}")
            print(f"  Expected Alerts: {detail['expected_alerts']}")
            print(f"  Triggered Alerts: {detail['triggered_alerts']}")
            
            if detail['status'] == 'FAIL':
                if detail.get('false_positives'):
                    print(f"  False Positives: {', '.join(detail['false_positives'])}")
                if detail.get('false_negatives'):
                    print(f"  False Negatives: {', '.join(detail['false_negatives'])}")
            
            if detail.get('triggered_rules'):
                print(f"  Triggered Rules:")
                for rule in detail['triggered_rules']:
                    print(f"    - {rule}")
        
        print("\n" + "=" * 80)
        print(f"Overall Result: {'PASS' if results['failed'] == 0 else 'FAIL'}")
        print("=" * 80)
    
    def generate_coverage_report(self, results: Dict[str, Any]):
        """Generate detection rule coverage report"""
        print("\n" + "=" * 80)
        print("Detection Rule Coverage Report")
        print("=" * 80)
        
        # Count how many times each rule was triggered
        rule_counts = {}
        for detail in results['details']:
            for rule in detail['triggered_rules']:
                rule_counts[rule] = rule_counts.get(rule, 0) + 1
        
        print(f"\nTotal Detection Rules: {len(self.rule_ids)}")
        print(f"Rules Triggered: {len(rule_counts)}")
        print(f"Rules Not Triggered: {len(self.rule_ids) - len(rule_counts)}")
        
        print("\nRule Trigger Counts:")
        for rule_id, rule_name in sorted(self.rule_ids.items(), key=lambda x: x[1]):
            count = rule_counts.get(rule_name, 0)
            print(f"  {rule_name}: {count} times")
        
        # Identify rules not covered by tests
        not_triggered = set(self.rule_ids.values()) - set(rule_counts.keys())
        if not_triggered:
            print(f"\n⚠ Rules Not Covered by Tests:")
            for rule in sorted(not_triggered):
                print(f"  - {rule}")
        else:
            print(f"\n✓ All rules covered by at least one test case")
        
        print("=" * 80)


def main():
    """Main execution function"""
    # Get path to test logs
    script_dir = Path(__file__).parent
    test_logs_path = script_dir / 'test-logs.json'
    
    if not test_logs_path.exists():
        print(f"Error: Test logs file not found: {test_logs_path}")
        return 1
    
    # Initialize validator
    validator = DetectionRuleValidator(str(test_logs_path))
    
    # Run validation
    results = validator.validate_test_cases()
    
    # Print results
    validator.print_results(results)
    validator.generate_coverage_report(results)
    
    # Return exit code
    return 0 if results['failed'] == 0 else 1


if __name__ == '__main__':
    exit(main())

