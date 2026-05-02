#!/usr/bin/env python3
"""
Test script for SAFE-T1502 File-Based Credential Harvest detection rule.

This script validates the detection logic against sample log data to ensure
accurate identification of credential file access attempts while minimizing
false positives.
"""

import json
import yaml
import sys
from pathlib import Path
from typing import List, Dict, Any


class DetectionRuleTester:
    """Tests Sigma detection rules against sample log data."""
    
    def __init__(self, rule_path: str, logs_path: str):
        """
        Initialize the tester with rule and log file paths.
        
        Args:
            rule_path: Path to the Sigma detection rule YAML file
            logs_path: Path to the test logs JSON file
        """
        self.rule_path = Path(rule_path)
        self.logs_path = Path(logs_path)
        self.rule = self._load_rule()
        self.logs = self._load_logs()
        
    def _load_rule(self) -> Dict[str, Any]:
        """Load and parse the Sigma detection rule."""
        try:
            with open(self.rule_path, 'r') as f:
                return yaml.safe_load(f)
        except Exception as e:
            print(f"Error loading rule file: {e}")
            sys.exit(1)
            
    def _load_logs(self) -> List[Dict[str, Any]]:
        """Load and parse the test logs."""
        try:
            with open(self.logs_path, 'r') as f:
                return json.load(f)
        except Exception as e:
            print(f"Error loading logs file: {e}")
            sys.exit(1)
    
    def _check_contains(self, value: str, patterns: List[str]) -> bool:
        """Check if value contains any of the patterns."""
        return any(pattern in value for pattern in patterns)
    
    def _check_endswith(self, value: str, patterns: List[str]) -> bool:
        """Check if value ends with any of the patterns."""
        return any(value.endswith(pattern) for pattern in patterns)
    
    def _match_selection(self, log_entry: Dict[str, Any], selection: Dict[str, Any]) -> bool:
        """
        Check if a log entry matches a selection criteria.
        
        Args:
            log_entry: Single log entry to check
            selection: Selection criteria from the detection rule
            
        Returns:
            True if the log entry matches the selection criteria
        """
        for field, criteria in selection.items():
            # Handle different field operators
            if '|contains' in field:
                actual_field = field.split('|')[0]
                if actual_field not in log_entry:
                    return False
                if not self._check_contains(log_entry[actual_field], criteria):
                    return False
            elif '|endswith' in field:
                actual_field = field.split('|')[0]
                if actual_field not in log_entry:
                    return False
                if not self._check_endswith(log_entry[actual_field], criteria):
                    return False
            else:
                # Direct field match
                if field not in log_entry:
                    return False
                if isinstance(criteria, list):
                    if log_entry[field] not in criteria:
                        return False
                else:
                    if log_entry[field] != criteria:
                        return False
        return True
    
    def _evaluate_detection(self, log_entry: Dict[str, Any]) -> bool:
        """
        Evaluate if a log entry triggers the detection rule.
        
        Args:
            log_entry: Single log entry to evaluate
            
        Returns:
            True if the log entry should trigger an alert
        """
        detection = self.rule.get('detection', {})
        
        # Check each selection criteria
        matches = {}
        for key, value in detection.items():
            if key.startswith('selection_'):
                matches[key] = self._match_selection(log_entry, value)
        
        # Evaluate condition (simplified - handles OR conditions)
        condition = detection.get('condition', '')
        if 'or' in condition:
            return any(matches.values())
        elif 'and' in condition:
            return all(matches.values())
        else:
            # Default to OR if condition is unclear
            return any(matches.values())
    
    def run_tests(self) -> Dict[str, Any]:
        """
        Run detection tests against all log entries.
        
        Returns:
            Dictionary containing test results and statistics
        """
        results = {
            'total_logs': len(self.logs),
            'true_positives': 0,
            'true_negatives': 0,
            'false_positives': 0,
            'false_negatives': 0,
            'details': []
        }
        
        for log_entry in self.logs:
            detected = self._evaluate_detection(log_entry)
            expected = log_entry.get('expected_detection', False)
            
            result = {
                'timestamp': log_entry.get('timestamp'),
                'file_path': log_entry.get('file_path'),
                'detected': detected,
                'expected': expected,
                'description': log_entry.get('description')
            }
            
            # Classify result
            if detected and expected:
                results['true_positives'] += 1
                result['classification'] = 'TRUE_POSITIVE'
            elif not detected and not expected:
                results['true_negatives'] += 1
                result['classification'] = 'TRUE_NEGATIVE'
            elif detected and not expected:
                results['false_positives'] += 1
                result['classification'] = 'FALSE_POSITIVE'
            else:  # not detected and expected
                results['false_negatives'] += 1
                result['classification'] = 'FALSE_NEGATIVE'
            
            results['details'].append(result)
        
        return results
    
    def print_results(self, results: Dict[str, Any]) -> None:
        """Print test results in a readable format."""
        print("\n" + "="*80)
        print("SAFE-T1502 Detection Rule Test Results")
        print("="*80)
        print(f"\nRule: {self.rule.get('title')}")
        print(f"Rule ID: {self.rule.get('id')}")
        print(f"Total Log Entries: {results['total_logs']}")
        print("\n" + "-"*80)
        print("Summary Statistics:")
        print("-"*80)
        print(f"True Positives:  {results['true_positives']:3d} (Correctly detected malicious activity)")
        print(f"True Negatives:  {results['true_negatives']:3d} (Correctly ignored benign activity)")
        print(f"False Positives: {results['false_positives']:3d} (Incorrectly flagged benign activity)")
        print(f"False Negatives: {results['false_negatives']:3d} (Missed malicious activity)")
        
        # Calculate metrics
        total_positive = results['true_positives'] + results['false_negatives']
        total_negative = results['true_negatives'] + results['false_positives']
        
        if total_positive > 0:
            sensitivity = results['true_positives'] / total_positive * 100
            print(f"\nSensitivity (True Positive Rate): {sensitivity:.1f}%")
        
        if total_negative > 0:
            specificity = results['true_negatives'] / total_negative * 100
            print(f"Specificity (True Negative Rate): {specificity:.1f}%")
        
        if results['true_positives'] + results['false_positives'] > 0:
            precision = results['true_positives'] / (results['true_positives'] + results['false_positives']) * 100
            print(f"Precision: {precision:.1f}%")
        
        # Print detailed results for failures
        if results['false_positives'] > 0 or results['false_negatives'] > 0:
            print("\n" + "-"*80)
            print("Issues Found:")
            print("-"*80)
            
            for detail in results['details']:
                if detail['classification'] in ['FALSE_POSITIVE', 'FALSE_NEGATIVE']:
                    print(f"\n{detail['classification']}:")
                    print(f"  File: {detail['file_path']}")
                    print(f"  Time: {detail['timestamp']}")
                    print(f"  Description: {detail['description']}")
                    print(f"  Detected: {detail['detected']}, Expected: {detail['expected']}")
        
        print("\n" + "="*80)
        
        # Determine overall test result
        if results['false_positives'] == 0 and results['false_negatives'] == 0:
            print("✓ ALL TESTS PASSED")
            print("="*80 + "\n")
            return True
        else:
            print("✗ TESTS FAILED - Review issues above")
            print("="*80 + "\n")
            return False


def main():
    """Main test execution function."""
    # Determine file paths
    script_dir = Path(__file__).parent
    rule_path = script_dir / "detection-rule.yml"
    logs_path = script_dir / "test-logs.json"
    
    # Check if files exist
    if not rule_path.exists():
        print(f"Error: Detection rule not found at {rule_path}")
        sys.exit(1)
    
    if not logs_path.exists():
        print(f"Error: Test logs not found at {logs_path}")
        sys.exit(1)
    
    # Run tests
    tester = DetectionRuleTester(str(rule_path), str(logs_path))
    results = tester.run_tests()
    success = tester.print_results(results)
    
    # Exit with appropriate code
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()


