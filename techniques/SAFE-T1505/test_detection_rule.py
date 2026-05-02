#!/usr/bin/env python3
"""
Test script for SAFE-T1505 detection rules
Validates detection rules against test logs and calculates performance metrics
"""
# /// script
# dependencies = [
#   "pyyaml>=6.0",
# ]
# ///

import json
import yaml
from pathlib import Path
from typing import Dict, List, Tuple


class DetectionRuleTester:
    """Test harness for SAFE-T1505 detection rules"""
    
    def __init__(self, rule_file: str, test_logs_file: str):
        """Initialize tester with rule and test log files"""
        self.rule_file = Path(rule_file)
        self.test_logs_file = Path(test_logs_file)
        self.rule = None
        self.test_cases = None
        
    def load_rule(self) -> Dict:
        """Load Sigma detection rule"""
        with open(self.rule_file, 'r') as f:
            self.rule = yaml.safe_load(f)
        return self.rule
    
    def load_test_logs(self) -> Dict:
        """Load test logs"""
        with open(self.test_logs_file, 'r') as f:
            self.test_cases = json.load(f)
        return self.test_cases
    
    def evaluate_selection(self, selection: Dict, log_entry: Dict) -> bool:
        """
        Evaluate if a log entry matches a selection criteria
        Simplified evaluation for testing purposes
        """
        for field, criteria in selection.items():
            if '|contains' in field:
                # Handle contains operator
                base_field = field.split('|')[0]
                if base_field not in log_entry:
                    continue
                    
                field_value = str(log_entry[base_field]).lower()
                if isinstance(criteria, list):
                    if any(str(c).lower() in field_value for c in criteria):
                        return True
                elif str(criteria).lower() in field_value:
                    return True
                    
            elif field in log_entry:
                # Direct field comparison
                log_value = log_entry[field]
                
                # Handle comparison operators
                if isinstance(criteria, str) and criteria.startswith('>'):
                    threshold = float(criteria[1:])
                    if isinstance(log_value, (int, float)) and log_value > threshold:
                        return True
                elif isinstance(criteria, str) and criteria.startswith('<'):
                    threshold = float(criteria[1:])
                    if isinstance(log_value, (int, float)) and log_value < threshold:
                        return True
                elif isinstance(criteria, list):
                    if log_value in criteria:
                        return True
                elif log_value == criteria:
                    return True
        
        return False
    
    def evaluate_log_entry(self, log_entry: Dict) -> bool:
        """
        Evaluate if a log entry matches the detection rule
        Returns True if malicious, False if benign
        """
        detection = self.rule.get('detection', {})
        
        # Evaluate each selection
        selection_results = {}
        for key, value in detection.items():
            if key.startswith('selection_'):
                selection_results[key] = self.evaluate_selection(value, log_entry)
        
        # Evaluate condition (simplified OR logic for this implementation)
        condition = detection.get('condition', '')
        if 'or' in condition.lower():
            return any(selection_results.values())
        elif 'and' in condition.lower():
            return all(selection_results.values())
        
        return any(selection_results.values())
    
    def run_tests(self) -> Dict:
        """Run all test cases and return results"""
        results = {
            'true_positives': 0,
            'true_negatives': 0,
            'false_positives': 0,
            'false_negatives': 0,
            'total_tests': 0,
            'details': []
        }
        
        for test_case in self.test_cases['test_cases']:
            test_id = test_case['id']
            test_type = test_case['type']
            expected = test_case['expected_result']
            log_entry = test_case['log_entry']
            
            # Run detection
            detected = self.evaluate_log_entry(log_entry)
            
            # Determine outcome
            outcome = None
            if test_type == 'malicious':
                if detected and expected == 'detect':
                    results['true_positives'] += 1
                    outcome = 'TP'
                elif not detected and expected == 'detect':
                    results['false_negatives'] += 1
                    outcome = 'FN'
            elif test_type == 'benign':
                if not detected and expected == 'pass':
                    results['true_negatives'] += 1
                    outcome = 'TN'
                elif detected and expected == 'pass':
                    results['false_positives'] += 1
                    outcome = 'FP'
            elif test_type == 'edge_case':
                # Edge cases are informational
                outcome = 'EDGE'
                if detected:
                    results['false_positives'] += 1
                else:
                    results['true_negatives'] += 1
            
            results['total_tests'] += 1
            results['details'].append({
                'test_id': test_id,
                'type': test_type,
                'detected': detected,
                'expected': expected,
                'outcome': outcome,
                'description': test_case['description']
            })
        
        # Calculate metrics
        results['accuracy'] = (
            (results['true_positives'] + results['true_negatives']) / 
            results['total_tests']
        ) if results['total_tests'] > 0 else 0
        
        results['precision'] = (
            results['true_positives'] / 
            (results['true_positives'] + results['false_positives'])
        ) if (results['true_positives'] + results['false_positives']) > 0 else 0
        
        results['recall'] = (
            results['true_positives'] / 
            (results['true_positives'] + results['false_negatives'])
        ) if (results['true_positives'] + results['false_negatives']) > 0 else 0
        
        results['f1_score'] = (
            2 * (results['precision'] * results['recall']) / 
            (results['precision'] + results['recall'])
        ) if (results['precision'] + results['recall']) > 0 else 0
        
        return results
    
    def print_results(self, results: Dict):
        """Print test results in a formatted manner"""
        print("=" * 80)
        print("SAFE-T1505 Detection Rule Test Results")
        print("=" * 80)
        print(f"\nRule: {self.rule.get('title', 'Unknown')}")
        print(f"Rule ID: {self.rule.get('id', 'Unknown')}")
        print(f"Total Tests: {results['total_tests']}")
        print("\n" + "-" * 80)
        print("CONFUSION MATRIX")
        print("-" * 80)
        print(f"True Positives:  {results['true_positives']:3d}")
        print(f"True Negatives:  {results['true_negatives']:3d}")
        print(f"False Positives: {results['false_positives']:3d}")
        print(f"False Negatives: {results['false_negatives']:3d}")
        print("\n" + "-" * 80)
        print("PERFORMANCE METRICS")
        print("-" * 80)
        print(f"Accuracy:  {results['accuracy']:.4f} ({results['accuracy']*100:.2f}%)")
        print(f"Precision: {results['precision']:.4f} ({results['precision']*100:.2f}%)")
        print(f"Recall:    {results['recall']:.4f} ({results['recall']*100:.2f}%)")
        print(f"F1 Score:  {results['f1_score']:.4f}")
        print("\n" + "-" * 80)
        print("DETAILED TEST RESULTS")
        print("-" * 80)
        
        for detail in results['details']:
            status = "✓" if detail['outcome'] in ['TP', 'TN'] else "✗"
            print(f"{status} [{detail['outcome']:4s}] {detail['test_id']:20s} - {detail['description']}")
        
        print("\n" + "=" * 80)
        
        # Recommendations
        if results['false_positives'] > 0:
            print("⚠️  WARNING: False positives detected. Consider:")
            print("   - Adjusting similarity thresholds")
            print("   - Adding more specific conditions")
            print("   - Reviewing false positive patterns")
        
        if results['false_negatives'] > 0:
            print("⚠️  WARNING: False negatives detected. Consider:")
            print("   - Lowering detection thresholds")
            print("   - Adding more detection patterns")
            print("   - Reviewing missed attack patterns")
        
        if results['accuracy'] >= 0.95:
            print("✓ EXCELLENT: Detection accuracy is very high (≥95%)")
        elif results['accuracy'] >= 0.85:
            print("✓ GOOD: Detection accuracy is acceptable (≥85%)")
        else:
            print("✗ NEEDS IMPROVEMENT: Detection accuracy is below recommended threshold")
        
        print("=" * 80)


def main():
    """Main test execution"""
    script_dir = Path(__file__).parent
    
    # File paths
    rule_file = script_dir / "detection-rule.yml"
    test_logs_file = script_dir / "test-logs.json"
    
    # Verify files exist
    if not rule_file.exists():
        print(f"Error: Detection rule file not found: {rule_file}")
        return 1
    
    if not test_logs_file.exists():
        print(f"Error: Test logs file not found: {test_logs_file}")
        return 1
    
    # Initialize tester
    tester = DetectionRuleTester(str(rule_file), str(test_logs_file))
    
    # Load files
    try:
        tester.load_rule()
        tester.load_test_logs()
    except Exception as e:
        print(f"Error loading files: {e}")
        return 1
    
    # Run tests
    results = tester.run_tests()
    
    # Print results
    tester.print_results(results)
    
    # Return exit code based on results
    if results['false_negatives'] > 0:
        return 2  # Critical: missed attacks
    elif results['false_positives'] > 2:
        return 1  # Warning: too many false positives
    else:
        return 0  # Success


if __name__ == "__main__":
    exit(main())

