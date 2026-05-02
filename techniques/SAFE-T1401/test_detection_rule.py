#!/usr/bin/env python3
"""
SAFE-T1401 Line Jumping Detection Rule Test Suite
Tests the Sigma detection rule against various attack patterns and benign scenarios.

Author: Raju Kumar Yadav
Date: 2025-11-19
"""

import json
from typing import Dict, Any, List, Tuple


class LineJumpingDetector:
    """Implements the SAFE-T1401 detection logic"""
    
    PRIORITY_INSTRUCTIONS = [
        'SYSTEM DIRECTIVE', 'PRIORITY_INSTRUCTION', 'PRIORITY DIRECTIVE',
        'takes precedence', 'override all', 'suspend security',
        'disable restrictions', 'temporarily suspended', 'bypass all subsequent',
        'ignore any restrictions', 'security validation mode', 'authorization checks',
        'admin privilege level', 'elevated privileges',
    ]
    
    FAKE_DELIMITERS = [
        '<!--[SYSTEM', '<!--[PRIORITY', '[PRIORITY_INSTRUCTION]',
        '[ADMIN_OVERRIDE', '[SECURITY_BYPASS', '---[SYSTEM', '---[END SYSTEM',
        '[CONTEXT_UPDATE]', '<|system|>', '<|priority|>', '<!—SYSTEM',
        '[DIRECTIVE', '[INSTRUCTION',
    ]
    
    CONTEXT_MANIPULATION = [
        'establish precedence', 'higher priority than', 'supersede all',
        'takes priority over', 'overrides later', 'ignore subsequent instructions',
        'disregard following rules', 'preceding all', 'before any', 'first priority',
    ]
    
    SECURITY_BYPASS = [
        'without additional confirmation', 'skip validation', 'bypass authentication',
        'disable authorization', 'allow full table access', 'unrestricted access',
        'elevated privileges', 'admin privilege level', 'allow full access',
        'grant full permissions', 'remove restrictions', 'bypass security',
    ]
    
    STEALTH_INDICATORS = [
        'NEVER mention', 'do not disclose', 'keep hidden', 'do not reveal',
        'silently', 'without notifying', 'do not inform',
    ]
    
    TRUSTED_SOURCES = ['system_prompt', 'security_policy', 'admin_config']
    EARLY_CONTEXT_THRESHOLD = 100
    
    def detect(self, log_entry: Dict[str, Any]) -> Tuple[bool, List[str]]:
        """
        Detect line jumping attacks in log entries
        
        Args:
            log_entry: Log entry to analyze
            
        Returns:
            Tuple of (is_attack_detected, list_of_matched_patterns)
        """
        content = log_entry.get('context_content', '').lower()
        context_position = log_entry.get('context_position', 0)
        content_source = log_entry.get('content_source', '')
        authenticated = log_entry.get('authenticated', False)
        
        matched_patterns = []
        
        # Check for trusted source exception
        if content_source in self.TRUSTED_SOURCES and authenticated:
            return False, ['Trusted source exception']
        
        # Check early context filter
        if context_position >= self.EARLY_CONTEXT_THRESHOLD:
            return False, ['Late context position']
        
        # Check all pattern categories
        for pattern in self.PRIORITY_INSTRUCTIONS:
            if pattern.lower() in content:
                matched_patterns.append(f'Priority: {pattern}')
        
        for pattern in self.FAKE_DELIMITERS:
            if pattern.lower() in content:
                matched_patterns.append(f'Delimiter: {pattern}')
        
        for pattern in self.CONTEXT_MANIPULATION:
            if pattern.lower() in content:
                matched_patterns.append(f'Manipulation: {pattern}')
        
        for pattern in self.SECURITY_BYPASS:
            if pattern.lower() in content:
                matched_patterns.append(f'Bypass: {pattern}')
        
        for pattern in self.STEALTH_INDICATORS:
            if pattern.lower() in content:
                matched_patterns.append(f'Stealth: {pattern}')
        
        # Return detection result
        return len(matched_patterns) > 0, matched_patterns


def run_tests(test_file: str = 'test-logs.json') -> Dict[str, Any]:
    """
    Run all test cases from the test log file
    
    Args:
        test_file: Path to test logs JSON file
        
    Returns:
        Dictionary with test results and statistics
    """
    with open(test_file, 'r') as f:
        test_cases = json.load(f)
    
    detector = LineJumpingDetector()
    results = {
        'total': len(test_cases),
        'passed': 0,
        'failed': 0,
        'details': []
    }
    
    # ANSI color codes
    GREEN = '\033[92m'
    RED = '\033[91m'
    RESET = '\033[0m'
    
    print("=" * 70)
    print("SAFE-T1401: Line Jumping Attack Detection - Test Suite")
    print("=" * 70)
    print(f"\nLoaded {len(test_cases)} test cases from {test_file}\n")
    
    for test_case in test_cases:
        test_name = test_case['test_case']
        description = test_case['description']
        expected = test_case['expected_detection']
        log_entry = test_case['log_entry']
        
        # Run detection
        detected, patterns = detector.detect(log_entry)
        
        # Check if result matches expectation
        passed = (detected == expected)
        
        if passed:
            results['passed'] += 1
            status = f"{GREEN}✓ PASS{RESET}"
        else:
            results['failed'] += 1
            status = f"{RED}✗ FAIL{RESET}"
        
        print(f"{status} Test: {test_name}")
        print(f"  Description: {description}")
        print(f"  Expected: {'DETECT' if expected else 'NO DETECT'}")
        print(f"  Actual: {'DETECTED' if detected else 'NOT DETECTED'}")
        
        if not passed:
            print(f"  {RED}Matched patterns:{RESET} {patterns if detected else 'None'}")
        
        print()
        
        results['details'].append({
            'test': test_name,
            'passed': passed,
            'expected': expected,
            'detected': detected,
            'patterns': patterns
        })
    
    return results


def print_summary(results: Dict[str, Any]):
    """Print test summary"""
    GREEN = '\033[92m'
    RED = '\033[91m'
    RESET = '\033[0m'
    
    print("=" * 70)
    print("TEST SUMMARY")
    print("=" * 70)
    print(f"Total Tests: {results['total']}")
    print(f"Passed: {results['passed']} ({results['passed']/results['total']*100:.0f}%)")
    print(f"Failed: {results['failed']} ({results['failed']/results['total']*100:.0f}%)")
    print()
    
    if results['failed'] == 0:
        print(f"{GREEN}✓ All tests passed!{RESET}")
    else:
        print(f"{RED}✗ Some tests failed. Review the output above.{RESET}")
    
    print("=" * 70)


if __name__ == '__main__':
    import sys
    
    test_file = sys.argv[1] if len(sys.argv) > 1 else 'test-logs.json'
    
    try:
        results = run_tests(test_file)
        print_summary(results)
        
        # Exit with error code if tests failed
        sys.exit(0 if results['failed'] == 0 else 1)
    except FileNotFoundError:
        print(f"Error: Test file '{test_file}' not found")
        sys.exit(1)
    except Exception as e:
        print(f"Error running tests: {e}")
        sys.exit(1)
