#!/usr/bin/env python3
"""
SAFE-T2103 Code Sabotage Detection Rule Test Suite
Tests the Sigma detection rule against various code sabotage attack patterns and benign scenarios.

Author: SAFE-MCP Team
Date: 2025-11-20
"""

import json
import re
from typing import Dict, Any, List, Tuple


class CodeSabotageDetector:
    """Implements the SAFE-T2103 detection logic"""
    
    # Suspicious code patterns (excluding os.getenv and subprocess which need context)
    SUSPICIOUS_CODE = [
        'DEBUG_AUTH',
        'BACKDOOR',
        'eval(',
        'exec(',
        '__import__',
        'subprocess.call',
        'subprocess.Popen',
        'urllib.request.urlopen',
        'base64.b64decode',
        'pickle.loads',
        'marshal.loads',
        'yaml.load',
        'compile(',
        'globals()',
        'locals()',
    ]
    
    # Code patterns that need additional context to be suspicious
    CONTEXT_DEPENDENT_CODE = [
        'os.getenv(',
        'subprocess.run',
        'requests.post',
        'requests.get',
    ]
    
    # Hardcoded credential pattern
    HARDCODED_CREDS_PATTERN = re.compile(
        r'(password|secret|key|token|api_key|apikey|access_token)\s*=\s*["\'][^"\']{8,}["\']',
        re.IGNORECASE
    )
    
    # Suspicious dependency patterns
    SUSPICIOUS_DEPS = [
        '@attacker.com',
        'malicious',
        'backdoor',
        '.local',
        'http://',
        'git+http://',
        'file://',
    ]
    
    # Package file extensions
    PACKAGE_FILES = [
        'requirements.txt',
        'package.json',
        'pom.xml',
        'Gemfile',
        'Cargo.toml',
        'go.mod',
    ]
    
    # Authentication bypass patterns
    AUTH_BYPASS = [
        'if user == "admin"',
        'return True',
        'bypass',
        'skip_validation',
        'DEBUG_MODE',
        'is_admin = True',
        'authenticated = True',
        'check_auth() == False',
    ]
    
    # Data exfiltration patterns
    DATA_EXFIL_FUNCTIONS = [
        'requests.post',
        'requests.get',
        'urllib.request',
        'urllib2.urlopen',
        'socket.connect',
        'http.client',
        'httplib',
        'curl',
    ]
    
    DATA_EXFIL_KEYWORDS = [
        'attacker',
        'malicious',
        'exfil',
        'collect',
        'steal',
        'send.*data',
        'post.*secret',
    ]
    
    # SQL injection pattern
    SQL_INJECTION_PATTERN = re.compile(
        r'(SELECT|INSERT|UPDATE|DELETE).*\+.*(request|input|param|user_input)',
        re.IGNORECASE
    )
    
    # Command injection pattern
    COMMAND_INJECTION_PATTERN = re.compile(
        r'(os\.system|subprocess|popen|shell_exec|exec|eval).*\+.*(request|input|param)',
        re.IGNORECASE
    )
    
    # Security-critical file paths
    SECURITY_FILES = [
        '/auth',
        '/security',
        '/crypto',
        '/encryption',
        '/validation',
        'middleware',
        'permission',
        'access_control',
    ]
    
    # Suspicious commit message patterns
    SUSPICIOUS_COMMIT_MSG_PATTERN = re.compile(
        r'(fix.*security|improve.*auth|add.*debug|temporary.*bypass)',
        re.IGNORECASE
    )
    
    def detect(self, log_entry: Dict[str, Any]) -> Tuple[bool, List[str]]:
        """
        Detect code sabotage attacks in log entries
        
        Args:
            log_entry: Log entry to analyze
            
        Returns:
            Tuple of (is_attack_detected, list_of_matched_patterns)
        """
        matched_patterns = []
        event_type = log_entry.get('event_type', '')
        source = log_entry.get('source', '')
        code_content = log_entry.get('code_content', '').lower()
        file_path = log_entry.get('file_path', '').lower()
        commit_message = log_entry.get('commit_message', '').lower()
        
        # Only check MCP agent commits
        if event_type != 'code_commit' or source != 'mcp_agent':
            return False, ['Not an MCP agent code commit']
        
        # Check suspicious code patterns
        for pattern in self.SUSPICIOUS_CODE:
            if pattern.lower() in code_content:
                matched_patterns.append(f'Suspicious Code: {pattern}')
                break
        
        # Check context-dependent code patterns
        # os.getenv is only suspicious if combined with DEBUG_AUTH or similar
        if 'os.getenv(' in code_content:
            if any(ctx in code_content for ctx in ['debug_auth', 'debug_mode', 'bypass', 'admin', 'superuser']):
                matched_patterns.append('Suspicious Code: os.getenv( (with debug/bypass context)')
        
        # subprocess.run and requests.post are only suspicious if combined with user input or exfiltration
        if 'subprocess.run' in code_content:
            # Check if combined with user input (command injection risk)
            if any(ui in code_content for ui in ['user_input', 'request', 'input', 'param', '+']):
                matched_patterns.append('Suspicious Code: subprocess.run (with user input)')
        
        # requests.post is handled in data exfiltration check below
        
        # Check hardcoded credentials
        if self.HARDCODED_CREDS_PATTERN.search(code_content):
            matched_patterns.append('Hardcoded Credentials: password/secret/key pattern')
        
        # Check suspicious dependencies in package files
        if any(file_path.endswith(pkg_file) for pkg_file in self.PACKAGE_FILES):
            for pattern in self.SUSPICIOUS_DEPS:
                if pattern.lower() in code_content:
                    matched_patterns.append(f'Suspicious Dependency: {pattern}')
                    break
        
        # Check authentication bypass (with context - "return True" alone in auth function is suspicious)
        # But need to avoid false positives on legitimate conditional returns
        if 'return True' in code_content:
            # Only flag if it's in an auth-related function without proper conditions
            if any(auth_term in code_content for auth_term in ['def is_authenticated', 'def check_auth', 'def authenticate', 'auth']):
                # Check if there's a proper condition before return True
                if not re.search(r'if\s+.*:\s*return\s+True', code_content):
                    matched_patterns.append('Auth Bypass: return True (unconditional in auth function)')
        
        # Check other bypass patterns
        for pattern in ['bypass', 'skip_validation', 'DEBUG_MODE', 'is_admin = True', 'authenticated = True', 'check_auth() == False']:
            if pattern.lower() in code_content:
                matched_patterns.append(f'Auth Bypass: {pattern}')
                break
        
        # Check data exfiltration
        # requests.post/get are only suspicious if combined with exfiltration keywords
        has_requests = 'requests.post' in code_content or 'requests.get' in code_content
        has_exfil_keyword = any(
            re.search(keyword.replace('.*', '.*'), code_content, re.IGNORECASE)
            for keyword in self.DATA_EXFIL_KEYWORDS
        )
        
        # Check other exfiltration functions
        has_other_exfil = any(func.lower() in code_content for func in ['urllib.request', 'urllib2.urlopen', 'http.client', 'httplib', 'curl'])
        
        # Check for socket-based exfiltration
        has_socket = 'socket.connect' in code_content or ('socket.socket' in code_content and 'connect' in code_content)
        has_steal_send = any(kw in code_content for kw in ['steal', 'send', 'collect', 'exfil', 'attacker', 'malicious'])
        
        if has_requests and has_exfil_keyword:
            matched_patterns.append('Data Exfiltration: HTTP request with exfiltration keywords')
        elif has_other_exfil and has_exfil_keyword:
            matched_patterns.append('Data Exfiltration: HTTP request with exfiltration keywords')
        elif has_socket and has_steal_send:
            matched_patterns.append('Data Exfiltration: Socket connection with exfiltration keywords')
        
        # Check SQL injection
        if self.SQL_INJECTION_PATTERN.search(code_content):
            matched_patterns.append('SQL Injection: SQL query with user input concatenation')
        
        # Check command injection
        if self.COMMAND_INJECTION_PATTERN.search(code_content):
            matched_patterns.append('Command Injection: Command execution with user input')
        
        # Check unusual commits with security file modifications
        commit_count = log_entry.get('commit_count', 0)
        time_window = log_entry.get('time_window', '')
        files_modified = log_entry.get('files_modified', [])
        
        if commit_count > 5:
            # Check if security files were modified
            security_file_modified = any(
                any(sec_file in str(f).lower() for sec_file in self.SECURITY_FILES)
                for f in files_modified
            )
            if security_file_modified:
                matched_patterns.append(f'Unusual Commits: {commit_count} commits with security file modifications')
        
        # Check suspicious commit message
        if self.SUSPICIOUS_COMMIT_MSG_PATTERN.search(commit_message):
            matched_patterns.append('Suspicious Commit Message: security/auth/debug keywords')
        
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
    
    detector = CodeSabotageDetector()
    results = {
        'total': len(test_cases),
        'passed': 0,
        'failed': 0,
        'details': []
    }
    
    # ANSI color codes
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    RESET = '\033[0m'
    
    print("=" * 70)
    print("SAFE-T2103: Code Sabotage Detection - Test Suite")
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
        
        if patterns:
            print(f"  {YELLOW}Matched patterns:{RESET} {', '.join(patterns)}")
        
        if not passed:
            if expected and not detected:
                print(f"  {RED}ERROR: Should have detected but didn't{RESET}")
            elif not expected and detected:
                print(f"  {RED}ERROR: False positive - detected when shouldn't{RESET}")
        
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
    YELLOW = '\033[93m'
    RESET = '\033[0m'
    
    print("=" * 70)
    print("TEST SUMMARY")
    print("=" * 70)
    print(f"Total Tests: {results['total']}")
    
    pass_rate = (results['passed'] / results['total'] * 100) if results['total'] > 0 else 0
    fail_rate = (results['failed'] / results['total'] * 100) if results['total'] > 0 else 0
    
    print(f"Passed: {results['passed']} ({pass_rate:.1f}%)")
    print(f"Failed: {results['failed']} ({fail_rate:.1f}%)")
    print()
    
    if results['failed'] == 0:
        print(f"{GREEN}✓ All tests passed!{RESET}")
    else:
        print(f"{RED}✗ Some tests failed. Review the output above.{RESET}")
        
        # Show failed test details
        print(f"\n{YELLOW}Failed Test Details:{RESET}")
        for detail in results['details']:
            if not detail['passed']:
                print(f"  - {detail['test']}: Expected {detail['expected']}, Got {detail['detected']}")
                if detail['patterns']:
                    print(f"    Patterns: {', '.join(detail['patterns'])}")
    
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
    except json.JSONDecodeError as e:
        print(f"Error: Invalid JSON in test file: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"Error running tests: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

