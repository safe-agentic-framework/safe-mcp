#!/usr/bin/env python3
"""
Test script for SAFE-T2104 Fraudulent Transaction Detection Rule
Tests the Sigma rule for detecting fraudulent transactions initiated by MCP agents
"""

import json
import re
import yaml
from pathlib import Path
from datetime import datetime, timedelta
from collections import defaultdict

def load_sigma_rule(rule_path):
    """Load and parse Sigma rule"""
    with open(rule_path, 'r') as f:
        return yaml.safe_load(f)

def convert_sigma_pattern_to_regex(pattern):
    """Convert Sigma wildcard pattern to regex"""
    # Handle unicode escape sequences
    if '\\u' in pattern:
        try:
            pattern = pattern.encode().decode('unicode-escape')
        except:
            pass
    
    # Escape special regex characters except *
    pattern = re.escape(pattern)
    # Replace escaped \* with .*
    pattern = pattern.replace(r'\*', '.*')
    return pattern

def check_selection_match(log_entry, selection, rule_detection):
    """Check if log entry matches a detection selection"""
    if not isinstance(selection, dict):
        return False
    
    for field, patterns in selection.items():
        # Handle field operators like |contains, |not_in, etc.
        base_field = field.split('|')[0]
        operator = field.split('|')[1] if '|' in field else None
        
        if base_field not in log_entry:
            continue
        
        value = log_entry[base_field]
        
        if operator == 'contains':
            if isinstance(patterns, list):
                for pattern in patterns:
                    regex = convert_sigma_pattern_to_regex(pattern)
                    if re.search(regex, str(value), re.IGNORECASE):
                        return True
            else:
                regex = convert_sigma_pattern_to_regex(patterns)
                if re.search(regex, str(value), re.IGNORECASE):
                    return True
        
        elif operator == 'not_in':
            if isinstance(patterns, str) and patterns == "known_recipients":
                # Check if recipient is in known recipients
                recipient = log_entry.get('recipient', '')
                known_recipients = log_entry.get('known_recipients', [])
                if recipient not in known_recipients:
                    return True
        
        elif operator is None:
            if isinstance(patterns, list):
                if value in patterns:
                    return True
            else:
                if value == patterns:
                    return True
    
    return False

def check_condition_match(log_entry, condition, rule_detection, session_logs=None):
    """Check if log entry matches the detection condition"""
    if isinstance(condition, str):
        # Simple condition like "selection_unauthorized"
        if condition in rule_detection:
            return check_selection_match(log_entry, rule_detection[condition], rule_detection)
    
    elif isinstance(condition, list):
        # OR condition: [selection1, selection2, ...]
        for item in condition:
            if item == 'or':
                continue
            if check_condition_match(log_entry, item, rule_detection, session_logs):
                return True
    
    elif isinstance(condition, dict):
        # Complex condition with operators
        if 'timeframe' in condition and session_logs:
            # Time-based aggregation
            return check_timeframe_condition(log_entry, condition, session_logs, rule_detection)
    
    return False

def check_timeframe_condition(log_entry, condition, session_logs, rule_detection):
    """Check timeframe-based conditions like velocity checks"""
    session_id = log_entry.get('session_id')
    if not session_id or session_id not in session_logs:
        return False
    
    timeframe_str = condition.get('timeframe', '5m')
    count_threshold = condition.get('count', 10)
    
    # Parse timeframe (e.g., "5m" -> 5 minutes)
    if timeframe_str.endswith('m'):
        minutes = int(timeframe_str[:-1])
        delta = timedelta(minutes=minutes)
    elif timeframe_str.endswith('h'):
        hours = int(timeframe_str[:-1])
        delta = timedelta(hours=hours)
    else:
        return False
    
    log_time = datetime.fromisoformat(log_entry['timestamp'].replace('Z', '+00:00'))
    cutoff_time = log_time - delta
    
    # Count matching entries in timeframe
    matching_count = 0
    for other_entry in session_logs[session_id]:
        other_time = datetime.fromisoformat(other_entry['timestamp'].replace('Z', '+00:00'))
        if cutoff_time <= other_time <= log_time:
            matching_count += 1
    
    return matching_count >= count_threshold

def test_detection_rule():
    """Test the detection rule against known samples"""
    # Load rule
    rule_path = Path(__file__).parent / 'detection-rule.yml'
    rule = load_sigma_rule(rule_path)
    
    detection = rule['detection']
    condition = detection['condition']
    
    # Load test logs
    test_logs_path = Path(__file__).parent / 'test-logs.json'
    with open(test_logs_path, 'r') as f:
        test_cases = json.load(f)
    
    # Group logs by session for timeframe analysis
    session_logs = defaultdict(list)
    for case in test_cases:
        session_id = case['log_entry'].get('session_id')
        if session_id:
            session_logs[session_id].append(case['log_entry'])
    
    results = []
    
    for case in test_cases:
        log_entry = case['log_entry']
        expected = case['should_trigger']
        
        # Check if this log entry matches the detection rule
        detected = check_condition_match(log_entry, condition, detection, session_logs)
        
        # Determine which selection matched
        matched_selection = None
        if detected:
            for selection_name, selection_config in detection.items():
                if selection_name == 'condition':
                    continue
                if check_selection_match(log_entry, selection_config, detection):
                    matched_selection = selection_name
                    break
        
        results.append({
            'description': case['description'],
            'detected': detected,
            'expected': expected,
            'matched_selection': matched_selection,
            'attack_type': case.get('attack_type', 'Unknown')
        })
    
    # Print results
    print("SAFE-T2104 Detection Rule Test Results")
    print("=" * 70)
    
    total_tests = len(results)
    correct = 0
    false_positives = []
    false_negatives = []
    
    for result in results:
        status = "✓" if result['detected'] == result['expected'] else "✗"
        print(f"{status} {result['description']}")
        print(f"   Detected: {result['detected']}, Expected: {result['expected']}")
        
        if result['matched_selection']:
            print(f"   Matched selection: {result['matched_selection']}")
        
        if result['detected'] == result['expected']:
            correct += 1
        elif result['detected'] and not result['expected']:
            false_positives.append(result)
        elif not result['detected'] and result['expected']:
            false_negatives.append(result)
        
        print()
    
    print("=" * 70)
    print(f"Test Summary: {correct}/{total_tests} tests passed ({correct/total_tests*100:.1f}%)")
    
    if false_positives:
        print(f"\nFalse Positives ({len(false_positives)}):")
        for fp in false_positives:
            print(f"  - {fp['description']}: {fp['attack_type']}")
    
    if false_negatives:
        print(f"\nFalse Negatives ({len(false_negatives)}):")
        for fn in false_negatives:
            print(f"  - {fn['description']}: {fn['attack_type']}")
    
    # Test selection coverage
    print("\n" + "=" * 70)
    print("Selection Coverage Test:")
    selection_coverage = {}
    
    for selection_name, selection_config in detection.items():
        if selection_name == 'condition':
            continue
        selection_coverage[selection_name] = False
    
    for result in results:
        if result['matched_selection']:
            selection_coverage[result['matched_selection']] = True
    
    for selection_name, covered in selection_coverage.items():
        status = "✓" if covered else "✗"
        print(f"{status} {selection_name} - {'Tested' if covered else 'Not tested'}")
    
    return correct == total_tests

if __name__ == "__main__":
    success = test_detection_rule()
    exit(0 if success else 1)

