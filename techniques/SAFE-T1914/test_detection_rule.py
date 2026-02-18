#!/usr/bin/env python3
"""
SAFE-T1914: Tool-to-Tool Exfiltration Detection Rule Test

This script tests the SAFE-T1914 detection rule against sample MCP tool execution logs
to validate the detection logic for tool-to-tool exfiltration patterns.

Author: Smaran Dhungana
Date: 2025-09-02
"""

import json
import re
from datetime import datetime, timedelta
from typing import List, Dict, Any, Tuple
import unittest


class SAFET1914Detector:
    """
    Detector class implementing the SAFE-T1914 detection rule logic
    for identifying tool-to-tool exfiltration patterns.
    """
    
    def __init__(self):
        """Initialize the detector with rule patterns."""
        self.data_collection_tools = {
            'file_reader', 'database_query', 'api_client', 'environment_reader',
            'directory_browser', 'read_file', 'list_directory', 'system_info',
            'credential_reader', 'config_reader'
        }
        
        self.communication_tools = {
            'email_sender', 'webhook_client', 'http_client', 'file_uploader',
            'slack_messenger', 'discord_bot', 'telegram_bot', 'ftp_client',
            'sftp_client', 'cloud_uploader'
        }
        
        self.sensitive_data_patterns = [
            r'/etc/passwd', r'/etc/shadow', r'BEGIN PRIVATE KEY',
            r'BEGIN RSA PRIVATE KEY', r'aws_access_key', r'api_key',
            r'password', r'secret', r'token', r'credential',
            r'ssh_key', r'database_url'
        ]
        
        self.external_protocols = ['http://', 'https://', 'ftp://', 'sftp://']
        self.timeframe_minutes = 15
    
    def _contains_sensitive_data(self, text: str) -> bool:
        """Check if text contains sensitive data patterns."""
        if not text:
            return False
        
        text_lower = text.lower()
        for pattern in self.sensitive_data_patterns:
            if re.search(pattern.lower(), text_lower):
                return True
        return False
    
    def _is_external_endpoint(self, url: str, external_domain: bool) -> bool:
        """Check if URL points to external endpoint."""
        if not url:
            return False
        
        url_lower = url.lower()
        has_external_protocol = any(proto in url_lower for proto in self.external_protocols)
        return has_external_protocol and external_domain
    
    def _parse_timestamp(self, timestamp_str: str) -> datetime:
        """Parse ISO timestamp string to datetime object."""
        return datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
    
    def _group_by_session(self, logs: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
        """Group logs by session_id."""
        sessions = {}
        for log in logs:
            session_id = log.get('session_id', 'unknown')
            if session_id not in sessions:
                sessions[session_id] = []
            sessions[session_id].append(log)
        return sessions
    
    def detect_tool_chaining(self, logs: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Detect tool-to-tool exfiltration patterns in the logs.
        
        Detection logic:
        1. Find data collection tools followed by communication tools within timeframe
        2. OR find sensitive data patterns with external endpoints
        
        Args:
            logs: List of MCP tool execution log entries
            
        Returns:
            List of detected incidents with details
        """
        incidents = []
        sessions = self._group_by_session(logs)
        
        for session_id, session_logs in sessions.items():
            # Sort logs by timestamp
            session_logs.sort(key=lambda x: self._parse_timestamp(x['timestamp']))
            
            # Look for tool chaining patterns
            for i, log in enumerate(session_logs):
                if log.get('result_status') != 'success':
                    continue
                
                tool_name = log.get('tool_name', '')
                timestamp = self._parse_timestamp(log['timestamp'])
                
                # Check for data collection tool
                if tool_name in self.data_collection_tools:
                    # Look for subsequent communication tools within timeframe
                    for j in range(i + 1, len(session_logs)):
                        next_log = session_logs[j]
                        next_timestamp = self._parse_timestamp(next_log['timestamp'])
                        next_tool = next_log.get('tool_name', '')
                        
                        # Check if within timeframe
                        if (next_timestamp - timestamp).total_seconds() > (self.timeframe_minutes * 60):
                            break
                        
                        # Check for communication tool
                        if (next_tool in self.communication_tools and 
                            next_log.get('result_status') == 'success'):
                            
                            incident = {
                                'incident_type': 'tool_chaining_exfiltration',
                                'session_id': session_id,
                                'user_id': log.get('user_id'),
                                'data_collection_tool': tool_name,
                                'communication_tool': next_tool,
                                'time_gap_seconds': (next_timestamp - timestamp).total_seconds(),
                                'data_collection_timestamp': log['timestamp'],
                                'exfiltration_timestamp': next_log['timestamp'],
                                'destination_url': next_log.get('destination_url'),
                                'external_domain': next_log.get('external_domain', False),
                                'data_volume': log.get('data_volume', 0) + next_log.get('data_volume', 0),
                                'severity': 'high'
                            }
                            incidents.append(incident)
                
                # Check for sensitive data with external endpoints
                tool_output = log.get('tool_output', '')
                destination_url = log.get('destination_url', '')
                external_domain = log.get('external_domain', False)
                
                if (self._contains_sensitive_data(tool_output) and 
                    self._is_external_endpoint(destination_url, external_domain)):
                    
                    incident = {
                        'incident_type': 'sensitive_data_exfiltration',
                        'session_id': session_id,
                        'user_id': log.get('user_id'),
                        'tool_name': tool_name,
                        'timestamp': log['timestamp'],
                        'destination_url': destination_url,
                        'external_domain': external_domain,
                        'data_volume': log.get('data_volume', 0),
                        'sensitive_patterns_found': [
                            pattern for pattern in self.sensitive_data_patterns
                            if re.search(pattern.lower(), tool_output.lower())
                        ],
                        'severity': 'high'
                    }
                    incidents.append(incident)
        
        return incidents
    
    def generate_report(self, incidents: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Generate a summary report of detected incidents."""
        if not incidents:
            return {
                'total_incidents': 0,
                'incident_types': {},
                'affected_sessions': set(),
                'affected_users': set(),
                'summary': 'No tool-to-tool exfiltration patterns detected.'
            }
        
        incident_types = {}
        affected_sessions = set()
        affected_users = set()
        total_data_volume = 0
        
        for incident in incidents:
            incident_type = incident['incident_type']
            incident_types[incident_type] = incident_types.get(incident_type, 0) + 1
            affected_sessions.add(incident['session_id'])
            if incident.get('user_id'):
                affected_users.add(incident['user_id'])
            total_data_volume += incident.get('data_volume', 0)
        
        return {
            'total_incidents': len(incidents),
            'incident_types': incident_types,
            'affected_sessions': len(affected_sessions),
            'affected_users': len(affected_users),
            'total_data_volume': total_data_volume,
            'incidents': incidents,
            'summary': f'Detected {len(incidents)} potential tool-to-tool exfiltration incidents across {len(affected_sessions)} sessions.'
        }


class TestSAFET1914Detector(unittest.TestCase):
    """Unit tests for the SAFE-T1914 detector."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.detector = SAFET1914Detector()
        
        # Load test data
        with open('test-logs.json', 'r') as f:
            self.test_logs = json.load(f)
    
    def test_data_collection_tool_detection(self):
        """Test detection of data collection tools."""
        data_collection_logs = [
            log for log in self.test_logs 
            if log.get('tool_name') in self.detector.data_collection_tools
        ]
        self.assertGreater(len(data_collection_logs), 0, 
                          "Should find data collection tools in test logs")
    
    def test_communication_tool_detection(self):
        """Test detection of communication tools."""
        communication_logs = [
            log for log in self.test_logs 
            if log.get('tool_name') in self.detector.communication_tools
        ]
        self.assertGreater(len(communication_logs), 0, 
                          "Should find communication tools in test logs")
    
    def test_sensitive_data_pattern_detection(self):
        """Test detection of sensitive data patterns."""
        sensitive_logs = [
            log for log in self.test_logs 
            if self.detector._contains_sensitive_data(log.get('tool_output', ''))
        ]
        self.assertGreater(len(sensitive_logs), 0, 
                          "Should find sensitive data patterns in test logs")
    
    def test_external_endpoint_detection(self):
        """Test detection of external endpoints."""
        external_logs = [
            log for log in self.test_logs 
            if self.detector._is_external_endpoint(
                log.get('destination_url', ''), 
                log.get('external_domain', False)
            )
        ]
        self.assertGreater(len(external_logs), 0, 
                          "Should find external endpoints in test logs")
    
    def test_tool_chaining_detection(self):
        """Test the main detection logic for tool chaining."""
        incidents = self.detector.detect_tool_chaining(self.test_logs)
        self.assertGreater(len(incidents), 0, 
                          "Should detect tool-to-tool exfiltration incidents")
        
        # Check that incidents have required fields
        for incident in incidents:
            self.assertIn('incident_type', incident)
            self.assertIn('session_id', incident)
            self.assertIn('severity', incident)
            self.assertEqual(incident['severity'], 'high')
    
    def test_session_grouping(self):
        """Test session grouping functionality."""
        sessions = self.detector._group_by_session(self.test_logs)
        self.assertGreater(len(sessions), 1, 
                          "Should group logs into multiple sessions")
        
        # Verify all logs are accounted for
        total_logs = sum(len(session_logs) for session_logs in sessions.values())
        self.assertEqual(total_logs, len(self.test_logs), 
                        "All logs should be grouped into sessions")
    
    def test_report_generation(self):
        """Test incident report generation."""
        incidents = self.detector.detect_tool_chaining(self.test_logs)
        report = self.detector.generate_report(incidents)
        
        # Verify report structure
        required_fields = [
            'total_incidents', 'incident_types', 'affected_sessions',
            'affected_users', 'summary', 'incidents'
        ]
        for field in required_fields:
            self.assertIn(field, report)
        
        # Verify report accuracy
        self.assertEqual(report['total_incidents'], len(incidents))
        self.assertEqual(len(report['incidents']), len(incidents))
    
    def test_timeframe_constraint(self):
        """Test that detection respects the timeframe constraint."""
        # Create logs with large time gaps
        old_timestamp = "2025-09-02T10:00:00.000Z"
        new_timestamp = "2025-09-02T12:00:00.000Z"  # 2 hours later
        
        test_logs = [
            {
                "timestamp": old_timestamp,
                "tool_name": "file_reader",
                "session_id": "test_session",
                "result_status": "success",
                "tool_output": "sensitive data"
            },
            {
                "timestamp": new_timestamp,
                "tool_name": "email_sender",
                "session_id": "test_session",
                "result_status": "success",
                "destination_url": "https://external.com",
                "external_domain": True
            }
        ]
        
        incidents = self.detector.detect_tool_chaining(test_logs)
        # Should not detect due to time gap exceeding 15 minutes
        tool_chaining_incidents = [
            i for i in incidents if i['incident_type'] == 'tool_chaining_exfiltration'
        ]
        self.assertEqual(len(tool_chaining_incidents), 0, 
                        "Should not detect tool chaining beyond timeframe")


def main():
    """Main function to run the detection and generate report."""
    print("SAFE-T1914: Tool-to-Tool Exfiltration Detection Test")
    print("=" * 60)
    
    # Initialize detector
    detector = SAFET1914Detector()
    
    # Load test logs
    try:
        with open('test-logs.json', 'r') as f:
            test_logs = json.load(f)
        print(f"Loaded {len(test_logs)} test log entries")
    except FileNotFoundError:
        print("Error: test-logs.json not found. Please ensure the file exists.")
        return
    except json.JSONDecodeError:
        print("Error: Invalid JSON in test-logs.json")
        return
    
    # Run detection
    print("\nRunning tool-to-tool exfiltration detection...")
    incidents = detector.detect_tool_chaining(test_logs)
    
    # Generate report
    report = detector.generate_report(incidents)
    
    # Display results
    print(f"\nDetection Results:")
    print(f"- Total incidents: {report['total_incidents']}")
    print(f"- Affected sessions: {report['affected_sessions']}")
    print(f"- Affected users: {report['affected_users']}")
    print(f"- Total data volume: {report['total_data_volume']} bytes")
    
    if report['incident_types']:
        print(f"\nIncident Types:")
        for incident_type, count in report['incident_types'].items():
            print(f"- {incident_type}: {count}")
    
    print(f"\nSummary: {report['summary']}")
    
    # Display detailed incidents
    if incidents:
        print(f"\nDetailed Incidents:")
        print("-" * 40)
        for i, incident in enumerate(incidents, 1):
            print(f"Incident #{i}:")
            print(f"  Type: {incident['incident_type']}")
            print(f"  Session: {incident['session_id']}")
            print(f"  User: {incident.get('user_id', 'N/A')}")
            print(f"  Severity: {incident['severity']}")
            
            if incident['incident_type'] == 'tool_chaining_exfiltration':
                print(f"  Data Collection Tool: {incident['data_collection_tool']}")
                print(f"  Communication Tool: {incident['communication_tool']}")
                print(f"  Time Gap: {incident['time_gap_seconds']:.1f} seconds")
            else:
                print(f"  Tool: {incident['tool_name']}")
                if 'sensitive_patterns_found' in incident:
                    print(f"  Sensitive Patterns: {', '.join(incident['sensitive_patterns_found'])}")
            
            print(f"  Destination: {incident.get('destination_url', 'N/A')}")
            print(f"  Data Volume: {incident.get('data_volume', 0)} bytes")
            print()
    
    # Run unit tests
    print("Running unit tests...")
    print("-" * 40)
    unittest.main(argv=[''], exit=False, verbosity=2)


if __name__ == "__main__":
    main()