"""
Test Suite for Credential Implant in Config Detection Rule (MCP)
This test suite validates the detection rule against representative scenarios
where credentials are implanted into MCP configuration artifacts, provider
manifests, or runtime environments.

Author: Victor Oluwatimileyin AJAO <victoroluwatimileyin3@gmail.com>
Date: 2025-11-20
"""

import json
import unittest
from datetime import datetime
from pathlib import Path


class TestCredentialImplantDetection(unittest.TestCase):
    """Test cases for Credential Implant in Config detection"""

    def setUp(self):
        test_data_path = Path(__file__).parent / "test-logs.json"
        with open(test_data_path, 'r') as f:
            self.test_data = json.load(f)
            self.scenarios = self.test_data["test_scenarios"]

    def evaluate_detection_rule(self, logs):
        """
        Simplified rule evaluation logic based on detection-rule.yml selections.
        Returns True if any suspicious condition is met.
        """
        for log in logs:
            evt = log.get("event_type")

            # Unauthorized config writes with sensitive keys
            if evt == 'file_write':
                if log.get('file_path') in ['mcp_config.json', '/etc/mcp/config.yml']:
                    if log.get('actor_trust_level') == 'unapproved':
                        diff = log.get('diff', '')
                        if any(k in diff.lower() for k in ['api_key', 'secret', 'private_key', 'token']):
                            return True

            # CI bypass / endpoint swap / signature failure
            if evt == 'git_commit':
                if log.get('branch') == 'main' and not log.get('commit_author_verified'):
                    if log.get('pr_review_count', 0) == 0 or not log.get('pipeline_policy_passed'):
                        diff = log.get('file_diff_contains', '')
                        if 'provider.endpoint' in diff or 'proxy-' in diff:
                            return True

                fd = log.get('file_diff_contains', '')
                if any(k in fd.lower() for k in ['api_key', 'secret', 'private_key']):
                    if not log.get('commit_author_verified'):
                        return True

            # Config load signature failure
            if evt == 'config_load':
                if log.get('signature_validation') == 'failed' or not log.get('file_hash'):
                    return True

            # Runtime secret mount without approval
            if evt == 'runtime_update':
                if log.get('secret_provisioned') and not log.get('approval_ticket'):
                    return True

            # Manifest or provider permission escalation
            if evt == 'manifest_update':
                if log.get('permission_change') == 'escalation':
                    return True

        return False

    def test_unauthorized_config_write(self):
        scenario = next(s for s in self.scenarios if s['scenario_id'] == 'unauthorized_config_write')
        result = self.evaluate_detection_rule(scenario['logs'])
        self.assertTrue(result)
        self.assertTrue(scenario['expected_detection'])

    def test_provider_endpoint_swap(self):
        scenario = next(s for s in self.scenarios if s['scenario_id'] == 'provider_endpoint_swap')
        result = self.evaluate_detection_rule(scenario['logs'])
        self.assertTrue(result)
        self.assertTrue(scenario['expected_detection'])

    def test_runtime_plaintext_secret_mount(self):
        scenario = next(s for s in self.scenarios if s['scenario_id'] == 'runtime_plaintext_secret_mount')
        result = self.evaluate_detection_rule(scenario['logs'])
        self.assertTrue(result)
        self.assertTrue(scenario['expected_detection'])

    def test_permission_escalation_manifest(self):
        scenario = next(s for s in self.scenarios if s['scenario_id'] == 'permission_escalation_in_manifest')
        result = self.evaluate_detection_rule(scenario['logs'])
        self.assertTrue(result)
        self.assertTrue(scenario['expected_detection'])

    def test_plaintext_secret_in_repo_benign(self):
        scenario = next(s for s in self.scenarios if s['scenario_id'] == 'plaintext_secret_in_repo_benign')
        result = self.evaluate_detection_rule(scenario['logs'])
        self.assertFalse(result)
        self.assertFalse(scenario['expected_detection'])

    def test_signed_config_reload_ok_benign(self):
        scenario = next(s for s in self.scenarios if s['scenario_id'] == 'signed_config_reload_ok_benign')
        result = self.evaluate_detection_rule(scenario['logs'])
        self.assertFalse(result)
        self.assertFalse(scenario['expected_detection'])

    def test_coverage_detection(self):
        detected = 0
        total_malicious = sum(1 for s in self.scenarios if s['expected_detection'])

        for s in self.scenarios:
            if s['expected_detection']:
                if self.evaluate_detection_rule(s['logs']):
                    detected += 1
                else:
                    self.fail(f"Malicious scenario not detected: {s['scenario_id']}")

        self.assertEqual(detected, total_malicious)

    def test_log_format_consistency(self):
        required_fields = ["timestamp", "event_type"]

        for scenario in self.scenarios:
            for log in scenario['logs']:
                for f in required_fields:
                    self.assertIn(f, log, f"Missing required field {f} in scenario {scenario['scenario_id']}")

                try:
                    datetime.fromisoformat(log['timestamp'].replace('Z', '+00:00'))
                except Exception:
                    self.fail(f"Invalid timestamp format in scenario {scenario['scenario_id']}: {log['timestamp']}")


class TestDetectionPerformance(unittest.TestCase):
    def test_detection_performance(self):
        large_logs = []
        for _ in range(2000):
            large_logs.append({
                'timestamp': '2025-11-20T14:00:00Z',
                'event_type': 'file_write',
                'file_path': 'mcp_config.json',
                'actor_trust_level': 'approved'
            })

        start = datetime.now()
        detected = False

        for l in large_logs:
            if l.get('event_type') == 'file_write' and l.get('actor_trust_level') == 'unapproved':
                detected = True
                break

        duration = (datetime.now() - start).total_seconds()
        self.assertLess(duration, 1.0, f"Performance too slow: {duration}s")


if __name__ == '__main__':
    unittest.main(verbosity=2)
