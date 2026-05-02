#!/usr/bin/env python3
"""
Test Suite for SAFE-T1203: Backdoored Server Binary (Install-Time Persistence)

This test suite validates example detection logic against curated test scenarios.
It is intentionally stdlib-only (no pytest, no PyYAML) to match repository patterns.

Author: Vikranth Kumar Shivaa
Date: 2025-12-11
"""

import json
import unittest
from datetime import datetime
from pathlib import Path


def _contains_any(haystack: str, needles) -> bool:
    if not haystack:
        return False
    h = haystack.lower()
    return any((n.lower() in h) for n in needles)


class TestSafeT1203Detection(unittest.TestCase):
    """Test cases for SAFE-T1203 detection logic."""

    # Keep these lists aligned with techniques/SAFE-T1203/detection-rule.yml
    SUSPICIOUS_CMD_TOKENS = [
        "crontab",
        "/etc/cron",
        "/etc/crontab",
        "systemctl enable",
        "systemctl daemon-reload",
        "launchctl",
        "schtasks",
        "reg add run",
        "authorized_keys",
        "curl ",
        "wget ",
        "nc ",
        "ncat ",
        "bash -c",
        "/dev/tcp/",
        "powershell -enc",
    ]

    PERSISTENCE_PATH_TOKENS = [
        "/etc/cron",
        "/var/spool/cron",
        "/etc/systemd/system/",
        "/lib/systemd/system/",
        "/.config/autostart/",
        "/.ssh/authorized_keys",
        "\\microsoft\\windows\\start menu\\programs\\startup\\",
    ]

    SUSPICIOUS_NET_DEST_TOKENS = [
        "pastebin",
        "discord",
        "ngrok",
        ".onion",
    ]

    def setUp(self):
        test_data_path = Path(__file__).parent / "test-logs.json"
        with open(test_data_path, "r", encoding="utf-8") as f:
            self.test_data = json.load(f)

        self.malicious_scenarios = self.test_data["test_scenarios"]
        self.benign_scenarios = self.test_data["benign_scenarios"]

    def evaluate_detection_rule(self, logs):
        """
        Simulate detection-rule.yml intent using simple substring checks.

        Returns:
            bool: True if the rule should trigger, False otherwise.
        """
        for log in logs:
            cmd = (log.get("command_line") or "")
            file_path = (log.get("file_path") or "")
            dest = (log.get("network_destination") or "")

            if _contains_any(cmd, self.SUSPICIOUS_CMD_TOKENS):
                return True

            if _contains_any(file_path, self.PERSISTENCE_PATH_TOKENS):
                return True

            if _contains_any(dest, self.SUSPICIOUS_NET_DEST_TOKENS):
                return True

        return False

    def test_detection_rule_coverage(self):
        """All malicious scenarios should be detected."""
        for scenario in self.malicious_scenarios:
            result = self.evaluate_detection_rule(scenario["logs"])
            self.assertTrue(
                scenario["expected_detection"],
                f"Malicious scenario {scenario['scenario_id']} should expect detection",
            )
            self.assertEqual(
                result,
                scenario["expected_detection"],
                f"Detection mismatch for scenario {scenario['scenario_id']}",
            )

    def test_false_positive_rate(self):
        """Benign scenarios should not be detected."""
        for scenario in self.benign_scenarios:
            result = self.evaluate_detection_rule(scenario["logs"])
            self.assertFalse(
                scenario["expected_detection"],
                f"Benign scenario {scenario['scenario_id']} should not expect detection",
            )
            self.assertEqual(
                result,
                scenario["expected_detection"],
                f"False positive for scenario {scenario['scenario_id']}",
            )

    def test_test_data_integrity(self):
        """Validate metadata and basic structure of test data."""
        metadata = self.test_data["metadata"]
        self.assertEqual(metadata["author"], "Vikranth Kumar Shivaa")
        self.assertEqual(metadata["version"], "1.0")
        self.assertEqual(metadata["created_date"], "2025-12-11")

        self.assertEqual(len(self.malicious_scenarios), metadata["malicious_scenarios"])
        self.assertEqual(len(self.benign_scenarios), metadata["benign_scenarios"])
        self.assertEqual(
            len(self.malicious_scenarios) + len(self.benign_scenarios),
            metadata["total_scenarios"],
        )

    def test_log_format_consistency(self):
        """All log entries should have a timestamp and event_type with valid ISO timestamps."""
        required_fields = ["timestamp", "event_type"]
        all_scenarios = self.malicious_scenarios + self.benign_scenarios

        for scenario in all_scenarios:
            for log in scenario["logs"]:
                for field in required_fields:
                    self.assertIn(
                        field,
                        log,
                        f"Log entry missing '{field}' in scenario {scenario['scenario_id']}",
                    )

                # Validate timestamp format
                ts = log["timestamp"]
                try:
                    datetime.fromisoformat(ts.replace("Z", "+00:00"))
                except ValueError as e:
                    self.fail(
                        f"Invalid timestamp format in scenario {scenario['scenario_id']}: {ts} ({e})"
                    )


if __name__ == "__main__":
    unittest.main(verbosity=2)


