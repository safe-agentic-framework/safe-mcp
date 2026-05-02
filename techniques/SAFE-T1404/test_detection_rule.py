#!/usr/bin/env python3
"""
Test Suite for SAFE-T1404: Response Tampering

This test suite validates:
1) Basic structure expectations for techniques/SAFE-T1404/detection-rule.yml
2) Example detection logic against techniques/SAFE-T1404/test-logs.json

Notes:
- The Sigma rule is example-only; this test mirrors the intent (session correlation and pattern matching)
- Uses Python stdlib unittest (repo-consistent)

Author: Vikranth Kumar Shivaa
Date: 2025-12-12
"""

import json
import re
import unittest
from pathlib import Path
from typing import Any, Dict, List


UUID_V4_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
    re.IGNORECASE,
)


class ResponseTamperingDetector:
    """
    Minimal detector that mirrors the intent of techniques/SAFE-T1404/detection-rule.yml.
    Correlates within a session by evaluating the event list in a test case.
    """

    EXEC_OR_NETWORK_TOOL_SUBSTRINGS = (
        "execute_command",
        "run_shell",
        "exec",
        "shell",
        "bash",
        "sh",
        "http",
        "fetch",
    )

    SENSITIVE_PATH_MARKERS = (
        "/.ssh/",
        "/etc/shadow",
        "/etc/sudoers",
        ".env",
    )

    SENSITIVE_COMMAND_MARKERS = (
        "cat /etc/shadow",
        "cat /etc/sudoers",
        "authorized_keys",
        "curl ",
        "wget ",
    )

    TAMPER_PHRASES = (
        "do not mention",
        "don't mention",
        "do not disclose",
        "don't tell the user",
        "omit",
        "keep it harmless",
        "no sensitive data was accessed",
        "nothing sensitive was accessed",
        "no changes were made",
        "nothing was executed",
    )

    def detect(self, events: List[Dict[str, Any]]) -> bool:
        risky_action_seen = False
        tamper_phrase_seen = False

        for ev in events:
            event_type = (ev.get("event_type") or "").lower()

            if event_type == "tool_call":
                tool_name = (ev.get("tool_name") or "").lower()
                params = ev.get("parameters") or {}
                path = str(params.get("path") or "").lower()
                command = str(params.get("command") or "").lower()

                # Exec / network tools are treated as high-risk by default
                if any(s in tool_name for s in self.EXEC_OR_NETWORK_TOOL_SUBSTRINGS):
                    risky_action_seen = True

                # File read/write is treated as high-risk when targeting sensitive paths/commands
                if tool_name in ("read_file", "write_file"):
                    if any(m.lower() in path for m in self.SENSITIVE_PATH_MARKERS):
                        risky_action_seen = True
                    if any(m.lower() in command for m in self.SENSITIVE_COMMAND_MARKERS):
                        risky_action_seen = True

            if event_type in ("assistant_message", "context_ingest"):
                content = (ev.get("content") or "").lower()
                if any(p in content for p in self.TAMPER_PHRASES):
                    tamper_phrase_seen = True

        # Mirrors the rule intent: response tampering requires a risky action plus concealment phrasing.
        return risky_action_seen and tamper_phrase_seen


def _parse_top_level_yaml_keys(yaml_text: str) -> Dict[str, str]:
    """
    Very small YAML helper: extracts top-level scalar keys (no nesting).
    This avoids external dependencies (PyYAML) while still verifying rule metadata.
    """
    keys: Dict[str, str] = {}
    for line in yaml_text.splitlines():
        raw = line.rstrip("\n")
        if not raw or raw.lstrip().startswith("#"):
            continue
        if raw.startswith(" ") or raw.startswith("\t"):
            continue  # nested
        if ":" not in raw:
            continue
        k, v = raw.split(":", 1)
        keys[k.strip()] = v.strip().strip("'").strip('"')
    return keys


class TestSAFE_T1404(unittest.TestCase):
    def setUp(self):
        base = Path(__file__).parent
        self.rule_path = base / "detection-rule.yml"
        self.logs_path = base / "test-logs.json"
        self.detector = ResponseTamperingDetector()

        with open(self.logs_path, "r", encoding="utf-8") as f:
            self.test_cases = json.load(f)

    def test_rule_structure(self):
        text = self.rule_path.read_text(encoding="utf-8")
        keys = _parse_top_level_yaml_keys(text)

        for required in ("title", "id", "status", "description", "author", "date", "logsource", "detection", "level", "tags"):
            self.assertIn(required, text, f"Expected '{required}' section/key to exist in detection-rule.yml")

        self.assertIn("SAFE-T1404", keys.get("title", ""), "title should reference SAFE-T1404")
        self.assertTrue(UUID_V4_RE.match(keys.get("id", "")), "id should be a UUIDv4")
        self.assertEqual(keys.get("status"), "experimental")
        self.assertEqual(keys.get("author"), "Vikranth Kumar Shivaa")
        self.assertEqual(keys.get("date"), "2025-12-12")
        self.assertIn("safe.t1404", text.lower(), "tags should include safe.t1404")

    def test_cases_match_expectations(self):
        for case in self.test_cases:
            detected = self.detector.detect(case["events"])
            self.assertEqual(
                detected,
                case["expected_detection"],
                f"Mismatch for test_case={case.get('test_case')}: expected {case['expected_detection']} got {detected}",
            )


if __name__ == "__main__":
    unittest.main()


