#!/usr/bin/env python3
"""
Test script for SAFE-T1112 Sampling Request Abuse detection rule validation.

This script validates that the example detection logic correctly identifies
suspicious MCP sampling activity from the provided test log data.
"""

from __future__ import annotations

import json
import re
import sys
import uuid
from pathlib import Path
from typing import Any, Dict, List

try:
    import yaml  # type: ignore
except Exception:  # pragma: no cover
    yaml = None


SENSITIVE_TOOLS = {
    "read_file",
    "fs.read",
    "http_request",
    "web.fetch",
    "run_shell",
    "execute_command",
}

SENSITIVE_FOLLOW_ON_MARKERS = (
    "read_file",
    "run_shell",
    "http_request",
    "credential_lookup",
)


def load_rule(rule_path: Path) -> Dict[str, Any]:
    text = rule_path.read_text(encoding="utf-8")

    if yaml is not None:
        data = yaml.safe_load(text)
        if not isinstance(data, dict):
            raise ValueError("Rule file did not parse into a mapping")
        return data

    # Minimal fallback validation when PyYAML is unavailable.
    required_markers = [
        "title:",
        "id:",
        "status:",
        "description:",
        "author:",
        "date:",
        "logsource:",
        "detection:",
        "method: sampling/createMessage",
        "safe.t1112",
    ]
    for marker in required_markers:
        if marker not in text:
            raise ValueError(f"Missing required marker in detection-rule.yml: {marker}")

    # Return metadata parsed with regex for basic validation.
    title_match = re.search(r"^title:\s*(.+)$", text, re.MULTILINE)
    id_match = re.search(r"^id:\s*([0-9a-fA-F-]+)$", text, re.MULTILINE)
    date_match = re.search(r"^date:\s*(\d{4}-\d{2}-\d{2})$", text, re.MULTILINE)

    return {
        "title": title_match.group(1).strip() if title_match else "",
        "id": id_match.group(1).strip() if id_match else "",
        "date": date_match.group(1).strip() if date_match else "",
        "detection": {
            "selection_sampling": {
                "event_type": "mcp.request",
                "method": "sampling/createMessage",
            }
        },
    }


def validate_rule_metadata(rule: Dict[str, Any]) -> None:
    title = rule.get("title")
    if not title or "Sampling" not in str(title):
        raise ValueError("Detection rule title is missing or does not mention Sampling")

    rule_id = str(rule.get("id", "")).strip()
    try:
        uuid.UUID(rule_id)
    except Exception as exc:
        raise ValueError(f"Detection rule id is not a valid UUID: {rule_id}") from exc

    date = str(rule.get("date", "")).strip()
    if not re.fullmatch(r"\d{4}-\d{2}-\d{2}", date):
        raise ValueError(f"Detection rule date is not YYYY-MM-DD: {date}")


def detect_sampling_abuse(event: Dict[str, Any]) -> bool:
    if event.get("event_type") != "mcp.request":
        return False
    if event.get("method") != "sampling/createMessage":
        return False

    burst_count = int(event.get("burst_count", 0))
    max_tokens = int(event.get("max_tokens", 0))
    requested_tools = {str(t) for t in event.get("requested_tools", [])}
    approval_state = str(event.get("approval_state", ""))
    follow_on_action = str(event.get("follow_on_action", ""))

    suspicious_volume = burst_count >= 3
    suspicious_tokens = max_tokens >= 4000
    suspicious_tooling = any(tool in SENSITIVE_TOOLS for tool in requested_tools)
    weak_approval = approval_state in {"missing", "auto_approved"}
    suspicious_follow_on = any(marker in follow_on_action for marker in SENSITIVE_FOLLOW_ON_MARKERS)

    return any(
        [
            suspicious_volume,
            suspicious_tokens,
            suspicious_tooling,
            weak_approval,
            suspicious_follow_on,
        ]
    )


def main() -> int:
    here = Path(__file__).resolve().parent
    rule_path = here / "detection-rule.yml"
    logs_path = here / "test-logs.json"

    rule = load_rule(rule_path)
    validate_rule_metadata(rule)

    cases: List[Dict[str, Any]] = json.loads(logs_path.read_text(encoding="utf-8"))
    failures: List[str] = []

    for case in cases:
        actual = detect_sampling_abuse(case)
        expected = bool(case.get("expected_detection"))
        if actual != expected:
            failures.append(
                f"{case.get('case_id')}: expected {expected}, got {actual}"
            )

    if failures:
        print("SAFE-T1112 detection validation failed:")
        for failure in failures:
            print(f"  - {failure}")
        return 1

    print(f"SAFE-T1112 detection validation passed for {len(cases)} test cases.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
