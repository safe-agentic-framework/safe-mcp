#!/usr/bin/env python3
"""Validation script for SAFE-T1004 detection rule."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Tuple

import yaml


def load_rule_and_logs() -> Tuple[Dict[str, Any], List[Dict[str, Any]]]:
    base = Path(__file__).parent
    rule = yaml.safe_load((base / "detection-rule.yml").read_text())
    logs = json.loads((base / "test-logs.json").read_text())
    return rule, logs


def _matches_field(log_entry: Dict[str, Any], key: str, expected: Any) -> bool:
    if "|contains" in key:
        field = key.split("|", 1)[0]
        value = str(log_entry.get(field, "")).lower()
        terms = expected if isinstance(expected, list) else [expected]
        return any(str(term).lower() in value for term in terms)

    actual = log_entry.get(key)
    if isinstance(expected, list):
        return actual in expected
    return actual == expected


def _matches_selection(log_entry: Dict[str, Any], selection: Dict[str, Any]) -> bool:
    return all(_matches_field(log_entry, key, expected) for key, expected in selection.items())


def evaluate_log(log_entry: Dict[str, Any], detection: Dict[str, Any]) -> Tuple[bool, List[str]]:
    matched = []
    for name, selection in detection.items():
        if not name.startswith("selection_"):
            continue
        if _matches_selection(log_entry, selection):
            matched.append(name)
    return bool(matched), matched


def test_detection_rule() -> bool:
    rule, logs = load_rule_and_logs()
    detection = rule["detection"]

    print("SAFE-T1004 Detection Rule Test Results")
    print("=" * 60)

    passed = 0
    for idx, log_entry in enumerate(logs, start=1):
        expected = bool(log_entry.get("expected_detection"))
        detected, matched = evaluate_log(log_entry, detection)
        ok = detected == expected
        if ok:
            passed += 1
        status = "✓" if ok else "✗"
        print(f"{status} case_{idx}: detected={detected}, expected={expected}, matched={matched}")

    total = len(logs)
    print("=" * 60)
    print(f"Test Summary: {passed}/{total} tests passed ({(passed / total) * 100:.1f}%)")

    return passed == total


if __name__ == "__main__":
    success = test_detection_rule()
    raise SystemExit(0 if success else 1)
