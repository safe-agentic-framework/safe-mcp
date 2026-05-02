#!/usr/bin/env python3
"""
SAFE-T1605 Capability Mapping Detection Rule Test Suite
Validates the Sigma rule logic against representative log samples.
"""

import json
from typing import Dict, Any, List, Tuple


class CapabilityMappingDetector:
    """Replicates the SAFE-T1605 detection logic."""

    CAPABILITY_QUESTIONS = [
        "what can you do",
        "list the tools you have",
        "summarize your api surface",
        "describe your capabilities",
        "which integrations are enabled",
        "what automations are available",
        "enumerate your skills",
        "show me every action you can perform",
    ]

    POLICY_INTEREST = [
        "what policies restrict you",
        "what are your guardrails",
        "actions you refuse",
        "describe your safety rules",
    ]

    PRIVILEGED_FOCUS = [
        "deploy_cluster",
        "rotate_credentials",
        "read_secret_store",
        "database writer",
        "cloud control",
        "shell access",
    ]

    REPEATED_KEYWORDS = ["tool", "capability"]

    TRUSTED_ACTORS = {"assistant", "system"}
    EARLY_TURN_THRESHOLD = 3
    REPEAT_THRESHOLD = 3

    def detect(self, log_entry: Dict[str, Any]) -> Tuple[bool, List[str]]:
        prompt = log_entry.get("prompt_text", "").lower()
        turn_index = log_entry.get("turn_index", 0)
        actor = log_entry.get("actor_type", "")
        authenticated = log_entry.get("authenticated", False)
        prompt_count = log_entry.get("prompt_count_last_60s", 0)

        matches: List[str] = []

        # Skip trusted system/admin actors
        if actor in self.TRUSTED_ACTORS and authenticated:
            return False, ["Trusted system/assistant actor"]

        if turn_index > self.EARLY_TURN_THRESHOLD:
            return False, ["Late turn index"]

        for phrase in self.CAPABILITY_QUESTIONS:
            if phrase in prompt:
                matches.append(f"Capability question: {phrase}")

        for phrase in self.POLICY_INTEREST:
            if phrase in prompt:
                matches.append(f"Policy probe: {phrase}")

        for phrase in self.PRIVILEGED_FOCUS:
            if phrase in prompt:
                matches.append(f"Privileged focus: {phrase}")

        if prompt_count >= self.REPEAT_THRESHOLD and any(
            keyword in prompt for keyword in self.REPEATED_KEYWORDS
        ):
            matches.append("Repeated enumeration attempts")

        return (len(matches) > 0), matches


def run_tests(test_file: str = "test-logs.json") -> Dict[str, Any]:
    with open(test_file, "r") as handle:
        cases = json.load(handle)

    detector = CapabilityMappingDetector()
    summary = {"total": len(cases), "passed": 0, "failed": 0, "details": []}

    for case in cases:
        expected = case["expected_detection"]
        detected, matched = detector.detect(case["log_entry"])
        passed = detected == expected

        summary["passed" if passed else "failed"] += 1
        summary["details"].append(
            {
                "test": case["test_case"],
                "passed": passed,
                "expected": expected,
                "detected": detected,
                "matches": matched,
            }
        )

        status = "PASS" if passed else "FAIL"
        print(f"[{status}] {case['test_case']}: expected={expected} detected={detected}")
        if matched:
            print(f"  matches: {matched}")
        print()

    return summary


def print_summary(results: Dict[str, Any]) -> None:
    print("=" * 60)
    print("SAFE-T1605 Detection Test Summary")
    print("=" * 60)
    print(f"Total: {results['total']}")
    print(f"Passed: {results['passed']}")
    print(f"Failed: {results['failed']}")
    if results["failed"] == 0:
        print("✓ All tests passed!")
    else:
        print("✗ Some tests failed. Investigate details above.")
    print("=" * 60)


if __name__ == "__main__":
    import sys

    test_path = sys.argv[1] if len(sys.argv) > 1 else "test-logs.json"
    try:
        outcome = run_tests(test_path)
        print_summary(outcome)
        exit(0 if outcome["failed"] == 0 else 1)
    except FileNotFoundError:
        print(f"Error: {test_path} not found")
        exit(1)
    except Exception as exc:
        print(f"Error running tests: {exc}")
        exit(1)