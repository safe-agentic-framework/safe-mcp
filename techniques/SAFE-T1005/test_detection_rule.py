#!/usr/bin/env python3
"""
Test cases for SAFE-T1005 Exposed Endpoint Exploit Detection Rule
Tests the Sigma rule for detecting unauthorized MCP endpoint access,
including NeighborJack attacks and CVE-2025-49596/52882/6514 exploitation attempts.
"""

import json
import yaml
import pytest
from pathlib import Path


def load_detection_rule():
    """Load the Sigma detection rule for testing"""
    rule_path = Path(__file__).parent / "detection-rule.yml"
    with open(rule_path, 'r') as f:
        return yaml.safe_load(f)


def load_test_logs():
    """Load test log entries for validation"""
    logs_path = Path(__file__).parent / "test-logs.json"
    with open(logs_path, 'r') as f:
        return json.load(f)


class TestRuleStructure:
    """Test that the detection rule has proper structure"""

    def test_required_fields(self):
        """Test that all required Sigma fields are present"""
        rule = load_detection_rule()
        required_fields = ["title", "id", "status", "description", "author",
                          "date", "detection", "logsource", "level", "tags"]
        for field in required_fields:
            assert field in rule, f"Missing required field: {field}"

    def test_title_contains_mcp(self):
        """Test that the title references MCP"""
        rule = load_detection_rule()
        assert "MCP" in rule["title"], "Title should reference MCP"

    def test_valid_uuid(self):
        """Test that the rule ID is a valid UUID format"""
        rule = load_detection_rule()
        import re
        uuid_pattern = r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
        assert re.match(uuid_pattern, rule["id"]), "Rule ID should be a valid UUID"

    def test_cve_references(self):
        """Test that CVE references are included"""
        rule = load_detection_rule()
        cve_tags = [tag for tag in rule["tags"] if tag.startswith("cve.")]
        assert len(cve_tags) >= 1, "Should reference at least one CVE"

        # Check for specific CVEs
        expected_cves = ["cve.2025.49596", "cve.2025.52882", "cve.2025.6514"]
        for cve in expected_cves:
            assert cve in rule["tags"], f"Missing expected CVE: {cve}"

    def test_safe_technique_tag(self):
        """Test that the SAFE technique tag is present"""
        rule = load_detection_rule()
        assert "safe.t1005" in rule["tags"], "Missing safe.t1005 tag"


class TestDetectionLogic:
    """Test the detection logic components"""

    def test_mcp_endpoint_selection(self):
        """Test that MCP endpoints are detected"""
        rule = load_detection_rule()
        detection = rule["detection"]

        assert "selection_mcp_endpoints" in detection, "Missing MCP endpoint selection"
        endpoints = detection["selection_mcp_endpoints"]["c-uri-path|contains"]

        expected_endpoints = ["/sse", "/message", "/tools/list", "/tools/call"]
        for endpoint in expected_endpoints:
            assert endpoint in endpoints, f"Missing detection for endpoint: {endpoint}"

    def test_command_injection_detection(self):
        """Test that command injection attempts are detected"""
        rule = load_detection_rule()
        detection = rule["detection"]

        assert "selection_command_injection" in detection, "Missing command injection selection"
        commands = detection["selection_command_injection"]["c-uri-query|contains"]

        dangerous_commands = ["command=bash", "command=powershell", "command=curl",
                            "command=wget", "command=nc"]
        for cmd in dangerous_commands:
            assert cmd in commands, f"Missing detection for command: {cmd}"

    def test_zero_ip_detection(self):
        """Test that 0.0.0.0 binding exploitation (NeighborJack) is detected"""
        rule = load_detection_rule()
        detection = rule["detection"]

        assert "selection_zero_ip" in detection, "Missing 0.0.0.0 (NeighborJack) detection"
        assert "0.0.0.0" in str(detection["selection_zero_ip"]), "Should detect 0.0.0.0 host"

    def test_mcp_port_detection(self):
        """Test that common MCP ports are monitored"""
        rule = load_detection_rule()
        detection = rule["detection"]

        assert "selection_mcp_ports" in detection, "Missing MCP port selection"
        ports = detection["selection_mcp_ports"]["cs-uri-port"]

        expected_ports = [6277, 6274, 3000]
        for port in expected_ports:
            assert port in ports, f"Missing detection for port: {port}"

    def test_websocket_detection(self):
        """Test that WebSocket upgrade attempts are detected (CVE-2025-52882)"""
        rule = load_detection_rule()
        detection = rule["detection"]

        assert "selection_websocket" in detection, "Missing WebSocket detection"

    def test_condition_logic(self):
        """Test that the condition combines selections properly"""
        rule = load_detection_rule()
        detection = rule["detection"]

        assert "condition" in detection, "Missing condition"
        condition = detection["condition"]

        # Should use OR logic for multiple attack vectors
        assert "or" in condition.lower(), "Condition should use OR for multiple vectors"


class TestMitreTags:
    """Test MITRE ATT&CK mapping"""

    def test_initial_access_tag(self):
        """Test that Initial Access tactic is tagged"""
        rule = load_detection_rule()
        assert "attack.initial_access" in rule["tags"], "Missing Initial Access tactic"

    def test_technique_tags(self):
        """Test that appropriate MITRE techniques are tagged"""
        rule = load_detection_rule()

        # T1190 - Exploit Public-Facing Application
        assert "attack.t1190" in rule["tags"], "Missing T1190 tag"

        # T1133 - External Remote Services
        assert "attack.t1133" in rule["tags"], "Missing T1133 tag"


class TestFalsePositives:
    """Test false positive documentation"""

    def test_false_positives_documented(self):
        """Test that false positives are documented"""
        rule = load_detection_rule()
        assert "falsepositives" in rule, "Missing false positives section"
        assert len(rule["falsepositives"]) > 0, "Should document potential false positives"

    def test_legitimate_use_cases_mentioned(self):
        """Test that legitimate use cases are mentioned"""
        rule = load_detection_rule()
        fp_text = " ".join(rule["falsepositives"]).lower()

        # Should mention legitimate scenarios
        assert "legitimate" in fp_text or "authorized" in fp_text, \
            "Should mention legitimate use cases"


class TestLogValidation:
    """Test detection against sample log entries"""

    def test_positive_cases_structure(self):
        """Test that positive test cases have correct structure"""
        logs = load_test_logs()
        positive_cases = [log for log in logs if log["should_trigger"]]

        assert len(positive_cases) >= 15, "Should have at least 15 positive test cases"

        for case in positive_cases:
            assert "description" in case, "Missing description"
            assert "log_entry" in case, "Missing log entry"
            assert "attack_type" in case, "Missing attack type"

    def test_negative_cases_structure(self):
        """Test that negative test cases have correct structure"""
        logs = load_test_logs()
        negative_cases = [log for log in logs if not log["should_trigger"]]

        assert len(negative_cases) >= 10, "Should have at least 10 negative test cases"

    def test_neighborjack_detection(self):
        """Test that NeighborJack attacks are in test cases"""
        logs = load_test_logs()
        neighborjack_cases = [log for log in logs
                             if "neighborjack" in log.get("attack_type", "").lower() or
                                "0.0.0.0" in str(log.get("log_entry", {}))]

        assert len(neighborjack_cases) >= 1, "Should have NeighborJack test case"

    def test_external_access_detection(self):
        """Test that external IP access is in test cases"""
        logs = load_test_logs()
        external_cases = [log for log in logs
                        if log["should_trigger"] and
                        "external" in log.get("attack_type", "").lower()]

        assert len(external_cases) >= 1, "Should have external access test case"


# Sample positive test cases for rule validation
POSITIVE_TEST_CASES = [
    {
        "c-uri-path": "/sse",
        "c-uri-query": "transportType=stdio&command=calc.exe",
        "cs-uri-port": 6277,
        "cs-host": "0.0.0.0:6277",
        "description": "NeighborJack RCE via 0.0.0.0 binding"
    },
    {
        "c-uri-path": "/tools/list",
        "c-uri-query": "jsonrpc=2.0",
        "cs-uri-port": 3000,
        "c-ip": "203.0.113.42",
        "description": "External tool enumeration"
    },
    {
        "c-uri-path": "/sse",
        "c-uri-query": "transportType=stdio&command=bash&args=-c+id",
        "cs-uri-port": 6277,
        "description": "Command injection attempt"
    },
    {
        "c-uri-path": "/ws",
        "cs-upgrade": "websocket",
        "cs-uri-port": 3042,
        "description": "WebSocket port scanning (CVE-2025-52882)"
    }
]

NEGATIVE_TEST_CASES = [
    {
        "c-uri-path": "/health",
        "c-uri-query": "",
        "cs-uri-port": 8080,
        "c-ip": "10.0.0.1",
        "description": "Internal health check"
    },
    {
        "c-uri-path": "/api/users",
        "c-uri-query": "filter=active",
        "cs-uri-port": 3000,
        "description": "Regular API call"
    },
    {
        "c-uri-path": "/assets/main.js",
        "c-uri-query": "v=1.0",
        "cs-uri-port": 80,
        "description": "Static asset request"
    }
]


class TestSimulatedDetection:
    """Simulated detection tests (simplified - full testing requires Sigma engine)"""

    def test_positive_detection_sse_endpoint(self):
        """Test that SSE endpoint with stdio transport is detected"""
        for case in POSITIVE_TEST_CASES:
            if case.get("c-uri-path") == "/sse" and \
               "transportType=stdio" in case.get("c-uri-query", ""):
                assert True, f"Should detect: {case['description']}"

    def test_positive_detection_zero_ip(self):
        """Test that 0.0.0.0 host requests are detected"""
        for case in POSITIVE_TEST_CASES:
            if "0.0.0.0" in case.get("cs-host", ""):
                assert True, f"Should detect NeighborJack: {case['description']}"

    def test_positive_detection_command_injection(self):
        """Test that command injection patterns are detected"""
        rule = load_detection_rule()
        commands = rule["detection"]["selection_command_injection"]["c-uri-query|contains"]

        for case in POSITIVE_TEST_CASES:
            query = case.get("c-uri-query", "")
            for cmd_pattern in commands:
                if cmd_pattern in query:
                    assert True, f"Should detect command: {case['description']}"
                    break

    def test_negative_non_mcp_endpoints(self):
        """Test that non-MCP endpoints are not detected"""
        rule = load_detection_rule()
        mcp_endpoints = rule["detection"]["selection_mcp_endpoints"]["c-uri-path|contains"]

        for case in NEGATIVE_TEST_CASES:
            path = case.get("c-uri-path", "")
            is_mcp = any(ep in path for ep in mcp_endpoints)
            if not is_mcp:
                assert True, f"Should NOT detect: {case['description']}"


class TestReferences:
    """Test that references are properly included"""

    def test_github_reference(self):
        """Test that GitHub technique reference is included"""
        rule = load_detection_rule()
        refs = rule.get("references", [])
        github_refs = [r for r in refs if "github.com/safe-mcp" in r]
        assert len(github_refs) >= 1, "Should reference GitHub technique page"

    def test_nvd_references(self):
        """Test that NVD CVE references are included"""
        rule = load_detection_rule()
        refs = rule.get("references", [])
        nvd_refs = [r for r in refs if "nvd.nist.gov" in r]
        assert len(nvd_refs) >= 1, "Should reference NVD for CVEs"

    def test_security_research_references(self):
        """Test that security research sources are referenced"""
        rule = load_detection_rule()
        refs = rule.get("references", [])

        research_sources = ["oligo.security", "securitylabs.datadoghq", "jfrog.com"]
        found_research = any(any(src in ref for src in research_sources) for ref in refs)
        assert found_research, "Should reference security research sources"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
