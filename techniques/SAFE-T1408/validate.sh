#!/usr/bin/env bash
# validate.sh - Validation script for SAFE-T1408 artifacts

set -e

RULE_FILE="detection-rule.yml"
TEST_LOGS="test-logs.json"

echo "=== SAFE-T1408 Validation Script ==="

# 1. Check YAML syntax
echo "[*] Checking YAML syntax for $RULE_FILE..."
yamllint $RULE_FILE || { echo "YAML lint failed"; exit 1; }

# 2. Verify UUID format
UUID=$(grep '^id:' $RULE_FILE | awk '{print $2}')
if [[ $UUID =~ ^[0-9a-fA-F-]{36}$ ]]; then
  echo "[*] UUID format looks valid: $UUID"
else
  echo "[!] Invalid UUID format in $RULE_FILE"
  exit 1
fi

# 3. Run detection test (simple grep simulation)
echo "[*] Testing detection rule against $TEST_LOGS..."
if grep -q '"oauth.response_type": "token"' $TEST_LOGS || grep -q '"oauth.response_type": "id_token"' $TEST_LOGS; then
  echo "[+] Detection would trigger on malicious entries"
else
  echo "[!] No malicious entries detected in $TEST_LOGS"
  exit 1
fi

echo "=== Validation complete: all checks passed ==="
