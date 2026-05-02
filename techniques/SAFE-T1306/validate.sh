#!/bin/bash

echo "Validating detection rule syntax..."
#yamllint detection-rule.yml || exit 1

echo "Running test detection script..."
python3 test_detection_rule.py
