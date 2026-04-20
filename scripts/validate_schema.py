#!/usr/bin/env python3
"""
SAFE-MCP Schema Validator
Validates that the generated JSON matches the defined schemas.
"""

import json
import sys
from pathlib import Path
from jsonschema import validate, ValidationError, Draft7Validator
from typing import Dict, List, Any
import argparse


def load_json(file_path: Path) -> Dict[str, Any]:
    """Load JSON file."""
    with open(file_path, 'r', encoding='utf-8') as f:
        return json.load(f)


def validate_against_schema(data: Any, schema: Dict[str, Any], name: str) -> List[str]:
    """Validate data against schema and return list of errors."""
    errors = []
    validator = Draft7Validator(schema)

    for error in validator.iter_errors(data):
        error_path = ' -> '.join(str(p) for p in error.absolute_path) if error.absolute_path else 'root'
        errors.append(f"{name} [{error_path}]: {error.message}")

    return errors


def main():
    parser = argparse.ArgumentParser(description='Validate SAFE-MCP JSON against schemas')
    parser.add_argument('--root-dir', default='.', help='Root directory of SAFE-MCP repository')
    parser.add_argument('--data-file', default='data/safe-mcp-index.json', help='JSON data file to validate')
    parser.add_argument('--verbose', action='store_true', help='Verbose output')
    args = parser.parse_args()

    root_dir = Path(args.root_dir).resolve()
    schemas_dir = root_dir / 'schemas'
    data_file = root_dir / args.data_file

    print("SAFE-MCP Schema Validator")
    print("=" * 50)

    if not data_file.exists():
        print(f"❌ Data file not found: {data_file}")
        sys.exit(1)

    # Load schemas
    print(f"\nLoading schemas from {schemas_dir}...")
    technique_schema = load_json(schemas_dir / 'technique-schema.json')
    mitigation_schema = load_json(schemas_dir / 'mitigation-schema.json')
    tactic_schema = load_json(schemas_dir / 'tactic-schema.json')
    print("✓ Loaded 3 schemas")

    # Load data
    print(f"\nLoading data from {data_file}...")
    data = load_json(data_file)
    print(f"✓ Loaded data:")
    print(f"  - {len(data.get('tactics', []))} tactics")
    print(f"  - {len(data.get('techniques', []))} techniques")
    print(f"  - {len(data.get('mitigations', []))} mitigations")

    # Validate
    print("\nValidating...")
    all_errors = []

    # Validate tactics
    for tactic in data.get('tactics', []):
        errors = validate_against_schema(tactic, tactic_schema, f"Tactic {tactic.get('id', 'unknown')}")
        all_errors.extend(errors)
        if args.verbose and not errors:
            print(f"  ✓ {tactic.get('id', 'unknown')}")

    # Validate techniques
    for technique in data.get('techniques', []):
        errors = validate_against_schema(technique, technique_schema, f"Technique {technique.get('id', 'unknown')}")
        all_errors.extend(errors)
        if args.verbose and not errors:
            print(f"  ✓ {technique.get('id', 'unknown')}")

    # Validate mitigations
    for mitigation in data.get('mitigations', []):
        errors = validate_against_schema(mitigation, mitigation_schema, f"Mitigation {mitigation.get('id', 'unknown')}")
        all_errors.extend(errors)
        if args.verbose and not errors:
            print(f"  ✓ {mitigation.get('id', 'unknown')}")

    # Report results
    print("\n" + "=" * 50)
    if all_errors:
        print(f"❌ Validation FAILED with {len(all_errors)} error(s):\n")
        for error in all_errors[:20]:  # Show first 20 errors
            print(f"  • {error}")
        if len(all_errors) > 20:
            print(f"\n  ... and {len(all_errors) - 20} more errors")
        sys.exit(1)
    else:
        print("✅ Validation PASSED")
        print("\nAll data conforms to the defined schemas.")
        sys.exit(0)


if __name__ == '__main__':
    main()
