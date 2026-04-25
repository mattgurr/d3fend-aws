#!/usr/bin/env python3
"""Validate all D3FEND-AWS technique YAML files against the JSON Schema."""

import json
import sys
from pathlib import Path

try:
    import jsonschema
    import yaml
except ImportError:
    print("ERROR: Missing dependencies. Install with:")
    print("  pip install pyyaml jsonschema")
    sys.exit(2)

ROOT = Path(__file__).resolve().parent.parent
SCHEMA_PATH = ROOT / "schema" / "technique.schema.json"
DATA_DIR = ROOT / "data"
TACTIC_DIRS = ["detect", "harden", "evict"]


def load_schema():
    with open(SCHEMA_PATH) as f:
        return json.load(f)


def validate_file(filepath: Path, schema: dict) -> list[str]:
    errors = []
    try:
        with open(filepath) as f:
            doc = yaml.safe_load(f)
    except yaml.YAMLError as e:
        return [f"{filepath}: YAML parse error: {e}"]

    if doc is None:
        return [f"{filepath}: empty file"]

    validator = jsonschema.Draft202012Validator(schema)
    for error in sorted(validator.iter_errors(doc), key=lambda e: list(e.path)):
        path = ".".join(str(p) for p in error.absolute_path) or "(root)"
        errors.append(f"{filepath}: {path}: {error.message}")

    # Cross-check: tactic field must match parent directory
    expected_tactic = filepath.parent.name
    if doc.get("tactic") and doc["tactic"] != expected_tactic:
        errors.append(
            f"{filepath}: tactic '{doc['tactic']}' does not match "
            f"directory '{expected_tactic}'"
        )

    return errors


def main():
    schema = load_schema()
    all_errors = []
    file_count = 0

    for tactic in TACTIC_DIRS:
        tactic_dir = DATA_DIR / tactic
        if not tactic_dir.exists():
            continue
        for filepath in sorted(tactic_dir.glob("*.yaml")):
            file_count += 1
            errors = validate_file(filepath, schema)
            all_errors.extend(errors)

    if file_count == 0:
        print("WARNING: No technique YAML files found in data/")
        sys.exit(0)

    if all_errors:
        print(f"FAILED: {len(all_errors)} error(s) in {file_count} file(s):\n")
        for err in all_errors:
            print(f"  - {err}")
        sys.exit(1)

    print(f"OK: {file_count} file(s) validated successfully.")
    sys.exit(0)


if __name__ == "__main__":
    main()
