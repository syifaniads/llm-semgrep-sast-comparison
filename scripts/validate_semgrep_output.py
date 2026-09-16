#!/usr/bin/env python3
"""Validate a Semgrep JSON result generated against the educational fixtures."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("result")
    args = parser.parse_args()

    data = json.loads(Path(args.result).read_text(encoding="utf-8"))
    errors = data.get("errors", [])
    results = data.get("results", [])

    if errors:
        raise AssertionError(f"Semgrep returned configuration/runtime errors: {errors}")
    if not results:
        raise AssertionError("custom rules produced zero findings on intentionally vulnerable fixtures")

    paths = {str(item.get("path", "")) for item in results}
    if not any("vulnerable-samples/python/" in p for p in paths):
        raise AssertionError("expected at least one Python fixture finding")
    if not any("vulnerable-samples/javascript/" in p for p in paths):
        raise AssertionError("expected at least one JavaScript fixture finding")

    check_ids = {str(item.get("check_id", "")) for item in results}
    if not all(check_ids):
        raise AssertionError("every Semgrep result should expose a check_id")

    print(f"Semgrep fixture validation passed: {len(results)} findings, {len(check_ids)} rule IDs")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except AssertionError as exc:
        print(f"validation failed: {exc}", file=sys.stderr)
        raise SystemExit(1)
