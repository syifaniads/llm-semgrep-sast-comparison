from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("compare_module", ROOT / "comparison" / "compare.py")
assert SPEC and SPEC.loader
compare = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = compare
SPEC.loader.exec_module(compare)


class CompareTests(unittest.TestCase):
    def write_json(self, payload: dict) -> str:
        handle = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False, encoding="utf-8")
        json.dump(payload, handle)
        handle.close()
        self.addCleanup(lambda: Path(handle.name).unlink(missing_ok=True))
        return handle.name

    def test_llm_loader_normalizes_basename_severity_and_cwe(self):
        path = self.write_json({
            "results": [{
                "file": "vulnerable-samples/python/sql_injection.py",
                "vulnerabilities": [{
                    "line_start": 12,
                    "severity": "high",
                    "category": "SQL Injection",
                    "cwe_id": "cwe-89",
                    "title": "Unsafe SQL construction"
                }]
            }]
        })
        findings = compare.load_llm(path)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].file, "sql_injection.py")
        self.assertEqual(findings[0].severity, "HIGH")
        self.assertEqual(findings[0].cwe, "CWE-89")

    def test_semgrep_loader_uses_metadata_cwe_and_basename(self):
        path = self.write_json({
            "results": [{
                "check_id": "python.sql-injection",
                "path": "vulnerable-samples/python/sql_injection.py",
                "start": {"line": 12},
                "extra": {
                    "severity": "ERROR",
                    "message": "Potential SQL injection",
                    "metadata": {"category": "SQL Injection", "cwe": "CWE-89"}
                }
            }]
        })
        findings = compare.load_semgrep(path)
        self.assertEqual(findings[0].file, "sql_injection.py")
        self.assertEqual(findings[0].cwe, "CWE-89")
        self.assertEqual(findings[0].severity, "ERROR")

    def test_report_matches_on_file_and_cwe(self):
        llm = [compare.Finding("LLM", "app.py", 10, "HIGH", "SQL Injection", "CWE-89", "x")]
        semgrep = [compare.Finding("Semgrep", "app.py", 11, "ERROR", "SQL Injection", "CWE-89", "y")]
        report = compare.build_report(llm, semgrep)
        self.assertEqual(report["matched_keys"], [("app.py", "CWE-89")])
        self.assertEqual(report["llm_only_keys"], [])
        self.assertEqual(report["semgrep_only_keys"], [])

    def test_category_fallback_is_case_normalized(self):
        a = compare.Finding("LLM", "app.js", 1, "MEDIUM", "Open Redirect", "", "")
        b = compare.Finding("Semgrep", "app.js", 2, "WARNING", " open redirect ", "", "")
        self.assertEqual(compare.key(a), compare.key(b))

    def test_html_escapes_finding_fields(self):
        report = {
            "llm_total": 1,
            "semgrep_total": 0,
            "matched_keys": [],
            "llm_only_keys": [("<script>.py", "CWE-79<script>")],
            "semgrep_only_keys": [],
            "llm_severity": {},
            "semgrep_severity": {},
        }
        rendered = compare.render_html(report)
        self.assertNotIn("<script>.py", rendered)
        self.assertIn("&lt;script&gt;.py", rendered)


if __name__ == "__main__":
    unittest.main()
