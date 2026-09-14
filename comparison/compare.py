#!/usr/bin/env python3
"""Compare normalized LLM and Semgrep SAST findings."""

from __future__ import annotations

import argparse
import html
import json
from collections import Counter
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Finding:
    tool: str
    file: str
    line: int
    severity: str
    category: str
    cwe: str
    title: str


def basename(value: str) -> str:
    return Path(value).name


def load_llm(path: str) -> list[Finding]:
    data = json.loads(Path(path).read_text(encoding='utf-8'))
    findings: list[Finding] = []
    for result in data.get('results', []):
        for item in result.get('vulnerabilities', []):
            findings.append(Finding(
                tool='LLM',
                file=basename(item.get('file') or result.get('file', '')),
                line=int(item.get('line_start', 0) or 0),
                severity=str(item.get('severity', 'MEDIUM')).upper(),
                category=str(item.get('category', 'Unknown')),
                cwe=str(item.get('cwe_id', '')).upper(),
                title=str(item.get('title', '')),
            ))
    return findings


def load_semgrep(path: str) -> list[Finding]:
    data = json.loads(Path(path).read_text(encoding='utf-8'))
    findings: list[Finding] = []
    for item in data.get('results', []):
        extra = item.get('extra', {})
        metadata = extra.get('metadata', {}) or {}
        findings.append(Finding(
            tool='Semgrep',
            file=basename(item.get('path', '')),
            line=int((item.get('start') or {}).get('line', 0) or 0),
            severity=str(extra.get('severity', 'WARNING')).upper(),
            category=str(metadata.get('category') or extra.get('message') or item.get('check_id', 'Unknown')),
            cwe=str(metadata.get('cwe', '')).upper(),
            title=str(item.get('check_id', '')),
        ))
    return findings


def key(finding: Finding) -> tuple[str, str]:
    """Use file + CWE when available, otherwise file + normalized category."""
    identity = finding.cwe or finding.category.lower().strip()
    return finding.file, identity


def build_report(llm: list[Finding], semgrep: list[Finding]) -> dict:
    llm_keys = {key(f) for f in llm}
    semgrep_keys = {key(f) for f in semgrep}
    return {
        'llm_total': len(llm),
        'semgrep_total': len(semgrep),
        'matched_keys': sorted(llm_keys & semgrep_keys),
        'llm_only_keys': sorted(llm_keys - semgrep_keys),
        'semgrep_only_keys': sorted(semgrep_keys - llm_keys),
        'llm_severity': Counter(f.severity for f in llm),
        'semgrep_severity': Counter(f.severity for f in semgrep),
    }


def render_html(report: dict) -> str:
    def rows(values: list[tuple[str, str]]) -> str:
        if not values:
            return '<tr><td colspan="2">None</td></tr>'
        return ''.join(
            f'<tr><td>{html.escape(file)}</td><td>{html.escape(identity)}</td></tr>'
            for file, identity in values
        )

    return f"""<!doctype html>
<html><head><meta charset='utf-8'><title>LLM vs Semgrep SAST Comparison</title>
<style>body{{font-family:system-ui;max-width:1000px;margin:40px auto;padding:0 20px}}table{{border-collapse:collapse;width:100%;margin-bottom:28px}}th,td{{border:1px solid #ddd;padding:8px;text-align:left}}code{{background:#eee;padding:2px 4px}}</style></head>
<body>
<h1>LLM vs Semgrep SAST Comparison</h1>
<p>This report uses a lightweight <code>file + CWE/category</code> normalization key. It is not a substitute for human validation.</p>
<ul><li>LLM findings: {report['llm_total']}</li><li>Semgrep findings: {report['semgrep_total']}</li><li>Matched normalized keys: {len(report['matched_keys'])}</li></ul>
<h2>Matched</h2><table><tr><th>File</th><th>CWE / Category</th></tr>{rows(report['matched_keys'])}</table>
<h2>LLM only</h2><table><tr><th>File</th><th>CWE / Category</th></tr>{rows(report['llm_only_keys'])}</table>
<h2>Semgrep only</h2><table><tr><th>File</th><th>CWE / Category</th></tr>{rows(report['semgrep_only_keys'])}</table>
</body></html>"""


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument('--llm', required=True)
    parser.add_argument('--semgrep', required=True)
    parser.add_argument('--output', default='results/comparison_report.html')
    args = parser.parse_args()

    report = build_report(load_llm(args.llm), load_semgrep(args.semgrep))
    Path(args.output).parent.mkdir(parents=True, exist_ok=True)
    Path(args.output).write_text(render_html(report), encoding='utf-8')
    print(f"Report written to {args.output}")


if __name__ == '__main__':
    main()
