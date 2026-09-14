#!/usr/bin/env python3
"""LLM-assisted SAST analyzer used by the portfolio experiment."""

from __future__ import annotations

import argparse
import json
import os
import time
from dataclasses import asdict, dataclass
from pathlib import Path

from json_repair import repair_json
from openai import OpenAI


@dataclass
class Vulnerability:
    file: str
    line_start: int
    line_end: int
    severity: str
    category: str
    cwe_id: str
    title: str
    description: str
    vulnerable_code: str
    remediation: str
    confidence: str


@dataclass
class AnalysisResult:
    file: str
    language: str
    total_lines: int
    vulnerabilities: list[Vulnerability]
    scan_duration_seconds: float
    model_used: str
    tokens_used: int


SYSTEM_PROMPT = """You are an application-security reviewer.
Analyze the supplied source code for security vulnerabilities and return ONLY a JSON array.
For each finding return: line_start, line_end, severity, category, cwe_id, title,
description, vulnerable_code, remediation, confidence.
Use CRITICAL/HIGH/MEDIUM/LOW/INFO severity and HIGH/MEDIUM/LOW confidence.
Do not invent vulnerabilities when the code does not support them.
"""


def detect_language(path: str) -> str:
    return {
        '.py': 'Python', '.js': 'JavaScript', '.ts': 'TypeScript', '.tsx': 'TypeScript',
        '.java': 'Java', '.go': 'Go', '.rb': 'Ruby', '.php': 'PHP', '.cs': 'C#',
    }.get(Path(path).suffix.lower(), 'Unknown')


def read_numbered(path: str) -> tuple[str, int]:
    lines = Path(path).read_text(encoding='utf-8', errors='replace').splitlines()
    return '\n'.join(f'{i:4d} | {line}' for i, line in enumerate(lines, 1)), len(lines)


def parse_findings(raw: str) -> list[dict]:
    cleaned = raw.replace('```json', '').replace('```', '').strip()
    try:
        parsed = json.loads(cleaned)
    except json.JSONDecodeError:
        parsed = json.loads(repair_json(cleaned))

    if isinstance(parsed, list):
        return parsed
    if isinstance(parsed, dict):
        return parsed.get('vulnerabilities') or parsed.get('findings') or parsed.get('results') or []
    return []


def analyze_file(client: OpenAI, path: str, model: str) -> AnalysisResult:
    language = detect_language(path)
    numbered, total_lines = read_numbered(path)
    prompt = f"""File: {path}\nLanguage: {language}\n\n{numbered}\n\nReturn a JSON array only."""
    started = time.time()

    response = client.chat.completions.create(
        model=model,
        messages=[
            {'role': 'system', 'content': SYSTEM_PROMPT},
            {'role': 'user', 'content': prompt},
        ],
        temperature=0.1,
        timeout=120,
    )

    findings: list[Vulnerability] = []
    for item in parse_findings(response.choices[0].message.content or '[]'):
        findings.append(Vulnerability(
            file=path,
            line_start=int(item.get('line_start', 0)),
            line_end=int(item.get('line_end', 0)),
            severity=str(item.get('severity', 'MEDIUM')).upper(),
            category=str(item.get('category', 'Unknown')),
            cwe_id=str(item.get('cwe_id', '')),
            title=str(item.get('title', '')),
            description=str(item.get('description', '')),
            vulnerable_code=str(item.get('vulnerable_code', '')),
            remediation=str(item.get('remediation', '')),
            confidence=str(item.get('confidence', 'MEDIUM')).upper(),
        ))

    tokens = response.usage.total_tokens if response.usage else 0
    return AnalysisResult(
        file=path,
        language=language,
        total_lines=total_lines,
        vulnerabilities=findings,
        scan_duration_seconds=round(time.time() - started, 2),
        model_used=model,
        tokens_used=tokens,
    )


def scan_directory(client: OpenAI, directory: str, model: str) -> list[AnalysisResult]:
    extensions = {'.py', '.js', '.ts', '.tsx'}
    files = sorted(p for p in Path(directory).rglob('*') if p.is_file() and p.suffix in extensions)
    return [analyze_file(client, str(path), model) for path in files]


def save(results: list[AnalysisResult], output: str) -> None:
    payload = {
        'tool': 'LLM SAST Analyzer',
        'scan_timestamp': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
        'total_files': len(results),
        'total_vulnerabilities': sum(len(r.vulnerabilities) for r in results),
        'results': [asdict(r) for r in results],
    }
    Path(output).parent.mkdir(parents=True, exist_ok=True)
    Path(output).write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding='utf-8')


def main() -> None:
    parser = argparse.ArgumentParser(description='LLM-assisted SAST analyzer')
    target = parser.add_mutually_exclusive_group(required=True)
    target.add_argument('--file')
    target.add_argument('--dir')
    parser.add_argument('--model', default='qwen/qwen3-coder-480b-a35b-instruct')
    parser.add_argument('--output', default='results/llm_results.json')
    args = parser.parse_args()

    key = os.getenv('NVIDIA_API_KEY')
    if not key:
        raise SystemExit('NVIDIA_API_KEY is required')

    client = OpenAI(api_key=key, base_url='https://integrate.api.nvidia.com/v1')
    results = [analyze_file(client, args.file, args.model)] if args.file else scan_directory(client, args.dir, args.model)
    save(results, args.output)

    print(f'Analyzed {len(results)} files; findings: {sum(len(r.vulnerabilities) for r in results)}')
    print(f'Output: {args.output}')


if __name__ == '__main__':
    main()
