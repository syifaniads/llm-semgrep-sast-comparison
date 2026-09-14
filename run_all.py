#!/usr/bin/env python3
"""Run LLM SAST, Semgrep and the comparison report."""

from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path


def run(cmd: list[str]) -> int:
    print('+', ' '.join(cmd))
    return subprocess.run(cmd, check=False).returncode


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument('--model', default='qwen/qwen3-coder-480b-a35b-instruct')
    parser.add_argument('--target', default='vulnerable-samples')
    parser.add_argument('--only-llm', action='store_true')
    parser.add_argument('--only-semgrep', action='store_true')
    parser.add_argument('--only-compare', action='store_true')
    args = parser.parse_args()

    Path('results').mkdir(exist_ok=True)

    run_llm = not args.only_semgrep and not args.only_compare
    run_semgrep = not args.only_llm and not args.only_compare
    run_compare = not args.only_llm and not args.only_semgrep

    if run_llm:
        rc = run([
            sys.executable, 'llm-sast/analyzer.py',
            '--dir', args.target,
            '--model', args.model,
            '--output', 'results/llm_results.json',
        ])
        if rc != 0:
            print('LLM scan failed; comparison may be unavailable.')

    if run_semgrep:
        rc = run([
            'semgrep',
            '--config', 'p/owasp-top-ten',
            '--config', 'semgrep-sast/rules',
            '--json',
            '--metrics=off',
            '--output', 'results/semgrep_results.json',
            args.target,
        ])
        if rc not in (0, 1):
            print('Semgrep scan failed; comparison may be unavailable.')

    if run_compare or args.only_compare:
        llm = Path('results/llm_results.json')
        semgrep = Path('results/semgrep_results.json')
        if llm.exists() and semgrep.exists():
            run([
                sys.executable, 'comparison/compare.py',
                '--llm', str(llm),
                '--semgrep', str(semgrep),
                '--output', 'results/comparison_report.html',
            ])
        else:
            print('Comparison skipped: result files are missing.')


if __name__ == '__main__':
    main()
