# Limitations

This project is an educational SAST comparison, not a benchmark proving production-grade detection superiority.

## Dataset limitations

The sample corpus is intentionally vulnerable and relatively small. It is useful for controlled experiments but does not represent the complexity, framework diversity, dependency graph, data flow, and business logic of a large production codebase.

## Semgrep limitations

- results depend on registry/custom rule coverage;
- syntactic patterns can miss semantically equivalent code written differently;
- some patterns can over-match without data-flow constraints;
- a rule match is not automatically proof of exploitability.

## LLM limitations

- output can vary between runs/models;
- findings can be hallucinated or assigned incorrect severity/CWE;
- context-window limits may prevent whole-repository reasoning;
- API latency and cost affect CI/CD suitability;
- structured JSON output can require repair/parsing fallbacks;
- sending proprietary source to an external model requires privacy/security review.

## Comparison limitations

Matching findings across tools is not trivial. Different tools may use different names, line ranges, severity scales or vulnerability granularity. A useful comparison therefore needs normalization and human review rather than simply comparing raw finding counts.

## Safe interpretation

The project supports the conclusion that **rule-based and LLM-assisted SAST expose different trade-offs**. It does not support a blanket claim that one tool is universally more accurate.

In a real AppSec program, scanner output should be triaged, validated and connected to exploitability, asset criticality and remediation ownership.