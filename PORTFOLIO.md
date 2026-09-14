# Portfolio Summary

## LLM vs Semgrep SAST Comparison

**Project type:** Collaborative security tooling / AppSec experiment  
**Stack:** Python, Semgrep, OpenAI-compatible model API, CWE, OWASP

### One-line summary

Built and evaluated a collaborative SAST experiment that scans intentionally vulnerable code with both custom Semgrep rules and an LLM analyzer, normalizes findings, and compares the trade-offs between deterministic and model-assisted security review.

### Portfolio description

The project explores two different SAST strategies over the same controlled code corpus. Semgrep provides fast, deterministic rules suitable for CI/CD guardrails, while the LLM analyzer provides contextual explanations and remediation suggestions at the cost of latency, model variability and the need for validation. The project includes vulnerable fixtures, custom rules, structured JSON output and a comparison workflow.

This personal repository presents the collaborative project with explicit team attribution rather than claiming sole authorship.

### Skills demonstrated

- Static Application Security Testing (SAST)
- Semgrep custom rule design
- Python security tooling
- LLM-assisted code review
- OWASP / CWE classification
- Structured finding normalization
- False-positive / false-negative reasoning
- Security tool comparison
- DevSecOps integration thinking
- Secure API-key handling
- Collaborative Git/GitHub workflow

### CV-ready bullets

- Contributed to a collaborative SAST experiment comparing LLM-assisted code review with Semgrep across intentionally vulnerable Python/JavaScript samples and custom OWASP/CWE-aware rules.
- Evaluated the engineering trade-offs between deterministic CI-friendly rules and contextual LLM analysis, including reproducibility, latency, cost, explainability and false-positive risk.
- Worked within the broader DevSecOps group project as group lead, with security engineering experience spanning SAST, threat modeling, vulnerability assessment and security-tooling experimentation.

### Interview discussion points

- Why raw scanner finding counts are a weak comparison metric.
- How to match findings across different tools and naming conventions.
- Why LLM results require human validation.
- Why Semgrep is attractive for CI/CD even when its semantic context is limited.
- How custom rules can encode organization-specific secure-coding policy.
- How to avoid leaking proprietary code or API keys when using external model APIs.
- How to evaluate precision/recall on a labeled security corpus.