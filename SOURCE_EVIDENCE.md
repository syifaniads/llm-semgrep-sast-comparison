# Source Evidence

## Original collaborative repository

https://github.com/dso-1/sast-llm

The original repository contains:

- `llm-sast/analyzer.py` — model-based SAST analyzer;
- `llm-sast/prompts.py` — prompt material;
- `semgrep-sast/rules/` — custom Python/JavaScript security rules;
- `semgrep-sast/run_semgrep.sh` — Semgrep workflow;
- `comparison/compare.py` — result comparison/reporting;
- `vulnerable-samples/` — intentionally vulnerable and secure code examples;
- `run_all.py` — orchestration script;
- later history that also includes application material from the broader group project.

## Historical repository relationship

The latest `sast-llm` history also contains an `app-web` copy related to the Go Reserve project. In this portfolio that application is separated into its own case study:

https://github.com/syifaniads/go-reserve-devsecops-platform

This keeps the SAST comparison repo focused on security tooling rather than mixing two distinct recruiter stories.

## Portfolio curation

This mirror keeps the core SAST experiment, representative vulnerable fixtures, custom rules, methodology, limitations and attribution. Generated `results/` are excluded by default because they can be recreated and can vary between LLM models/runs.

## Secret handling

The original project expects an external model API key through an environment variable. No real API key is preserved in this portfolio. `.env.example` contains only a placeholder.

## Authorship

The original project is collaborative team/course work. Some work across the broader group project was performed from shared development machines, so commit metadata is not treated as a complete individual contribution map. See `TEAM_ATTRIBUTION.md`.