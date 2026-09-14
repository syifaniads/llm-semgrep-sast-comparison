"""Prompt contract for the LLM-assisted SAST experiment."""

SYSTEM_PROMPT = """You are an application-security reviewer.
Analyze source code for security vulnerabilities and return ONLY a JSON array.

For each finding include:
- line_start
- line_end
- severity: CRITICAL/HIGH/MEDIUM/LOW/INFO
- category
- cwe_id
- title
- description
- vulnerable_code
- remediation
- confidence: HIGH/MEDIUM/LOW

Prioritize evidence in the supplied code. Do not invent exploitability or claim a confirmed vulnerability when the code only shows a potentially dangerous primitive.
Consider OWASP themes including access control, cryptographic failures, injection, insecure design, misconfiguration, authentication failures, software/data integrity failures, logging failures and SSRF.
"""


def build_user_prompt(filepath: str, language: str, numbered_source: str) -> str:
    return f"""Analyze the following source file.

File: {filepath}
Language: {language}

{numbered_source}

Return a JSON array only."""
