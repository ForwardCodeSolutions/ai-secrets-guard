"""Detect prompt injection patterns in source code."""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from ai_secrets_guard.core.models import Finding
from ai_secrets_guard.core.severity import Severity


@dataclass(frozen=True)
class InjectionPattern:
    rule_id: str
    pattern: re.Pattern[str]
    severity: Severity
    title: str
    description: str


_PATTERNS: list[InjectionPattern] = [
    # --- Classic injection ---
    InjectionPattern(
        rule_id="PI-IGNORE-001",
        pattern=re.compile(
            r"ignore\s+(all\s+)?(previous|above|prior)\s+(instructions|prompts|rules)",
            re.IGNORECASE,
        ),
        severity=Severity.HIGH,
        title="Prompt override instruction",
        description=(
            "Text instructs LLM to ignore prior instructions"
            " — classic prompt injection vector"
        ),
    ),
    InjectionPattern(
        rule_id="PI-ROLE-001",
        pattern=re.compile(r"you\s+are\s+now\s+(a|an|the)\s+\w+", re.IGNORECASE),
        severity=Severity.MEDIUM,
        title="Role reassignment attempt",
        description="Attempts to override the LLM's assigned role",
    ),
    InjectionPattern(
        rule_id="PI-SYSTEM-001",
        pattern=re.compile(r"(system[\s_]*prompt|system[\s_]*message)\s*[:=]", re.IGNORECASE),
        severity=Severity.MEDIUM,
        title="Hardcoded system prompt in source",
        description="System prompt defined inline — should be externalized and protected",
    ),
    InjectionPattern(
        rule_id="PI-JAILBREAK-001",
        pattern=re.compile(
            r"(\bDAN\b|do\s+anything\s+now|\bjailbreak\b|bypass\s+safety)", re.IGNORECASE
        ),
        severity=Severity.HIGH,
        title="Jailbreak keyword detected",
        description="Known jailbreak terminology found in source code",
    ),
    InjectionPattern(
        rule_id="PI-EXFIL-001",
        pattern=re.compile(
            r"(repeat|print|output|reveal|show)\s+(the\s+)?(system\s+prompt|instructions|rules|context)",
            re.IGNORECASE,
        ),
        severity=Severity.HIGH,
        title="System prompt extraction attempt",
        description="Text attempts to extract the system prompt or internal instructions",
    ),
    InjectionPattern(
        rule_id="PI-DELIM-001",
        pattern=re.compile(r"```\s*(system|assistant)\b", re.IGNORECASE),
        severity=Severity.MEDIUM,
        title="Delimiter injection",
        description="Code fence used to inject fake system/assistant messages",
    ),
    InjectionPattern(
        rule_id="PI-ENCODE-001",
        pattern=re.compile(r"(base64|rot13|hex)\s*(encode|decode|convert)", re.IGNORECASE),
        severity=Severity.LOW,
        title="Encoding-based obfuscation",
        description=(
            "References to encoding schemes that may be used"
            " to obfuscate prompt injections"
        ),
    ),
    # --- Unsanitized input interpolation ---
    InjectionPattern(
        rule_id="PI-UNSANITIZED-001",
        pattern=re.compile(
            r"f['\"].*\{.*user.*input.*\}|\.format\(.*user.*\)|%s.*user", re.IGNORECASE
        ),
        severity=Severity.HIGH,
        title="Unsanitized user input in prompt",
        description="User input interpolated directly into prompt template without sanitization",
    ),
    InjectionPattern(
        rule_id="PI-CONCAT-001",
        pattern=re.compile(r"prompt\s*[\+]=\s*.*(?:request|input|query|message)\b", re.IGNORECASE),
        severity=Severity.MEDIUM,
        title="Direct prompt concatenation via +=",
        description="User-controlled data concatenated directly into prompt string",
    ),
    # --- NEW: String concatenation via + in prompt context ---
    InjectionPattern(
        rule_id="PI-CONCAT-002",
        pattern=re.compile(
            r"(?:prompt|system_message|instruction)\s*=\s*.*\+\s*(?:user|request|input|query|message)\w*",
            re.IGNORECASE,
        ),
        severity=Severity.HIGH,
        title="String concatenation in prompt construction",
        description="User-controlled data concatenated into prompt via + operator",
    ),
    # --- NEW: format() / format_map() with user data ---
    InjectionPattern(
        rule_id="PI-FORMAT-001",
        pattern=re.compile(
            r"\.format(?:_map)?\s*\(\s*.*(?:user|request|input|query|body|params)\b",
            re.IGNORECASE,
        ),
        severity=Severity.HIGH,
        title="format()/format_map() with user-controlled data",
        description=(
            "Prompt template rendered via .format() or .format_map()"
            " with user input — injection risk"
        ),
    ),
    # --- NEW: Jinja2 render without sandboxing ---
    InjectionPattern(
        rule_id="PI-JINJA-001",
        pattern=re.compile(
            r"(?<!Sandboxed)(?:Template|Environment)\s*\(.*\)\.(?:render|from_string)\s*\(",
            re.IGNORECASE,
        ),
        severity=Severity.HIGH,
        title="Jinja2 template render without SandboxedEnvironment",
        description="Template rendered via Jinja2 without using SandboxedEnvironment — SSTI risk",
    ),
    # --- NEW: No sanitization before LLM call ---
    InjectionPattern(
        rule_id="PI-NOSANITIZE-001",
        pattern=re.compile(
            r"(?:messages|prompt)\s*=\s*\[.*(?:request\.|input\[|body\[|params\[|args\.).*\]",
            re.IGNORECASE,
        ),
        severity=Severity.HIGH,
        title="Unsanitized data passed directly to LLM",
        description=(
            "User-controlled data placed directly into LLM"
            " messages/prompt without sanitization"
        ),
    ),
]


def scan_file(path: Path) -> list[Finding]:
    findings: list[Finding] = []
    try:
        text = path.read_text(errors="ignore")
    except OSError:
        return findings
    for i, line in enumerate(text.splitlines(), start=1):
        for ip in _PATTERNS:
            if ip.pattern.search(line):
                findings.append(
                    Finding(
                        rule_id=ip.rule_id,
                        severity=ip.severity,
                        title=ip.title,
                        description=ip.description,
                        file_path=str(path),
                        line_number=i,
                        matched_text=line.strip()[:120],
                    )
                )
    return findings
