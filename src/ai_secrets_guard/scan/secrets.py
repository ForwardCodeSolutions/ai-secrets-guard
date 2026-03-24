"""Detection of leaked API keys for 25+ AI/ML providers."""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from ai_secrets_guard.core.models import Finding
from ai_secrets_guard.core.severity import Severity


@dataclass(frozen=True)
class SecretPattern:
    provider: str
    rule_id: str
    pattern: re.Pattern[str]
    severity: Severity = Severity.CRITICAL
    description: str = ""


def _build_patterns() -> list[SecretPattern]:
    raw: list[tuple[str, str, str, Severity, str]] = [
        # --- OpenAI ---
        (
            "OpenAI",
            "SEC-OPENAI-001",
            r"sk-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20}",
            Severity.CRITICAL,
            "OpenAI API key (legacy)",
        ),
        (
            "OpenAI",
            "SEC-OPENAI-002",
            r"sk-proj-[A-Za-z0-9\-_]{80,}",
            Severity.CRITICAL,
            "OpenAI project API key",
        ),
        # --- OpenRouter ---
        (
            "OpenRouter",
            "SEC-OPENROUTER-001",
            r"sk-or-v1-[A-Za-z0-9]{64}",
            Severity.CRITICAL,
            "OpenRouter API key",
        ),
        # --- Anthropic ---
        (
            "Anthropic",
            "SEC-ANTHROPIC-001",
            r"sk-ant-api03-[A-Za-z0-9\-_]{90,}",
            Severity.CRITICAL,
            "Anthropic API key",
        ),
        # --- HuggingFace ---
        (
            "HuggingFace",
            "SEC-HF-001",
            r"hf_[A-Za-z0-9]{34,}",
            Severity.CRITICAL,
            "HuggingFace access token",
        ),
        # --- Google ---
        (
            "Google AI",
            "SEC-GOOGLE-001",
            r"AIzaSy[A-Za-z0-9\-_]{33}",
            Severity.CRITICAL,
            "Google AI / Gemini API key",
        ),
        (
            "Google Cloud",
            "SEC-GCP-001",
            r"ya29\.[A-Za-z0-9\-_]+",
            Severity.HIGH,
            "Google Cloud OAuth token",
        ),
        # --- Cohere ---
        (
            "Cohere",
            "SEC-COHERE-001",
            r"[A-Za-z0-9]{40}",
            Severity.CRITICAL,
            "Cohere API key (contextual)",
        ),
        (
            "Cohere",
            "SEC-COHERE-002",
            r"co-[A-Za-z0-9]{40,}",
            Severity.CRITICAL,
            "Cohere API key v2",
        ),
        # --- Replicate ---
        (
            "Replicate",
            "SEC-REPLICATE-001",
            r"r8_[A-Za-z0-9]{40}",
            Severity.CRITICAL,
            "Replicate API token",
        ),
        # --- Stability AI ---
        (
            "Stability AI",
            "SEC-STABILITY-001",
            r"sk-[A-Za-z0-9]{48,}",
            Severity.HIGH,
            "Stability AI API key",
        ),
        # --- Mistral (contextual) ---
        (
            "Mistral",
            "SEC-MISTRAL-001",
            r"[A-Za-z0-9]{32}",
            Severity.HIGH,
            "Mistral AI API key (contextual)",
        ),
        # --- AWS ---
        ("AWS", "SEC-AWS-001", r"AKIA[A-Z0-9]{16}", Severity.CRITICAL, "AWS access key ID"),
        (
            "AWS",
            "SEC-AWS-002",
            r"(?:aws_secret_access_key|AWS_SECRET_ACCESS_KEY)\s*[=:]\s*[A-Za-z0-9/+=]{40}",
            Severity.CRITICAL,
            "AWS secret access key",
        ),
        # --- Azure OpenAI (contextual) ---
        (
            "Azure OpenAI",
            "SEC-AZURE-001",
            r"[0-9a-f]{32}",
            Severity.HIGH,
            "Azure OpenAI API key (contextual)",
        ),
        # --- Pinecone ---
        (
            "Pinecone",
            "SEC-PINECONE-001",
            r"pcsk_[A-Za-z0-9]{32,}",
            Severity.CRITICAL,
            "Pinecone API key (v2)",
        ),
        (
            "Pinecone",
            "SEC-PINECONE-002",
            r"[A-Za-z0-9\-]{36}",
            Severity.HIGH,
            "Pinecone API key (UUID, contextual)",
        ),
        # --- Weaviate (contextual) ---
        (
            "Weaviate",
            "SEC-WEAVIATE-001",
            r"[A-Za-z0-9]{40,}",
            Severity.HIGH,
            "Weaviate API key (contextual)",
        ),
        # --- Qdrant (contextual) ---
        (
            "Qdrant",
            "SEC-QDRANT-001",
            r"[A-Za-z0-9\-_]{32,}",
            Severity.HIGH,
            "Qdrant API key (contextual)",
        ),
        # --- Voyage AI ---
        (
            "Voyage AI",
            "SEC-VOYAGE-001",
            r"pa-[A-Za-z0-9\-_]{40,}",
            Severity.CRITICAL,
            "Voyage AI API key",
        ),
        # --- Together AI (contextual) ---
        (
            "Together AI",
            "SEC-TOGETHER-001",
            r"[a-f0-9]{64}",
            Severity.HIGH,
            "Together AI API key (contextual)",
        ),
        # --- Groq ---
        ("Groq", "SEC-GROQ-001", r"gsk_[A-Za-z0-9]{52}", Severity.CRITICAL, "Groq API key"),
        # --- Fireworks AI ---
        (
            "Fireworks AI",
            "SEC-FIREWORKS-001",
            r"fw_[A-Za-z0-9]{32,}",
            Severity.CRITICAL,
            "Fireworks AI API key",
        ),
        # --- Perplexity ---
        (
            "Perplexity",
            "SEC-PERPLEXITY-001",
            r"pplx-[A-Za-z0-9]{48,}",
            Severity.CRITICAL,
            "Perplexity API key",
        ),
        # --- DeepSeek (contextual) ---
        (
            "DeepSeek",
            "SEC-DEEPSEEK-001",
            r"sk-[a-f0-9]{32}",
            Severity.HIGH,
            "DeepSeek API key (contextual)",
        ),
        # --- LangSmith ---
        (
            "LangSmith",
            "SEC-LANGSMITH-001",
            r"ls__[A-Za-z0-9]{32,}",
            Severity.CRITICAL,
            "LangSmith API key",
        ),
        # --- Weights & Biases (contextual) ---
        (
            "Weights & Biases",
            "SEC-WANDB-001",
            r"[0-9a-f]{40}",
            Severity.HIGH,
            "W&B API key (contextual)",
        ),
        # --- GitHub ---
        (
            "GitHub",
            "SEC-GITHUB-001",
            r"gh[pousr]_[A-Za-z0-9]{36,}",
            Severity.CRITICAL,
            "GitHub personal access token",
        ),
        # --- Slack ---
        ("Slack", "SEC-SLACK-001", r"xox[baprs]-[A-Za-z0-9\-]{10,}", Severity.HIGH, "Slack token"),
    ]
    patterns = []
    for provider, rule_id, regex, severity, desc in raw:
        patterns.append(
            SecretPattern(
                provider=provider,
                rule_id=rule_id,
                pattern=re.compile(regex),
                severity=severity,
                description=desc,
            )
        )
    return patterns


PATTERNS: list[SecretPattern] = _build_patterns()

_CONTEXT_KEYWORDS: dict[str, list[str]] = {
    "SEC-COHERE-001": ["cohere", "co_api_key", "COHERE_API_KEY"],
    "SEC-MISTRAL-001": ["mistral", "MISTRAL_API_KEY"],
    "SEC-AZURE-001": ["azure", "openai.azure", "AZURE_OPENAI", "azure.openai.com"],
    "SEC-PINECONE-002": ["pinecone", "PINECONE_API_KEY"],
    "SEC-WEAVIATE-001": ["weaviate", "WEAVIATE_API_KEY"],
    "SEC-QDRANT-001": ["qdrant", "QDRANT_API_KEY"],
    "SEC-TOGETHER-001": ["together", "TOGETHER_API_KEY"],
    "SEC-WANDB-001": ["wandb", "WANDB_API_KEY"],
    "SEC-DEEPSEEK-001": ["deepseek", "DEEPSEEK_API_KEY"],
}


def _needs_context(rule_id: str) -> bool:
    return rule_id in _CONTEXT_KEYWORDS


def _has_context(rule_id: str, line: str) -> bool:
    keywords = _CONTEXT_KEYWORDS.get(rule_id, [])
    lower = line.lower()
    return any(k.lower() in lower for k in keywords)


def scan_line(line: str, line_number: int, file_path: str) -> list[Finding]:
    findings: list[Finding] = []
    for sp in PATTERNS:
        match = sp.pattern.search(line)
        if not match:
            continue
        if _needs_context(sp.rule_id) and not _has_context(sp.rule_id, line):
            continue
        findings.append(
            Finding(
                rule_id=sp.rule_id,
                severity=sp.severity,
                title=f"Leaked {sp.provider} secret",
                description=sp.description,
                file_path=file_path,
                line_number=line_number,
                matched_text=_redact(match.group()),
            )
        )
    return findings


def scan_file(path: Path) -> list[Finding]:
    findings: list[Finding] = []
    try:
        text = path.read_text(errors="ignore")
    except OSError:
        return findings
    for i, line in enumerate(text.splitlines(), start=1):
        findings.extend(scan_line(line, i, str(path)))
    return findings


def _redact(value: str) -> str:
    if len(value) <= 8:
        return "***"
    return value[:4] + "***" + value[-4:]
