from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, Field


class ScanConfig(BaseModel):
    exclude_paths: list[str] = Field(
        default_factory=lambda: [
            ".git",
            "node_modules",
            ".venv",
            "__pycache__",
            ".pytest_cache",
            ".ruff_cache",
            ".mypy_cache",
        ]
    )
    exclude_extensions: list[str] = Field(
        default_factory=lambda: [".pyc", ".whl", ".tar.gz", ".zip"]
    )
    max_file_size_kb: int = 512
    custom_patterns_file: str | None = None


class ProbeConfig(BaseModel):
    timeout_seconds: int = 30
    max_retries: int = 2
    concurrent_requests: int = 5
    delay_ms: int = 500
    judge_model: str = "claude-sonnet-4-5"
    judge_enabled: bool = True
    confidence_threshold: float = 0.7


class ReportConfig(BaseModel):
    output_dir: str = "reports"
    title: str = "AI Secrets Guard Report"


class AppConfig(BaseModel):
    scan: ScanConfig = Field(default_factory=ScanConfig)
    probe: ProbeConfig = Field(default_factory=ProbeConfig)
    report: ReportConfig = Field(default_factory=ReportConfig)

    @classmethod
    def from_yaml(cls, path: str | Path) -> AppConfig:
        p = Path(path)
        if not p.exists():
            return cls()
        raw: dict[str, Any] = yaml.safe_load(p.read_text()) or {}
        return cls.model_validate(raw)
