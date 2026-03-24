"""Orchestrates all scan modules into a unified scan pipeline."""

from __future__ import annotations

import datetime as dt
from pathlib import Path

from ai_secrets_guard.core.config import ScanConfig
from ai_secrets_guard.core.models import ScanResult
from ai_secrets_guard.scan import deps, mcp_audit, prompt_injection, secrets

_TEXT_EXTENSIONS = {
    ".py",
    ".js",
    ".ts",
    ".jsx",
    ".tsx",
    ".java",
    ".go",
    ".rs",
    ".rb",
    ".yaml",
    ".yml",
    ".json",
    ".toml",
    ".ini",
    ".cfg",
    ".conf",
    ".env",
    ".sh",
    ".bash",
    ".zsh",
    ".fish",
    ".md",
    ".txt",
    ".rst",
    ".html",
    ".xml",
    ".csv",
    ".dockerfile",
    ".tf",
    ".hcl",
}


def run_scan(project_path: str, *, config: ScanConfig | None = None) -> ScanResult:
    config = config or ScanConfig()
    root = Path(project_path).resolve()

    result = ScanResult(project_path=str(root))

    files = _collect_files(root, config)

    for fpath in files:
        result.findings.extend(secrets.scan_file(fpath))
        result.findings.extend(prompt_injection.scan_file(fpath))

    result.findings.extend(mcp_audit.audit_mcp_config(root))
    result.findings.extend(deps.scan_requirements(root))

    result.finished_at = dt.datetime.now(dt.UTC)
    return result


def _collect_files(root: Path, config: ScanConfig) -> list[Path]:
    files: list[Path] = []
    max_size = config.max_file_size_kb * 1024

    for fpath in root.rglob("*"):
        if not fpath.is_file():
            continue

        rel = fpath.relative_to(root)
        parts = rel.parts
        if any(excl in parts for excl in config.exclude_paths):
            continue

        if fpath.suffix in config.exclude_extensions:
            continue

        if fpath.suffix and fpath.suffix not in _TEXT_EXTENSIONS:
            continue

        try:
            if fpath.stat().st_size > max_size:
                continue
        except OSError:
            continue

        files.append(fpath)

    return sorted(files)
