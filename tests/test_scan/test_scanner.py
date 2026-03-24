from __future__ import annotations

import json
from pathlib import Path

from ai_secrets_guard.scan.scanner import run_scan


class TestScanner:
    def test_full_scan_clean_project(self, tmp_project: Path) -> None:
        result = run_scan(str(tmp_project))
        assert result.findings == []
        assert result.finished_at is not None

    def test_full_scan_with_leaked_key(self, tmp_path: Path) -> None:
        (tmp_path / "config.py").write_text('KEY = "sk-ant-api03-' + "x" * 95 + '"\n')
        result = run_scan(str(tmp_path))
        assert len(result.findings) >= 1

    def test_full_scan_with_mcp_issue(self, tmp_path: Path) -> None:
        cursor_dir = tmp_path / ".cursor"
        cursor_dir.mkdir()
        config = {"mcpServers": {"bad": {"command": "x", "required_permissions": ["all"]}}}
        (cursor_dir / "mcp.json").write_text(json.dumps(config))
        (tmp_path / "app.py").write_text("x = 1\n")

        result = run_scan(str(tmp_path))
        assert any("MCP" in f.rule_id for f in result.findings)

    def test_scan_excludes_git_dir(self, tmp_path: Path) -> None:
        git_dir = tmp_path / ".git"
        git_dir.mkdir()
        (git_dir / "config.py").write_text('KEY = "sk-ant-api03-' + "z" * 95 + '"\n')
        (tmp_path / "main.py").write_text("print(1)\n")

        result = run_scan(str(tmp_path))
        git_findings = [f for f in result.findings if ".git" in (f.file_path or "")]
        assert git_findings == []
