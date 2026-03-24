from __future__ import annotations

import json
from pathlib import Path

from click.testing import CliRunner

from ai_secrets_guard.cli import cli


class TestCli:
    def test_version(self) -> None:
        runner = CliRunner()
        result = runner.invoke(cli, ["--version"])
        assert result.exit_code == 0
        assert "0.1.0" in result.output

    def test_help(self) -> None:
        runner = CliRunner()
        result = runner.invoke(cli, ["--help"])
        assert result.exit_code == 0
        assert "scan" in result.output
        assert "probe" in result.output
        assert "report" in result.output

    def test_scan_clean_project(self, tmp_path: Path) -> None:
        (tmp_path / "main.py").write_text("print('hello')\n")
        runner = CliRunner()
        result = runner.invoke(cli, ["scan", str(tmp_path)])
        assert result.exit_code == 0

    def test_scan_json_output(self, tmp_path: Path) -> None:
        (tmp_path / "main.py").write_text("print('hello')\n")
        runner = CliRunner()
        result = runner.invoke(cli, ["scan", str(tmp_path), "--format", "json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert "findings" in data

    def test_scan_with_finding_exits_1(self, tmp_path: Path) -> None:
        (tmp_path / "leaked.py").write_text('KEY = "sk-ant-api03-' + "a" * 95 + '"\n')
        runner = CliRunner()
        result = runner.invoke(cli, ["scan", str(tmp_path), "--fail-on", "high"])
        assert result.exit_code == 1

    def test_scan_fail_on_critical_passes_for_high(self, tmp_path: Path) -> None:
        (tmp_path / "leaked.py").write_text('KEY = "sk-ant-api03-' + "a" * 95 + '"\n')
        runner = CliRunner()
        result = runner.invoke(cli, ["scan", str(tmp_path), "--fail-on", "critical"])
        assert result.exit_code == 1

    def test_report_command(self, sample_scan_result, tmp_path: Path) -> None:
        input_file = tmp_path / "input.json"
        input_file.write_text(sample_scan_result.model_dump_json())

        runner = CliRunner()
        out_dir = tmp_path / "reports"
        result = runner.invoke(
            cli,
            [
                "report",
                "--input",
                str(input_file),
                "--output",
                str(out_dir),
                "--format",
                "all",
            ],
        )
        assert result.exit_code == 0
        assert (out_dir / "report.html").exists()
        assert (out_dir / "report.json").exists()
        assert (out_dir / "report.md").exists()
