from __future__ import annotations

from pathlib import Path

from ai_secrets_guard.scan.deps import scan_requirements, VULNERABLE_PACKAGES


# ---------------------------------------------------------------------------
# Database completeness
# ---------------------------------------------------------------------------

class TestDatabase:
    def test_has_required_packages(self) -> None:
        required = ["langchain", "langchain-core", "openai", "gradio", "flowise", "llama-index"]
        for pkg in required:
            assert pkg in VULNERABLE_PACKAGES, f"Missing {pkg} in VULNERABLE_PACKAGES"


# ---------------------------------------------------------------------------
# requirements.txt scanning
# ---------------------------------------------------------------------------

class TestRequirementsFile:
    def test_detects_vulnerable_langchain(self, tmp_path: Path) -> None:
        (tmp_path / "requirements.txt").write_text("langchain==0.0.300\n")
        findings = scan_requirements(tmp_path)
        assert any("langchain" in f.title.lower() for f in findings)

    def test_detects_old_openai(self, tmp_path: Path) -> None:
        (tmp_path / "requirements.txt").write_text("openai==0.28.0\n")
        assert any("openai" in f.title.lower() for f in scan_requirements(tmp_path))

    def test_safe_versions(self, tmp_path: Path) -> None:
        (tmp_path / "requirements.txt").write_text("langchain==0.1.0\nopenai==1.5.0\n")
        assert scan_requirements(tmp_path) == []

    def test_no_requirements(self, tmp_path: Path) -> None:
        assert scan_requirements(tmp_path) == []

    def test_comments_and_empty_lines(self, tmp_path: Path) -> None:
        (tmp_path / "requirements.txt").write_text("# comment\n\nrequests==2.31.0\n")
        assert scan_requirements(tmp_path) == []

    def test_flags_skipped(self, tmp_path: Path) -> None:
        (tmp_path / "requirements.txt").write_text("-r base.txt\n--index-url https://pypi.org\n")
        assert scan_requirements(tmp_path) == []

    def test_package_without_version(self, tmp_path: Path) -> None:
        (tmp_path / "requirements.txt").write_text("langchain\n")
        findings = scan_requirements(tmp_path)
        assert any("langchain" in f.title.lower() for f in findings)


# ---------------------------------------------------------------------------
# pyproject.toml scanning
# ---------------------------------------------------------------------------

class TestPyprojectScanning:
    def test_detects_in_pyproject(self, tmp_path: Path) -> None:
        (tmp_path / "pyproject.toml").write_text(
            '[project]\ndependencies = [\n    "langchain>=0.0.200",\n]\n'
        )
        assert any("langchain" in f.title.lower() for f in scan_requirements(tmp_path))

    def test_safe_pyproject(self, tmp_path: Path) -> None:
        (tmp_path / "pyproject.toml").write_text(
            '[project]\ndependencies = [\n    "langchain>=0.1.0",\n]\n'
        )
        assert scan_requirements(tmp_path) == []


# ---------------------------------------------------------------------------
# NEW: langchain-core
# ---------------------------------------------------------------------------

class TestLangchainCore:
    def test_vulnerable(self, tmp_path: Path) -> None:
        (tmp_path / "requirements.txt").write_text("langchain-core==0.1.10\n")
        findings = scan_requirements(tmp_path)
        assert any("langchain-core" in f.title.lower() for f in findings)
        assert any("CVE-2024-LC-CORE" in f.rule_id for f in findings)

    def test_safe(self, tmp_path: Path) -> None:
        (tmp_path / "requirements.txt").write_text("langchain-core==0.1.17\n")
        assert not any("langchain-core" in f.title.lower() for f in scan_requirements(tmp_path))

    def test_newer_safe(self, tmp_path: Path) -> None:
        (tmp_path / "requirements.txt").write_text("langchain-core==0.2.0\n")
        assert not any("langchain-core" in f.title.lower() for f in scan_requirements(tmp_path))


# ---------------------------------------------------------------------------
# NEW: flowise
# ---------------------------------------------------------------------------

class TestFlowise:
    def test_vulnerable(self, tmp_path: Path) -> None:
        (tmp_path / "requirements.txt").write_text("flowise==1.5.0\n")
        findings = scan_requirements(tmp_path)
        assert any("flowise" in f.title.lower() for f in findings)
        assert any(f.severity.label == "CRITICAL" for f in findings if "flowise" in f.title.lower())

    def test_safe(self, tmp_path: Path) -> None:
        (tmp_path / "requirements.txt").write_text("flowise==2.0.0\n")
        assert not any("flowise" in f.title.lower() for f in scan_requirements(tmp_path))


# ---------------------------------------------------------------------------
# NEW: gradio XSS
# ---------------------------------------------------------------------------

class TestGradioXSS:
    def test_vulnerable_old_gradio(self, tmp_path: Path) -> None:
        (tmp_path / "requirements.txt").write_text("gradio==3.50.0\n")
        findings = scan_requirements(tmp_path)
        gradio_findings = [f for f in findings if "gradio" in f.title.lower()]
        assert len(gradio_findings) >= 2
        cves = {f.metadata.get("cve") for f in gradio_findings}
        assert "CVE-2023-51449" in cves
        assert "CVE-2024-GRADIO-XSS" in cves

    def test_safe_gradio(self, tmp_path: Path) -> None:
        (tmp_path / "requirements.txt").write_text("gradio==4.1.0\n")
        assert not any("gradio" in f.title.lower() for f in scan_requirements(tmp_path))


# ---------------------------------------------------------------------------
# NEW: llama-index path traversal
# ---------------------------------------------------------------------------

class TestLlamaIndexPathTraversal:
    def test_very_old_version(self, tmp_path: Path) -> None:
        (tmp_path / "requirements.txt").write_text("llama-index==0.8.0\n")
        findings = scan_requirements(tmp_path)
        llama_findings = [f for f in findings if "llama-index" in f.title.lower()]
        assert len(llama_findings) >= 2

    def test_between_versions(self, tmp_path: Path) -> None:
        (tmp_path / "requirements.txt").write_text("llama-index==0.9.5\n")
        findings = scan_requirements(tmp_path)
        llama_findings = [f for f in findings if "llama-index" in f.title.lower()]
        assert len(llama_findings) == 1
        assert "CVE-2024-LLAMA-PT" in llama_findings[0].rule_id

    def test_safe_version(self, tmp_path: Path) -> None:
        (tmp_path / "requirements.txt").write_text("llama-index==0.10.0\n")
        assert not any("llama-index" in f.title.lower() for f in scan_requirements(tmp_path))


# ---------------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------------

class TestEdgeCases:
    def test_underscore_package_name(self, tmp_path: Path) -> None:
        (tmp_path / "requirements.txt").write_text("langchain_core==0.1.10\n")
        findings = scan_requirements(tmp_path)
        assert any("langchain-core" in f.title.lower() for f in findings)

    def test_multiple_vulnerabilities(self, tmp_path: Path) -> None:
        (tmp_path / "requirements.txt").write_text(
            "langchain==0.0.300\nopenai==0.28.0\nflowise==1.0.0\n"
        )
        findings = scan_requirements(tmp_path)
        packages = {f.metadata.get("package") for f in findings if f.metadata.get("package")}
        assert "langchain" in packages
        assert "openai" in packages
        assert "flowise" in packages

    def test_nested_requirements(self, tmp_path: Path) -> None:
        sub = tmp_path / "backend"
        sub.mkdir()
        (sub / "requirements.txt").write_text("gradio==3.0.0\n")
        findings = scan_requirements(tmp_path)
        assert any("gradio" in f.title.lower() for f in findings)
