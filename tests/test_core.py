from __future__ import annotations

from ai_secrets_guard.core.config import AppConfig, ProbeConfig
from ai_secrets_guard.core.models import Finding, ProbeResponse, ProbeResult, ScanResult
from ai_secrets_guard.core.scoring import (
    OWASP_LLM_TOP_10,
    OWASPCoverage,
    _clamp,
    _score_to_grade,
    compute_score,
)
from ai_secrets_guard.core.severity import Severity


class TestSeverity:
    def test_ordering(self) -> None:
        assert Severity.CRITICAL > Severity.HIGH > Severity.MEDIUM > Severity.LOW > Severity.INFO

    def test_label(self) -> None:
        assert Severity.CRITICAL.label == "CRITICAL"
        assert Severity.INFO.label == "INFO"

    def test_color(self) -> None:
        assert Severity.CRITICAL.color == "bold red"
        assert Severity.INFO.color == "dim"


class TestModels:
    def test_finding_creation(self) -> None:
        f = Finding(
            rule_id="TEST-001",
            severity=Severity.HIGH,
            title="Test finding",
            description="A test",
        )
        assert f.rule_id == "TEST-001"
        assert f.severity == Severity.HIGH

    def test_scan_result_counts(self) -> None:
        findings = [
            Finding(rule_id="A", severity=Severity.CRITICAL, title="a", description="a"),
            Finding(rule_id="B", severity=Severity.CRITICAL, title="b", description="b"),
            Finding(rule_id="C", severity=Severity.HIGH, title="c", description="c"),
        ]
        result = ScanResult(findings=findings)
        assert result.counts_by_severity == {"CRITICAL": 2, "HIGH": 1}

    def test_max_severity_empty(self) -> None:
        result = ScanResult()
        assert result.max_severity == Severity.INFO

    def test_max_severity_with_findings(self) -> None:
        findings = [
            Finding(rule_id="A", severity=Severity.LOW, title="a", description="a"),
            Finding(rule_id="B", severity=Severity.HIGH, title="b", description="b"),
        ]
        result = ScanResult(findings=findings)
        assert result.max_severity == Severity.HIGH

    def test_scan_result_serialization(self) -> None:
        result = ScanResult(project_path="/test")
        data = result.model_dump()
        assert "findings" in data
        assert data["project_path"] == "/test"


class TestConfig:
    def test_default_config(self) -> None:
        cfg = AppConfig()
        assert ".git" in cfg.scan.exclude_paths
        assert cfg.probe.judge_model == "claude-sonnet-4-5"
        assert cfg.probe.timeout_seconds == 30

    def test_from_yaml_nonexistent(self, tmp_path) -> None:
        cfg = AppConfig.from_yaml(tmp_path / "nonexistent.yaml")
        assert cfg.scan.max_file_size_kb == 512

    def test_from_yaml_valid(self, tmp_path) -> None:
        f = tmp_path / "config.yaml"
        f.write_text("scan:\n  max_file_size_kb: 1024\nprobe:\n  timeout_seconds: 60\n")
        cfg = AppConfig.from_yaml(f)
        assert cfg.scan.max_file_size_kb == 1024
        assert cfg.probe.timeout_seconds == 60

    def test_probe_config_new_fields(self) -> None:
        cfg = ProbeConfig()
        assert cfg.delay_ms == 500
        assert cfg.confidence_threshold == 0.7


# ---------------------------------------------------------------------------
# Scoring
# ---------------------------------------------------------------------------


class TestScoring:
    def test_empty_scan_score_zero(self) -> None:
        scan = ScanResult(project_path="/empty")
        result = compute_score(scan=scan)
        assert result.score == 0.0
        assert result.grade == "A"

    def test_critical_findings_raise_score(self) -> None:
        findings = [
            Finding(
                rule_id="SEC-KEY-001",
                severity=Severity.CRITICAL,
                title="t",
                description="d",
            ),
            Finding(
                rule_id="SEC-KEY-002",
                severity=Severity.CRITICAL,
                title="t2",
                description="d2",
            ),
        ]
        scan = ScanResult(findings=findings)
        result = compute_score(scan=scan)
        assert result.score >= 6.0
        assert result.grade in ("D", "F")

    def test_score_clamped_at_10(self) -> None:
        findings = [
            Finding(rule_id=f"SEC-{i}", severity=Severity.CRITICAL, title="t", description="d")
            for i in range(20)
        ]
        scan = ScanResult(findings=findings)
        result = compute_score(scan=scan)
        assert result.score == 10.0
        assert result.grade == "F"

    def test_probe_vulnerabilities_add_to_score(self) -> None:
        probe = ProbeResult(
            target_url="http://test",
            responses=[
                ProbeResponse(
                    payload_name="p1",
                    raw_response="PWNED",
                    is_vulnerable=True,
                    technique="injection",
                ),
            ],
        )
        result = compute_score(probe=probe)
        assert result.score > 0

    def test_owasp_mapping_from_findings(self) -> None:
        findings = [
            Finding(
                rule_id="SEC-OPENAI-001",
                severity=Severity.CRITICAL,
                title="t",
                description="d",
            ),
            Finding(
                rule_id="PI-IGNORE-001",
                severity=Severity.HIGH,
                title="t2",
                description="d2",
            ),
        ]
        scan = ScanResult(findings=findings)
        result = compute_score(scan=scan)
        assert "LLM06" in result.owasp.covered_ids
        assert "LLM01" in result.owasp.covered_ids

    def test_owasp_mapping_from_probes(self) -> None:
        probe = ProbeResult(
            target_url="http://test",
            responses=[
                ProbeResponse(
                    payload_name="p1",
                    raw_response="leaked",
                    is_vulnerable=True,
                    technique="exfiltration",
                ),
            ],
        )
        result = compute_score(probe=probe)
        assert "LLM01" in result.owasp.covered_ids
        assert "LLM06" in result.owasp.covered_ids

    def test_top_findings_limited_to_3(self) -> None:
        findings = [
            Finding(rule_id=f"X-{i}", severity=Severity.HIGH, title=f"t{i}", description="d")
            for i in range(10)
        ]
        scan = ScanResult(findings=findings)
        result = compute_score(scan=scan)
        assert len(result.top_findings) == 3

    def test_remediation_includes_actions(self) -> None:
        findings = [
            Finding(
                rule_id="SEC-KEY-001",
                severity=Severity.CRITICAL,
                title="Leaked key",
                description="d",
            ),
            Finding(
                rule_id="DEP-CVE-001",
                severity=Severity.HIGH,
                title="Old dep",
                description="d",
            ),
        ]
        scan = ScanResult(findings=findings)
        result = compute_score(scan=scan)
        assert len(result.remediation) >= 2
        assert any("Rotate" in a for a in result.remediation)
        assert any("Update" in a for a in result.remediation)

    def test_remediation_deduplicates_rule_ids(self) -> None:
        findings = [
            Finding(
                rule_id="SEC-KEY-001",
                severity=Severity.CRITICAL,
                title="Leaked key",
                description="d",
            ),
            Finding(
                rule_id="SEC-KEY-001",
                severity=Severity.CRITICAL,
                title="Leaked key",
                description="d",
            ),
        ]
        scan = ScanResult(findings=findings)
        result = compute_score(scan=scan)
        rotate_actions = [a for a in result.remediation if "Rotate" in a]
        assert len(rotate_actions) == 1

    def test_remediation_with_probe_vulns(self) -> None:
        probe = ProbeResult(
            target_url="http://test",
            responses=[
                ProbeResponse(
                    payload_name="p1",
                    raw_response="PWNED",
                    is_vulnerable=True,
                    technique="injection",
                ),
            ],
        )
        result = compute_score(probe=probe)
        assert any("probe" in a.lower() for a in result.remediation)

    def test_remediation_mcp_and_generic(self) -> None:
        findings = [
            Finding(
                rule_id="MCP-PERM-ALL",
                severity=Severity.HIGH,
                title="MCP issue",
                description="d",
            ),
            Finding(
                rule_id="UNKNOWN-001",
                severity=Severity.LOW,
                title="Something",
                description="d",
            ),
        ]
        scan = ScanResult(findings=findings)
        result = compute_score(scan=scan)
        assert any("MCP" in a for a in result.remediation)
        assert any("Investigate" in a for a in result.remediation)

    def test_combined_scan_and_probe(self, sample_scan_result, sample_probe_result) -> None:
        result = compute_score(scan=sample_scan_result, probe=sample_probe_result)
        assert result.score > 0
        assert result.grade in ("A", "B", "C", "D", "F")
        assert result.owasp.covered_count > 0

    def test_no_scan_no_probe(self) -> None:
        result = compute_score()
        assert result.score == 0.0
        assert result.grade == "A"
        assert result.remediation == []


class TestScoreToGrade:
    def test_grade_a(self) -> None:
        assert _score_to_grade(0.0) == "A"
        assert _score_to_grade(1.9) == "A"

    def test_grade_b(self) -> None:
        assert _score_to_grade(2.0) == "B"
        assert _score_to_grade(3.9) == "B"

    def test_grade_c(self) -> None:
        assert _score_to_grade(4.0) == "C"
        assert _score_to_grade(5.9) == "C"

    def test_grade_d(self) -> None:
        assert _score_to_grade(6.0) == "D"
        assert _score_to_grade(7.9) == "D"

    def test_grade_f(self) -> None:
        assert _score_to_grade(8.0) == "F"
        assert _score_to_grade(10.0) == "F"


class TestOWASPCoverage:
    def test_empty_coverage(self) -> None:
        cov = OWASPCoverage()
        assert cov.covered_count == 0
        assert cov.covered_ids == []

    def test_partial_coverage(self) -> None:
        cov = OWASPCoverage()
        cov.items["LLM01"] = True
        cov.items["LLM06"] = True
        assert cov.covered_count == 2
        assert "LLM01" in cov.covered_ids

    def test_owasp_top_10_has_10_items(self) -> None:
        assert len(OWASP_LLM_TOP_10) == 10


class TestClamp:
    def test_within_range(self) -> None:
        assert _clamp(5.0, 0.0, 10.0) == 5.0

    def test_below_min(self) -> None:
        assert _clamp(-1.0, 0.0, 10.0) == 0.0

    def test_above_max(self) -> None:
        assert _clamp(15.0, 0.0, 10.0) == 10.0
