"""Risk scoring, grading, and OWASP LLM Top 10 mapping."""

from __future__ import annotations

from dataclasses import dataclass, field

from ai_secrets_guard.core.models import Finding, ProbeResponse, ProbeResult, ScanResult
from ai_secrets_guard.core.severity import Severity

# ---------------------------------------------------------------------------
# OWASP LLM Top 10 (2025) mapping
# ---------------------------------------------------------------------------

OWASP_LLM_TOP_10: dict[str, str] = {
    "LLM01": "Prompt Injection",
    "LLM02": "Insecure Output Handling",
    "LLM03": "Training Data Poisoning",
    "LLM04": "Model Denial of Service",
    "LLM05": "Supply Chain Vulnerabilities",
    "LLM06": "Sensitive Information Disclosure",
    "LLM07": "Insecure Plugin Design",
    "LLM08": "Excessive Agency",
    "LLM09": "Overreliance",
    "LLM10": "Model Theft",
}

_RULE_TO_OWASP: dict[str, list[str]] = {
    "PI-": ["LLM01"],
    "SEC-": ["LLM06"],
    "DEP-": ["LLM05"],
    "MCP-PERM": ["LLM08", "LLM07"],
    "MCP-SECRET": ["LLM06"],
    "MCP-CMD": ["LLM08"],
    "MCP-HEADER": ["LLM02"],
    "MCP-TOOL": ["LLM07"],
    "MCP-SCHEMA": ["LLM07"],
    "MCP-TRANSPORT": ["LLM06"],
}

_PROBE_CATEGORY_TO_OWASP: dict[str, list[str]] = {
    "injection": ["LLM01"],
    "jailbreak": ["LLM01"],
    "exfiltration": ["LLM06", "LLM01"],
}

# ---------------------------------------------------------------------------
# Severity weights for score calculation
# ---------------------------------------------------------------------------

_SEVERITY_WEIGHTS: dict[Severity, float] = {
    Severity.CRITICAL: 3.0,
    Severity.HIGH: 2.0,
    Severity.MEDIUM: 1.0,
    Severity.LOW: 0.3,
    Severity.INFO: 0.0,
}

_PROBE_VULN_WEIGHT: float = 1.5


@dataclass
class OWASPCoverage:
    """Which OWASP LLM Top 10 items are covered by the scan."""

    items: dict[str, bool] = field(default_factory=lambda: dict.fromkeys(OWASP_LLM_TOP_10, False))

    @property
    def covered_ids(self) -> list[str]:
        return sorted(k for k, v in self.items.items() if v)

    @property
    def covered_count(self) -> int:
        return sum(1 for v in self.items.values() if v)


@dataclass
class ScoreResult:
    score: float
    grade: str
    owasp: OWASPCoverage
    top_findings: list[Finding]
    remediation: list[str]


def _clamp(value: float, lo: float, hi: float) -> float:
    return max(lo, min(hi, value))


def compute_score(
    scan: ScanResult | None = None,
    probe: ProbeResult | None = None,
) -> ScoreResult:
    """Compute overall risk score (0.0 = safe, 10.0 = critical).

    Grade scale:
        A: 0–2  (excellent)
        B: 2–4  (good)
        C: 4–6  (moderate risk)
        D: 6–8  (high risk)
        F: 8–10 (critical)
    """
    raw = 0.0
    owasp = OWASPCoverage()
    all_findings: list[Finding] = []

    if scan:
        all_findings = list(scan.findings)
        for finding in scan.findings:
            raw += _SEVERITY_WEIGHTS.get(finding.severity, 0.0)
            _map_finding_to_owasp(finding, owasp)

    if probe:
        for resp in probe.responses:
            if resp.is_vulnerable:
                raw += _PROBE_VULN_WEIGHT
            _map_probe_to_owasp(resp, owasp)

    score = _clamp(raw, 0.0, 10.0)
    grade = _score_to_grade(score)

    sorted_findings = sorted(all_findings, key=lambda f: f.severity, reverse=True)
    top_findings = sorted_findings[:3]

    remediation = _build_remediation(all_findings, probe)

    return ScoreResult(
        score=round(score, 1),
        grade=grade,
        owasp=owasp,
        top_findings=top_findings,
        remediation=remediation,
    )


def _score_to_grade(score: float) -> str:
    if score < 2.0:
        return "A"
    if score < 4.0:
        return "B"
    if score < 6.0:
        return "C"
    if score < 8.0:
        return "D"
    return "F"


def _map_finding_to_owasp(finding: Finding, owasp: OWASPCoverage) -> None:
    for prefix, ids in _RULE_TO_OWASP.items():
        if finding.rule_id.startswith(prefix):
            for owasp_id in ids:
                owasp.items[owasp_id] = True


def _map_probe_to_owasp(resp: ProbeResponse, owasp: OWASPCoverage) -> None:
    technique = resp.technique or ""
    for cat, ids in _PROBE_CATEGORY_TO_OWASP.items():
        if cat in technique:
            for owasp_id in ids:
                owasp.items[owasp_id] = True
    if resp.is_vulnerable:
        owasp.items["LLM01"] = True


def _build_remediation(
    findings: list[Finding],
    probe: ProbeResult | None,
) -> list[str]:
    """Build prioritised remediation steps, ordered by severity."""
    actions: list[tuple[int, str]] = []
    seen: set[str] = set()

    severity_order = {
        Severity.CRITICAL: 0,
        Severity.HIGH: 1,
        Severity.MEDIUM: 2,
        Severity.LOW: 3,
        Severity.INFO: 4,
    }

    for f in findings:
        key = f.rule_id
        if key in seen:
            continue
        seen.add(key)
        priority = severity_order.get(f.severity, 4)

        sev = f.severity.label
        if f.rule_id.startswith("SEC-"):
            msg = f"[{sev}] Rotate compromised secret: {f.title}"
        elif f.rule_id.startswith("PI-"):
            msg = f"[{sev}] Add input sanitisation: {f.title}"
        elif f.rule_id.startswith("DEP-"):
            msg = f"[{sev}] Update vulnerable dependency: {f.title}"
        elif f.rule_id.startswith("MCP-"):
            msg = f"[{sev}] Review MCP configuration: {f.title}"
        else:
            msg = f"[{sev}] Investigate: {f.title}"
        actions.append((priority, msg))

    if probe:
        vuln_count = sum(1 for r in probe.responses if r.is_vulnerable)
        if vuln_count:
            msg = f"[CRITICAL] {vuln_count} probe(s) exploited — review prompt injection defences"
            actions.append((0, msg))

    actions.sort(key=lambda x: x[0])
    return [a[1] for a in actions]
