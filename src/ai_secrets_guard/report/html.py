"""Generate professional self-contained HTML report with dark theme."""

from __future__ import annotations

import datetime as dt
from pathlib import Path

from jinja2 import Environment, PackageLoader, select_autoescape

import ai_secrets_guard
from ai_secrets_guard.core.models import ProbeResult, ScanResult
from ai_secrets_guard.core.scoring import OWASP_LLM_TOP_10, ScoreResult, compute_score

_GRADE_COLORS: dict[str, str] = {
    "A": "#3fb950",
    "B": "#58a6ff",
    "C": "#d29922",
    "D": "#f0883e",
    "F": "#f85149",
}


def _create_env() -> Environment:
    return Environment(
        loader=PackageLoader("ai_secrets_guard", "report/templates"),
        autoescape=select_autoescape(["html"]),
    )


def render_html(
    result: ScanResult,
    *,
    title: str = "Security Scan Report",
    probe: ProbeResult | None = None,
) -> str:
    """Render a full HTML report with all five sections."""
    env = _create_env()
    template = env.get_template("report.html")

    duration = ""
    if result.finished_at and result.started_at:
        delta = result.finished_at - result.started_at
        duration = f"{delta.total_seconds():.1f}s"

    sorted_findings = sorted(result.findings, key=lambda f: f.severity, reverse=True)

    scoring: ScoreResult = compute_score(scan=result, probe=probe)
    gauge_color = _GRADE_COLORS.get(scoring.grade, "#8b949e")
    gauge_dash = round((scoring.score / 10.0) * 314, 1)

    owasp_items = list(OWASP_LLM_TOP_10.items())
    owasp_covered = set(scoring.owasp.covered_ids)

    probe_responses = probe.responses if probe else []

    return template.render(
        title=title,
        version=ai_secrets_guard.__version__,
        generated_at=dt.datetime.now(dt.UTC).strftime("%Y-%m-%d %H:%M UTC"),
        project_path=result.project_path,
        scan_id=result.scan_id,
        duration=duration,
        counts=result.counts_by_severity,
        findings=sorted_findings,
        score=scoring.score,
        grade=scoring.grade,
        gauge_color=gauge_color,
        gauge_dash=gauge_dash,
        top_findings=scoring.top_findings,
        probe_responses=probe_responses,
        owasp_items=owasp_items,
        owasp_covered=owasp_covered,
        remediation=scoring.remediation,
    )


def write_html(
    result: ScanResult,
    output_path: str | Path,
    *,
    probe: ProbeResult | None = None,
    **kwargs: str,
) -> Path:
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    html = render_html(result, probe=probe, **kwargs)
    path.write_text(html)
    return path
