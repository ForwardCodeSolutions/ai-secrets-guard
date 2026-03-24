"""Markdown report with GitHub badges, OWASP coverage, and collapsible details."""

from __future__ import annotations

from pathlib import Path

from ai_secrets_guard.core.models import ProbeResult, ScanResult
from ai_secrets_guard.core.scoring import OWASP_LLM_TOP_10, compute_score
from ai_secrets_guard.core.severity import Severity

_BADGE_COLORS: dict[str, str] = {
    "CRITICAL": "critical",
    "HIGH": "orange",
    "MEDIUM": "yellow",
    "LOW": "blue",
    "INFO": "lightgrey",
}

_GRADE_BADGE_COLORS: dict[str, str] = {
    "A": "brightgreen",
    "B": "blue",
    "C": "yellow",
    "D": "orange",
    "F": "critical",
}


def _badge(label: str, value: int | str, color: str) -> str:
    label_enc = str(label).replace("-", "--").replace(" ", "_")
    return f"![{label}](https://img.shields.io/badge/{label_enc}-{value}-{color})"


def render_markdown(
    result: ScanResult,
    *,
    title: str = "Security Scan Report",
    probe: ProbeResult | None = None,
) -> str:
    scoring = compute_score(scan=result, probe=probe)
    lines: list[str] = []

    lines.append(f"# {title}\n")

    # Badges
    badges = []
    total = len(result.findings)
    max_sev = result.max_severity
    status_color = (
        "brightgreen" if max_sev <= Severity.LOW else _BADGE_COLORS.get(max_sev.label, "red")
    )
    badges.append(_badge("security", f"{total}_findings", status_color))
    badges.append(
        _badge("risk_score", f"{scoring.score}/10", _GRADE_BADGE_COLORS.get(scoring.grade, "red")),
    )

    owasp_covered = scoring.owasp.covered_ids
    if owasp_covered:
        badges.append(
            _badge("OWASP_LLM", f"{len(owasp_covered)}_items", "orange"),
        )

    for sev_name, color in _BADGE_COLORS.items():
        count = result.counts_by_severity.get(sev_name, 0)
        if count:
            badges.append(_badge(sev_name.lower(), count, color))

    lines.append(" ".join(badges))
    lines.append("")

    # Metadata
    lines.append(f"**Project:** `{result.project_path}`  ")
    lines.append(f"**Scan ID:** `{result.scan_id}`  ")
    lines.append(f"**Risk Score:** {scoring.score}/10 (Grade **{scoring.grade}**)  ")
    if result.finished_at and result.started_at:
        delta = result.finished_at - result.started_at
        lines.append(f"**Duration:** {delta.total_seconds():.1f}s  ")
    lines.append("")

    if not result.findings and (not probe or not probe.responses):
        lines.append("> No security issues detected.\n")
        return "\n".join(lines)

    # Summary table
    if result.findings:
        lines.append("## Summary\n")
        lines.append("| Severity | Count |")
        lines.append("|----------|-------|")
        for sev_name in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            count = result.counts_by_severity.get(sev_name, 0)
            if count:
                lines.append(f"| {sev_name} | {count} |")
        lines.append("")

        # Findings table
        lines.append("## Findings\n")
        lines.append("| Severity | Rule | Title | Location |")
        lines.append("|----------|------|-------|----------|")

        sorted_findings = sorted(
            result.findings,
            key=lambda f: f.severity,
            reverse=True,
        )
        for f in sorted_findings:
            loc = ""
            if f.file_path:
                loc = f"`{f.file_path}"
                if f.line_number:
                    loc += f":{f.line_number}"
                loc += "`"
            lines.append(
                f"| **{f.severity.label}** | `{f.rule_id}` | {f.title} | {loc} |",
            )
        lines.append("")

        # Collapsible details
        lines.append("<details>")
        lines.append("<summary>Detailed Findings</summary>\n")
        for f in sorted_findings:
            lines.append(f"### {f.severity.label}: {f.title}\n")
            lines.append(f"- **Rule:** `{f.rule_id}`")
            lines.append(f"- **Description:** {f.description}")
            if f.file_path:
                loc = f.file_path
                if f.line_number:
                    loc += f":{f.line_number}"
                lines.append(f"- **Location:** `{loc}`")
            if f.matched_text:
                lines.append(f"- **Matched:** `{f.matched_text}`")
            lines.append("")
        lines.append("</details>\n")

    # Probe results
    if probe and probe.responses:
        lines.append("## Probe Results\n")
        lines.append("| Payload | Verdict | Confidence |")
        lines.append("|---------|---------|------------|")
        for r in probe.responses:
            verdict = "Vulnerable" if r.is_vulnerable else "Safe"
            conf = f"{r.judge_confidence * 100:.0f}%"
            lines.append(f"| `{r.payload_name}` | {verdict} | {conf} |")
        lines.append("")

    # OWASP coverage
    lines.append("## OWASP LLM Top 10 Coverage\n")
    for owasp_id, owasp_title in OWASP_LLM_TOP_10.items():
        check = "x" if owasp_id in owasp_covered else " "
        lines.append(f"- [{check}] **{owasp_id}**: {owasp_title}")
    lines.append("")

    # Remediation
    if scoring.remediation:
        lines.append("## Remediation Plan\n")
        for i, action in enumerate(scoring.remediation, 1):
            lines.append(f"{i}. {action}")
        lines.append("")

    return "\n".join(lines)


def write_markdown(
    result: ScanResult,
    output_path: str | Path,
    *,
    probe: ProbeResult | None = None,
    **kwargs: str,
) -> Path:
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(render_markdown(result, probe=probe, **kwargs))
    return path
