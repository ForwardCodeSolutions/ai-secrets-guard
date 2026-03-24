"""JSON report output for CI/CD integration.

Produces a machine-readable report with metadata, scan results, probe results,
risk score, OWASP coverage, and a severity summary for quick pipeline checks.
"""

from __future__ import annotations

import datetime as dt
import json
from pathlib import Path
from typing import Any

import ai_secrets_guard
from ai_secrets_guard.core.models import ProbeResult, ScanResult
from ai_secrets_guard.core.scoring import OWASP_LLM_TOP_10, compute_score


def render_json(
    result: ScanResult,
    *,
    indent: int = 2,
    probe: ProbeResult | None = None,
) -> str:
    """Render a full JSON report with all sections."""
    scoring = compute_score(scan=result, probe=probe)

    report: dict[str, Any] = {
        "metadata": {
            "tool": "ai-secrets-guard",
            "version": ai_secrets_guard.__version__,
            "generated_at": dt.datetime.now(dt.UTC).isoformat(),
            "project_path": result.project_path,
            "scan_id": result.scan_id,
        },
        "score": {
            "value": scoring.score,
            "grade": scoring.grade,
            "max": 10.0,
        },
        "summary": result.counts_by_severity,
        "scan_results": {
            "total_findings": len(result.findings),
            "findings": [
                {
                    "rule_id": f.rule_id,
                    "severity": f.severity.label,
                    "title": f.title,
                    "description": f.description,
                    "file_path": f.file_path,
                    "line_number": f.line_number,
                    "matched_text": f.matched_text,
                }
                for f in sorted(
                    result.findings,
                    key=lambda f: f.severity,
                    reverse=True,
                )
            ],
        },
        "probe_results": _probe_section(probe),
        "owasp_coverage": {
            "covered": scoring.owasp.covered_ids,
            "items": {
                owasp_id: {
                    "title": title,
                    "covered": owasp_id in scoring.owasp.covered_ids,
                }
                for owasp_id, title in OWASP_LLM_TOP_10.items()
            },
        },
        "remediation": scoring.remediation,
    }

    return json.dumps(report, indent=indent, default=str)


def _probe_section(probe: ProbeResult | None) -> dict[str, Any]:
    if not probe:
        return {"total": 0, "vulnerable": 0, "responses": []}
    return {
        "target_url": probe.target_url,
        "total": len(probe.responses),
        "vulnerable": probe.vulnerable_count,
        "responses": [
            {
                "payload_name": r.payload_name,
                "is_vulnerable": r.is_vulnerable,
                "confidence": r.judge_confidence,
                "evidence": r.evidence,
                "technique": r.technique,
                "verdict": r.judge_verdict,
                "raw_response_preview": r.raw_response[:200],
            }
            for r in probe.responses
        ],
    }


def write_json(
    result: ScanResult,
    output_path: str | Path,
    *,
    probe: ProbeResult | None = None,
) -> Path:
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(render_json(result, probe=probe))
    return path
