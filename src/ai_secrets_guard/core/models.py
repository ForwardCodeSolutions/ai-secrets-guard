from __future__ import annotations

import datetime as dt
from typing import Any

from pydantic import BaseModel, Field

from .severity import Severity


class Finding(BaseModel):
    rule_id: str
    severity: Severity
    title: str
    description: str
    file_path: str | None = None
    line_number: int | None = None
    matched_text: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class ScanResult(BaseModel):
    scan_id: str = Field(default_factory=lambda: dt.datetime.now(dt.UTC).strftime("%Y%m%d%H%M%S"))
    project_path: str = ""
    started_at: dt.datetime = Field(default_factory=lambda: dt.datetime.now(dt.UTC))
    finished_at: dt.datetime | None = None
    findings: list[Finding] = Field(default_factory=list)

    @property
    def counts_by_severity(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for f in self.findings:
            key = f.severity.label
            counts[key] = counts.get(key, 0) + 1
        return counts

    @property
    def max_severity(self) -> Severity:
        if not self.findings:
            return Severity.INFO
        return max(f.severity for f in self.findings)


class ProbePayload(BaseModel):
    name: str
    category: str
    messages: list[dict[str, str]]
    expected_behavior: str = ""


class ProbeLog(BaseModel):
    """Full request/response log entry for audit trail."""

    payload_name: str
    request_url: str = ""
    request_headers: dict[str, str] = Field(default_factory=dict)
    request_body: dict[str, object] = Field(default_factory=dict)
    response_status: int = 0
    response_headers: dict[str, str] = Field(default_factory=dict)
    response_body: str = ""
    timestamp: dt.datetime = Field(default_factory=lambda: dt.datetime.now(dt.UTC))
    duration_ms: float = 0.0
    error: str | None = None


class ProbeResponse(BaseModel):
    payload_name: str
    raw_response: str
    is_vulnerable: bool = False
    judge_verdict: str = ""
    judge_confidence: float = 0.0
    evidence: str = ""
    technique: str = ""


class ProbeResult(BaseModel):
    target_url: str
    model: str = ""
    started_at: dt.datetime = Field(default_factory=lambda: dt.datetime.now(dt.UTC))
    finished_at: dt.datetime | None = None
    responses: list[ProbeResponse] = Field(default_factory=list)
    logs: list[ProbeLog] = Field(default_factory=list)

    @property
    def vulnerable_count(self) -> int:
        return sum(1 for r in self.responses if r.is_vulnerable)
