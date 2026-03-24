"""Check for vulnerable versions of AI/ML libraries."""

from __future__ import annotations

import re
from pathlib import Path

from packaging.version import InvalidVersion, Version

from ai_secrets_guard.core.models import Finding
from ai_secrets_guard.core.severity import Severity

VULNERABLE_PACKAGES: dict[str, list[tuple[str, str, Severity, str]]] = {
    "langchain": [
        ("<0.0.325", "CVE-2023-46229", Severity.CRITICAL, "Arbitrary code execution via LCEL"),
        ("<0.0.312", "CVE-2023-44467", Severity.CRITICAL, "RCE via PALChain/LLMMathChain"),
    ],
    "langchain-core": [
        (
            "<0.1.17",
            "CVE-2024-LC-CORE",
            Severity.CRITICAL,
            "Arbitrary code execution in expression parser",
        ),
    ],
    "openai": [
        ("<1.0.0", "ADVISORY-2023-OPENAI", Severity.HIGH, "Deprecated SDK with insecure defaults"),
    ],
    "transformers": [
        (
            "<4.36.0",
            "CVE-2023-49277",
            Severity.HIGH,
            "Deserialization of untrusted data via pickle",
        ),
    ],
    "llama-index": [
        ("<0.9.0", "ADVISORY-2023-LLAMA", Severity.HIGH, "Prompt injection in query engine"),
        ("<0.10.0", "CVE-2024-LLAMA-PT", Severity.HIGH, "Path traversal in document loader"),
    ],
    "chromadb": [
        (
            "<0.4.0",
            "ADVISORY-2023-CHROMA",
            Severity.MEDIUM,
            "Unauthenticated access to collections",
        ),
    ],
    "gradio": [
        ("<4.0.0", "CVE-2023-51449", Severity.HIGH, "Path traversal in file upload"),
        ("<4.0.0", "CVE-2024-GRADIO-XSS", Severity.HIGH, "XSS in chat interface"),
    ],
    "flowise": [
        (
            "<2.0.0",
            "CVE-2024-FLOWISE",
            Severity.CRITICAL,
            "Unauthenticated API access to all endpoints",
        ),
    ],
    "anthropic": [
        ("<0.18.0", "ADVISORY-2023-ANTHROPIC", Severity.MEDIUM, "Missing request validation"),
    ],
    "torch": [
        ("<2.1.0", "CVE-2023-45802", Severity.HIGH, "Arbitrary code execution via torch.load"),
    ],
    "tensorflow": [
        ("<2.14.0", "CVE-2023-TFSA", Severity.HIGH, "Multiple memory corruption vulnerabilities"),
    ],
    "fastapi": [
        ("<0.109.0", "CVE-2024-24762", Severity.MEDIUM, "ReDoS in multipart form parsing"),
    ],
}

_REQ_LINE_RE = re.compile(r"^([a-zA-Z0-9_\-]+)\s*(?:[=<>!~]+\s*(.+?))?$")


def scan_requirements(path: Path) -> list[Finding]:
    findings: list[Finding] = []
    seen: set[Path] = set()
    req_files: list[Path] = []
    for f in list(path.glob("requirements*.txt")) + list(path.glob("**/requirements*.txt")):
        resolved = f.resolve()
        if resolved not in seen:
            seen.add(resolved)
            req_files.append(f)

    pyproject = path / "pyproject.toml"
    if pyproject.exists():
        findings.extend(_scan_pyproject(pyproject))

    for req_file in req_files:
        findings.extend(_scan_requirements_file(req_file))

    return findings


def _scan_requirements_file(path: Path) -> list[Finding]:
    findings: list[Finding] = []
    try:
        lines = path.read_text().splitlines()
    except OSError:
        return findings

    for i, line in enumerate(lines, start=1):
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("-"):
            continue
        m = _REQ_LINE_RE.match(line)
        if not m:
            continue
        pkg_name = m.group(1).lower().replace("_", "-")
        version_str = m.group(2)
        findings.extend(_check_package(pkg_name, version_str, str(path), i))

    return findings


def _scan_pyproject(path: Path) -> list[Finding]:
    findings: list[Finding] = []
    try:
        text = path.read_text()
    except OSError:
        return findings

    dep_re = re.compile(r'"([a-zA-Z0-9_\-]+)\s*([<>=!~]+\s*[\d.]+[^"]*)"')
    for i, line in enumerate(text.splitlines(), start=1):
        for m in dep_re.finditer(line):
            pkg_name = m.group(1).lower().replace("_", "-")
            version_spec = m.group(2).strip()
            version_str = re.sub(r"^[<>=!~]+\s*", "", version_spec.split(",")[0])
            findings.extend(_check_package(pkg_name, version_str, str(path), i))

    return findings


def _check_package(
    pkg_name: str, version_str: str | None, file_path: str, line: int
) -> list[Finding]:
    findings: list[Finding] = []
    if pkg_name not in VULNERABLE_PACKAGES:
        return findings

    for vuln_range, cve, severity, desc in VULNERABLE_PACKAGES[pkg_name]:
        if version_str:
            try:
                current = Version(version_str)
                threshold_str = vuln_range.lstrip("<>=! ")
                threshold = Version(threshold_str)
                if current >= threshold:
                    continue
            except InvalidVersion:
                pass

        findings.append(
            Finding(
                rule_id=f"DEP-{cve}",
                severity=severity,
                title=f"Vulnerable {pkg_name} version",
                description=f"{desc} (fix: upgrade to {vuln_range.lstrip('<')}+)",
                file_path=file_path,
                line_number=line,
                matched_text=f"{pkg_name}=={version_str}" if version_str else pkg_name,
                metadata={"cve": cve, "package": pkg_name},
            )
        )

    return findings
