"""Audit MCP server configurations for dangerous permissions."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from ai_secrets_guard.core.models import Finding
from ai_secrets_guard.core.severity import Severity

DANGEROUS_PERMISSIONS = {
    "full_network": (Severity.HIGH, "Unrestricted network access allows data exfiltration"),
    "all": (Severity.CRITICAL, "Sandbox completely disabled — arbitrary code execution possible"),
    "git_write": (Severity.MEDIUM, "Git write access can modify repository history"),
}

RISKY_TOOL_PATTERNS = [
    ("shell", "exec", Severity.HIGH, "Shell execution tool can run arbitrary commands"),
    ("filesystem", "write", Severity.MEDIUM, "File write access outside workspace"),
    ("browser", "navigate", Severity.MEDIUM, "Browser automation can access arbitrary URLs"),
]

DANGEROUS_TOOL_KEYWORDS = ["exec", "shell", "subprocess", "eval", "os.system", "popen"]

MCP_CONFIG_FILES = [
    ".cursor/mcp.json",
    ".vscode/mcp.json",
    "mcp.json",
    "claude_desktop_config.json",
    ".mcp/config.json",
]


def audit_mcp_config(path: Path) -> list[Finding]:
    findings: list[Finding] = []
    for config_name in MCP_CONFIG_FILES:
        config_path = path / config_name
        if config_path.exists():
            findings.extend(_audit_single_config(config_path))
    return findings


def _audit_single_config(config_path: Path) -> list[Finding]:
    findings: list[Finding] = []
    try:
        data = json.loads(config_path.read_text())
    except (json.JSONDecodeError, OSError):
        findings.append(
            Finding(
                rule_id="MCP-PARSE-001",
                severity=Severity.LOW,
                title="Malformed MCP config",
                description="Could not parse MCP configuration file",
                file_path=str(config_path),
            )
        )
        return findings

    servers = data.get("mcpServers", data.get("servers", {}))
    if not isinstance(servers, dict):
        return findings

    for server_name, server_cfg in servers.items():
        if not isinstance(server_cfg, dict):
            continue

        _check_permissions(server_name, server_cfg, str(config_path), findings)
        _check_command_risks(server_name, server_cfg, str(config_path), findings)
        _check_env_secrets(server_name, server_cfg, str(config_path), findings)
        _check_header_trust(server_name, server_cfg, str(config_path), findings)
        _check_tool_descriptions(server_name, server_cfg, str(config_path), findings)
        _check_missing_input_schema(server_name, server_cfg, str(config_path), findings)
        _check_insecure_transport(server_name, server_cfg, str(config_path), findings)

    return findings


def _check_permissions(
    server_name: str,
    server_cfg: dict[str, Any],
    file_path: str,
    findings: list[Finding],
) -> None:
    perms = server_cfg.get("required_permissions", server_cfg.get("permissions", []))
    if not isinstance(perms, list):
        return
    for perm in perms:
        if perm in DANGEROUS_PERMISSIONS:
            severity, desc = DANGEROUS_PERMISSIONS[perm]
            findings.append(
                Finding(
                    rule_id=f"MCP-PERM-{perm.upper().replace('_', '')}",
                    severity=severity,
                    title=f"Dangerous MCP permission: {perm}",
                    description=f"Server '{server_name}': {desc}",
                    file_path=file_path,
                    metadata={"server": server_name, "permission": perm},
                )
            )


def _check_command_risks(
    server_name: str,
    server_cfg: dict[str, Any],
    file_path: str,
    findings: list[Finding],
) -> None:
    command = server_cfg.get("command", "")
    args = server_cfg.get("args", [])
    full_cmd = f"{command} {' '.join(str(a) for a in args) if isinstance(args, list) else ''}"
    for tool_key, risk_key, severity, desc in RISKY_TOOL_PATTERNS:
        if tool_key in full_cmd.lower() and risk_key in full_cmd.lower():
            findings.append(
                Finding(
                    rule_id="MCP-TOOL-RISK",
                    severity=severity,
                    title="Risky MCP tool configuration",
                    description=f"Server '{server_name}': {desc}",
                    file_path=file_path,
                    metadata={"server": server_name, "command": command},
                )
            )


def _check_env_secrets(
    server_name: str,
    server_cfg: dict[str, Any],
    file_path: str,
    findings: list[Finding],
) -> None:
    env = server_cfg.get("env", {})
    if not isinstance(env, dict):
        return
    for key, val in env.items():
        if isinstance(val, str) and _looks_like_secret(val):
            findings.append(
                Finding(
                    rule_id="MCP-ENV-SECRET",
                    severity=Severity.CRITICAL,
                    title="Hardcoded secret in MCP config",
                    description=f"Server '{server_name}' has potential secret in env var '{key}'",
                    file_path=file_path,
                    metadata={"server": server_name, "env_key": key},
                )
            )


def _check_header_trust(
    server_name: str,
    server_cfg: dict[str, Any],
    file_path: str,
    findings: list[Finding],
) -> None:
    """Detect x-request-from or similar internal-trust headers."""
    headers = server_cfg.get("headers", {})
    if not isinstance(headers, dict):
        return
    trust_headers = {"x-request-from", "x-internal", "x-trusted", "x-bypass-auth"}
    for header_name in headers:
        if header_name.lower() in trust_headers:
            findings.append(
                Finding(
                    rule_id="MCP-HEADER-TRUST",
                    severity=Severity.HIGH,
                    title="Internal header trust pattern",
                    description=(
                        f"Server '{server_name}' uses header "
                        f"'{header_name}' — can be spoofed by attackers"
                    ),
                    file_path=file_path,
                    metadata={"server": server_name, "header": header_name},
                )
            )


def _check_tool_descriptions(
    server_name: str,
    server_cfg: dict[str, Any],
    file_path: str,
    findings: list[Finding],
) -> None:
    """Detect tools whose descriptions mention exec/shell/subprocess."""
    tools = server_cfg.get("tools", [])
    if not isinstance(tools, list):
        return
    for tool in tools:
        if not isinstance(tool, dict):
            continue
        desc = str(tool.get("description", "")).lower()
        name = str(tool.get("name", "")).lower()
        combined = f"{name} {desc}"
        for keyword in DANGEROUS_TOOL_KEYWORDS:
            if keyword in combined:
                findings.append(
                    Finding(
                        rule_id="MCP-TOOL-EXEC",
                        severity=Severity.HIGH,
                        title="Tool with execution capability",
                        description=f"Server '{server_name}', tool '{tool.get('name', '?')}' — "
                        f"contains '{keyword}' in description/name",
                        file_path=file_path,
                        metadata={
                            "server": server_name,
                            "tool": tool.get("name", ""),
                            "keyword": keyword,
                        },
                    )
                )
                break


def _check_missing_input_schema(
    server_name: str,
    server_cfg: dict[str, Any],
    file_path: str,
    findings: list[Finding],
) -> None:
    """Detect tools without input schema validation."""
    tools = server_cfg.get("tools", [])
    if not isinstance(tools, list):
        return
    for tool in tools:
        if not isinstance(tool, dict):
            continue
        has_schema = bool(
            tool.get("inputSchema") or tool.get("input_schema") or tool.get("parameters")
        )
        if not has_schema:
            findings.append(
                Finding(
                    rule_id="MCP-NO-SCHEMA",
                    severity=Severity.MEDIUM,
                    title="Tool missing input schema validation",
                    description=f"Server '{server_name}', tool '{tool.get('name', '?')}' — "
                    "no input schema defined, user input is unvalidated",
                    file_path=file_path,
                    metadata={"server": server_name, "tool": tool.get("name", "")},
                )
            )


def _check_insecure_transport(
    server_name: str,
    server_cfg: dict[str, Any],
    file_path: str,
    findings: list[Finding],
) -> None:
    """Detect HTTP (not HTTPS) URLs for remote servers."""
    url = server_cfg.get("url", server_cfg.get("endpoint", ""))
    if not isinstance(url, str):
        return
    if re.match(r"^http://(?!localhost|127\.0\.0\.1|0\.0\.0\.0|\[::1\])", url):
        findings.append(
            Finding(
                rule_id="MCP-INSECURE-HTTP",
                severity=Severity.HIGH,
                title="Insecure HTTP transport for remote MCP server",
                description=f"Server '{server_name}' uses unencrypted HTTP: {url}",
                file_path=file_path,
                metadata={"server": server_name, "url": url},
            )
        )


def _looks_like_secret(value: str) -> bool:
    if len(value) < 16:
        return False
    prefixes = ("sk-", "sk-ant-", "hf_", "gsk_", "r8_", "fw_", "pplx-", "ghp_", "xox", "pcsk_")
    if any(value.startswith(p) for p in prefixes):
        return True
    return bool(value.startswith("AKIA"))
