from __future__ import annotations

import json
from pathlib import Path

from ai_secrets_guard.scan.mcp_audit import audit_mcp_config


def _write_mcp(tmp_path: Path, config: dict) -> None:
    d = tmp_path / ".cursor"
    d.mkdir(exist_ok=True)
    (d / "mcp.json").write_text(json.dumps(config))


# ---------------------------------------------------------------------------
# Existing checks
# ---------------------------------------------------------------------------


class TestPermissions:
    def test_detects_all_permission(self, tmp_path: Path) -> None:
        cfg = {"mcpServers": {"s": {"command": "x", "required_permissions": ["all"]}}}
        _write_mcp(tmp_path, cfg)
        findings = audit_mcp_config(tmp_path)
        assert any("all" in f.title.lower() for f in findings)

    def test_detects_full_network(self, tmp_path: Path) -> None:
        cfg = {"mcpServers": {"s": {"command": "x", "required_permissions": ["full_network"]}}}
        _write_mcp(tmp_path, cfg)
        findings = audit_mcp_config(tmp_path)
        assert any(f.severity.label == "HIGH" for f in findings)

    def test_detects_git_write(self, tmp_path: Path) -> None:
        cfg = {"mcpServers": {"s": {"command": "x", "required_permissions": ["git_write"]}}}
        _write_mcp(tmp_path, cfg)
        findings = audit_mcp_config(tmp_path)
        assert any("git_write" in f.title for f in findings)

    def test_no_permissions_is_clean(self, tmp_path: Path) -> None:
        _write_mcp(tmp_path, {"mcpServers": {"s": {"command": "node", "args": ["s.js"]}}})
        assert audit_mcp_config(tmp_path) == []


class TestEnvSecrets:
    def test_detects_hardcoded_secret(self, tmp_path: Path) -> None:
        secret = "sk-ant-api03-" + "x" * 90
        _write_mcp(tmp_path, {"mcpServers": {"s": {"command": "x", "env": {"K": secret}}}})
        assert any(f.rule_id == "MCP-ENV-SECRET" for f in audit_mcp_config(tmp_path))

    def test_short_value_ignored(self, tmp_path: Path) -> None:
        _write_mcp(tmp_path, {"mcpServers": {"s": {"command": "x", "env": {"K": "short"}}}})
        assert not any(f.rule_id == "MCP-ENV-SECRET" for f in audit_mcp_config(tmp_path))


class TestParseErrors:
    def test_malformed_json(self, tmp_path: Path) -> None:
        d = tmp_path / ".cursor"
        d.mkdir()
        (d / "mcp.json").write_text("{bad")
        assert any(f.rule_id == "MCP-PARSE-001" for f in audit_mcp_config(tmp_path))

    def test_servers_not_dict(self, tmp_path: Path) -> None:
        _write_mcp(tmp_path, {"mcpServers": "not_a_dict"})
        assert audit_mcp_config(tmp_path) == []

    def test_server_value_not_dict(self, tmp_path: Path) -> None:
        _write_mcp(tmp_path, {"mcpServers": {"s": "bad_value"}})
        assert audit_mcp_config(tmp_path) == []

    def test_no_config_files(self, tmp_path: Path) -> None:
        assert audit_mcp_config(tmp_path) == []


class TestCommandRisks:
    def test_shell_exec_detected(self, tmp_path: Path) -> None:
        _write_mcp(tmp_path, {"mcpServers": {"s": {"command": "shell-exec", "args": ["--exec"]}}})
        assert any(f.rule_id == "MCP-TOOL-RISK" for f in audit_mcp_config(tmp_path))

    def test_safe_command_clean(self, tmp_path: Path) -> None:
        _write_mcp(tmp_path, {"mcpServers": {"s": {"command": "node", "args": ["server.js"]}}})
        assert audit_mcp_config(tmp_path) == []


# ---------------------------------------------------------------------------
# NEW: Header trust pattern
# ---------------------------------------------------------------------------


class TestHeaderTrust:
    def test_detects_x_request_from(self, tmp_path: Path) -> None:
        _write_mcp(
            tmp_path,
            {
                "mcpServers": {
                    "s": {
                        "command": "node",
                        "headers": {"X-Request-From": "internal"},
                    }
                }
            },
        )
        findings = audit_mcp_config(tmp_path)
        assert any(f.rule_id == "MCP-HEADER-TRUST" for f in findings)

    def test_detects_x_bypass_auth(self, tmp_path: Path) -> None:
        _write_mcp(
            tmp_path,
            {
                "mcpServers": {
                    "s": {
                        "command": "node",
                        "headers": {"x-bypass-auth": "true"},
                    }
                }
            },
        )
        findings = audit_mcp_config(tmp_path)
        assert any(f.rule_id == "MCP-HEADER-TRUST" for f in findings)

    def test_safe_headers_clean(self, tmp_path: Path) -> None:
        _write_mcp(
            tmp_path,
            {
                "mcpServers": {
                    "s": {
                        "command": "node",
                        "headers": {"Content-Type": "application/json"},
                    }
                }
            },
        )
        assert not any(f.rule_id == "MCP-HEADER-TRUST" for f in audit_mcp_config(tmp_path))

    def test_no_headers_key(self, tmp_path: Path) -> None:
        _write_mcp(tmp_path, {"mcpServers": {"s": {"command": "node"}}})
        assert not any(f.rule_id == "MCP-HEADER-TRUST" for f in audit_mcp_config(tmp_path))


# ---------------------------------------------------------------------------
# NEW: Exec/shell/subprocess in tool descriptions
# ---------------------------------------------------------------------------


class TestToolDescriptions:
    def test_detects_exec_in_description(self, tmp_path: Path) -> None:
        _write_mcp(
            tmp_path,
            {
                "mcpServers": {
                    "s": {
                        "command": "node",
                        "tools": [
                            {"name": "run_code", "description": "Execute arbitrary shell commands"}
                        ],
                    }
                }
            },
        )
        findings = audit_mcp_config(tmp_path)
        assert any(f.rule_id == "MCP-TOOL-EXEC" for f in findings)

    def test_detects_subprocess_in_name(self, tmp_path: Path) -> None:
        _write_mcp(
            tmp_path,
            {
                "mcpServers": {
                    "s": {
                        "command": "node",
                        "tools": [{"name": "subprocess_runner", "description": "Runs things"}],
                    }
                }
            },
        )
        assert any(f.rule_id == "MCP-TOOL-EXEC" for f in audit_mcp_config(tmp_path))

    def test_detects_eval(self, tmp_path: Path) -> None:
        _write_mcp(
            tmp_path,
            {
                "mcpServers": {
                    "s": {
                        "command": "node",
                        "tools": [{"name": "code_eval", "description": "eval python expressions"}],
                    }
                }
            },
        )
        assert any(f.rule_id == "MCP-TOOL-EXEC" for f in audit_mcp_config(tmp_path))

    def test_safe_tool_clean(self, tmp_path: Path) -> None:
        _write_mcp(
            tmp_path,
            {
                "mcpServers": {
                    "s": {
                        "command": "node",
                        "tools": [{"name": "search", "description": "Search the web"}],
                    }
                }
            },
        )
        assert not any(f.rule_id == "MCP-TOOL-EXEC" for f in audit_mcp_config(tmp_path))

    def test_no_tools_key(self, tmp_path: Path) -> None:
        _write_mcp(tmp_path, {"mcpServers": {"s": {"command": "node"}}})
        assert not any(f.rule_id == "MCP-TOOL-EXEC" for f in audit_mcp_config(tmp_path))


# ---------------------------------------------------------------------------
# NEW: Missing input schema validation
# ---------------------------------------------------------------------------


class TestMissingInputSchema:
    def test_detects_no_schema(self, tmp_path: Path) -> None:
        _write_mcp(
            tmp_path,
            {
                "mcpServers": {
                    "s": {
                        "command": "node",
                        "tools": [{"name": "dangerous_tool", "description": "Does stuff"}],
                    }
                }
            },
        )
        findings = audit_mcp_config(tmp_path)
        assert any(f.rule_id == "MCP-NO-SCHEMA" for f in findings)

    def test_input_schema_present_is_clean(self, tmp_path: Path) -> None:
        _write_mcp(
            tmp_path,
            {
                "mcpServers": {
                    "s": {
                        "command": "node",
                        "tools": [
                            {
                                "name": "good_tool",
                                "inputSchema": {"type": "object", "properties": {}},
                            }
                        ],
                    }
                }
            },
        )
        assert not any(f.rule_id == "MCP-NO-SCHEMA" for f in audit_mcp_config(tmp_path))

    def test_parameters_key_counts(self, tmp_path: Path) -> None:
        _write_mcp(
            tmp_path,
            {
                "mcpServers": {
                    "s": {
                        "command": "node",
                        "tools": [{"name": "t", "parameters": {"type": "object"}}],
                    }
                }
            },
        )
        assert not any(f.rule_id == "MCP-NO-SCHEMA" for f in audit_mcp_config(tmp_path))

    def test_multiple_tools_mixed(self, tmp_path: Path) -> None:
        _write_mcp(
            tmp_path,
            {
                "mcpServers": {
                    "s": {
                        "command": "node",
                        "tools": [
                            {"name": "safe", "inputSchema": {"type": "object"}},
                            {"name": "unsafe", "description": "No schema"},
                        ],
                    }
                }
            },
        )
        findings = audit_mcp_config(tmp_path)
        schema_findings = [f for f in findings if f.rule_id == "MCP-NO-SCHEMA"]
        assert len(schema_findings) == 1
        assert "unsafe" in schema_findings[0].description


# ---------------------------------------------------------------------------
# NEW: HTTP instead of HTTPS
# ---------------------------------------------------------------------------


class TestInsecureTransport:
    def test_detects_http_remote(self, tmp_path: Path) -> None:
        _write_mcp(
            tmp_path,
            {
                "mcpServers": {
                    "s": {
                        "command": "node",
                        "url": "http://api.evil.com/mcp",
                    }
                }
            },
        )
        findings = audit_mcp_config(tmp_path)
        assert any(f.rule_id == "MCP-INSECURE-HTTP" for f in findings)

    def test_http_localhost_allowed(self, tmp_path: Path) -> None:
        _write_mcp(
            tmp_path,
            {
                "mcpServers": {
                    "s": {
                        "command": "node",
                        "url": "http://localhost:3000/mcp",
                    }
                }
            },
        )
        assert not any(f.rule_id == "MCP-INSECURE-HTTP" for f in audit_mcp_config(tmp_path))

    def test_http_127_allowed(self, tmp_path: Path) -> None:
        _write_mcp(
            tmp_path,
            {
                "mcpServers": {
                    "s": {
                        "command": "node",
                        "url": "http://127.0.0.1:8080/mcp",
                    }
                }
            },
        )
        assert not any(f.rule_id == "MCP-INSECURE-HTTP" for f in audit_mcp_config(tmp_path))

    def test_https_is_clean(self, tmp_path: Path) -> None:
        _write_mcp(
            tmp_path,
            {
                "mcpServers": {
                    "s": {
                        "command": "node",
                        "url": "https://api.secure.com/mcp",
                    }
                }
            },
        )
        assert not any(f.rule_id == "MCP-INSECURE-HTTP" for f in audit_mcp_config(tmp_path))

    def test_endpoint_field(self, tmp_path: Path) -> None:
        _write_mcp(
            tmp_path,
            {
                "mcpServers": {
                    "s": {
                        "command": "node",
                        "endpoint": "http://remote.server.com:9090",
                    }
                }
            },
        )
        assert any(f.rule_id == "MCP-INSECURE-HTTP" for f in audit_mcp_config(tmp_path))

    def test_no_url_is_clean(self, tmp_path: Path) -> None:
        _write_mcp(tmp_path, {"mcpServers": {"s": {"command": "node"}}})
        assert not any(f.rule_id == "MCP-INSECURE-HTTP" for f in audit_mcp_config(tmp_path))
