# ai-secrets-guard

[![CI](https://github.com/ForwardCodeSolutions/ai-secrets-guard/actions/workflows/ci.yml/badge.svg)](https://github.com/ForwardCodeSolutions/ai-secrets-guard/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/ForwardCodeSolutions/ai-secrets-guard/branch/main/graph/badge.svg)](https://codecov.io/gh/ForwardCodeSolutions/ai-secrets-guard)
[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![PyPI](https://img.shields.io/pypi/v/ai-secrets-guard.svg)](https://pypi.org/project/ai-secrets-guard/)

**Security scanner for AI/LLM projects** — find leaked API keys, unsafe MCP configs, prompt injection vectors, and vulnerable dependencies before they reach production.

## Features

- **Secrets Detection** — 25+ AI/ML providers covered (OpenAI, Anthropic, Google, HuggingFace, Cohere, Pinecone, LangSmith, AWS, and more), with contextual matching to reduce false positives
- **MCP Config Audit** — dangerous permissions, hardcoded secrets, insecure HTTP transport, shell execution tools, missing input schemas, spoofable headers
- **Prompt Injection Analysis** — 12 pattern rules: override instructions, jailbreak keywords, system prompt extraction, unsanitized f-strings, unsafe `.format()`, Jinja2 SSTI
- **Dynamic Endpoint Probing** — 24 built-in payloads across 3 categories (injection, jailbreak, exfiltration) with LLM-as-judge verdict scoring

## Installation

```bash
# via uv (recommended)
uv tool install ai-secrets-guard

# via pip
pip install ai-secrets-guard
```

## Quick Start

### Static scan

```bash
$ ai-secrets-guard scan ./my-project
```

```
                 Security Findings
 ───────────────────────────────────────────────────
  Severity   Rule             Title                Location
 ───────────────────────────────────────────────────
  CRITICAL   SEC-OPENAI-001   Leaked OpenAI secret config.py:10
  CRITICAL   MCP-PERM-ALL     Dangerous MCP perm…  .cursor/mcp.json
  HIGH       PI-IGNORE-001    Prompt override      prompts/base.txt:3
 ───────────────────────────────────────────────────

  Total: 3 findings
```

### Dynamic probe

```bash
$ ai-secrets-guard probe --target https://api.example.com/v1/chat
```

```
  3/24 payloads triggered vulnerabilities

  * direct_override:        Vulnerable (confidence 0.95)
  * system_tag_injection:   Vulnerable (confidence 0.88)
  * html_comment_escape:    Safe
  ...
```

### Generate reports

```bash
$ ai-secrets-guard report --input results.json --format all
```

```
  + HTML:     reports/report.html
  + JSON:     reports/report.json
  + Markdown: reports/report.md
```

## Modes

| Mode | Command | Description | Key Flags |
|------|---------|-------------|-----------|
| **Scan** | `ai-secrets-guard scan <path>` | Static analysis of source files | `--format json\|table` `--fail-on <severity>` |
| **Probe** | `ai-secrets-guard probe --target <url>` | Live endpoint testing with payloads | `--model <name>` `--judge/--no-judge` `--category <cat>` |
| **Report** | `ai-secrets-guard report --input <file>` | Generate HTML/JSON/Markdown reports | `--format html\|json\|markdown\|all` `--title <text>` |

## GitHub Action

Add to any repository to scan PRs automatically:

```yaml
# .github/workflows/security.yml
name: Security Scan
on: [pull_request]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: ForwardCodeSolutions/ai-secrets-guard@main
        with:
          path: "."
          fail-on: "high"
```

## OWASP LLM Top 10 Coverage

| ID | Risk | Covered | How |
|----|------|---------|-----|
| LLM01 | Prompt Injection | Yes | 12 static patterns + 24 dynamic payloads |
| LLM02 | Insecure Output Handling | Partial | Detects unsanitized template interpolation |
| LLM03 | Training Data Poisoning | No | Out of scope (runtime scanner) |
| LLM04 | Model Denial of Service | No | Out of scope |
| LLM05 | Supply Chain Vulnerabilities | Yes | Vulnerable dependency checks (12 packages) |
| LLM06 | Sensitive Information Disclosure | Yes | 25 providers, 38 secret patterns |
| LLM07 | Insecure Plugin Design | Yes | Full MCP config audit (7 checks) |
| LLM08 | Excessive Agency | Partial | MCP permission and tool description audit |
| LLM09 | Overreliance | No | Out of scope |
| LLM10 | Model Theft | Partial | Detects leaked API keys that grant model access |

## How Probe Judging Works

When running dynamic probes, each payload is sent to the target endpoint and the response is evaluated by an LLM acting as a security judge. The judge analyzes whether the model was exploited across three dimensions: system prompt disclosure, behavioral override, and jailbreak compliance. Each verdict includes a confidence score (0.0 to 1.0), and low-confidence results are automatically downgraded to avoid false positives.

## Docker

```bash
docker build -t ai-secrets-guard .
docker run --rm -v $(pwd):/workspace ai-secrets-guard scan /workspace
```

## License

MIT License - Copyright (c) 2026 ForwardCodeSolutions

See [LICENSE](LICENSE) for full text.
