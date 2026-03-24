# Examples

## Vulnerable Project Demo

The `vulnerable_project/` directory contains an intentionally insecure AI application with multiple security issues that `ai-secrets-guard` can detect.

### What's inside

| File | Vulnerabilities |
|------|----------------|
| `app.py` | Hardcoded OpenAI key, f-string prompt injection, unsanitized `.format()`, prompt override pattern |
| `.env` | Leaked API keys for OpenAI, Anthropic, Groq, LangSmith |
| `mcp_config.json` | Sandbox disabled (`"all"`), hardcoded secret in env, insecure HTTP transport, shell exec tool, spoofable auth header |
| `requirements.txt` | Vulnerable versions of langchain, gradio, openai, transformers, torch |

### Run the demo

```bash
# From the repository root
ai-secrets-guard scan examples/vulnerable_project/
```

Expected output: multiple CRITICAL and HIGH findings across secrets, MCP config, prompt injection, and dependency checks.

### Generate a full report

```bash
ai-secrets-guard scan examples/vulnerable_project/ --format json > results.json
ai-secrets-guard report --input results.json --format all
```

This creates HTML, JSON, and Markdown reports in the `reports/` directory.
