# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/).

## [0.1.0] — 2026-03-24

### Added

- Initial release
- **Static scanning**: secrets detection for 25+ AI/ML providers (OpenAI, Anthropic, Google, HuggingFace, Cohere, Pinecone, LangSmith, AWS, and more)
- **MCP config audit**: dangerous permissions, hardcoded secrets, insecure transport, shell execution tools, missing input schemas, header trust patterns
- **Prompt injection analysis**: 12 pattern rules covering override instructions, jailbreak keywords, system prompt extraction, unsanitized interpolation, Jinja2 SSTI
- **Vulnerable dependency checks**: 12 known-vulnerable AI/ML packages (langchain, gradio, transformers, torch, and more)
- **Dynamic probing**: 24 built-in payloads across injection, jailbreak, and exfiltration categories with LLM-as-judge verdict scoring
- **Reports**: HTML (dark theme, collapsible findings, risk gauge), JSON (machine-readable), Markdown (GitHub-ready)
- **GitHub Action** for automated PR scanning
- **Docker** support with multi-stage build
- **CI pipeline**: lint, typecheck, test matrix (Python 3.11/3.12/3.13), coverage reporting
