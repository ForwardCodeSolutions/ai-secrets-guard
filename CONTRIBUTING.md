# Contributing to ai-secrets-guard

Thank you for your interest in contributing!

## Requirements

- Python 3.11+
- [uv](https://docs.astral.sh/uv/) package manager

## Setup

```bash
git clone https://github.com/ForwardCodeSolutions/ai-secrets-guard.git
cd ai-secrets-guard
uv sync --all-extras
```

## Development

### Run tests

```bash
uv run pytest
uv run pytest --cov=src/ai_secrets_guard --cov-branch   # with coverage
```

### Code style

This project uses [Ruff](https://docs.astral.sh/ruff/) for linting and formatting:

```bash
uv run ruff check src/ tests/
uv run ruff format src/ tests/
```

### Type checking

```bash
uv run mypy src/
```

## Pull Request Guidelines

- **One feature per PR** — keep changes focused and reviewable
- All tests must pass (`uv run pytest`)
- No lint errors (`uv run ruff check src/`)
- Add tests for new functionality
- Update `CHANGELOG.md` under an `[Unreleased]` section
