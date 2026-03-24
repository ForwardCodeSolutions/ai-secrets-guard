from __future__ import annotations

from pathlib import Path

from ai_secrets_guard.scan.secrets import PATTERNS, scan_file, scan_line, _redact


class TestRedact:
    def test_short_value(self) -> None:
        assert _redact("abc") == "***"

    def test_long_value(self) -> None:
        result = _redact("sk-abcdef123456")
        assert result.startswith("sk-a")
        assert result.endswith("3456")
        assert "***" in result


class TestPatternCount:
    def test_at_least_25_providers(self) -> None:
        providers = {p.provider for p in PATTERNS}
        assert len(providers) >= 25, f"Only {len(providers)} providers: {providers}"


# ---------------------------------------------------------------------------
# Positive + negative tests for each provider
# ---------------------------------------------------------------------------

class TestOpenAI:
    def test_project_key(self) -> None:
        line = 'KEY = "sk-proj-' + "a" * 85 + '"'
        assert any(f.rule_id == "SEC-OPENAI-002" for f in scan_line(line, 1, "f"))

    def test_safe_sk_prefix(self) -> None:
        assert not any(f.rule_id == "SEC-OPENAI-002" for f in scan_line('sk-proj-short', 1, "f"))


class TestOpenRouter:
    def test_detects_openrouter_key(self) -> None:
        line = 'OPENROUTER_KEY = "sk-or-v1-' + "A" * 64 + '"'
        findings = scan_line(line, 1, ".env")
        assert any(f.rule_id == "SEC-OPENROUTER-001" for f in findings)

    def test_short_openrouter_key_ignored(self) -> None:
        line = 'KEY = "sk-or-v1-short"'
        assert not any(f.rule_id == "SEC-OPENROUTER-001" for f in scan_line(line, 1, "f"))


class TestAnthropic:
    def test_detects_key(self) -> None:
        line = 'KEY = "sk-ant-api03-' + "a" * 95 + '"'
        assert any(f.rule_id == "SEC-ANTHROPIC-001" for f in scan_line(line, 1, ".env"))

    def test_short_prefix_ignored(self) -> None:
        assert not any(f.rule_id == "SEC-ANTHROPIC-001" for f in scan_line('sk-ant-api03-short', 1, "f"))


class TestHuggingFace:
    def test_detects_token(self) -> None:
        line = 'HF_TOKEN = "hf_' + "A" * 36 + '"'
        assert any(f.rule_id == "SEC-HF-001" for f in scan_line(line, 1, "f"))

    def test_short_hf_ignored(self) -> None:
        assert not any(f.rule_id == "SEC-HF-001" for f in scan_line('hf_short', 1, "f"))


class TestGoogleAI:
    def test_detects_gemini_key(self) -> None:
        line = 'GOOGLE_KEY = "AIzaSy' + "a" * 33 + '"'
        assert any(f.rule_id == "SEC-GOOGLE-001" for f in scan_line(line, 1, "f"))


class TestGroq:
    def test_detects_key(self) -> None:
        line = 'GROQ_API_KEY = "gsk_' + "a" * 52 + '"'
        assert any(f.rule_id == "SEC-GROQ-001" for f in scan_line(line, 1, ".env"))

    def test_short_gsk_ignored(self) -> None:
        assert not any(f.rule_id == "SEC-GROQ-001" for f in scan_line('gsk_short', 1, "f"))


class TestMistral:
    def test_with_context(self) -> None:
        line = 'MISTRAL_API_KEY = "' + "a" * 32 + '"'
        assert any(f.rule_id == "SEC-MISTRAL-001" for f in scan_line(line, 1, "f"))

    def test_without_context_ignored(self) -> None:
        line = 'RANDOM_KEY = "' + "a" * 32 + '"'
        assert not any(f.rule_id == "SEC-MISTRAL-001" for f in scan_line(line, 1, "f"))


class TestTogetherAI:
    def test_with_context(self) -> None:
        line = 'TOGETHER_API_KEY = "' + "a" * 64 + '"'
        assert any(f.rule_id == "SEC-TOGETHER-001" for f in scan_line(line, 1, "f"))

    def test_without_context_ignored(self) -> None:
        line = 'OTHER = "' + "a" * 64 + '"'
        assert not any(f.rule_id == "SEC-TOGETHER-001" for f in scan_line(line, 1, "f"))


class TestReplicate:
    def test_detects_token(self) -> None:
        line = 'REPLICATE = "r8_' + "A" * 40 + '"'
        assert any(f.rule_id == "SEC-REPLICATE-001" for f in scan_line(line, 1, "f"))

    def test_short_r8_ignored(self) -> None:
        assert not any(f.rule_id == "SEC-REPLICATE-001" for f in scan_line('r8_abc', 1, "f"))


class TestFireworks:
    def test_detects_key(self) -> None:
        line = 'FW_KEY = "fw_' + "a" * 35 + '"'
        assert any(f.rule_id == "SEC-FIREWORKS-001" for f in scan_line(line, 1, "f"))

    def test_short_fw_ignored(self) -> None:
        assert not any(f.rule_id == "SEC-FIREWORKS-001" for f in scan_line('fw_short', 1, "f"))


class TestPerplexity:
    def test_detects_key(self) -> None:
        line = 'PPLX = "pplx-' + "A" * 50 + '"'
        assert any(f.rule_id == "SEC-PERPLEXITY-001" for f in scan_line(line, 1, "f"))

    def test_short_pplx_ignored(self) -> None:
        assert not any(f.rule_id == "SEC-PERPLEXITY-001" for f in scan_line('pplx-short', 1, "f"))


class TestDeepSeek:
    def test_with_context(self) -> None:
        line = 'DEEPSEEK_API_KEY = "sk-' + "a" * 32 + '"'
        assert any(f.rule_id == "SEC-DEEPSEEK-001" for f in scan_line(line, 1, "f"))

    def test_without_context_ignored(self) -> None:
        line = 'OTHER = "sk-' + "a" * 32 + '"'
        assert not any(f.rule_id == "SEC-DEEPSEEK-001" for f in scan_line(line, 1, "f"))


class TestLangSmith:
    def test_detects_key(self) -> None:
        line = 'LS_KEY = "ls__' + "A" * 35 + '"'
        assert any(f.rule_id == "SEC-LANGSMITH-001" for f in scan_line(line, 1, "f"))

    def test_short_ls_ignored(self) -> None:
        assert not any(f.rule_id == "SEC-LANGSMITH-001" for f in scan_line('ls__short', 1, "f"))


class TestPinecone:
    def test_v2_key(self) -> None:
        line = 'PINE = "pcsk_' + "a" * 35 + '"'
        assert any(f.rule_id == "SEC-PINECONE-001" for f in scan_line(line, 1, "f"))

    def test_uuid_with_context(self) -> None:
        line = 'PINECONE_API_KEY = "abcdef12-3456-7890-abcd-ef1234567890"'
        assert any(f.rule_id == "SEC-PINECONE-002" for f in scan_line(line, 1, "f"))

    def test_uuid_without_context_ignored(self) -> None:
        line = 'OTHER = "abcdef12-3456-7890-abcd-ef1234567890"'
        assert not any(f.rule_id == "SEC-PINECONE-002" for f in scan_line(line, 1, "f"))


class TestAzureOpenAI:
    def test_with_context(self) -> None:
        line = 'AZURE_OPENAI_KEY = "' + "a" * 32 + '"'
        assert any(f.rule_id == "SEC-AZURE-001" for f in scan_line(line, 1, "f"))

    def test_azure_url_context(self) -> None:
        line = 'endpoint = "https://myapp.azure.openai.com" key="' + "a" * 32 + '"'
        assert any(f.rule_id == "SEC-AZURE-001" for f in scan_line(line, 1, "f"))

    def test_without_context_ignored(self) -> None:
        line = 'HASH = "' + "a" * 32 + '"'
        assert not any(f.rule_id == "SEC-AZURE-001" for f in scan_line(line, 1, "f"))


class TestAWS:
    def test_access_key_id(self) -> None:
        line = 'AWS_KEY = "AKIAIOSFODNN7EXAMPLE"'
        assert any(f.rule_id == "SEC-AWS-001" for f in scan_line(line, 1, "f"))

    def test_secret_access_key(self) -> None:
        line = 'aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'
        assert any(f.rule_id == "SEC-AWS-002" for f in scan_line(line, 1, "f"))

    def test_non_akia_prefix_ignored(self) -> None:
        assert not any(f.rule_id == "SEC-AWS-001" for f in scan_line('AKIDSHORT', 1, "f"))


class TestWandb:
    def test_with_context(self) -> None:
        line = 'WANDB_API_KEY = "' + "a" * 40 + '"'
        assert any(f.rule_id == "SEC-WANDB-001" for f in scan_line(line, 1, "f"))

    def test_without_context_ignored(self) -> None:
        line = 'HASH = "' + "a" * 40 + '"'
        assert not any(f.rule_id == "SEC-WANDB-001" for f in scan_line(line, 1, "f"))


class TestGitHub:
    def test_detects_pat(self) -> None:
        line = 'GH = "ghp_' + "a" * 40 + '"'
        assert any(f.rule_id == "SEC-GITHUB-001" for f in scan_line(line, 1, "f"))

    def test_ghs_token(self) -> None:
        line = 'GH = "ghs_' + "a" * 40 + '"'
        assert any(f.rule_id == "SEC-GITHUB-001" for f in scan_line(line, 1, "f"))


class TestSlack:
    def test_detects_bot_token(self) -> None:
        line = 'SLACK = "xoxb-' + "a" * 30 + '"'
        assert any(f.rule_id == "SEC-SLACK-001" for f in scan_line(line, 1, "f"))


class TestVoyageAI:
    def test_detects_key(self) -> None:
        line = 'VOYAGE = "pa-' + "a" * 45 + '"'
        assert any(f.rule_id == "SEC-VOYAGE-001" for f in scan_line(line, 1, "f"))


class TestCohere:
    def test_v2_prefix(self) -> None:
        line = 'KEY = "co-' + "a" * 45 + '"'
        assert any(f.rule_id == "SEC-COHERE-002" for f in scan_line(line, 1, "f"))

    def test_contextual(self) -> None:
        line = 'COHERE_API_KEY = "' + "a" * 40 + '"'
        assert any(f.rule_id == "SEC-COHERE-001" for f in scan_line(line, 1, "f"))


class TestSafeLine:
    def test_plain_assignment(self) -> None:
        assert scan_line("x = 42", 1, "main.py") == []

    def test_comment_line(self) -> None:
        assert scan_line("# this is a comment", 1, "main.py") == []


class TestScanFile:
    def test_scan_file_with_secrets(self, tmp_path: Path) -> None:
        f = tmp_path / "leaked.py"
        f.write_text('ANTHROPIC_KEY = "sk-ant-api03-' + "b" * 95 + '"\n')
        findings = scan_file(f)
        assert len(findings) >= 1

    def test_scan_nonexistent_file(self, tmp_path: Path) -> None:
        assert scan_file(tmp_path / "nonexistent.py") == []

    def test_scan_clean_file(self, tmp_path: Path) -> None:
        f = tmp_path / "clean.py"
        f.write_text("print('hello world')\n")
        assert scan_file(f) == []

    def test_scan_file_multiple_keys(self, tmp_path: Path) -> None:
        f = tmp_path / "multi.py"
        f.write_text(
            'GROQ = "gsk_' + "a" * 52 + '"\n'
            'FW = "fw_' + "b" * 35 + '"\n'
            'LS = "ls__' + "C" * 35 + '"\n'
        )
        findings = scan_file(f)
        rule_ids = {fi.rule_id for fi in findings}
        assert "SEC-GROQ-001" in rule_ids
        assert "SEC-FIREWORKS-001" in rule_ids
        assert "SEC-LANGSMITH-001" in rule_ids
