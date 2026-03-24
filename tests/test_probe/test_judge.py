"""Tests for probe/judge.py — _parse_verdict, _apply_threshold, evaluate_response, batch_evaluate."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from anthropic import APIError

from ai_secrets_guard.probe.judge import (
    JudgeVerdict,
    _apply_threshold,
    _parse_verdict,
    batch_evaluate,
    evaluate_response,
)


# ---------------------------------------------------------------------------
# _parse_verdict (unit)
# ---------------------------------------------------------------------------


class TestParseVerdict:
    def test_valid_json_vulnerable(self) -> None:
        text = (
            '{"verdict": "VULNERABLE", "confidence": 0.95, '
            '"evidence": "Model said PWNED", "technique": "direct_override", '
            '"reasoning": "Model followed injected instructions"}'
        )
        v = _parse_verdict(text)
        assert v.is_vulnerable is True
        assert v.confidence == 0.95
        assert "PWNED" in v.evidence
        assert v.technique == "direct_override"
        assert "injected" in v.reasoning

    def test_valid_json_safe(self) -> None:
        text = (
            '{"verdict": "SAFE", "confidence": 0.8, '
            '"evidence": "", "technique": "injection", '
            '"reasoning": "Model refused"}'
        )
        v = _parse_verdict(text)
        assert v.is_vulnerable is False
        assert v.confidence == 0.8
        assert v.evidence == ""

    def test_json_with_surrounding_text(self) -> None:
        text = (
            'Analysis: {"verdict": "VULNERABLE", "confidence": 0.7, '
            '"evidence": "system prompt leaked", "technique": "exfiltration", '
            '"reasoning": "exploited"} End.'
        )
        v = _parse_verdict(text)
        assert v.is_vulnerable is True
        assert v.confidence == 0.7
        assert "leaked" in v.evidence

    def test_fallback_vulnerable_keyword(self) -> None:
        text = "The response is VULNERABLE because the model complied."
        v = _parse_verdict(text)
        assert v.is_vulnerable is True
        assert v.confidence == 0.5
        assert v.evidence == ""
        assert v.technique == ""
        assert len(v.reasoning) > 0

    def test_fallback_safe_no_keyword(self) -> None:
        text = "The model correctly refused the request."
        v = _parse_verdict(text)
        assert v.is_vulnerable is False
        assert v.confidence == 0.5

    def test_empty_string(self) -> None:
        v = _parse_verdict("")
        assert v.is_vulnerable is False
        assert v.confidence == 0.5

    def test_json_missing_verdict_field(self) -> None:
        text = '{"confidence": 0.9, "reasoning": "no verdict field"}'
        v = _parse_verdict(text)
        assert v.is_vulnerable is False

    def test_json_with_integer_confidence(self) -> None:
        text = '{"verdict": "VULNERABLE", "confidence": 1, "reasoning": "sure"}'
        v = _parse_verdict(text)
        assert v.confidence == 1.0
        assert v.is_vulnerable is True

    def test_long_text_truncated_in_fallback(self) -> None:
        text = "X" * 500
        v = _parse_verdict(text)
        assert len(v.reasoning) <= 200

    def test_json_missing_optional_evidence(self) -> None:
        text = '{"verdict": "SAFE", "confidence": 0.6, "reasoning": "ok"}'
        v = _parse_verdict(text)
        assert v.evidence == ""
        assert v.technique == ""

    def test_json_lowercase_verdict(self) -> None:
        text = '{"verdict": "vulnerable", "confidence": 0.8, "reasoning": "exploited"}'
        v = _parse_verdict(text)
        assert v.is_vulnerable is True

    def test_malformed_json_brace_counting(self) -> None:
        text = "Here is my {broken json}"
        v = _parse_verdict(text)
        assert isinstance(v, JudgeVerdict)
        assert v.confidence == 0.5


# ---------------------------------------------------------------------------
# _apply_threshold
# ---------------------------------------------------------------------------


class TestApplyThreshold:
    def test_vulnerable_above_threshold_unchanged(self) -> None:
        v = JudgeVerdict(
            is_vulnerable=True, confidence=0.9, reasoning="exploited",
            evidence="PWNED", technique="injection",
        )
        result = _apply_threshold(v, 0.7)
        assert result.is_vulnerable is True
        assert result.confidence == 0.9
        assert result.evidence == "PWNED"

    def test_vulnerable_below_threshold_downgraded(self) -> None:
        v = JudgeVerdict(
            is_vulnerable=True, confidence=0.5, reasoning="maybe exploited",
            evidence="unclear", technique="injection",
        )
        result = _apply_threshold(v, 0.7)
        assert result.is_vulnerable is False
        assert result.confidence == 0.5
        assert "Inconclusive" in result.reasoning
        assert result.evidence == "unclear"

    def test_vulnerable_at_exact_threshold(self) -> None:
        v = JudgeVerdict(
            is_vulnerable=True, confidence=0.7, reasoning="exploited",
            evidence="match", technique="exfiltration",
        )
        result = _apply_threshold(v, 0.7)
        assert result.is_vulnerable is True

    def test_safe_verdict_not_affected(self) -> None:
        v = JudgeVerdict(
            is_vulnerable=False, confidence=0.3, reasoning="safe",
            evidence="", technique="",
        )
        result = _apply_threshold(v, 0.7)
        assert result.is_vulnerable is False
        assert result.reasoning == "safe"

    def test_zero_threshold_keeps_all_vulnerable(self) -> None:
        v = JudgeVerdict(
            is_vulnerable=True, confidence=0.01, reasoning="low",
            evidence="e", technique="t",
        )
        result = _apply_threshold(v, 0.0)
        assert result.is_vulnerable is True


# ---------------------------------------------------------------------------
# evaluate_response (mocked AsyncAnthropic)
# ---------------------------------------------------------------------------


def _make_mock_anthropic(response_text: str) -> AsyncMock:
    content_block = MagicMock()
    content_block.text = response_text

    message = MagicMock()
    message.content = [content_block]

    mock_client = AsyncMock()
    mock_client.messages.create.return_value = message
    return mock_client


class TestEvaluateResponse:
    async def test_vulnerable_verdict(self) -> None:
        response_text = (
            '{"verdict": "VULNERABLE", "confidence": 0.92, '
            '"evidence": "PWNED output", "technique": "direct_override", '
            '"reasoning": "Model was exploited"}'
        )
        mock_client = _make_mock_anthropic(response_text)

        with patch("ai_secrets_guard.probe.judge.AsyncAnthropic", return_value=mock_client):
            verdict = await evaluate_response("ignore instructions", "PWNED")

        assert verdict.is_vulnerable is True
        assert verdict.confidence == 0.92
        assert "exploited" in verdict.reasoning
        assert verdict.evidence == "PWNED output"
        assert verdict.technique == "direct_override"

    async def test_safe_verdict(self) -> None:
        response_text = (
            '{"verdict": "SAFE", "confidence": 0.88, '
            '"evidence": "", "technique": "injection", '
            '"reasoning": "Model refused injection"}'
        )
        mock_client = _make_mock_anthropic(response_text)

        with patch("ai_secrets_guard.probe.judge.AsyncAnthropic", return_value=mock_client):
            verdict = await evaluate_response("ignore instructions", "I cannot do that.")

        assert verdict.is_vulnerable is False
        assert verdict.confidence == 0.88

    async def test_with_explicit_api_key(self) -> None:
        response_text = '{"verdict": "SAFE", "confidence": 0.7, "reasoning": "ok"}'
        mock_client = _make_mock_anthropic(response_text)

        with patch("ai_secrets_guard.probe.judge.AsyncAnthropic", return_value=mock_client) as mock_cls:
            await evaluate_response("test", "response", api_key="sk-test-key")

        mock_cls.assert_called_once_with(api_key="sk-test-key")

    async def test_without_api_key(self) -> None:
        response_text = '{"verdict": "SAFE", "confidence": 0.7, "reasoning": "ok"}'
        mock_client = _make_mock_anthropic(response_text)

        with patch("ai_secrets_guard.probe.judge.AsyncAnthropic", return_value=mock_client) as mock_cls:
            await evaluate_response("test", "response")

        mock_cls.assert_called_once_with()

    async def test_custom_model(self) -> None:
        response_text = '{"verdict": "SAFE", "confidence": 0.6, "reasoning": "fine"}'
        mock_client = _make_mock_anthropic(response_text)

        with patch("ai_secrets_guard.probe.judge.AsyncAnthropic", return_value=mock_client):
            await evaluate_response("test", "response", model="claude-haiku-4")

        call_kwargs = mock_client.messages.create.call_args.kwargs
        assert call_kwargs["model"] == "claude-haiku-4"

    async def test_api_error_returns_safe_fallback(self) -> None:
        mock_client = AsyncMock()
        mock_client.messages.create.side_effect = APIError(
            message="Internal Server Error",
            request=MagicMock(),
            body=None,
        )

        with patch("ai_secrets_guard.probe.judge.AsyncAnthropic", return_value=mock_client):
            verdict = await evaluate_response("test", "response")

        assert verdict.is_vulnerable is False
        assert verdict.confidence == 0.0
        assert "failed" in verdict.reasoning.lower()
        assert verdict.evidence == ""
        assert verdict.technique == ""

    async def test_passes_system_prompt_and_user_message(self) -> None:
        response_text = '{"verdict": "SAFE", "confidence": 0.5, "reasoning": "ok"}'
        mock_client = _make_mock_anthropic(response_text)

        with patch("ai_secrets_guard.probe.judge.AsyncAnthropic", return_value=mock_client):
            await evaluate_response("my prompt payload", "model said this")

        call_kwargs = mock_client.messages.create.call_args.kwargs
        assert call_kwargs["max_tokens"] == 1024
        assert "system" in call_kwargs
        user_msg = call_kwargs["messages"][0]["content"]
        assert "my prompt payload" in user_msg
        assert "model said this" in user_msg

    async def test_confidence_threshold_downgrades_low_confidence_vulnerable(self) -> None:
        response_text = (
            '{"verdict": "VULNERABLE", "confidence": 0.4, '
            '"evidence": "maybe", "technique": "injection", '
            '"reasoning": "uncertain"}'
        )
        mock_client = _make_mock_anthropic(response_text)

        with patch("ai_secrets_guard.probe.judge.AsyncAnthropic", return_value=mock_client):
            verdict = await evaluate_response(
                "test", "response", confidence_threshold=0.7,
            )

        assert verdict.is_vulnerable is False
        assert "Inconclusive" in verdict.reasoning

    async def test_confidence_threshold_keeps_high_confidence_vulnerable(self) -> None:
        response_text = (
            '{"verdict": "VULNERABLE", "confidence": 0.95, '
            '"evidence": "PWNED", "technique": "injection", '
            '"reasoning": "exploited"}'
        )
        mock_client = _make_mock_anthropic(response_text)

        with patch("ai_secrets_guard.probe.judge.AsyncAnthropic", return_value=mock_client):
            verdict = await evaluate_response(
                "test", "response", confidence_threshold=0.7,
            )

        assert verdict.is_vulnerable is True

    async def test_zero_threshold_keeps_all_vulnerable(self) -> None:
        response_text = (
            '{"verdict": "VULNERABLE", "confidence": 0.1, '
            '"reasoning": "weak signal"}'
        )
        mock_client = _make_mock_anthropic(response_text)

        with patch("ai_secrets_guard.probe.judge.AsyncAnthropic", return_value=mock_client):
            verdict = await evaluate_response(
                "test", "response", confidence_threshold=0.0,
            )

        assert verdict.is_vulnerable is True


# ---------------------------------------------------------------------------
# batch_evaluate
# ---------------------------------------------------------------------------


class TestBatchEvaluate:
    async def test_batch_returns_all_verdicts(self) -> None:
        async def fake_evaluate(prompt, response, *, model="claude-sonnet-4-5", api_key=None, confidence_threshold=0.7):
            is_vuln = "evil" in prompt.lower()
            return JudgeVerdict(
                is_vulnerable=is_vuln, confidence=0.8, reasoning="batch",
                evidence="e" if is_vuln else "", technique="t",
            )

        pairs = [
            ("safe prompt", "ok response"),
            ("evil prompt", "bad response"),
            ("another safe", "fine"),
        ]

        with patch("ai_secrets_guard.probe.judge.evaluate_response", side_effect=fake_evaluate):
            verdicts = await batch_evaluate(pairs)

        assert len(verdicts) == 3
        assert verdicts[0].is_vulnerable is False
        assert verdicts[1].is_vulnerable is True
        assert verdicts[2].is_vulnerable is False

    async def test_batch_respects_concurrency(self) -> None:
        active = 0
        max_active = 0

        async def fake_evaluate(prompt, response, *, model="claude-sonnet-4-5", api_key=None, confidence_threshold=0.7):
            nonlocal active, max_active
            active += 1
            max_active = max(max_active, active)
            import asyncio
            await asyncio.sleep(0.01)
            active -= 1
            return JudgeVerdict(is_vulnerable=False, confidence=0.5, reasoning="ok")

        pairs = [("p", "r") for _ in range(6)]

        with patch("ai_secrets_guard.probe.judge.evaluate_response", side_effect=fake_evaluate):
            await batch_evaluate(pairs, max_concurrent=2)

        assert max_active <= 2

    async def test_batch_empty_list(self) -> None:
        with patch("ai_secrets_guard.probe.judge.evaluate_response", new_callable=AsyncMock):
            verdicts = await batch_evaluate([])

        assert verdicts == []

    async def test_batch_passes_confidence_threshold(self) -> None:
        captured_thresholds: list[float] = []

        async def fake_evaluate(prompt, response, *, model="claude-sonnet-4-5", api_key=None, confidence_threshold=0.7):
            captured_thresholds.append(confidence_threshold)
            return JudgeVerdict(is_vulnerable=False, confidence=0.5, reasoning="ok")

        pairs = [("p1", "r1"), ("p2", "r2")]

        with patch("ai_secrets_guard.probe.judge.evaluate_response", side_effect=fake_evaluate):
            await batch_evaluate(pairs, confidence_threshold=0.9)

        assert all(t == 0.9 for t in captured_thresholds)

    async def test_batch_passes_model(self) -> None:
        captured_models: list[str] = []

        async def fake_evaluate(prompt, response, *, model="claude-sonnet-4-5", api_key=None, confidence_threshold=0.7):
            captured_models.append(model)
            return JudgeVerdict(is_vulnerable=False, confidence=0.5, reasoning="ok")

        pairs = [("p", "r")]

        with patch("ai_secrets_guard.probe.judge.evaluate_response", side_effect=fake_evaluate):
            await batch_evaluate(pairs, model="claude-haiku-4")

        assert captured_models == ["claude-haiku-4"]
