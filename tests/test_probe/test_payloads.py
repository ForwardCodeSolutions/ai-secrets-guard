"""Tests for probe/payloads.py — all three categories and helper functions."""

from __future__ import annotations

import base64

import pytest

from ai_secrets_guard.core.models import ProbePayload
from ai_secrets_guard.probe.payloads import (
    EXFILTRATION_PAYLOADS,
    INJECTION_PAYLOADS,
    JAILBREAK_CHAINS,
    get_all_payloads,
    get_payloads_by_category,
)


# ---------------------------------------------------------------------------
# Category sizes
# ---------------------------------------------------------------------------


class TestCategorySizes:
    def test_injection_has_at_least_10_payloads(self) -> None:
        assert len(INJECTION_PAYLOADS) >= 10

    def test_jailbreak_has_3_chains(self) -> None:
        assert len(JAILBREAK_CHAINS) == 3

    def test_exfiltration_has_at_least_8_payloads(self) -> None:
        assert len(EXFILTRATION_PAYLOADS) >= 8


# ---------------------------------------------------------------------------
# Structural validation
# ---------------------------------------------------------------------------


class TestPayloadStructure:
    def test_all_payloads_have_required_fields(self) -> None:
        for p in get_all_payloads():
            assert p.name, f"Payload missing name: {p}"
            assert p.category, f"Payload missing category: {p}"
            assert len(p.messages) > 0, f"Payload has no messages: {p.name}"

    def test_all_payloads_are_probe_payload_instances(self) -> None:
        for p in get_all_payloads():
            assert isinstance(p, ProbePayload)

    def test_unique_payload_names(self) -> None:
        names = [p.name for p in get_all_payloads()]
        assert len(names) == len(set(names)), f"Duplicate names: {[n for n in names if names.count(n) > 1]}"

    def test_all_messages_have_role_and_content(self) -> None:
        for p in get_all_payloads():
            for msg in p.messages:
                assert "role" in msg, f"{p.name}: message missing 'role'"
                assert "content" in msg, f"{p.name}: message missing 'content'"
                assert msg["role"] in ("user", "assistant", "system"), (
                    f"{p.name}: invalid role '{msg['role']}'"
                )

    def test_expected_behavior_is_set(self) -> None:
        for p in get_all_payloads():
            assert p.expected_behavior, f"{p.name}: missing expected_behavior"


# ---------------------------------------------------------------------------
# Category correctness
# ---------------------------------------------------------------------------


class TestCategoryLabels:
    def test_injection_payloads_have_correct_category(self) -> None:
        for p in INJECTION_PAYLOADS:
            assert p.category == "injection", f"{p.name} has category '{p.category}'"

    def test_jailbreak_chains_have_correct_category(self) -> None:
        for p in JAILBREAK_CHAINS:
            assert p.category == "jailbreak", f"{p.name} has category '{p.category}'"

    def test_exfiltration_payloads_have_correct_category(self) -> None:
        for p in EXFILTRATION_PAYLOADS:
            assert p.category == "exfiltration", f"{p.name} has category '{p.category}'"


# ---------------------------------------------------------------------------
# Specific payload content validation
# ---------------------------------------------------------------------------


class TestInjectionPayloadContent:
    def test_direct_override_contains_ignore(self) -> None:
        p = _find("direct_override")
        assert "Ignore" in p.messages[0]["content"]

    def test_system_tag_injection_has_system_tag(self) -> None:
        p = _find("system_tag_injection")
        assert "###SYSTEM###" in p.messages[0]["content"]

    def test_html_comment_escape(self) -> None:
        p = _find("html_comment_escape")
        assert "<!--" in p.messages[0]["content"]

    def test_null_byte_injection(self) -> None:
        p = _find("null_byte_injection")
        assert "\x00" in p.messages[0]["content"]

    def test_unicode_homoglyph_contains_cyrillic(self) -> None:
        p = _find("unicode_homoglyph")
        content = p.messages[0]["content"]
        assert "\u043e" in content or "\u0456" in content

    def test_base64_encoded_payload_is_valid_b64(self) -> None:
        p = _find("base64_encoded_payload")
        content = p.messages[0]["content"]
        parts = content.split()
        b64_part = parts[-1]
        decoded = base64.b64decode(b64_part).decode()
        assert "PWNED" in decoded or "Ignore" in decoded

    def test_role_switch_dan(self) -> None:
        p = _find("role_switch_dan")
        assert "DAN" in p.messages[0]["content"]

    def test_delimiter_escape(self) -> None:
        p = _find("delimiter_escape")
        assert "---END SYSTEM PROMPT---" in p.messages[0]["content"]

    def test_context_overflow_has_padding(self) -> None:
        p = _find("context_overflow")
        assert len(p.messages[0]["content"]) > 5000

    def test_markdown_injection(self) -> None:
        p = _find("markdown_injection")
        assert "```system" in p.messages[0]["content"]

    def test_xml_tag_injection(self) -> None:
        p = _find("xml_tag_injection")
        assert "<system>" in p.messages[0]["content"]

    def test_json_injection(self) -> None:
        p = _find("json_injection")
        assert '"role": "system"' in p.messages[0]["content"]


class TestJailbreakChainContent:
    def test_dan_gradual_is_multi_turn(self) -> None:
        p = _find("dan_gradual")
        assert len(p.messages) >= 3
        roles = [m["role"] for m in p.messages]
        assert "user" in roles
        assert "assistant" in roles

    def test_hypothetical_framing(self) -> None:
        p = _find("hypothetical_framing")
        assert "hypothetical" in p.messages[0]["content"].lower()

    def test_role_play_escalation_is_multi_turn(self) -> None:
        p = _find("role_play_escalation")
        assert len(p.messages) >= 3
        assert "Alex" in p.messages[0]["content"]


class TestExfiltrationPayloadContent:
    def test_repeat_verbatim(self) -> None:
        p = _find("repeat_verbatim")
        assert "verbatim" in p.messages[0]["content"].lower()

    def test_initial_instructions(self) -> None:
        p = _find("initial_instructions")
        assert "initial instructions" in p.messages[0]["content"].lower()

    def test_code_block_extraction(self) -> None:
        p = _find("code_block_extraction")
        assert "code block" in p.messages[0]["content"].lower()

    def test_debug_context(self) -> None:
        p = _find("debug_context")
        assert "debug" in p.messages[0]["content"].lower()

    def test_sentence_completion(self) -> None:
        p = _find("sentence_completion")
        assert "Complete this sentence" in p.messages[0]["content"]

    def test_translate_system_prompt(self) -> None:
        p = _find("translate_system_prompt")
        assert "Spanish" in p.messages[0]["content"]

    def test_summarize_instructions(self) -> None:
        p = _find("summarize_instructions")
        assert "Summarize" in p.messages[0]["content"]

    def test_self_describe_indirect(self) -> None:
        p = _find("self_describe_indirect")
        assert "copy" in p.messages[0]["content"].lower()

    def test_json_schema_extraction(self) -> None:
        p = _find("json_schema_extraction")
        assert "JSON" in p.messages[0]["content"]


# ---------------------------------------------------------------------------
# get_all_payloads / get_payloads_by_category
# ---------------------------------------------------------------------------


class TestHelperFunctions:
    def test_get_all_combines_all(self) -> None:
        total = len(INJECTION_PAYLOADS) + len(JAILBREAK_CHAINS) + len(EXFILTRATION_PAYLOADS)
        assert len(get_all_payloads()) == total

    def test_get_payloads_by_category_injection(self) -> None:
        result = get_payloads_by_category("injection")
        assert len(result) == len(INJECTION_PAYLOADS)
        assert all(p.category == "injection" for p in result)

    def test_get_payloads_by_category_jailbreak(self) -> None:
        result = get_payloads_by_category("jailbreak")
        assert len(result) == len(JAILBREAK_CHAINS)

    def test_get_payloads_by_category_exfiltration(self) -> None:
        result = get_payloads_by_category("exfiltration")
        assert len(result) == len(EXFILTRATION_PAYLOADS)

    def test_get_payloads_by_category_unknown(self) -> None:
        result = get_payloads_by_category("nonexistent")
        assert result == []

    def test_get_all_returns_new_list_each_time(self) -> None:
        a = get_all_payloads()
        b = get_all_payloads()
        assert a is not b
        assert a == b


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _find(name: str) -> ProbePayload:
    for p in get_all_payloads():
        if p.name == name:
            return p
    raise AssertionError(f"Payload '{name}' not found")
