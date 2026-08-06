from __future__ import annotations

import socket
from collections.abc import Callable
from dataclasses import asdict
from types import SimpleNamespace
from typing import Any

import pytest

import hivemind_weave.pii as pii_module
from hivemind_weave.atif import map_atif
from hivemind_weave.attribute_safety import MAX_ATTRIBUTE_VALUE_CHARS
from hivemind_weave.models import ChatMessage, MappedSubAgent, Session
from hivemind_weave.pii import (
    configure_weave_pii,
    redact_agent_name,
    redact_model_name,
    redact_source_coordinate,
    redact_upload_data,
    sanitize_mapped_conversation,
)
from hivemind_weave.utils import sha256_json


def test_presidio_configuration_is_offline_and_redacts_pii(monkeypatch: Any) -> None:
    def reject_network(*_: object, **__: object) -> None:
        raise AssertionError("PII initialization attempted network access")

    monkeypatch.setattr(socket.socket, "connect", reject_network)
    configure_weave_pii.cache_clear()
    configure_weave_pii()

    from weave.utils.pii_redaction import redact_pii_string

    redacted = redact_pii_string(
        "Alice Johnson lives in New York; contact alice@example.com or 212-555-1212"
    )
    assert "Alice Johnson" not in redacted
    assert "New York" not in redacted
    assert "alice@example.com" not in redacted
    assert "212-555-1212" not in redacted


def test_full_text_analyzer_raises_spacy_limit_without_splitting_content() -> None:
    class CapturingAnalyzer:
        def __init__(self) -> None:
            self.calls: list[str] = []

        def analyze(self, *, text: str, language: str, **_: Any) -> list[Any]:
            assert language == "en"
            assert pipeline.max_length >= len(text)
            self.calls.append(text)
            return []

    pipeline = type("Pipeline", (), {"max_length": 10})()
    nlp_engine = type("NlpEngine", (), {"nlp": {"en": pipeline}})()
    captured = CapturingAnalyzer()
    analyzer = pii_module._FullTextAnalyzer(captured, nlp_engine)
    source = f"{'x' * 16}Alice Johnson{'y' * 60}"

    analyzer.analyze(text=source, language="en", entities=["PERSON"])
    analyzer.analyze(text="short", language="en", entities=["PERSON"])

    assert captured.calls == [source, "short"]
    assert pipeline.max_length == len(source)


def test_presidio_redacts_text_above_spacy_limit_without_truncation() -> None:
    # spaCy's default Language.max_length is 1,000,000. This exact shape raised
    # E088 before the analyzer adapter divided it into bounded, overlapping work.
    source = "x" * 1_000_001

    assert redact_upload_data(source) == source


def test_code_aware_redaction_preserves_ordinary_identifiers() -> None:
    code_samples = [
        "class Washington:\n    pass",
        "class Washington:\n    pass\n\nx = Washington()",
        "const Paris = new Map();",
        "class CustomerLedger:\n    pass",
        "def customer_ledger(value):\n    return value",
        "def jordan(value):\n    return value",
    ]
    assert [redact_upload_data(value) for value in code_samples] == code_samples
    assert redact_agent_name("cursor") == "cursor"
    assert redact_model_name("o3") == "o3"


@pytest.mark.parametrize(
    "code",
    [
        "class AliceJohnson:\n    pass",
        "const AliceJohnson = new Map();",
        "def AliceJohnson(value):\n    return value",
        "const result = new AliceJohnson();",
        "AliceJohnson::run()",
        "def alice_johnson(value):\n    return alice_johnson(value)",
        "const alice$johnson = 1;",
        "class Alice_Johnson:\n    pass",
        "const result = new Alice_Johnson();",
        "alice_johnson()",
        "Alice_Johnson::run()",
    ],
)
def test_person_names_cannot_hide_in_declared_code_identifiers(code: str) -> None:
    redacted = str(redact_upload_data(code))
    assert "Alice" not in redacted
    assert "Johnson" not in redacted


@pytest.mark.parametrize(
    "source",
    [
        "session-AliceJohnson",
        "call-JohnSmith",
        "gpt-AliceJohnson",
        "gpt-5-john-smith",
        "claude-3-john-smith",
        "gemini-2-john-smith",
        "codex-5-john-smith",
        "Claude",
    ],
)
def test_protocol_shaped_text_cannot_bypass_pii_redaction(source: str) -> None:
    redacted = str(redact_upload_data(source))
    assert redacted != source
    assert "john" not in redacted.lower()
    assert "smith" not in redacted.lower()
    assert "alice" not in redacted.lower()


def test_field_specific_model_metadata_keeps_reviewed_machine_names() -> None:
    for model in ("gpt-5.6-codex", "claude-sonnet-4-5", "gemini-2.5-pro", "o3"):
        assert redact_model_name(model) == model


@pytest.mark.parametrize(
    "model",
    [
        "gpt-5-john-smith",
        "claude-3-john-smith",
        "gemini-2-john-smith",
        "codex-5-john-smith",
    ],
)
def test_field_specific_model_metadata_scrubs_name_like_suffixes(model: str) -> None:
    redacted = redact_model_name(model)
    assert "john" not in redacted.lower()
    assert "smith" not in redacted.lower()


def test_agent_session_coordinate_is_redacted_as_content(
    session_payload: Callable[..., dict[str, Any]],
    atif_wrapper: Callable[..., dict[str, Any]],
) -> None:
    source = "nonopaque-source-coordinate"
    mapped = map_atif(
        Session.from_api(session_payload(agent_session_id=source)),
        atif_wrapper(),
    )
    turn = mapped.turns[0]
    turn.subagents.append(
        MappedSubAgent(
            name="worker",
            model="gpt-5.6-codex",
            agent_id=source,
            description="delegated review",
            version="1",
            system_instructions=[],
            started_at=turn.started_at,
            ended_at=turn.ended_at,
            timestamp_inferred=False,
        )
    )
    serialized = repr(asdict(sanitize_mapped_conversation(mapped)))

    assert source not in serialized
    assert "[REDACTED_SOURCE_COORDINATE]" in serialized


def test_source_coordinates_inside_preserved_atif_json_are_redacted(
    session_payload: Callable[..., dict[str, Any]],
    atif_wrapper: Callable[..., dict[str, Any]],
) -> None:
    source = "nonopaque-source-coordinate"
    wrapper = atif_wrapper(
        session_id=source,
        trajectory_id=source,
        extra={"parent_session_id": source},
        agent={
            "name": "codex",
            "version": "1.2.3",
            "model_name": "gpt-5.6-codex",
            "extra": {"agent_id": source},
        },
    )
    wrapper["metadata"] = {"agent_session_id": source}
    mapped = map_atif(Session.from_api(session_payload()), wrapper)

    serialized = repr(asdict(sanitize_mapped_conversation(mapped)))

    assert source not in serialized
    assert "[REDACTED_SOURCE_COORDINATE]" in serialized


def test_coordinate_bearing_mapping_keys_fail_closed_without_hashing_names() -> None:
    source = "nonopaque-source-coordinate"
    redacted = redact_upload_data(
        {
            "session_id": "11111111-1111-4111-8111-111111111111",
            "agent_session_id": source,
            "agent_id": source,
        }
    )

    assert redacted == {
        "session_id": "11111111-1111-4111-8111-111111111111",
        "agent_session_id": "[REDACTED_SOURCE_COORDINATE]",
        "agent_id": "[REDACTED_SOURCE_COORDINATE]",
    }
    assert redact_source_coordinate(source) == "[REDACTED_SOURCE_COORDINATE]"


def test_redacted_mapping_key_allocation_cannot_collide_on_a_later_pass() -> None:
    payload = {
        "[REDACTED_PII_KEY_0001]": "already redacted",
        "Alice_Johnson": "private field",
    }

    redacted = redact_upload_data(payload)

    assert redacted["[REDACTED_PII_KEY_0001]"] == "already redacted"
    assert redacted["[REDACTED_PII_KEY_0002]"] == "private field"


def test_code_aware_redaction_scrubs_comments_and_literals() -> None:
    code = (
        'class Washington:\n    owner = "Alice Johnson"\n'
        "    # Alice Johnson works in New York\n    pass"
    )
    redacted = redact_upload_data(code)
    assert "class Washington:" in redacted
    assert "Alice Johnson" not in redacted
    assert "New York" not in redacted

    fenced = '```python\nconst Paris = "Alice Johnson in New York";\n```'
    fenced_redacted = redact_upload_data(fenced)
    assert "const Paris" in fenced_redacted
    assert "Alice Johnson" not in fenced_redacted
    assert "New York" not in fenced_redacted

    mixed_syntax = (
        "# class Washington belongs to Alice Johnson in New York\n"
        "const template = `Alice Johnson in New York`;\n"
        "const pattern = /Alice Johnson in New York/;\n"
        "-- new Washington() for Alice Johnson in New York\n"
        "`class Washington for Alice Johnson in New York`"
    )
    mixed_redacted = redact_upload_data(mixed_syntax)
    assert "Alice" not in mixed_redacted
    assert "Johnson" not in mixed_redacted
    assert "Washington" not in mixed_redacted
    assert "New York" not in mixed_redacted


def test_scoped_code_identifiers_survive_presidio_ip_recognition() -> None:
    assert redact_upload_data("Washington::York::run()") == "Washington::York::run()"


def test_structured_schema_keys_and_versions_are_not_corrupted() -> None:
    payload = {
        "session_id": "atif-session",
        "schema_version": "ATIF-v1.7",
        "step_id": 1,
        "source": "agent",
        "message": "ok",
    }
    assert redact_upload_data(payload) == {
        **payload,
        "session_id": "[REDACTED_SOURCE_COORDINATE]",
    }


def test_code_aware_redaction_still_scrubs_credentials_inside_code() -> None:
    code = 'const apiKey = "sk-abcdefghijklmnopqrstuvwxyz123456";'
    redacted = redact_upload_data(code)
    assert "sk-abcdefghijklmnopqrstuvwxyz123456" not in redacted


def test_exact_upload_redaction_is_idempotent() -> None:
    source = "Alice Johnson in New York used api token: abcdefghijklmnopqrstuvwxyz0123456789ABCD"
    once = redact_upload_data(source)
    assert redact_upload_data(once) == once


def test_verification_signature_uses_sdk_dict_redaction_not_string_hook(
    monkeypatch: Any,
    session_payload: Callable[..., dict[str, Any]],
    atif_wrapper: Callable[..., dict[str, Any]],
) -> None:
    conversation = map_atif(Session.from_api(session_payload()), atif_wrapper())

    def local_pass_changes_text(value: Any) -> Any:
        return f"[local]{value}" if isinstance(value, str) else value

    monkeypatch.setattr(
        "hivemind_weave.pii.redact_upload_data",
        local_pass_changes_text,
    )
    from weave.utils import pii_redaction

    string_hook_calls: list[str] = []

    def sdk_string_pass(value: str) -> str:
        string_hook_calls.append(value)
        return f"[sdk-string]{value}"

    class Analyzer:
        def analyze(self, **_: Any) -> list[Any]:
            return []

    class Anonymizer:
        def anonymize(self, *, text: str, analyzer_results: list[Any]) -> Any:
            del analyzer_results
            redacted = f"[sdk-dict]{text}" if text.startswith("[local]") else text
            return SimpleNamespace(text=redacted)

    monkeypatch.setattr(pii_redaction, "redact_pii_string", sdk_string_pass)
    monkeypatch.setattr(pii_redaction, "_get_engines", lambda: (Analyzer(), Anonymizer()))
    turn = sanitize_mapped_conversation(conversation).turns[0]
    first_user = next(item.content for item in turn.messages if item.role == "user")
    last_assistant = next(
        item.content for item in reversed(turn.output_messages) if item.role == "assistant"
    )

    assert turn.verification_signature == sha256_json(
        {
            "started_at_ms": int(turn.started_at.timestamp() * 1000),
            "first_user": f"[sdk-dict]{local_pass_changes_text(first_user)}",
            "last_assistant": f"[sdk-dict]{local_pass_changes_text(last_assistant)}",
        }
    )
    assert string_hook_calls == []


def test_verification_signature_keeps_sdk_json_looking_content_as_text(
    monkeypatch: Any,
    session_payload: Callable[..., dict[str, Any]],
    atif_wrapper: Callable[..., dict[str, Any]],
) -> None:
    conversation = map_atif(Session.from_api(session_payload()), atif_wrapper())
    conversation.turns[0].messages[0] = pii_module.ChatMessage(
        role="user",
        content='{"person":"Alice Johnson"}',
    )
    conversation.turns[0].output_messages[0] = pii_module.ChatMessage(
        role="assistant",
        content='{"city":"New York"}',
    )

    def local_pass(value: Any) -> Any:
        if isinstance(value, str):
            return f"local({value})"
        return value

    from weave.utils import pii_redaction

    monkeypatch.setattr(pii_module, "redact_upload_data", local_pass)
    observed_roles: list[str] = []

    def sdk_message_pass(messages: list[Any]) -> list[Any]:
        observed_roles.extend(message.role for message in messages)
        return [
            message.model_copy(update={"content": f"sdk-message({message.content})"})
            for message in messages
        ]

    monkeypatch.setattr(pii_redaction, "redact_messages", sdk_message_pass)
    turn = sanitize_mapped_conversation(conversation).turns[0]
    first_user = next(item.content for item in turn.messages if item.role == "user")
    last_assistant = next(
        item.content for item in reversed(turn.output_messages) if item.role == "assistant"
    )

    assert turn.verification_signature == sha256_json(
        {
            "started_at_ms": int(turn.started_at.timestamp() * 1000),
            "first_user": f"sdk-message({local_pass(first_user)})",
            "last_assistant": f"sdk-message({local_pass(last_assistant)})",
        }
    )
    assert observed_roles == ["user", "assistant"]


def test_redaction_cache_uses_only_digest_keys_and_redacted_values(monkeypatch: Any) -> None:
    calls = 0

    def fake_redactor(value: str) -> str:
        nonlocal calls
        calls += 1
        return f"[safe:{len(value)}]"

    monkeypatch.setattr(pii_module, "_redact_pii_string_uncached", fake_redactor)
    source = "private-source-value " * 500
    pii_module._REDACTION_CACHE.clear()
    monkeypatch.setattr(pii_module, "_REDACTION_CACHE_CHARS", 0)

    assert pii_module._redact_pii_string(source) == f"[safe:{len(source)}]"
    assert pii_module._redact_pii_string(source) == f"[safe:{len(source)}]"
    assert calls == 1
    assert all(source not in str(key) for key in pii_module._REDACTION_CACHE)
    assert source not in pii_module._REDACTION_CACHE.values()


def test_sanitization_keeps_large_attributes_inline_for_fail_closed_preflight(
    monkeypatch: Any,
    session_payload: Callable[..., dict[str, Any]],
    atif_wrapper: Callable[..., dict[str, Any]],
) -> None:
    conversation = map_atif(Session.from_api(session_payload()), atif_wrapper())
    source = "x" * (MAX_ATTRIBUTE_VALUE_CHARS + 1)
    conversation.turns[0].attributes["hivemind.preserved_step_data"] = source
    monkeypatch.setattr("hivemind_weave.pii.redact_upload_data", lambda value: value)

    sanitized = sanitize_mapped_conversation(conversation)
    attributes = sanitized.turns[0].attributes

    assert attributes["hivemind.preserved_step_data"] == source


def test_source_payload_hash_tracks_the_complete_pii_redacted_semantics(
    monkeypatch: Any,
    session_payload: Callable[..., dict[str, Any]],
    atif_wrapper: Callable[..., dict[str, Any]],
) -> None:
    configure_weave_pii()

    def redactor(marker: str) -> Callable[[Any], Any]:
        def walk(value: Any) -> Any:
            if isinstance(value, str):
                return value.replace("Alice", marker)
            if isinstance(value, dict):
                return {key: walk(item) for key, item in value.items()}
            if isinstance(value, list):
                return [walk(item) for item in value]
            if isinstance(value, tuple):
                return tuple(walk(item) for item in value)
            return value

        return walk

    def mapped() -> Any:
        conversation = map_atif(Session.from_api(session_payload()), atif_wrapper())
        conversation.turns[0].attributes["hivemind.preserved_step_data"] = "Alice " * (
            MAX_ATTRIBUTE_VALUE_CHARS // 6 + 10
        )
        conversation.turns[0].finalize_hash()
        return conversation

    monkeypatch.setattr(pii_module, "redact_upload_data", redactor("<PERSON>"))
    first_mapped = mapped()
    first = sanitize_mapped_conversation(first_mapped).turns[0]
    monkeypatch.setattr(
        pii_module,
        "redact_upload_data",
        redactor("<POSSIBLE_PERSON_ENTITY>"),
    )
    second = sanitize_mapped_conversation(mapped()).turns[0]

    assert first.payload_sha256 != second.payload_sha256
    assert first.attributes["hivemind.source_payload_sha256"] == first.payload_sha256
    assert second.attributes["hivemind.source_payload_sha256"] == second.payload_sha256
    assert (
        first.attributes["hivemind.preserved_step_data"]
        != second.attributes["hivemind.preserved_step_data"]
    )


def test_source_payload_hash_never_depends_on_raw_credentials(
    monkeypatch: Any,
    session_payload: Callable[..., dict[str, Any]],
    atif_wrapper: Callable[..., dict[str, Any]],
) -> None:
    configure_weave_pii()

    def sanitize_with(secret: str, ordinary_text: str) -> Any:
        conversation = map_atif(Session.from_api(session_payload()), atif_wrapper())
        conversation.turns[0].messages[0] = ChatMessage(
            role="user",
            content=(f'{ordinary_text}\nAuthorization: Bearer {secret}\nOPENAI_API_KEY="{secret}"'),
        )
        conversation.turns[0].finalize_hash()
        return sanitize_mapped_conversation(conversation).turns[0]

    # Use the deterministic scrubber as the complete redaction pass. Raw
    # secrets must collapse to the same safe semantic representation while
    # ordinary source changes remain meaningful.
    monkeypatch.setattr(pii_module, "redact_upload_data", pii_module.redact_data)
    first_secret = "sk-abcdefghijklmnopqrstuvwxyz123456"
    second_secret = "sk-zyxwvutsrqponmlkjihgfedcba654321"
    first = sanitize_with(first_secret, "ordinary source")
    changed_secret = sanitize_with(second_secret, "ordinary source")
    changed_content = sanitize_with(first_secret, "different source")

    assert first.payload_sha256 == changed_secret.payload_sha256
    assert first.payload_sha256 != changed_content.payload_sha256
    assert first_secret not in str(first.payload_for_hash())
    assert second_secret not in str(changed_secret.payload_for_hash())


def test_source_payload_hash_never_becomes_a_raw_pii_equality_oracle(
    monkeypatch: Any,
    session_payload: Callable[..., dict[str, Any]],
    atif_wrapper: Callable[..., dict[str, Any]],
) -> None:
    configure_weave_pii()

    def redact_people(value: Any) -> Any:
        if isinstance(value, str):
            return value.replace("Alice Johnson", "[PERSON]").replace("Bob Williams", "[PERSON]")
        if isinstance(value, dict):
            return {key: redact_people(item) for key, item in value.items()}
        if isinstance(value, list):
            return [redact_people(item) for item in value]
        if isinstance(value, tuple):
            return tuple(redact_people(item) for item in value)
        return value

    def sanitize_with(name: str) -> Any:
        conversation = map_atif(Session.from_api(session_payload()), atif_wrapper())
        conversation.turns[0].messages[0] = ChatMessage(
            role="user",
            content=f"Please help {name} with the same task",
        )
        return sanitize_mapped_conversation(conversation).turns[0]

    monkeypatch.setattr(pii_module, "redact_upload_data", redact_people)
    first = sanitize_with("Alice Johnson")
    second = sanitize_with("Bob Williams")

    assert first.payload_sha256 == second.payload_sha256
    assert "Alice Johnson" not in str(first.payload_for_hash())
    assert "Bob Williams" not in str(second.payload_for_hash())
