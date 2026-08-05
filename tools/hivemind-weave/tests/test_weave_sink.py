from __future__ import annotations

import importlib
import json
import os
from collections.abc import Callable
from copy import deepcopy
from dataclasses import replace
from types import SimpleNamespace
from typing import Any

import pytest

from hivemind_weave.atif import map_atif
from hivemind_weave.attribute_safety import (
    MAX_ATTRIBUTE_VALUE_CHARS,
    MAX_ROOT_ATTRIBUTE_BYTES,
    MAX_SPILL_FRAGMENT_JSON_BYTES,
    SPILL_TOOL_NAME,
    SpillFragment,
    SpillManifest,
    chunk_large_attributes,
    json_string_wire_bytes,
    restore_chunked_attributes,
    restore_spilled_attributes,
    restore_spilled_tool,
    validate_upload_attributes,
)
from hivemind_weave.errors import WeaveImportError
from hivemind_weave.models import MappedSubAgent, Session
from hivemind_weave.pii import (
    configure_weave_pii,
    redact_upload_data,
    sanitize_mapped_conversation,
)
from hivemind_weave.utils import canonical_json
from hivemind_weave.weave_sink import WeaveSink, expected_turn_span_count


class Box:
    def __init__(self, **values: Any) -> None:
        self.__dict__.update(values)


class FakeConversationModule:
    Message = Box
    Usage = Box
    Reasoning = Box
    LLM = Box
    Tool = Box
    SubAgent = Box


class FakeWeave:
    def __init__(self, *, empty: bool = False) -> None:
        self.empty = empty
        self.initialized: tuple[str, dict[str, Any]] | None = None
        self.otel_export_batch_at_init: str | None = None
        self.logged: list[dict[str, Any]] = []
        self.finished = False

    def init(self, project: str, *, settings: dict[str, Any]) -> None:
        self.otel_export_batch_at_init = os.environ.get("OTEL_BSP_MAX_EXPORT_BATCH_SIZE")
        self.initialized = (project, settings)

    def log_turn(self, **payload: Any) -> SimpleNamespace:
        self.logged.append(payload)
        if self.empty:
            return SimpleNamespace(trace_ids=[], root_span_ids=[], span_count=0)
        return SimpleNamespace(
            trace_ids=["trace-1"],
            root_span_ids=["root-1"],
            span_count=1 + len(payload["spans"]),
        )

    def finish(self) -> None:
        self.finished = True


def _physical_fragments(
    payload: dict[str, Any],
    *,
    owner_kind: str,
) -> tuple[SpillFragment, ...]:
    fragments: list[SpillFragment] = []
    for span in payload["spans"]:
        if getattr(span, "name", "") != SPILL_TOOL_NAME:
            continue
        arguments = getattr(span, "arguments", None)
        if not isinstance(arguments, dict) or arguments.get("owner_kind") != owner_kind:
            continue
        fragments.append(
            SpillFragment(
                manifest=SpillManifest.from_dict(arguments),
                chunk_index=arguments["chunk_index"],
                content=span.result,
            )
        )
    return tuple(fragments)


def test_sink_builds_batch_sdk_objects_and_flushes(
    session_payload: Callable[..., dict[str, Any]],
    atif_wrapper: Callable[..., dict[str, Any]],
) -> None:
    conversation = map_atif(Session.from_api(session_payload()), atif_wrapper())
    fake = FakeWeave()
    sink = WeaveSink(
        weave_module=fake,
        conversation_module=FakeConversationModule,
        require_pii_dependencies=False,
    )
    sink.start("wandb/hivemind-chats")
    outcome = sink.log_turn(conversation, conversation.turns[0])
    sink.finish()

    assert fake.initialized is not None
    assert fake.initialized[1]["redact_pii"] is True
    payload = fake.logged[0]
    assert payload["conversation_id"].startswith("hivemind:")
    assert payload["output_messages"][0].content == "Created hello.txt."
    assert payload["include_content"] is True
    expected_spans = expected_turn_span_count(conversation.turns[0])
    assert all(type(span).__name__ == "Box" for span in payload["spans"])
    assert len(payload["spans"]) == expected_spans - 1
    assert outcome.trace_ids == ["trace-1"]
    assert outcome.span_count == expected_spans
    assert fake.finished is True


def test_sink_bounds_otel_export_batches_during_weave_init(monkeypatch: Any) -> None:
    monkeypatch.delenv("OTEL_BSP_MAX_EXPORT_BATCH_SIZE", raising=False)
    monkeypatch.delenv("OTEL_BSP_MAX_QUEUE_SIZE", raising=False)
    fake = FakeWeave()
    sink = WeaveSink(
        weave_module=fake,
        conversation_module=FakeConversationModule,
        require_pii_dependencies=False,
    )

    sink.start("wandb/hivemind-chats")

    assert fake.otel_export_batch_at_init == "4"
    assert "OTEL_BSP_MAX_EXPORT_BATCH_SIZE" not in os.environ


def test_sink_preserves_an_explicit_otel_export_batch(monkeypatch: Any) -> None:
    monkeypatch.setenv("OTEL_BSP_MAX_EXPORT_BATCH_SIZE", "7")
    fake = FakeWeave()
    sink = WeaveSink(
        weave_module=fake,
        conversation_module=FakeConversationModule,
        require_pii_dependencies=False,
    )

    sink.start("wandb/hivemind-chats")

    assert fake.otel_export_batch_at_init == "7"
    assert os.environ["OTEL_BSP_MAX_EXPORT_BATCH_SIZE"] == "7"


def test_sink_clamps_automatic_export_batch_to_explicit_queue(monkeypatch: Any) -> None:
    monkeypatch.delenv("OTEL_BSP_MAX_EXPORT_BATCH_SIZE", raising=False)
    monkeypatch.setenv("OTEL_BSP_MAX_QUEUE_SIZE", "2")
    fake = FakeWeave()
    sink = WeaveSink(
        weave_module=fake,
        conversation_module=FakeConversationModule,
        require_pii_dependencies=False,
    )

    sink.start("wandb/hivemind-chats")

    assert fake.otel_export_batch_at_init == "2"
    assert "OTEL_BSP_MAX_EXPORT_BATCH_SIZE" not in os.environ


def test_sink_restores_a_blank_otel_export_batch(monkeypatch: Any) -> None:
    monkeypatch.setenv("OTEL_BSP_MAX_EXPORT_BATCH_SIZE", "  ")
    monkeypatch.delenv("OTEL_BSP_MAX_QUEUE_SIZE", raising=False)
    fake = FakeWeave()
    sink = WeaveSink(
        weave_module=fake,
        conversation_module=FakeConversationModule,
        require_pii_dependencies=False,
    )

    sink.start("wandb/hivemind-chats")

    assert fake.otel_export_batch_at_init == "4"
    assert os.environ["OTEL_BSP_MAX_EXPORT_BATCH_SIZE"] == "  "


def test_empty_log_result_is_a_failure(
    session_payload: Callable[..., dict[str, Any]],
    atif_wrapper: Callable[..., dict[str, Any]],
) -> None:
    conversation = map_atif(Session.from_api(session_payload()), atif_wrapper())
    sink = WeaveSink(
        weave_module=FakeWeave(empty=True),
        conversation_module=FakeConversationModule,
        require_pii_dependencies=False,
    )
    sink.start("wandb/hivemind-chats")
    with pytest.raises(WeaveImportError, match="emitted no trace"):
        sink.log_turn(conversation, conversation.turns[0])


def test_real_weave_0534_conversation_models_accept_mapped_payload(
    monkeypatch: Any,
    session_payload: Callable[..., dict[str, Any]],
    atif_wrapper: Callable[..., dict[str, Any]],
) -> None:
    conversation_types = pytest.importorskip("weave.conversation")
    conversation = map_atif(Session.from_api(session_payload()), atif_wrapper())
    turn = conversation.turns[0]
    turn.subagents.append(
        MappedSubAgent(
            name="reviewer",
            model="o3",
            agent_id="child-1",
            description="explicit delegation",
            version="1",
            system_instructions=[],
            started_at=turn.started_at,
            ended_at=turn.ended_at,
            timestamp_inferred=True,
        )
    )
    fake = FakeWeave()
    sink = WeaveSink(
        weave_module=fake,
        conversation_module=conversation_types,
        require_pii_dependencies=False,
    )
    sink.start("wandb/hivemind-chats")
    sink.log_turn(conversation, turn)
    spans = fake.logged[0]["spans"]
    assert sum(isinstance(span, conversation_types.LLM) for span in spans) == 2
    expected_tools = expected_turn_span_count(turn) - 1 - len(turn.llms) - len(turn.subagents)
    assert sum(isinstance(span, conversation_types.Tool) for span in spans) == expected_tools
    assert sum(isinstance(span, conversation_types.SubAgent) for span in spans) == 1
    transport_spans = [span for span in spans if getattr(span, "name", "") == SPILL_TOOL_NAME]
    assert transport_spans
    conversation_impl = importlib.import_module("weave.conversation.conversation")
    monkeypatch.setattr(conversation_impl, "should_redact_pii", lambda: True)

    def unexpected_fragment_redaction(_value: str) -> str:
        raise AssertionError("pre-redacted transport fragment was redacted again")

    monkeypatch.setattr(
        conversation_impl.pii_redaction,
        "redact_pii_string",
        unexpected_fragment_redaction,
    )
    for span in transport_spans:
        attributes = span._build_attrs(
            conversation_id=conversation.conversation_id,
            include_content=True,
        )
        assert attributes["gen_ai.tool.call.arguments"] == span.arguments
        assert attributes["gen_ai.tool.call.result"] == span.result
        assert conversation_types.Turn(spans=[span]).spans[0] is span


def test_sink_applies_backpressure_before_the_otel_queue_can_fill(
    monkeypatch: Any,
    session_payload: Callable[..., dict[str, Any]],
    atif_wrapper: Callable[..., dict[str, Any]],
) -> None:
    conversation = map_atif(Session.from_api(session_payload()), atif_wrapper())
    sink = WeaveSink(
        weave_module=FakeWeave(),
        conversation_module=FakeConversationModule,
        require_pii_dependencies=False,
        flush_span_limit=3,
    )
    flushes: list[int] = []
    monkeypatch.setattr(sink, "_force_flush", lambda: flushes.append(1))
    sink.start("wandb/hivemind-chats")
    sink.log_turn(conversation, conversation.turns[0])
    assert flushes == [1]
    assert sink.pending_span_count == 0
    sink.finish()


def test_sink_rejects_a_single_turn_too_large_to_export_losslessly(
    session_payload: Callable[..., dict[str, Any]],
    atif_wrapper: Callable[..., dict[str, Any]],
) -> None:
    conversation = map_atif(Session.from_api(session_payload()), atif_wrapper())
    fake = FakeWeave()
    sink = WeaveSink(
        weave_module=fake,
        conversation_module=FakeConversationModule,
        require_pii_dependencies=False,
        max_single_turn_spans=3,
    )
    sink.start("wandb/hivemind-chats")
    with pytest.raises(WeaveImportError, match="lossless per-turn safety limit"):
        sink.log_turn(conversation, conversation.turns[0])
    assert fake.logged == []
    sink.finish()


def test_sink_chunks_an_attribute_that_weave_would_truncate(
    session_payload: Callable[..., dict[str, Any]],
    atif_wrapper: Callable[..., dict[str, Any]],
) -> None:
    conversation = map_atif(Session.from_api(session_payload()), atif_wrapper())
    conversation.turns[0].attributes["oversized"] = "x" * (MAX_ATTRIBUTE_VALUE_CHARS + 1)
    fake = FakeWeave()
    sink = WeaveSink(
        weave_module=fake,
        conversation_module=FakeConversationModule,
        require_pii_dependencies=False,
    )
    sink.start("wandb/hivemind-chats")

    sink.log_turn(conversation, conversation.turns[0])

    payload = fake.logged[0]
    attributes = payload["attributes"]
    assert "oversized" not in attributes
    fragments = _physical_fragments(payload, owner_kind="turn_attributes")
    restored = restore_spilled_attributes(attributes, fragments)
    assert restored["oversized"] == "x" * (MAX_ATTRIBUTE_VALUE_CHARS + 1)
    assert len(canonical_json(attributes).encode()) <= MAX_ROOT_ATTRIBUTE_BYTES
    assert all(
        json_string_wire_bytes(fragment.content) <= MAX_SPILL_FRAGMENT_JSON_BYTES
        for fragment in fragments
    )
    sink.finish()


def test_sink_rechunks_a_chunk_that_grows_during_final_redaction(
    session_payload: Callable[..., dict[str, Any]],
    atif_wrapper: Callable[..., dict[str, Any]],
) -> None:
    conversation = map_atif(Session.from_api(session_payload()), atif_wrapper())
    source = "x" * (MAX_ATTRIBUTE_VALUE_CHARS + 1)
    attributes = conversation.turns[0].attributes
    attributes.update(chunk_large_attributes({"oversized": source}))
    fake = FakeWeave()

    def expanding_redactor(value: Any) -> Any:
        if not isinstance(value, dict):
            return value
        return {
            key: item.replace("x", "xx") if key == "oversized" else item
            for key, item in value.items()
        }

    sink = WeaveSink(
        weave_module=fake,
        conversation_module=FakeConversationModule,
        require_pii_dependencies=False,
        upload_redactor=expanding_redactor,
    )
    sink.start("wandb/hivemind-chats")
    original_hash = conversation.turns[0].payload_sha256

    sink.log_turn(conversation, conversation.turns[0])

    payload = fake.logged[0]
    uploaded = payload["attributes"]
    assert "oversized" not in uploaded
    fragments = _physical_fragments(payload, owner_kind="turn_attributes")
    assert restore_spilled_attributes(uploaded, fragments)["oversized"] == source.replace("x", "xx")
    assert conversation.turns[0].payload_sha256 == original_hash
    assert conversation.turns[0].attributes == attributes
    validate_upload_attributes(uploaded)
    sink.finish()


def test_sink_transport_rechunking_never_changes_the_mapped_payload_hash(
    session_payload: Callable[..., dict[str, Any]],
    atif_wrapper: Callable[..., dict[str, Any]],
) -> None:
    conversation = map_atif(Session.from_api(session_payload()), atif_wrapper())
    conversation.turns[0].attributes["hivemind.preserved_step_data"] = "x" * (
        MAX_ATTRIBUTE_VALUE_CHARS + 1
    )
    conversation = sanitize_mapped_conversation(conversation)
    turn = conversation.turns[0]
    original_hash = turn.payload_sha256
    original_attributes = deepcopy(turn.attributes)
    fake = FakeWeave()
    sink = WeaveSink(
        weave_module=fake,
        conversation_module=FakeConversationModule,
        require_pii_dependencies=False,
        upload_redactor=lambda value: value,
    )
    sink.start("wandb/hivemind-chats")

    sink.log_turn(conversation, turn)

    assert turn.payload_sha256 == original_hash
    assert turn.attributes == original_attributes
    payload = fake.logged[0]
    fragments = _physical_fragments(payload, owner_kind="turn_attributes")
    assert restore_spilled_attributes(payload["attributes"], fragments) == (
        restore_chunked_attributes(original_attributes)
    )
    sink.finish()


def test_sink_fragments_large_tool_fields_after_full_redaction_without_truncation(
    session_payload: Callable[..., dict[str, Any]],
    atif_wrapper: Callable[..., dict[str, Any]],
) -> None:
    conversation = map_atif(Session.from_api(session_payload()), atif_wrapper())
    turn = conversation.turns[0]
    arguments = {
        "content": '🤖"\\\n\u0001' * 30_000,
        "options": [True, False, None],
    }
    result = 'result="\\\u0002🤖\n' * 35_000
    turn.tools[0] = replace(turn.tools[0], arguments=arguments, result=result)
    original_hash = turn.payload_sha256
    large_redaction_inputs: list[str] = []

    def tracking_redactor(value: Any) -> Any:
        if isinstance(value, str) and len(value) > 20_000:
            large_redaction_inputs.append(value)
        return value

    fake = FakeWeave()
    sink = WeaveSink(
        weave_module=fake,
        conversation_module=FakeConversationModule,
        require_pii_dependencies=False,
        upload_redactor=tracking_redactor,
    )
    sink.start("wandb/hivemind-chats")

    outcome = sink.log_turn(conversation, turn)

    payload = fake.logged[0]
    logical_tool = next(
        span for span in payload["spans"] if getattr(span, "name", "") == turn.tools[0].name
    )
    fragments = _physical_fragments(payload, owner_kind="tool")
    assert restore_spilled_tool(
        logical_tool.arguments,
        logical_tool.result,
        fragments,
    ) == (arguments, result)
    assert len(fragments) > 2
    assert all(
        json_string_wire_bytes(fragment.content) <= MAX_SPILL_FRAGMENT_JSON_BYTES
        for fragment in fragments
    )
    physical_fragment_spans = [
        span for span in payload["spans"] if getattr(span, "name", "") == SPILL_TOOL_NAME
    ]
    for span in physical_fragment_spans:
        # Match the SDK's JSONString coercion for arguments, then account for
        # the root attributes that log_turn copies onto every child.
        approximate_wire = canonical_json(
            {
                "attributes": payload["attributes"],
                "gen_ai.tool.call.arguments": json.dumps(
                    span.arguments,
                    ensure_ascii=False,
                    default=str,
                ),
                "gen_ai.tool.call.result": span.result,
                "gen_ai.tool.call.id": span.tool_call_id,
                "gen_ai.tool.name": span.name,
                "gen_ai.tool.type": span.tool_type,
            }
        )
        assert len(approximate_wire.encode()) < 64 * 1_024
    # The complete result is analyzed once. Arbitrary transport chunks never
    # re-enter the local redactor and cannot create boundary-sensitive output.
    assert large_redaction_inputs == [result]
    assert outcome.span_count == expected_turn_span_count(turn)
    assert turn.payload_sha256 == original_hash
    sink.finish()


def test_destination_redacts_complete_tool_field_before_base64_transport(
    session_payload: Callable[..., dict[str, Any]],
    atif_wrapper: Callable[..., dict[str, Any]],
) -> None:
    conversation = map_atif(Session.from_api(session_payload()), atif_wrapper())
    turn = conversation.turns[0]
    pass_three_only_pii = "third-pass-only@example.com"
    arguments = {
        "owner": pass_three_only_pii,
        "content": "x" * 100_000,
    }
    turn.tools[0] = replace(turn.tools[0], arguments=arguments, result="ok")
    destination_inputs: list[str] = []

    def non_idempotent_destination_redactor(value: str) -> str:
        destination_inputs.append(value)
        if pass_three_only_pii in value:
            return value.replace(pass_three_only_pii, "[PASS3_REDACTED]")
        if "[PASS3_REDACTED]" in value:
            return value.replace("[PASS3_REDACTED]", "[PASS4_REDACTED]")
        return value

    assert non_idempotent_destination_redactor("[PASS3_REDACTED]") == "[PASS4_REDACTED]"
    destination_inputs.clear()
    fake = FakeWeave()
    sink = WeaveSink(
        weave_module=fake,
        conversation_module=FakeConversationModule,
        require_pii_dependencies=False,
        upload_redactor=lambda value: value,
        destination_string_redactor=non_idempotent_destination_redactor,
    )
    sink.start("wandb/hivemind-chats")

    sink.log_turn(conversation, turn)

    payload = fake.logged[0]
    logical_tool = next(
        span for span in payload["spans"] if getattr(span, "name", "") == turn.tools[0].name
    )
    fragment_spans = [
        span
        for span in payload["spans"]
        if getattr(span, "name", "") == SPILL_TOOL_NAME
        and getattr(span, "arguments", {}).get("owner_kind") == "tool"
    ]
    # Simulate an additional generic redaction pass outside the fragment Tool's
    # SDK override. Neither encoded content nor compact metadata exposes the
    # marker, so this non-idempotent redactor cannot change the hashed archive.
    for span in fragment_spans:
        serialized_arguments = json.dumps(span.arguments, ensure_ascii=False, default=str)
        assert non_idempotent_destination_redactor(serialized_arguments) == (serialized_arguments)
        span.result = non_idempotent_destination_redactor(span.result)

    fragments = _physical_fragments(payload, owner_kind="tool")
    restored_arguments, restored_result = restore_spilled_tool(
        logical_tool.arguments,
        logical_tool.result,
        fragments,
    )
    assert restored_arguments == {
        "owner": "[PASS3_REDACTED]",
        "content": "x" * 100_000,
    }
    assert restored_result == "ok"
    assert sum(pass_three_only_pii in value for value in destination_inputs) == 1
    serialized_payload = json.dumps(
        payload,
        default=lambda value: getattr(value, "__dict__", str(value)),
        sort_keys=True,
    )
    assert pass_three_only_pii not in serialized_payload
    assert "[PASS3_REDACTED]" not in serialized_payload
    sink.finish()


def test_sink_counts_fragments_from_the_final_expanded_redaction_boundary(
    session_payload: Callable[..., dict[str, Any]],
    atif_wrapper: Callable[..., dict[str, Any]],
) -> None:
    conversation = map_atif(Session.from_api(session_payload()), atif_wrapper())
    turn = conversation.turns[0]
    source = "EXPAND_ON_PASS3:" + ("x" * 25_000)
    expanded = source * 4
    turn.tools[0] = replace(turn.tools[0], result=source)
    pre_boundary_count = expected_turn_span_count(turn)

    sink = WeaveSink(
        weave_module=(fake := FakeWeave()),
        conversation_module=FakeConversationModule,
        require_pii_dependencies=False,
        upload_redactor=lambda value: value,
        destination_string_redactor=lambda value: expanded if value == source else value,
    )
    sink.start("wandb/hivemind-chats")

    outcome = sink.log_turn(conversation, turn)

    assert outcome.span_count == 1 + len(fake.logged[0]["spans"])
    assert outcome.span_count > pre_boundary_count
    logical_tool = next(
        span for span in fake.logged[0]["spans"] if getattr(span, "name", "") == turn.tools[0].name
    )
    fragments = _physical_fragments(fake.logged[0], owner_kind="tool")
    assert restore_spilled_tool(logical_tool.arguments, logical_tool.result, fragments)[1] == (
        expanded
    )
    sink.finish()


def test_sink_fails_closed_when_weave_pii_is_disabled(monkeypatch: Any) -> None:
    monkeypatch.setenv("WEAVE_REDACT_PII", "false")
    sink = WeaveSink(weave_module=FakeWeave(), conversation_module=FakeConversationModule)
    with pytest.raises(WeaveImportError, match="disables required"):
        sink.start("wandb/hivemind-chats")


def test_exact_mocked_sdk_payload_has_local_pii_redaction(
    session_payload: Callable[..., dict[str, Any]],
    atif_wrapper: Callable[..., dict[str, Any]],
) -> None:
    ordinary_code = "class Washington:\n    pass"
    opaque_token = "plainopaquecredentialvalue1234567890"
    wrapper = atif_wrapper(
        agent={
            "name": "Alice Johnson",
            "version": "Alice Johnson version",
            "model_name": "alice@example.com",
            "provider_name": "Alice Johnson",
        }
    )
    wrapper["metadata"] = {"reviewer": "Alice Johnson in New York"}
    wrapper["trajectory"]["steps"][1]["message"] = (
        "Ask Alice Johnson in New York via alice@example.com"
    )
    wrapper["trajectory"]["steps"][2]["tool_calls"][0]["tool_call_id"] = "Alice Johnson"
    wrapper["trajectory"]["steps"][2]["tool_calls"][0]["arguments"]["content"] = ordinary_code
    wrapper["trajectory"]["steps"][2]["tool_calls"][0]["arguments"]["token"] = opaque_token
    wrapper["trajectory"]["steps"][2]["observation"]["results"][0]["source_call_id"] = (
        "Alice Johnson"
    )
    conversation = map_atif(
        Session.from_api(
            session_payload(
                title="Alice Johnson project in New York",
                agent_type="Alice Johnson",
                agent_session_id="/Users/Alice Johnson/session",
            )
        ),
        wrapper,
    )
    turn = conversation.turns[0]
    turn.subagents.append(
        MappedSubAgent(
            name="reviewer",
            model="alice@example.com",
            agent_id="/Users/Alice Johnson/project/child.json",
            description="delegated in New York",
            version="Alice Johnson version",
            system_instructions=[],
            started_at=turn.started_at,
            ended_at=turn.ended_at,
            timestamp_inferred=True,
        )
    )
    fake = FakeWeave()
    configure_weave_pii()
    sink = WeaveSink(
        weave_module=fake,
        conversation_module=FakeConversationModule,
        require_pii_dependencies=False,
        upload_redactor=redact_upload_data,
    )
    sink.start("wandb/hivemind-chats")
    sink.log_turn(conversation, turn)

    serialized = json.dumps(
        fake.logged[0],
        default=lambda value: getattr(value, "__dict__", str(value)),
        sort_keys=True,
    )
    assert "Alice Johnson" not in serialized
    assert "New York" not in serialized
    assert "alice@example.com" not in serialized
    assert "/Users/Alice Johnson" not in serialized
    assert opaque_token not in serialized
    assert any(
        getattr(span, "arguments", {}).get("content") == ordinary_code
        for span in fake.logged[0]["spans"]
    )
    assert fake.logged[0]["agent_name"] != "alice johnson"
    assert fake.logged[0]["model"] != "alice@example.com"
    attributes = fake.logged[0]["attributes"]
    assert attributes["hivemind.turn_key"] == conversation.turns[0].key
    assert attributes["hivemind.session_id"] == conversation.conversation_id.removeprefix(
        "hivemind:"
    )
