from __future__ import annotations

from collections.abc import Callable
from typing import Any

import pytest

from hivemind_weave.atif import content_to_text, map_atif
from hivemind_weave.errors import ATIFSchemaError
from hivemind_weave.models import Session
from hivemind_weave.redaction import redact_string


@pytest.mark.parametrize("unsafe_id", ["line\nbreak", "ansi\x1b[31m", "path/segment", "x" * 257])
def test_session_ids_use_a_bounded_terminal_safe_grammar(
    unsafe_id: str,
    session_payload: Callable[..., dict[str, Any]],
) -> None:
    with pytest.raises(ATIFSchemaError, match="unsafe or unsupported"):
        Session.from_api(session_payload(id=unsafe_id))


@pytest.mark.parametrize(
    "credential_shaped_id",
    [
        "sk-proj-1234567890abcdef",
        "AKIAIOSFODNN7EXAMPLE",
        "eyJabcde.abcdefgh.abcdefgh",
        "4111111111111111-1",
    ],
)
def test_session_ids_reject_values_changed_by_credential_redaction(
    credential_shaped_id: str,
    session_payload: Callable[..., dict[str, Any]],
) -> None:
    with pytest.raises(ATIFSchemaError, match="unsafe or unsupported"):
        Session.from_api(session_payload(id=credential_shaped_id))


def test_session_ids_preserve_normal_opaque_identifiers(
    session_payload: Callable[..., dict[str, Any]],
) -> None:
    source_id = "11111111-1111-4111-8111-111111111111"

    assert Session.from_api(session_payload(id=source_id)).id == source_id


@pytest.mark.parametrize("minor", [*range(8), 8, 42])
def test_accepts_supported_atif_versions(
    minor: int,
    session_payload: Callable[..., dict[str, Any]],
    atif_wrapper: Callable[..., dict[str, Any]],
) -> None:
    conversation = map_atif(
        Session.from_api(session_payload()),
        atif_wrapper(version=f"ATIF-v1.{minor}"),
    )
    assert conversation.schema_version == f"ATIF-v1.{minor}"
    assert conversation.turns


@pytest.mark.parametrize("version", ["ATIF-v2.0", "ATIF-v0.9", "", "banana"])
def test_rejects_unknown_atif_versions(
    version: str,
    session_payload: Callable[..., dict[str, Any]],
    atif_wrapper: Callable[..., dict[str, Any]],
) -> None:
    with pytest.raises(ATIFSchemaError, match="unsupported"):
        map_atif(Session.from_api(session_payload()), atif_wrapper(version=version))


def test_maps_system_reasoning_tools_usage_and_parent_link(
    session_payload: Callable[..., dict[str, Any]],
    atif_wrapper: Callable[..., dict[str, Any]],
) -> None:
    session = Session.from_api(
        session_payload(parent_session_id="parent-1", username="person@example.com")
    )
    conversation = map_atif(session, atif_wrapper())

    assert conversation.conversation_id == f"hivemind:{session.id}"
    assert conversation.agent_name == "codex"
    assert len(conversation.turns) == 1
    turn = conversation.turns[0]
    assert turn.system_instructions == ["You are a coding agent."]
    assert turn.messages[0].content == "Create hello.txt"
    assert turn.output_messages[0].content == "Created hello.txt."
    assert len(turn.llms) == 2
    assert turn.llms[0].provider == "openai"
    assert turn.llms[0].reasoning == "Use the write tool."
    assert turn.llms[0].usage == {
        "input_tokens": 10,
        "output_tokens": 4,
        "reasoning_tokens": 1,
        "cache_creation_input_tokens": 0,
        "cache_read_input_tokens": 2,
    }
    assert turn.tools[0].name == "write_file"
    assert turn.tools[0].result == {"ok": True}
    assert turn.attributes["hivemind.parent_session_id"] == "parent-1"
    assert turn.attributes["hivemind.is_subagent"] is True
    assert turn.attributes["hivemind.timestamp_inferred"] is True
    assert "hivemind.user" not in turn.attributes
    assert len(turn.payload_sha256) == 64
    assert turn.attributes["hivemind.payload_sha256"] == turn.payload_sha256


def test_missing_timestamps_are_inferred_and_stable(
    session_payload: Callable[..., dict[str, Any]],
    atif_wrapper: Callable[..., dict[str, Any]],
) -> None:
    steps = [
        {"step_id": 1, "source": "user", "message": "hello"},
        {"step_id": 2, "source": "agent", "message": "hi"},
    ]
    session = Session.from_api(session_payload())
    first = map_atif(session, atif_wrapper(steps=steps))
    second = map_atif(session, atif_wrapper(steps=steps))
    turn = first.turns[0]
    assert turn.attributes["hivemind.timestamp_inferred"] is True
    assert turn.llms[0].started_at >= session.started_at
    assert turn.payload_sha256 == second.turns[0].payload_sha256


def test_multimodal_and_unmatched_observation_are_preserved(
    session_payload: Callable[..., dict[str, Any]],
    atif_wrapper: Callable[..., dict[str, Any]],
) -> None:
    message = [
        {"type": "text", "text": "inspect this"},
        {"type": "image", "source": {"media_type": "image/png", "path": "/tmp/a.png"}},
    ]
    steps = [
        {"step_id": 1, "source": "user", "message": message},
        {
            "step_id": 2,
            "source": "agent",
            "message": "done",
            "observation": {"results": [{"source_call_id": "missing", "content": "orphan output"}]},
        },
    ]
    turn = map_atif(Session.from_api(session_payload()), atif_wrapper(steps=steps)).turns[0]
    assert "inspect this" in turn.messages[0].content
    assert "image/png" in turn.messages[0].content
    assert turn.tools[0].name == "unmatched_observation"
    assert turn.tools[0].result == "orphan output"
    assert "unmatched_observation:missing" in turn.attributes["hivemind.mapping_warnings"]


def test_synthetic_leading_agent_turn(
    session_payload: Callable[..., dict[str, Any]],
    atif_wrapper: Callable[..., dict[str, Any]],
) -> None:
    wrapper = atif_wrapper(
        steps=[
            {
                "step_id": 9,
                "timestamp": "2026-08-01T12:00:02Z",
                "source": "agent",
                "message": "restored output",
            }
        ]
    )
    turn = map_atif(Session.from_api(session_payload()), wrapper).turns[0]
    assert turn.key == "atif:synthetic:9"
    assert turn.attributes["hivemind.synthetic_turn"] is True


def test_wrapper_step_count_mismatch_is_rejected(
    session_payload: Callable[..., dict[str, Any]],
    atif_wrapper: Callable[..., dict[str, Any]],
) -> None:
    wrapper = atif_wrapper()
    wrapper["step_count"] += 1
    with pytest.raises(ATIFSchemaError, match="does not match trajectory length"):
        map_atif(Session.from_api(session_payload()), wrapper)


def test_content_to_text_preserves_structured_unknown_parts() -> None:
    rendered = content_to_text([{"type": "audio", "uri": "file.wav"}])
    assert rendered == '{"type":"audio","uri":"file.wav"}'


def test_wrapper_identity_is_enforced(
    session_payload: Callable[..., dict[str, Any]],
    atif_wrapper: Callable[..., dict[str, Any]],
) -> None:
    with pytest.raises(ATIFSchemaError, match="mismatched session_id"):
        map_atif(
            Session.from_api(session_payload()),
            atif_wrapper(wrapper_session_id="different"),
        )


def test_copied_context_is_input_not_a_duplicate_turn(
    session_payload: Callable[..., dict[str, Any]],
    atif_wrapper: Callable[..., dict[str, Any]],
) -> None:
    steps = [
        {"step_id": 1, "source": "user", "message": "old", "is_copied_context": True},
        {
            "step_id": 2,
            "source": "agent",
            "message": "old answer",
            "is_copied_context": True,
        },
        {"step_id": 3, "source": "user", "message": "new"},
        {"step_id": 4, "source": "agent", "message": "new answer"},
    ]
    conversation = map_atif(Session.from_api(session_payload()), atif_wrapper(steps=steps))
    assert len(conversation.turns) == 1
    turn = conversation.turns[0]
    assert [message.content for message in turn.messages] == ["new"]
    assert [message.content for message in turn.llms[0].input_messages] == [
        "old",
        "old answer",
        "new",
    ]
    assert turn.attributes["hivemind.copied_context_steps"] == 2


def test_trailing_copied_context_is_preserved_while_copy_only_waits_for_a_turn(
    session_payload: Callable[..., dict[str, Any]],
    atif_wrapper: Callable[..., dict[str, Any]],
) -> None:
    session = Session.from_api(session_payload())
    trailing_steps = [
        {"step_id": 1, "source": "user", "message": "live"},
        {"step_id": 2, "source": "agent", "message": "answer"},
        {
            "step_id": 3,
            "source": "user",
            "message": "trailing copied user",
            "is_copied_context": True,
        },
    ]
    trailing = map_atif(session, atif_wrapper(steps=trailing_steps)).turns[0]
    assert trailing.attributes["hivemind.copied_context_steps"] == 0
    assert trailing.attributes["hivemind.trailing_copied_context_steps"] == 1
    assert "trailing copied user" in trailing.attributes["hivemind.trailing_copied_step_data"]

    copied_steps = [
        {"step_id": 7, "source": "user", "message": "copied only", "is_copied_context": True},
        {
            "step_id": 8,
            "source": "agent",
            "message": "copied answer",
            "is_copied_context": True,
        },
    ]
    assert map_atif(session, atif_wrapper(steps=copied_steps)).turns == []


def test_trailing_copied_context_does_not_rehash_history_when_a_turn_is_appended(
    session_payload: Callable[..., dict[str, Any]],
    atif_wrapper: Callable[..., dict[str, Any]],
) -> None:
    session = Session.from_api(session_payload())
    prefix = [
        {"step_id": 1, "source": "user", "message": "live"},
        {"step_id": 2, "source": "agent", "message": "answer"},
        {
            "step_id": 3,
            "source": "user",
            "message": "copied context",
            "is_copied_context": True,
        },
    ]
    first = map_atif(session, atif_wrapper(steps=prefix)).turns[0]
    appended = map_atif(
        session,
        atif_wrapper(
            steps=[
                *prefix,
                {"step_id": 4, "source": "user", "message": "next"},
                {"step_id": 5, "source": "agent", "message": "next answer"},
            ]
        ),
    )

    assert first.payload_sha256 == appended.turns[0].payload_sha256
    assert appended.turns[0].attributes["hivemind.trailing_copied_context_steps"] == 0
    assert [message.content for message in appended.turns[1].llms[0].input_messages] == [
        "copied context",
        "next",
    ]


def test_system_only_prefix_waits_for_a_user_turn_without_a_stale_synthetic_turn(
    session_payload: Callable[..., dict[str, Any]],
    atif_wrapper: Callable[..., dict[str, Any]],
) -> None:
    session = Session.from_api(session_payload())
    prefix = [{"step_id": 1, "source": "system", "message": "follow policy"}]
    assert map_atif(session, atif_wrapper(steps=prefix)).turns == []

    appended = map_atif(
        session,
        atif_wrapper(
            steps=[
                *prefix,
                {"step_id": 2, "source": "user", "message": "hello"},
                {"step_id": 3, "source": "agent", "message": "world"},
            ]
        ),
    )
    assert len(appended.turns) == 1
    assert appended.turns[0].system_instructions == ["follow policy"]


def test_every_agent_step_gets_an_inferred_llm_span_even_when_count_is_zero(
    session_payload: Callable[..., dict[str, Any]],
    atif_wrapper: Callable[..., dict[str, Any]],
) -> None:
    steps = [
        {"step_id": 1, "source": "user", "message": "dispatch"},
        {
            "step_id": 2,
            "source": "agent",
            "message": "deterministic response",
            "llm_call_count": 0,
        },
    ]
    turn = map_atif(Session.from_api(session_payload()), atif_wrapper(steps=steps)).turns[0]
    assert len(turn.llms) == 1
    assert turn.output_messages[0].content == "deterministic response"
    assert "agent_step_2_llm_call_count_0" in turn.attributes["hivemind.mapping_warnings"]


def test_turn_end_covers_explicit_child_end(
    session_payload: Callable[..., dict[str, Any]],
    atif_wrapper: Callable[..., dict[str, Any]],
) -> None:
    steps = [
        {
            "step_id": 1,
            "timestamp": "2026-08-01T12:00:00Z",
            "source": "user",
            "message": "hello",
        },
        {
            "step_id": 2,
            "timestamp": "2026-08-01T12:00:01Z",
            "ended_at": "2026-08-01T12:00:09Z",
            "source": "agent",
            "message": "world",
        },
    ]
    turn = map_atif(Session.from_api(session_payload()), atif_wrapper(steps=steps)).turns[0]
    assert turn.ended_at == turn.llms[0].ended_at
    assert turn.attributes["hivemind.timestamp_inferred"] is False


def test_provider_metrics_extra_is_mapped(
    session_payload: Callable[..., dict[str, Any]],
    atif_wrapper: Callable[..., dict[str, Any]],
) -> None:
    steps = [
        {"step_id": 1, "source": "user", "message": "hello"},
        {
            "step_id": 2,
            "source": "agent",
            "message": "world",
            "metrics": {
                "prompt_tokens": 10,
                "completion_tokens": 2,
                "extra": {
                    "reasoning_tokens": 7,
                    "cache_creation_input_tokens": 5,
                },
            },
        },
    ]
    usage = (
        map_atif(Session.from_api(session_payload()), atif_wrapper(steps=steps))
        .turns[0]
        .llms[0]
        .usage
    )
    assert usage["reasoning_tokens"] == 7
    assert usage["cache_creation_input_tokens"] == 5


def test_embedded_subagent_reference_is_preserved(
    session_payload: Callable[..., dict[str, Any]],
    atif_wrapper: Callable[..., dict[str, Any]],
) -> None:
    child = {
        "schema_version": "ATIF-v1.7",
        "trajectory_id": "child-1",
        "agent": {"name": "child"},
        "steps": [],
    }
    steps = [
        {"step_id": 1, "source": "user", "message": "delegate"},
        {
            "step_id": 2,
            "source": "agent",
            "message": "delegating",
            "tool_calls": [
                {
                    "tool_call_id": "call-child",
                    "function_name": "subagent",
                    "arguments": {},
                }
            ],
            "observation": {
                "results": [
                    {
                        "source_call_id": "call-child",
                        "content": "delegation complete",
                        "subagent_trajectory_ref": [
                            {
                                "trajectory_id": "child-1",
                                "session_id": "child-session",
                                "extra": {"role": "reviewer"},
                            }
                        ],
                    }
                ]
            },
        },
    ]
    turn = map_atif(
        Session.from_api(session_payload()),
        atif_wrapper(steps=steps, subagent_trajectories=[child]),
    ).turns[0]
    assert turn.tools[0].result["content"] == "delegation complete"
    assert turn.tools[0].result["subagent_trajectory_ref"][0]["trajectory_id"] == "child-1"
    assert turn.tools[0].result["trajectory"]["trajectory_id"] == "child-1"
    assert turn.attributes["hivemind.embedded_subagent_count"] == 1
    assert len(turn.subagents) == 1
    assert turn.subagents[0].agent_id == "child-1"


def test_subagent_resolution_ids_do_not_use_colliding_informational_session_ids(
    session_payload: Callable[..., dict[str, Any]],
    atif_wrapper: Callable[..., dict[str, Any]],
) -> None:
    children = [
        {
            "schema_version": "ATIF-v1.7",
            "trajectory_id": trajectory_id,
            "agent": {"name": "child"},
            "steps": [],
        }
        for trajectory_id in ("child-1", "child-2")
    ]
    steps = [
        {"step_id": 1, "source": "user", "message": "delegate twice"},
        {
            "step_id": 2,
            "source": "agent",
            "message": "done",
            "observation": {
                "results": [
                    {
                        "content": "complete",
                        "subagent_trajectory_ref": [
                            {"trajectory_id": "child-1", "session_id": "shared"},
                            {"trajectory_id": "child-2", "session_id": "shared"},
                        ],
                    }
                ]
            },
        },
    ]
    turn = map_atif(
        Session.from_api(session_payload()),
        atif_wrapper(steps=steps, subagent_trajectories=children),
    ).turns[0]
    assert [item.agent_id for item in turn.subagents] == ["child-1", "child-2"]


def test_unreferenced_embedded_subagent_is_preserved_and_hashed(
    session_payload: Callable[..., dict[str, Any]],
    atif_wrapper: Callable[..., dict[str, Any]],
) -> None:
    session = Session.from_api(session_payload())
    child = {
        "schema_version": "ATIF-v1.7",
        "trajectory_id": "orphan-child",
        "agent": {"name": "child"},
        "steps": [{"step_id": 1, "source": "agent", "message": "SECRET CHILD CONTENT"}],
    }
    changed_child = {
        **child,
        "steps": [{"step_id": 1, "source": "agent", "message": "CHANGED CHILD CONTENT"}],
    }
    original = map_atif(
        session,
        atif_wrapper(subagent_trajectories=[child]),
    ).turns[0]
    changed = map_atif(
        session,
        atif_wrapper(subagent_trajectories=[changed_child]),
    ).turns[0]

    preserved = original.attributes["hivemind.unreferenced_subagent_trajectories"]
    assert "SECRET CHILD CONTENT" in preserved
    assert original.payload_sha256 != changed.payload_sha256
    assert original.subagents == []


def test_timestamp_less_orphan_subagent_does_not_move_when_a_turn_is_appended(
    session_payload: Callable[..., dict[str, Any]],
    atif_wrapper: Callable[..., dict[str, Any]],
) -> None:
    session = Session.from_api(session_payload())
    child = {
        "schema_version": "ATIF-v1.7",
        "trajectory_id": "orphan-child",
        "agent": {"name": "child"},
        "steps": [{"step_id": 1, "source": "agent", "message": "no timestamp"}],
    }
    first_steps = [
        {"step_id": 1, "source": "user", "message": "first"},
        {"step_id": 2, "source": "agent", "message": "answer"},
    ]
    first = map_atif(
        session,
        atif_wrapper(steps=first_steps, subagent_trajectories=[child]),
    )
    appended = map_atif(
        session,
        atif_wrapper(
            steps=[
                *first_steps,
                {"step_id": 3, "source": "user", "message": "second"},
                {"step_id": 4, "source": "agent", "message": "answer two"},
            ],
            subagent_trajectories=[child],
        ),
    )
    assert first.turns[0].payload_sha256 == appended.turns[0].payload_sha256
    assert "hivemind.unreferenced_subagent_trajectories" in appended.turns[0].attributes
    assert "hivemind.unreferenced_subagent_trajectories" not in appended.turns[1].attributes


def test_system_updates_apply_only_to_later_llms(
    session_payload: Callable[..., dict[str, Any]],
    atif_wrapper: Callable[..., dict[str, Any]],
) -> None:
    steps = [
        {"step_id": 1, "source": "user", "message": "hello"},
        {"step_id": 2, "source": "agent", "message": "first"},
        {"step_id": 3, "source": "system", "message": "compacted context"},
        {"step_id": 4, "source": "agent", "message": "second"},
    ]
    turn = map_atif(Session.from_api(session_payload()), atif_wrapper(steps=steps)).turns[0]
    assert turn.llms[0].system_instructions == []
    assert turn.llms[1].system_instructions == ["compacted context"]
    assert turn.system_instructions == []


def test_session_uses_real_git_fields_and_defers_unknown_activity(
    session_payload: Callable[..., dict[str, Any]],
) -> None:
    session = Session.from_api(session_payload(last_activity_at=None))
    assert session.repository == "wandb/hivemind"
    assert session.branch == "codex/importer"
    assert session.last_activity_known is False


def test_payload_hash_ignores_mutable_provenance_attributes(
    session_payload: Callable[..., dict[str, Any]],
    atif_wrapper: Callable[..., dict[str, Any]],
) -> None:
    turn = map_atif(Session.from_api(session_payload()), atif_wrapper()).turns[0]
    original_hash = turn.payload_sha256
    turn.attributes["hivemind.importer_version"] = "future-version"
    turn.attributes["hivemind.embedded_subagent_count"] = 99
    turn.finalize_hash()
    assert turn.payload_sha256 == original_hash


def test_payload_hash_includes_parent_linkage(
    session_payload: Callable[..., dict[str, Any]],
    atif_wrapper: Callable[..., dict[str, Any]],
) -> None:
    root = map_atif(Session.from_api(session_payload()), atif_wrapper()).turns[0]
    child = map_atif(
        Session.from_api(session_payload(parent_session_id="parent-1")),
        atif_wrapper(),
    ).turns[0]
    assert root.payload_sha256 != child.payload_sha256


def test_preserves_atif_extras_metrics_and_tool_definitions(
    session_payload: Callable[..., dict[str, Any]],
    atif_wrapper: Callable[..., dict[str, Any]],
) -> None:
    steps = [
        {"step_id": 1, "source": "user", "message": "analyze"},
        {
            "step_id": 2,
            "source": "agent",
            "message": "done",
            "reasoning_effort": "high",
            "extra": {"provider": "anthropic", "request_id": "req-1"},
            "metrics": {
                "prompt_tokens": 2,
                "completion_tokens": 1,
                "cost_usd": 0.01,
                "prompt_token_ids": [1, 2],
                "completion_token_ids": [3],
                "logprobs": [-0.2],
                "extra": {"cache_creation_input_tokens": 4},
            },
            "tool_calls": [
                {
                    "tool_call_id": "call-1",
                    "function_name": "inspect",
                    "arguments": {},
                    "extra": {"permission": "read"},
                }
            ],
            "observation": {
                "results": [
                    {
                        "source_call_id": "call-1",
                        "content": "ok",
                        "extra": {"exit_code": 0},
                    }
                ]
            },
        },
    ]
    wrapper = atif_wrapper(
        steps=steps,
        agent={
            "name": "custom-agent",
            "version": "1",
            "model_name": "private-model",
            "tool_definitions": [{"name": "inspect", "description": "read data"}],
            "extra": {"provider": "anthropic"},
        },
        extra={"continuation": "c-1"},
        final_metrics={"cost_usd": 0.01, "extra": {"source": "atif"}},
    )
    wrapper["metadata"] = {"exporter": "hivemind"}
    wrapper["vendor_export"] = {"revision": 7}
    turn = map_atif(Session.from_api(session_payload()), wrapper).turns[0]

    assert turn.llms[0].provider == "anthropic"
    assert turn.tools[0].result == {"content": "ok", "extra": {"exit_code": 0}}
    preserved = turn.attributes["hivemind.preserved_step_data"]
    assert "reasoning_effort" in preserved
    assert "prompt_token_ids" in preserved
    assert "permission" in preserved
    assert "inspect" in turn.attributes["hivemind.atif_tool_definitions"]
    assert "continuation" in turn.attributes["hivemind.atif_trajectory_extra"]
    assert "cost_usd" in turn.attributes["hivemind.atif_final_metrics"]
    assert "exporter" in turn.attributes["hivemind.atif_wrapper_metadata"]
    assert "revision" in turn.attributes["hivemind.atif_wrapper_extra"]


def test_preserves_terminal_context_multimodal_and_nested_function_metadata(
    session_payload: Callable[..., dict[str, Any]],
    atif_wrapper: Callable[..., dict[str, Any]],
) -> None:
    steps = [
        {
            "step_id": 1,
            "source": "user",
            "message": [
                {
                    "type": "text",
                    "text": "inspect",
                    "cache_control": {"type": "ephemeral"},
                }
            ],
        },
        {
            "step_id": 2,
            "source": "agent",
            "message": "working",
            "tool_calls": [
                {
                    "id": "call-1",
                    "type": "function",
                    "function": {
                        "name": "inspect",
                        "arguments": {"path": "a.txt"},
                        "description": "read a file",
                        "vendor_meta": {"safe": True},
                    },
                }
            ],
        },
        {"step_id": 3, "source": "system", "message": "terminal system update"},
        {"step_id": 4, "source": "file", "message": {"path": "artifact.txt"}},
    ]
    turn = map_atif(Session.from_api(session_payload()), atif_wrapper(steps=steps)).turns[0]
    preserved = turn.attributes["hivemind.preserved_step_data"]
    assert "cache_control" in preserved
    assert "terminal system update" in preserved
    assert "artifact.txt" in preserved
    assert "vendor_meta" in preserved
    assert turn.tools[0].description == "read a file"


def test_metrics_duration_ms_controls_span_end(
    session_payload: Callable[..., dict[str, Any]],
    atif_wrapper: Callable[..., dict[str, Any]],
) -> None:
    steps = [
        {
            "step_id": 1,
            "timestamp": "2026-08-01T12:00:00Z",
            "source": "user",
            "message": "start",
        },
        {
            "step_id": 2,
            "timestamp": "2026-08-01T12:00:01Z",
            "source": "agent",
            "message": "long call",
            "metrics": {"duration_ms": 5000},
        },
        {
            "step_id": 3,
            "timestamp": "2026-08-01T12:00:02Z",
            "source": "agent",
            "message": "overlapping follow-up",
        },
    ]
    turn = map_atif(Session.from_api(session_payload()), atif_wrapper(steps=steps)).turns[0]
    assert turn.llms[0].ended_at.isoformat() == "2026-08-01T12:00:06+00:00"
    assert turn.attributes["hivemind.timestamp_inferred"] is True


def test_duplicate_deterministic_turn_keys_are_rejected_before_upload(
    session_payload: Callable[..., dict[str, Any]],
    atif_wrapper: Callable[..., dict[str, Any]],
) -> None:
    steps = [
        {"step_id": 1, "source": "user", "message": "first"},
        {"step_id": 2, "source": "agent", "message": "answer"},
        {"step_id": 1, "source": "user", "message": "second"},
        {"step_id": 3, "source": "agent", "message": "answer two"},
    ]
    with pytest.raises(ATIFSchemaError, match="duplicate deterministic turn keys"):
        map_atif(Session.from_api(session_payload()), atif_wrapper(steps=steps))


def test_non_numeric_step_ids_use_position_without_a_hash_or_raw_value(
    session_payload: Callable[..., dict[str, Any]],
    atif_wrapper: Callable[..., dict[str, Any]],
) -> None:
    steps = [
        {"step_id": "/Users/Alice Johnson/private", "source": "user", "message": "hello"},
        {"step_id": "agent", "source": "agent", "message": "world"},
    ]
    turn = map_atif(Session.from_api(session_payload()), atif_wrapper(steps=steps)).turns[0]
    assert turn.key == "atif:step:index:0"
    assert "Alice" not in turn.key


def test_redaction_sensitive_numeric_step_ids_use_position_in_turn_keys(
    session_payload: Callable[..., dict[str, Any]],
    atif_wrapper: Callable[..., dict[str, Any]],
) -> None:
    card_number = "4111111111111111"
    steps = [
        {"step_id": card_number, "source": "user", "message": "hello"},
        {"step_id": 2, "source": "agent", "message": "world"},
    ]

    turn = map_atif(Session.from_api(session_payload()), atif_wrapper(steps=steps)).turns[0]

    assert turn.key == "atif:step:index:0"
    assert card_number not in turn.key
    assert redact_string(turn.key) == turn.key


def test_payload_hash_changes_when_preserved_step_data_changes(
    session_payload: Callable[..., dict[str, Any]],
    atif_wrapper: Callable[..., dict[str, Any]],
) -> None:
    original_steps = [
        {"step_id": 1, "source": "user", "message": "hello"},
        {"step_id": 2, "source": "agent", "message": "world", "extra": {"id": 1}},
    ]
    changed_steps = [
        *original_steps[:1],
        {**original_steps[1], "extra": {"id": 2}},
    ]
    session = Session.from_api(session_payload())
    original = map_atif(session, atif_wrapper(steps=original_steps)).turns[0]
    changed = map_atif(session, atif_wrapper(steps=changed_steps)).turns[0]
    assert original.payload_sha256 != changed.payload_sha256


def test_payload_hash_covers_wrapper_and_nonaggregate_trajectory_metadata(
    session_payload: Callable[..., dict[str, Any]],
    atif_wrapper: Callable[..., dict[str, Any]],
) -> None:
    session = Session.from_api(session_payload())
    original_wrapper = atif_wrapper(run_note="first")
    original_wrapper["metadata"] = {"exporter_revision": "a"}
    changed_wrapper_metadata = atif_wrapper(run_note="first")
    changed_wrapper_metadata["metadata"] = {"exporter_revision": "b"}
    changed_trajectory_metadata = atif_wrapper(run_note="second")
    changed_trajectory_metadata["metadata"] = {"exporter_revision": "a"}

    original = map_atif(session, original_wrapper).turns[0]
    wrapper_changed = map_atif(session, changed_wrapper_metadata).turns[0]
    trajectory_changed = map_atif(session, changed_trajectory_metadata).turns[0]
    assert original.payload_sha256 != wrapper_changed.payload_sha256
    assert original.payload_sha256 != trajectory_changed.payload_sha256


def test_mutable_session_final_metrics_do_not_rehash_historical_turns(
    session_payload: Callable[..., dict[str, Any]],
    atif_wrapper: Callable[..., dict[str, Any]],
) -> None:
    session = Session.from_api(session_payload())
    first = map_atif(session, atif_wrapper(final_metrics={"total_tokens": 10})).turns[0]
    after_append = map_atif(
        session,
        atif_wrapper(final_metrics={"total_tokens": 20}),
    ).turns[0]
    assert first.payload_sha256 == after_append.payload_sha256


def test_mutable_session_branch_does_not_rehash_historical_turns(
    session_payload: Callable[..., dict[str, Any]],
    atif_wrapper: Callable[..., dict[str, Any]],
) -> None:
    original = map_atif(
        Session.from_api(session_payload(git_branch="feature/one")),
        atif_wrapper(),
    ).turns[0]
    renamed = map_atif(
        Session.from_api(session_payload(git_branch="feature/two")),
        atif_wrapper(),
    ).turns[0]

    assert original.payload_sha256 == renamed.payload_sha256
    assert renamed.attributes["hivemind.branch"] == "feature/two"


def test_o_series_model_provider_inference(
    session_payload: Callable[..., dict[str, Any]],
    atif_wrapper: Callable[..., dict[str, Any]],
) -> None:
    steps = [
        {"step_id": 1, "source": "user", "message": "hello"},
        {"step_id": 2, "source": "agent", "message": "world", "model_name": "o3"},
    ]
    session = Session.from_api(session_payload(agent_type="cursor", model=""))
    turn = map_atif(session, atif_wrapper(steps=steps)).turns[0]
    assert turn.llms[0].provider == "openai"


def test_future_observation_is_not_leaked_into_intervening_llm_context(
    session_payload: Callable[..., dict[str, Any]],
    atif_wrapper: Callable[..., dict[str, Any]],
) -> None:
    steps = [
        {"step_id": 1, "source": "user", "message": "start"},
        {
            "step_id": 2,
            "source": "agent",
            "message": "calling",
            "tool_calls": [
                {
                    "tool_call_id": "later",
                    "function_name": "slow_tool",
                    "arguments": {},
                }
            ],
        },
        {"step_id": 3, "source": "agent", "message": "still waiting"},
        {
            "step_id": 4,
            "source": "observation",
            "source_call_id": "later",
            "content": "future result",
        },
        {"step_id": 5, "source": "agent", "message": "received"},
    ]
    turn = map_atif(Session.from_api(session_payload()), atif_wrapper(steps=steps)).turns[0]
    second_input = [message.content for message in turn.llms[1].input_messages]
    third_input = [message.content for message in turn.llms[2].input_messages]
    assert "future result" not in second_input
    assert "future result" in third_input
