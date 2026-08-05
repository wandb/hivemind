from __future__ import annotations

import json
from dataclasses import FrozenInstanceError, replace
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from pathlib import Path
from typing import Any

import pytest

from hivemind_weave import recovery_projection as projection

PROJECT = "wandb/hivemind-chats"
CONVERSATION_ID = "hivemind:session"
STARTED_AT = datetime(2026, 8, 3, 12, 0, tzinfo=UTC)
ENDED_AT = STARTED_AT + timedelta(seconds=1)
START_NS = int(STARTED_AT.timestamp() * 1_000_000_000)
END_NS = int(ENDED_AT.timestamp() * 1_000_000_000)


def _stable_attributes() -> dict[str, Any]:
    return {
        "hivemind.session_id": "session",
        "hivemind.turn_key": "atif:step:1",
        "hivemind.payload_sha256": "a" * 64,
        "hivemind.source_payload_sha256": "b" * 64,
        "hivemind.atif_schema_version": "ATIF-v1.2",
        "hivemind.importer_version": "0.1.0",
    }


def _capture(
    *,
    label: str = "legacy:root",
    span_name: str = "invoke_agent codex",
    started_at_ns: int = START_NS,
    attributes: dict[str, Any] | None = None,
) -> projection.LocalSpanCapture:
    values = {
        "weave.operation.name": "invoke_agent",
        "weave.agent.name": "codex",
        "weave.agent.version": "1.2.3",
        "weave.agent.id": "agent-1",
        "weave.conversation.id": CONVERSATION_ID,
        "gen_ai.input.messages": '[{"role":"user","content":"hello"}]',
        **_stable_attributes(),
    }
    if attributes:
        values.update(attributes)
    return projection.LocalSpanCapture(
        label=label,
        span_name=span_name,
        start_time_ns=started_at_ns,
        end_time_ns=started_at_ns + 1_000_000_000,
        attributes=values,
    )


def _attribution() -> projection.RootAttribution:
    return projection.RootAttribution(
        agent_name="codex",
        agent_version="1.2.3",
        agent_id="agent-1",
        conversation_id=CONVERSATION_ID,
    )


def _hosted_row(
    capture: projection.LocalSpanCapture | None = None,
) -> dict[str, Any]:
    capture = capture or _capture()
    row = projection.canonicalize_agent_span(
        projection.extract_local_row(capture, project=PROJECT),
        attribution=_attribution(),
        remote=False,
    )
    # The local extractor's Python Span shim produces a local-time naive
    # timestamp. Hosted Agents rows are UTC; local projection intentionally
    # takes historical core time from the capture rather than that shim field.
    row["started_at"] = datetime.fromtimestamp(
        capture.start_time_ns / 1_000_000_000, tz=UTC
    ).isoformat()
    row["ended_at"] = datetime.fromtimestamp(
        capture.end_time_ns / 1_000_000_000, tz=UTC
    ).isoformat()
    return row


def _custom_maps() -> dict[str, dict[str, Any]]:
    return {field: {} for field in projection.CUSTOM_MAP_FIELDS}


def _legacy_tool_projection(
    result: str,
    *,
    arguments: str = "{}",
    compact: bool = False,
) -> projection.NormalizedSpanProjection:
    attributes: dict[str, Any] = {
        "weave.operation.name": "execute_tool",
        "gen_ai.tool.name": "shell",
        "gen_ai.tool.call.id": "call-1",
        "gen_ai.tool.call.arguments": arguments,
        "gen_ai.tool.call.result": result,
    }
    if compact:
        attributes[projection.RECOVERY_CHILD_KEY] = "c" * 64
        attributes[projection.RECOVERY_SCHEMA_KEY] = projection.RECOVERY_SCHEMA
    return projection.project_local_capture(
        _capture(
            label="recovery:tool:0" if compact else "legacy:tool:0",
            span_name="execute_tool shell",
            attributes=attributes,
        ),
        attribution=_attribution(),
        project=PROJECT,
    )


def test_capture_is_defensively_immutable() -> None:
    original = _stable_attributes()
    original["nested"] = {"items": ["one", "two"]}
    capture = projection.LocalSpanCapture(
        label="legacy:tool:0",
        span_name="execute_tool shell",
        start_time_ns=START_NS,
        end_time_ns=END_NS,
        attributes=original,
    )

    original["nested"]["items"].append("changed")

    assert capture.attributes["nested"]["items"] == ("one", "two")
    with pytest.raises(TypeError):
        capture.attributes["new"] = "value"  # type: ignore[index]
    with pytest.raises(FrozenInstanceError):
        capture.label = "changed"  # type: ignore[misc]


def test_content_bearing_models_have_safe_representations() -> None:
    secret = "super-secret-conversation-content"
    capture = _capture(attributes={"hivemind.unselected": secret})
    selected = projection.SelectedCustomAttributes(
        tuple(_stable_attributes().items()),
        "legacy",
        None,
    )

    assert secret not in repr(capture)
    assert "session" not in repr(selected)
    assert CONVERSATION_ID not in repr(_attribution())


def test_otlp_roundtrip_recursively_converts_tuple_arrays() -> None:
    value = {"outer": ("one", ("two", "three")), "scalar": 1}

    assert projection.otlp_roundtrip_value(value) == {
        "outer": ["one", ["two", "three"]],
        "scalar": 1,
    }


def test_otlp_roundtrip_expands_dotted_keys_and_json_strings() -> None:
    expanded = projection.otlp_roundtrip_attributes(
        {
            "gen_ai.tool.call.arguments": '{"command":"echo hi"}',
            "gen_ai.tool.call.result": '[{"ok":true}]',
            "gen_ai.tool.description": "plain text",
            "gen_ai.tool.name": "{malformed",
        }
    )

    assert expanded["gen_ai"]["tool"]["call"]["arguments"] == {"command": "echo hi"}
    assert expanded["gen_ai"]["tool"]["call"]["result"] == [{"ok": True}]
    assert expanded["gen_ai"]["tool"]["description"] == "plain text"
    assert expanded["gen_ai"]["tool"]["name"] == "{malformed"


def test_local_extraction_filters_unknown_overflow_attributes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured_attributes: dict[str, Any] = {}

    class FakeSpan:
        def __init__(self, **kwargs: Any) -> None:
            self.attributes = kwargs["attributes"]
            self.resource = None
            self.events: list[Any] = []
            self.links: list[Any] = []
            captured_attributes.update(self.attributes)

    class Extracted:
        def model_dump(self, *, mode: str) -> dict[str, Any]:
            assert mode == "json"
            return {}

    monkeypatch.setattr(projection, "Span", FakeSpan)
    monkeypatch.setattr(
        projection,
        "_extract_genai_span",
        lambda: lambda _span, _project: Extracted(),
    )
    capture = _capture(
        attributes={
            "hivemind.unselected.large_archive": "x" * 1_000_000,
            "gen_ai.tool.name": "shell",
        }
    )

    projection.extract_local_row(capture, project=PROJECT)

    assert "unselected" not in captured_attributes["hivemind"]
    assert captured_attributes["gen_ai"]["tool"]["name"] == "shell"
    assert all(
        key.removeprefix("hivemind.") in captured_attributes["hivemind"]
        for key in projection.STABLE_CUSTOM_KEYS
    )


def test_local_extraction_reproduces_hosted_tool_json_serialization() -> None:
    capture = _capture(
        label="legacy:tool:0",
        span_name="execute_tool shell",
        attributes={
            "weave.operation.name": "execute_tool",
            "gen_ai.tool.name": "shell",
            "gen_ai.tool.call.arguments": '{"command":"echo hi"}',
            "gen_ai.tool.call.result": '[{"ok":true}]',
        },
    )

    row = projection.extract_local_row(capture, project=PROJECT)

    assert row["tool_call_arguments"] == '{"command": "echo hi"}'
    assert row["tool_call_result"] == '[{"ok": true}]'


def test_local_extraction_applies_hosted_structured_credential_redaction() -> None:
    capture = _capture(
        label="legacy:tool:0",
        span_name="execute_tool shell",
        attributes={
            "weave.operation.name": "execute_tool",
            "gen_ai.tool.name": "shell",
            "gen_ai.tool.call.result": '{"api_key":"synthetic-value","ok":true}',
        },
    )

    row = projection.extract_local_row(capture, project=PROJECT)
    result = json.loads(row["tool_call_result"])

    assert result["api_key"] != "synthetic-value"
    assert result["ok"] is True


def test_local_extraction_rejects_storage_dependent_inline_content() -> None:
    capture = _capture(
        label="legacy:tool:0",
        span_name="execute_tool shell",
        attributes={
            "weave.operation.name": "execute_tool",
            "gen_ai.tool.name": "shell",
            "gen_ai.tool.call.result": "A" * 9_000,
        },
    )

    with pytest.raises(
        projection.ProjectionValidationError,
        match="storage-dependent inline content",
    ):
        projection.extract_local_row(capture, project=PROJECT)


def test_local_extraction_allows_prefixed_transport_content() -> None:
    capture = _capture(
        label="recovery:tool:0:fragment:0",
        span_name="execute_tool hivemind_transport_fragment",
        attributes={
            "weave.operation.name": "execute_tool",
            "gen_ai.tool.name": "hivemind_transport_fragment",
            "gen_ai.tool.call.result": "hivemind-b64-v1:" + ("A" * 9_000),
            projection.RECOVERY_CHILD_KEY: "c" * 64,
            projection.RECOVERY_SCHEMA_KEY: projection.RECOVERY_SCHEMA,
        },
    )

    row = projection.extract_local_row(capture, project=PROJECT)

    assert row["tool_call_result"].startswith("hivemind-b64-v1:")


def test_legacy_tool_compatibility_retains_generic_typed_substitutions() -> None:
    expected = _legacy_tool_projection(
        '{"items":[{"message":"token [REDACTED] and <PERSON>"}],"ok":true}'
    )
    remote = _legacy_tool_projection(
        '{"ok":true,"items":[{"message":"token <EMAIL_ADDRESS> and <PERSON>"}]}'
    )

    match = projection.compare_legacy_tool_compatibility(expected, remote)

    assert match is not None
    assert match.substitution_relation == "generic_typed"
    assert match.substitution_count == 1
    assert match.changed_leaf_count == 1
    assert match.expected_exact_json_sha256 != match.remote_exact_json_sha256
    assert match.expected_secondary_sha256 == match.remote_secondary_sha256
    assert match.policy_sha256 == projection.LEGACY_TOOL_COMPATIBILITY_POLICY_SHA256
    assert match.vocabulary_sha256 == projection.LEGACY_TOOL_PLACEHOLDER_VOCABULARY_SHA256
    assert projection.compare_legacy_tool_compatibility(remote, expected) is not None


def test_legacy_tool_compatibility_accepts_distinct_known_typed_substitutions() -> None:
    expected = _legacy_tool_projection('{"value":"same <PERSON>"}')
    remote = _legacy_tool_projection('{"value":"same <EMAIL_ADDRESS>"}')

    match = projection.compare_legacy_tool_compatibility(expected, remote)

    assert match is not None
    assert match.substitution_relation == "typed_typed"
    assert match.substitution_count == 1
    assert match.changed_leaf_count == 1
    reverse = projection.compare_legacy_tool_compatibility(remote, expected)
    assert reverse is not None
    assert reverse.substitution_relation == "typed_typed"


def test_legacy_tool_compatibility_rejects_forged_unchanged_secondary_drift() -> None:
    expected = _legacy_tool_projection(
        '{"changed":"same <PERSON>","unchanged":"constant"}'
    )
    remote = _legacy_tool_projection(
        '{"changed":"same <EMAIL_ADDRESS>","unchanged":"constant"}'
    )
    expected_evidence = expected.legacy_tool_compatibility
    remote_evidence = remote.legacy_tool_compatibility
    assert expected_evidence is not None
    assert remote_evidence is not None
    unchanged_index = next(
        index
        for index, (expected_leaf, remote_leaf) in enumerate(
            zip(
                expected_evidence.value_leaves,
                remote_evidence.value_leaves,
                strict=True,
            )
        )
        if expected_leaf.exact_sha256 == remote_leaf.exact_sha256
    )
    forged_leaves = list(remote_evidence.value_leaves)
    forged_leaves[unchanged_index] = replace(
        forged_leaves[unchanged_index],
        secondary_sha256="0" * 64,
    )
    forged_remote = replace(
        remote,
        legacy_tool_compatibility=replace(
            remote_evidence,
            value_leaves=tuple(forged_leaves),
        ),
    )

    assert projection.compare_legacy_tool_compatibility(expected, forged_remote) is None


@pytest.mark.parametrize("forged_side", ["expected", "remote", "both"])
def test_legacy_tool_compatibility_rejects_duplicate_leaf_paths(
    forged_side: str,
) -> None:
    expected = _legacy_tool_projection(
        '{"changed":"same <PERSON>","unchanged":"constant"}'
    )
    remote = _legacy_tool_projection(
        '{"changed":"same <EMAIL_ADDRESS>","unchanged":"constant"}'
    )

    def duplicate_first_path(
        candidate: projection.NormalizedSpanProjection,
    ) -> projection.NormalizedSpanProjection:
        evidence = candidate.legacy_tool_compatibility
        assert evidence is not None
        assert len(evidence.value_leaves) == 2
        forged_leaves = list(evidence.value_leaves)
        forged_leaves[1] = replace(
            forged_leaves[1],
            path_sha256=forged_leaves[0].path_sha256,
        )
        return replace(
            candidate,
            legacy_tool_compatibility=replace(
                evidence,
                value_leaves=tuple(forged_leaves),
            ),
        )

    forged_expected = (
        duplicate_first_path(expected) if forged_side in {"expected", "both"} else expected
    )
    forged_remote = (
        duplicate_first_path(remote) if forged_side in {"remote", "both"} else remote
    )

    assert (
        projection.compare_legacy_tool_compatibility(forged_expected, forged_remote)
        is None
    )


@pytest.mark.parametrize(
    ("expected_result", "remote_result"),
    [
        ('{"value":"same [REDACTED]"}', '{"value":"same [REDACTED]"}'),
        ('{"value":"left [REDACTED]"}', '{"value":"right <PERSON>"}'),
        ('{"value":"same [REDACTED]"}', '{"value":"same REDACTED"}'),
        (
            '{"value":"same [REDACTED] and <PERSON>"}',
            '{"value":"same <EMAIL_ADDRESS> and <EMAIL_ADDRESS>"}',
        ),
        ('{"value":"same [REDACTED]"}', '{"value":"same <PERSON> <EMAIL_ADDRESS>"}'),
        ('{"value":"same [REDACTED]","n":1}', '{"value":"same <PERSON>","n":2}'),
        (
            '{"first":"same [REDACTED]","second":"same [REDACTED]"}',
            '{"first":"same <PERSON>","second":"same <EMAIL_ADDRESS>"}',
        ),
        ('{"left":"same [REDACTED]"}', '{"right":"same <PERSON>"}'),
        ('{"value":["same [REDACTED]"]}', '{"value":{"0":"same <PERSON>"}}'),
        ('{"value":"same [REDACTED]"}', '{"value":"same <NOT_RECOGNIZED>"}'),
    ],
)
def test_legacy_tool_compatibility_rejects_false_positives(
    expected_result: str,
    remote_result: str,
) -> None:
    expected = _legacy_tool_projection(expected_result)
    remote = _legacy_tool_projection(remote_result)

    assert projection.compare_legacy_tool_compatibility(expected, remote) is None
    assert projection.compare_legacy_tool_compatibility(remote, expected) is None


@pytest.mark.parametrize(
    "invalid_result",
    [
        '"scalar [REDACTED]"',
        '{"value":"\\ud800 [REDACTED]"}',
        "not json [REDACTED]",
    ],
)
def test_legacy_tool_compatibility_is_absent_for_non_strict_json(
    invalid_result: str,
) -> None:
    candidate = _legacy_tool_projection(invalid_result)

    assert candidate.legacy_tool_compatibility is None


@pytest.mark.parametrize(
    "invalid_result",
    [
        '{"duplicate":"[REDACTED]","duplicate":"<PERSON>"}',
        '{"number":NaN,"value":"[REDACTED]"}',
        '{"number":Infinity,"value":"[REDACTED]"}',
    ],
)
def test_legacy_tool_strict_json_boundary_rejects_extensions(
    invalid_result: str,
) -> None:
    with pytest.raises(projection.ProjectionValidationError, match="strict JSON"):
        projection._strict_json_result(invalid_result)


def test_legacy_tool_strict_json_boundary_converts_parser_recursion_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fail_parser(*_args: Any, **_kwargs: Any) -> Any:
        raise RecursionError

    monkeypatch.setattr(projection.json, "loads", fail_parser)

    with pytest.raises(projection.ProjectionValidationError, match="strict JSON"):
        projection._strict_json_result("[]")


def test_legacy_tool_strict_json_boundary_rejects_excessive_depth() -> None:
    adversarial = "[" * 2_000 + "]" * 2_000

    with pytest.raises(projection.ProjectionValidationError, match="structural bounds"):
        projection._strict_json_result(adversarial)


def test_legacy_tool_compatibility_requires_exact_normalized_context() -> None:
    expected = _legacy_tool_projection(
        '{"value":"same [REDACTED]"}',
        arguments='{"command":"one"}',
    )
    remote = _legacy_tool_projection(
        '{"value":"same <PERSON>"}',
        arguments='{"command":"two"}',
    )

    assert projection.compare_legacy_tool_compatibility(expected, remote) is None


def test_legacy_tool_compatibility_is_legacy_execute_tool_only() -> None:
    recovery_tool = _legacy_tool_projection('{"value":"same [REDACTED]"}', compact=True)
    chat = projection.project_local_capture(
        _capture(),
        attribution=_attribution(),
        project=PROJECT,
    )

    assert recovery_tool.legacy_tool_compatibility is None
    assert chat.legacy_tool_compatibility is None


def test_legacy_tool_compatibility_models_do_not_repr_content() -> None:
    secret = "unique-secret-canary"
    expected = _legacy_tool_projection(f'{{"value":"{secret} [REDACTED]"}}')
    remote = _legacy_tool_projection(f'{{"value":"{secret} <PERSON>"}}')
    match = projection.compare_legacy_tool_compatibility(expected, remote)

    assert expected.legacy_tool_compatibility is not None
    assert match is not None
    assert secret not in repr(expected)
    assert secret not in repr(expected.legacy_tool_compatibility)
    assert secret not in repr(match)


def test_legacy_tool_compatibility_evidence_rejects_relation_tampering() -> None:
    expected = _legacy_tool_projection('{"value":"same <PERSON>"}')
    remote = _legacy_tool_projection('{"value":"same <EMAIL_ADDRESS>"}')
    match = projection.compare_legacy_tool_compatibility(expected, remote)
    assert match is not None

    values = {**match.__dict__, "substitution_relation": "generic_typed"}
    with pytest.raises(
        projection.ProjectionValidationError,
        match="compatibility match was invalid",
    ):
        projection.LegacyToolCompatibilityMatch(**values)


def test_custom_attr_columns_cover_every_selected_key_and_map() -> None:
    columns = projection.custom_attr_columns()

    assert len(columns) == 32
    assert {(item["source"], item["key"]) for item in columns} == {
        (source, key)
        for source in projection.CUSTOM_MAP_FIELDS
        for key in projection.SELECTED_CUSTOM_KEYS
    }
    columns[0]["key"] = "mutated"
    assert projection.custom_attr_columns()[0]["key"] != "mutated"


def test_exact_agent_schema_canonicalization_and_local_attribution() -> None:
    capture = _capture(
        label="legacy:tool:0",
        span_name="execute_tool shell",
        attributes={
            "weave.operation.name": "execute_tool",
            "weave.agent.name": "",
            "weave.agent.version": "",
            "weave.agent.id": "",
        },
    )
    extracted = projection.extract_local_row(capture, project=PROJECT)
    canonical = projection.canonicalize_agent_span(
        extracted,
        attribution=_attribution(),
        remote=False,
    )

    assert len(projection.AGENT_SPAN_SCHEMA_FIELDS) == 77
    assert frozenset(canonical) == projection.AGENT_SPAN_SCHEMA_FIELDS
    assert (
        canonical["agent_name"],
        canonical["agent_version"],
        canonical["agent_id"],
    ) == _attribution().agent_identity
    assert canonical["conversation_id"] == CONVERSATION_ID


@pytest.mark.parametrize("change", ["remove", "add"])
def test_remote_canonicalization_requires_the_exact_schema(change: str) -> None:
    row = _hosted_row()
    if change == "remove":
        row.pop("operation_name")
    else:
        row["unexpected"] = "field"

    with pytest.raises(
        projection.ProjectionValidationError,
        match="response schema changed",
    ):
        projection.canonicalize_agent_span(
            row,
            attribution=_attribution(),
            remote=True,
        )


def test_remote_rows_are_never_re_attributed() -> None:
    row = _hosted_row()
    row["agent_name"] = ""
    row["agent_version"] = ""
    row["agent_id"] = ""
    row["conversation_id"] = ""

    canonical = projection.canonicalize_agent_span(
        row,
        attribution=_attribution(),
        remote=True,
    )

    assert canonical["agent_name"] == ""
    assert canonical["agent_version"] == ""
    assert canonical["agent_id"] == ""
    assert canonical["conversation_id"] == ""


def test_deterministic_root_attribution_preserves_atomic_agent_triple(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = _capture()
    same_time_same_agent = _capture(
        label="legacy:llm:0",
        span_name="chat model",
    )
    later_other_agent = _capture(
        label="legacy:subagent:0",
        span_name="invoke_agent claude",
        started_at_ns=START_NS + 1,
    )
    rows = {
        root.label: {
            "agent_name": "codex",
            "agent_version": "1.2.3",
            "agent_id": "agent-1",
            "conversation_id": CONVERSATION_ID,
        },
        same_time_same_agent.label: {
            "agent_name": "codex",
            "agent_version": "1.2.3",
            "agent_id": "agent-1",
            "conversation_id": "",
        },
        later_other_agent.label: {
            "agent_name": "claude",
            "agent_version": "4",
            "agent_id": "agent-2",
            "conversation_id": "",
        },
    }
    monkeypatch.setattr(
        projection,
        "extract_local_row",
        lambda capture, *, project: rows[capture.label],
    )

    attribution = projection.determine_root_attribution(
        (root, same_time_same_agent, later_other_agent),
        expected_conversation_id=CONVERSATION_ID,
        project=PROJECT,
    )

    assert attribution.agent_identity == ("codex", "1.2.3", "agent-1")
    assert attribution.conversation_id == CONVERSATION_ID


@pytest.mark.parametrize("mode", ["earlier", "tied-different"])
def test_root_attribution_rejects_nondeterministic_fallback(
    monkeypatch: pytest.MonkeyPatch,
    mode: str,
) -> None:
    root = _capture()
    child = _capture(
        label="legacy:subagent:0",
        span_name="invoke_agent claude",
        started_at_ns=START_NS - 1 if mode == "earlier" else START_NS,
    )
    rows = {
        root.label: {
            "agent_name": "codex",
            "agent_version": "1.2.3",
            "agent_id": "agent-1",
            "conversation_id": CONVERSATION_ID,
        },
        child.label: {
            "agent_name": "claude",
            "agent_version": "4",
            "agent_id": "agent-2",
            "conversation_id": "",
        },
    }
    monkeypatch.setattr(
        projection,
        "extract_local_row",
        lambda capture, *, project: rows[capture.label],
    )

    with pytest.raises(
        projection.ProjectionValidationError,
        match="deterministic trace agent fallback",
    ):
        projection.determine_root_attribution(
            (root, child),
            expected_conversation_id=CONVERSATION_ID,
            project=PROJECT,
        )


def test_root_attribution_rejects_ambiguous_conversation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = _capture()
    child = _capture(label="legacy:llm:0", span_name="chat model")
    rows = {
        root.label: {
            "agent_name": "codex",
            "agent_version": "1.2.3",
            "agent_id": "agent-1",
            "conversation_id": CONVERSATION_ID,
        },
        child.label: {
            "agent_name": "",
            "agent_version": "",
            "agent_id": "",
            "conversation_id": "hivemind:foreign",
        },
    }
    monkeypatch.setattr(
        projection,
        "extract_local_row",
        lambda capture, *, project: rows[capture.label],
    )

    with pytest.raises(
        projection.ProjectionValidationError,
        match="conversation attribution was ambiguous",
    ):
        projection.determine_root_attribution(
            (root, child),
            expected_conversation_id=CONVERSATION_ID,
            project=PROJECT,
        )


def test_selected_custom_parses_legacy_and_recovery_across_typed_maps() -> None:
    legacy = _custom_maps()
    for index, (key, value) in enumerate(_stable_attributes().items()):
        legacy[projection.CUSTOM_MAP_FIELDS[index % 4]][key] = value

    parsed_legacy = projection.parse_selected_custom(legacy)

    assert parsed_legacy.representation == "legacy"
    assert parsed_legacy.recovery_key is None
    assert parsed_legacy.as_dict()["representation"] == "legacy"

    recovery = {field: dict(values) for field, values in legacy.items()}
    recovery_key = "c" * 64
    recovery["custom_attrs_string"].update(
        {
            projection.RECOVERY_CHILD_KEY: recovery_key,
            projection.RECOVERY_SCHEMA_KEY: projection.RECOVERY_SCHEMA,
        }
    )
    parsed_recovery = projection.parse_selected_custom(recovery)

    assert parsed_recovery.representation == "recovery"
    assert parsed_recovery.recovery_key == recovery_key


@pytest.mark.parametrize("mode", ["missing", "duplicate", "partial", "mistyped"])
def test_selected_custom_rejects_invalid_evidence(mode: str) -> None:
    row = _custom_maps()
    row["custom_attrs_string"].update(_stable_attributes())
    if mode == "missing":
        row["custom_attrs_string"].pop("hivemind.turn_key")
    elif mode == "duplicate":
        row["custom_attrs_bool"]["hivemind.turn_key"] = "atif:step:1"
    elif mode == "partial":
        row["custom_attrs_string"][projection.RECOVERY_CHILD_KEY] = "c" * 64
    else:
        row["custom_attrs_string"][projection.RECOVERY_SCHEMA_KEY] = 123

    with pytest.raises(projection.ProjectionValidationError):
        projection.parse_selected_custom(row)


def test_local_and_remote_projections_match_after_hosted_core_normalization() -> None:
    capture = _capture()
    local = projection.project_local_capture(
        capture,
        attribution=_attribution(),
        project=PROJECT,
    )
    remote = projection.project_remote_span(
        _hosted_row(capture),
        span_name=capture.span_name,
        start_time_ns=capture.start_time_ns,
        end_time_ns=capture.end_time_ns,
        attribution=_attribution(),
    )

    assert remote == local
    assert remote.operation_name == "invoke_agent"


@pytest.mark.parametrize(
    ("start_milliseconds", "end_milliseconds"),
    [(1, 10), (11, 123), (250, 501), (777, 1)],
)
def test_remote_projection_accepts_weave_fractional_datetime_roundtrip(
    start_milliseconds: int,
    end_milliseconds: int,
) -> None:
    started_at = STARTED_AT + timedelta(milliseconds=start_milliseconds)
    ended_at = STARTED_AT + timedelta(seconds=2, milliseconds=end_milliseconds)
    start_ns = int(started_at.timestamp() * 1_000_000_000)
    end_ns = int(ended_at.timestamp() * 1_000_000_000)
    epoch = datetime(1970, 1, 1, tzinfo=UTC)
    exact_started_ms = (started_at - epoch) // timedelta(milliseconds=1)
    exact_ended_ms = (ended_at - epoch) // timedelta(milliseconds=1)
    assert start_ns // 1_000_000 == exact_started_ms - 1
    assert end_ns // 1_000_000 == exact_ended_ms - 1

    base = _capture(started_at_ns=start_ns)
    capture = projection.LocalSpanCapture(
        label=base.label,
        span_name=base.span_name,
        start_time_ns=start_ns,
        end_time_ns=end_ns,
        attributes=base.attributes,
    )
    local = projection.project_local_capture(
        capture,
        attribution=_attribution(),
        project=PROJECT,
    )
    remote = projection.project_remote_span(
        _hosted_row(capture),
        span_name=capture.span_name,
        start_time_ns=start_ns,
        end_time_ns=end_ns,
        attribution=_attribution(),
    )

    assert remote == local


@pytest.mark.parametrize("field", ["started_at", "ended_at"])
def test_remote_projection_rejects_true_one_millisecond_normalized_drift(
    field: str,
) -> None:
    started_at = STARTED_AT + timedelta(milliseconds=123)
    ended_at = STARTED_AT + timedelta(seconds=2, milliseconds=501)
    start_ns = int(started_at.timestamp() * 1_000_000_000)
    end_ns = int(ended_at.timestamp() * 1_000_000_000)
    base = _capture(started_at_ns=start_ns)
    capture = projection.LocalSpanCapture(
        label=base.label,
        span_name=base.span_name,
        start_time_ns=start_ns,
        end_time_ns=end_ns,
        attributes=base.attributes,
    )
    row = _hosted_row(capture)
    normalized = projection.parse_datetime(row[field])
    assert normalized is not None
    row[field] = (normalized + timedelta(milliseconds=1)).isoformat()

    with pytest.raises(
        projection.ProjectionValidationError,
        match="normalized and raw span core fields disagreed",
    ):
        projection.project_remote_span(
            row,
            span_name=capture.span_name,
            start_time_ns=start_ns,
            end_time_ns=end_ns,
            attribution=_attribution(),
        )


@pytest.mark.parametrize("field", ["name", "start", "end"])
def test_remote_projection_requires_normalized_and_raw_core_agreement(field: str) -> None:
    capture = _capture()
    kwargs = {
        "span_name": capture.span_name,
        "start_time_ns": capture.start_time_ns,
        "end_time_ns": capture.end_time_ns,
    }
    if field == "name":
        kwargs["span_name"] = "different"
    elif field == "start":
        kwargs["start_time_ns"] += 1_000_000
    else:
        kwargs["end_time_ns"] += 1_000_000

    with pytest.raises(
        projection.ProjectionValidationError,
        match="core fields disagreed",
    ):
        projection.project_remote_span(
            _hosted_row(capture),
            attribution=_attribution(),
            **kwargs,
        )


def test_remote_projection_rejects_invalid_raw_core_before_content_processing() -> None:
    with pytest.raises(
        projection.ProjectionValidationError,
        match="raw span core fields were invalid",
    ):
        projection.project_remote_span(
            {},
            span_name="invoke_agent codex",
            start_time_ns=END_NS,
            end_time_ns=START_NS,
            attribution=_attribution(),
        )


def test_projection_digest_binds_normalized_content_and_representation() -> None:
    capture = _capture()
    baseline = projection.project_remote_span(
        _hosted_row(capture),
        span_name=capture.span_name,
        start_time_ns=capture.start_time_ns,
        end_time_ns=capture.end_time_ns,
        attribution=_attribution(),
    )
    changed_content = _hosted_row(capture)
    changed_content["input_messages"] = [{"role": "user", "content": "changed"}]
    changed = projection.project_remote_span(
        changed_content,
        span_name=capture.span_name,
        start_time_ns=capture.start_time_ns,
        end_time_ns=capture.end_time_ns,
        attribution=_attribution(),
    )
    recovered = _hosted_row(capture)
    recovered["custom_attrs_string"].update(
        {
            projection.RECOVERY_CHILD_KEY: "c" * 64,
            projection.RECOVERY_SCHEMA_KEY: projection.RECOVERY_SCHEMA,
        }
    )
    recovery_result = projection.project_remote_span(
        recovered,
        span_name=capture.span_name,
        start_time_ns=capture.start_time_ns,
        end_time_ns=capture.end_time_ns,
        attribution=_attribution(),
    )

    assert changed.digest != baseline.digest
    assert recovery_result.digest != baseline.digest
    assert recovery_result.representation == "recovery"
    assert recovery_result.recovery_key == "c" * 64


def test_unselected_custom_attributes_do_not_change_projection() -> None:
    capture = _capture()
    baseline_row = _hosted_row(capture)
    extra_row = _hosted_row(capture)
    extra_row["custom_attrs_string"]["hivemind.unselected"] = "ignored"

    baseline = projection.project_remote_span(
        baseline_row,
        span_name=capture.span_name,
        start_time_ns=capture.start_time_ns,
        end_time_ns=capture.end_time_ns,
        attribution=_attribution(),
    )
    extra = projection.project_remote_span(
        extra_row,
        span_name=capture.span_name,
        start_time_ns=capture.start_time_ns,
        end_time_ns=capture.end_time_ns,
        attribution=_attribution(),
    )

    assert extra.digest == baseline.digest


def test_projection_exposes_operation_for_caller_gate() -> None:
    capture = _capture()
    row = _hosted_row(capture)
    row["operation_name"] = "future_operation"

    result = projection.project_remote_span(
        row,
        span_name=capture.span_name,
        start_time_ns=capture.start_time_ns,
        end_time_ns=capture.end_time_ns,
        attribution=_attribution(),
    )

    assert result.operation_name == "future_operation"


def test_pin_manifest_validates_exact_required_files(tmp_path: Path) -> None:
    first = tmp_path / "first.py"
    second = tmp_path / "second.py"
    first.write_bytes(b"first")
    second.write_bytes(b"second")
    pins = (
        projection.SourcePin(first, sha256(b"first").hexdigest()),
        projection.SourcePin(second, sha256(b"second").hexdigest()),
    )

    projection.validate_pin_manifest(pins, required_paths=(first, second))

    first.write_bytes(b"changed")
    with pytest.raises(
        projection.ProjectionValidationError,
        match="source pin changed",
    ):
        projection.validate_pin_manifest(pins, required_paths=(first, second))


def test_pin_manifest_rejects_missing_and_duplicate_entries(tmp_path: Path) -> None:
    path = tmp_path / "source.py"
    path.write_bytes(b"source")
    pin = projection.SourcePin(path, sha256(b"source").hexdigest())

    with pytest.raises(projection.ProjectionValidationError, match="incomplete"):
        projection.validate_pin_manifest(
            (pin,),
            required_paths=(path, tmp_path / "missing.py"),
        )
    with pytest.raises(projection.ProjectionValidationError, match="ambiguous"):
        projection.validate_pin_manifest((pin, pin))


def test_normalization_source_paths_are_unique_existing_files() -> None:
    paths = projection.normalization_source_paths()

    assert len(paths) == 12
    assert len(set(paths)) == len(paths)
    assert all(path.is_file() for path in paths)


def test_validation_errors_never_echo_span_content() -> None:
    secret = "super-secret-conversation-content"
    row = _hosted_row(_capture(attributes={"hivemind.unselected": secret}))
    row.pop("operation_name")

    with pytest.raises(projection.ProjectionValidationError) as raised:
        projection.project_remote_span(
            row,
            span_name="invoke_agent codex",
            start_time_ns=START_NS,
            end_time_ns=END_NS,
            attribution=_attribution(),
        )

    assert secret not in str(raised.value)
