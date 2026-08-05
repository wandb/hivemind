from __future__ import annotations

import hashlib
import json
from dataclasses import replace
from typing import Any

import pytest
from weave.trace_server.base64_content_conversion import is_base64, is_data_uri

from hivemind_weave.attribute_safety import (
    ATTRIBUTE_SPILL_MANIFEST_KEY,
    LEGACY_SPILL_TRANSPORT_ENCODING,
    MAX_ATTRIBUTE_VALUE_CHARS,
    MAX_CUSTOM_ATTRIBUTES,
    MAX_ROOT_ATTRIBUTE_BYTES,
    MAX_ROOT_ATTRIBUTES,
    MAX_SPILL_FRAGMENT_JSON_BYTES,
    SPILL_CHUNK_PREFIX,
    SPILL_PLACEHOLDER_KEY,
    SPILL_TRANSPORT_ENCODING,
    AttributeSafetyError,
    chunk_large_attributes,
    json_string_wire_bytes,
    plan_attribute_spill,
    plan_tool_spill,
    restore_chunked_attributes,
    restore_spilled_attributes,
    restore_spilled_tool,
    validate_upload_attributes,
)
from hivemind_weave.utils import canonical_json


def _restore(attributes: dict[str, Any], key: str) -> Any:
    """Rebuild one value, including recursively chunked chunk leaves."""
    if key in attributes:
        return attributes[key]
    count = attributes[f"{key}.chunk_count"]
    serialized = "".join(
        str(_restore(attributes, f"{key}.chunk.{index:04d}")) for index in range(count)
    )
    assert attributes[f"{key}.sha256"] == hashlib.sha256(serialized.encode()).hexdigest()
    if attributes[f"{key}.encoding"] == "canonical-json":
        return json.loads(serialized)
    return serialized


def test_large_attribute_is_chunked_and_exactly_reconstructable() -> None:
    source = "x" * (MAX_ATTRIBUTE_VALUE_CHARS * 2 + 7)
    attributes = chunk_large_attributes({"hivemind.preserved_step_data": source})

    assert attributes["hivemind.preserved_step_data.chunk_count"] == 3
    parts = [attributes[f"hivemind.preserved_step_data.chunk.{index:04d}"] for index in range(3)]
    assert "".join(parts) == source
    assert attributes["hivemind.preserved_step_data.encoding"] == "text"
    assert (
        attributes["hivemind.preserved_step_data.sha256"]
        == hashlib.sha256(source.encode("utf-8")).hexdigest()
    )
    validate_upload_attributes(attributes)


@pytest.mark.parametrize(
    "source",
    [
        {"outer": {"inner": "x" * (MAX_ATTRIBUTE_VALUE_CHARS * 2 + 7)}},
        [[{"payload": "y" * (MAX_ATTRIBUTE_VALUE_CHARS + 13)}], [1, 2, 3]],
        {"map": {f"key-{index}": [index, {"text": "z" * 10_000}] for index in range(30)}},
    ],
    ids=["nested-string", "nested-list", "large-map"],
)
def test_very_large_structured_attributes_round_trip_losslessly(source: Any) -> None:
    attributes = chunk_large_attributes({"hivemind.source": source})

    assert _restore(attributes, "hivemind.source") == source
    validate_upload_attributes(attributes)


def test_grown_existing_chunk_is_recursively_rechunked_and_reconstructable() -> None:
    source = "x" * (MAX_ATTRIBUTE_VALUE_CHARS + 9)
    first_pass = chunk_large_attributes({"hivemind.source": source})
    first_chunk_key = "hivemind.source.chunk.0000"
    grown_chunk = str(first_pass[first_chunk_key]).replace("x", "xx")
    del first_pass[first_chunk_key]
    first_pass.update(chunk_large_attributes({first_chunk_key: grown_chunk}))
    expected = grown_chunk + str(first_pass["hivemind.source.chunk.0001"])
    first_pass["hivemind.source.sha256"] = hashlib.sha256(expected.encode()).hexdigest()

    assert restore_chunked_attributes(first_pass) == {"hivemind.source": expected}
    validate_upload_attributes(first_pass)


def test_attribute_safety_rejects_values_or_counts_that_weave_might_truncate() -> None:
    with pytest.raises(AttributeSafetyError, match="too large"):
        validate_upload_attributes({"oversized": "x" * (MAX_ATTRIBUTE_VALUE_CHARS + 1)})
    with pytest.raises(AttributeSafetyError, match="too many"):
        validate_upload_attributes(
            {f"key-{index}": index for index in range(MAX_CUSTOM_ATTRIBUTES + 1)}
        )


def test_archival_attribute_spill_is_deterministic_bounded_and_lossless() -> None:
    archive = ('quoted="\\ control=\u0001 unicode=🤖\n' * 20_000) + "tail"
    attributes = {
        "hivemind.session_id": "session-1",
        "hivemind.turn_key": "atif:step:12",
        "hivemind.payload_sha256": "a" * 64,
        "hivemind.source_payload_sha256": "b" * 64,
        "hivemind.atif_schema_version": "ATIF-v1.7",
        "hivemind.importer_version": "test",
        "hivemind.repository": "wandb/hivemind",
        "hivemind.preserved_step_data": archive,
        "hivemind.atif_trajectory_metadata": {"nested": [1, True, None]},
    }

    first = plan_attribute_spill(attributes, owner_id="atif:step:12")
    second = plan_attribute_spill(attributes, owner_id="atif:step:12")

    assert first == second
    assert ATTRIBUTE_SPILL_MANIFEST_KEY in first.root_attributes
    assert "hivemind.preserved_step_data" not in first.root_attributes
    assert first.root_attributes["hivemind.session_id"] == "session-1"
    assert first.root_attributes["hivemind.turn_key"] == "atif:step:12"
    assert len(first.root_attributes) <= MAX_ROOT_ATTRIBUTES
    assert len(canonical_json(first.root_attributes).encode()) <= MAX_ROOT_ATTRIBUTE_BYTES
    assert len(first.fragments) > 1
    assert all("quoted" not in fragment.content for fragment in first.fragments)
    assert all(
        json_string_wire_bytes(fragment.content) <= MAX_SPILL_FRAGMENT_JSON_BYTES
        for fragment in first.fragments
    )
    assert restore_spilled_attributes(first.root_attributes, first.fragments) == attributes


def test_root_budget_spills_largest_noncorrelators_but_never_correlators() -> None:
    attributes = {
        "hivemind.session_id": "session-1",
        "hivemind.agent_session_id": "agent-session-1",
        "hivemind.turn_key": "turn-1",
        "hivemind.repository": "wandb/hivemind",
        "hivemind.branch": "main",
        "hivemind.parent_session_id": "parent-1",
        "hivemind.is_subagent": True,
        "hivemind.payload_sha256": "a" * 64,
        "hivemind.source_payload_sha256": "b" * 64,
        "hivemind.atif_schema_version": "ATIF-v1.7",
        "hivemind.importer_version": "test",
        "hivemind.timestamp_inferred": False,
        **{f"searchable-{index:03d}": "x" * 400 for index in range(80)},
    }

    plan = plan_attribute_spill(attributes, owner_id="turn-1")

    for key in (
        "hivemind.session_id",
        "hivemind.agent_session_id",
        "hivemind.turn_key",
        "hivemind.repository",
        "hivemind.branch",
        "hivemind.parent_session_id",
        "hivemind.is_subagent",
        "hivemind.payload_sha256",
        "hivemind.source_payload_sha256",
        "hivemind.atif_schema_version",
        "hivemind.importer_version",
        "hivemind.timestamp_inferred",
    ):
        assert plan.root_attributes[key] == attributes[key]
    assert len(plan.root_attributes) <= MAX_ROOT_ATTRIBUTES
    assert len(canonical_json(plan.root_attributes).encode()) <= MAX_ROOT_ATTRIBUTE_BYTES
    assert restore_spilled_attributes(plan.root_attributes, plan.fragments) == attributes


def test_large_tool_fields_round_trip_as_independently_hashed_fragments() -> None:
    arguments = {
        "path": "/tmp/example",
        "content": '🤖"\\\n\u0002' * 20_000,
        "flags": [True, False, None],
    }
    result = 'result="\\\u0003🤖\n' * 25_000

    first = plan_tool_spill(arguments, result, owner_id="turn:tool:0")
    second = plan_tool_spill(arguments, result, owner_id="turn:tool:0")

    assert first == second
    assert len(first.fragments) > 2
    assert all("result=" not in fragment.content for fragment in first.fragments)
    assert all(
        fragment.manifest.transport_encoding == SPILL_TRANSPORT_ENCODING
        and fragment.content.startswith(SPILL_CHUNK_PREFIX)
        and not is_base64(fragment.content)
        and not is_data_uri(fragment.content)
        for fragment in first.fragments
    )
    assert all(
        json_string_wire_bytes(fragment.content) <= MAX_SPILL_FRAGMENT_JSON_BYTES
        for fragment in first.fragments
    )
    assert restore_spilled_tool(first.arguments, first.result, first.fragments) == (
        arguments,
        result,
    )

    corrupted = (
        replace(first.fragments[0], content=first.fragments[0].content + "corrupt"),
        *first.fragments[1:],
    )
    with pytest.raises(
        AttributeSafetyError,
        match=r"base64-UTF8|byte count mismatch|hash mismatch",
    ):
        restore_spilled_tool(first.arguments, first.result, corrupted)


def test_legacy_bare_base64_spill_fragments_remain_readable() -> None:
    result = "legacy result " * 10_000
    plan = plan_tool_spill("ok", result, owner_id="turn:tool:legacy")
    assert plan.fragments
    manifest = replace(
        plan.fragments[0].manifest,
        transport_encoding=LEGACY_SPILL_TRANSPORT_ENCODING,
    )
    fragments = tuple(
        replace(
            fragment,
            manifest=manifest,
            content=fragment.content.removeprefix(SPILL_CHUNK_PREFIX),
        )
        for fragment in plan.fragments
    )
    placeholder = {SPILL_PLACEHOLDER_KEY: manifest.as_dict()}

    assert restore_spilled_tool(plan.arguments, placeholder, fragments) == (
        "ok",
        result,
    )


def test_reconstruction_rejects_missing_spill_fragments() -> None:
    plan = plan_tool_spill(
        {"content": "x" * 100_000},
        "y" * 100_000,
        owner_id="turn:tool:0",
    )

    with pytest.raises(AttributeSafetyError, match="incomplete"):
        restore_spilled_tool(plan.arguments, plan.result, plan.fragments[:-1])
