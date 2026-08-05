from __future__ import annotations

import os
from datetime import datetime
from pathlib import Path
from typing import Any

import pytest

from hivemind_weave.atif import map_atif
from hivemind_weave.attribute_safety import (
    ARCHIVAL_ATTRIBUTE_KEYS,
    ATTRIBUTE_SPILL_FRAGMENT_COUNT_KEY,
    ATTRIBUTE_SPILL_MANIFEST_KEY,
    restore_chunked_attributes,
)
from hivemind_weave.hivemind import HiveMindClient
from hivemind_weave.importer import ImportConfig, run_import
from hivemind_weave.models import MappedTurn, Session
from hivemind_weave.pii import sanitize_mapped_conversation
from hivemind_weave.utils import parse_datetime
from hivemind_weave.verify import WeaveVerifier
from hivemind_weave.weave_sink import expected_turn_span_count

pytestmark = pytest.mark.live


def _span_count(turn: MappedTurn) -> int:
    return expected_turn_span_count(turn)


def _root_attribute_trace_ids(
    verifier: WeaveVerifier,
    *,
    conversation_id: str,
    attribute: str,
    value: str,
) -> set[str]:
    def equals(field: str, expected: str) -> dict[str, Any]:
        return {"$eq": [{"$getField": field}, {"$literal": expected}]}

    response = verifier._post(
        "/agents/spans/query",
        {
            "project_id": verifier.project,
            "query": {
                "$expr": {
                    "$and": [
                        equals("conversation_id", conversation_id),
                        equals("parent_span_id", ""),
                        equals(f"custom_attrs_string.{attribute}", value),
                    ]
                }
            },
            "group_by": [{"source": "field", "key": "trace_id", "alias": "trace_id"}],
            "limit": 1000,
            "offset": 0,
        },
    )
    return {
        str(keys["trace_id"])
        for group in response.get("groups", [])
        if isinstance(group, dict)
        and isinstance((keys := group.get("group_keys")), dict)
        and isinstance(keys.get("trace_id"), str)
    }


def _root_span_attributes(
    verifier: WeaveVerifier,
    *,
    conversation_id: str,
    trace_id: str,
) -> dict[str, Any]:
    def equals(field: str, expected: str) -> dict[str, Any]:
        return {"$eq": [{"$getField": field}, {"$literal": expected}]}

    response = verifier._post(
        "/agents/spans/query",
        {
            "project_id": verifier.project,
            "query": {
                "$expr": {
                    "$and": [
                        equals("conversation_id", conversation_id),
                        equals("trace_id", trace_id),
                        equals("parent_span_id", ""),
                    ]
                }
            },
            "include_details": True,
            "limit": 2,
            "offset": 0,
        },
    )
    spans = response.get("spans")
    assert response.get("total_count") == 1
    assert isinstance(spans, list) and len(spans) == 1 and isinstance(spans[0], dict)
    root = spans[0]
    attributes: dict[str, Any] = {}
    for field in (
        "custom_attrs_string",
        "custom_attrs_int",
        "custom_attrs_float",
        "custom_attrs_bool",
    ):
        values = root.get(field, {})
        assert isinstance(values, dict)
        attributes.update(values)
    return attributes


def test_one_session_live_import_is_idempotent(tmp_path: Path) -> None:
    if os.environ.get("HIVEMIND_WEAVE_LIVE") != "1":
        pytest.skip("set HIVEMIND_WEAVE_LIVE=1 to enable the live smoke test")
    session_id = os.environ.get("HIVEMIND_WEAVE_LIVE_SESSION_ID")
    project = os.environ.get("HIVEMIND_WEAVE_LIVE_PROJECT")
    if not session_id or not project:
        pytest.fail(
            "live test requires HIVEMIND_WEAVE_LIVE_SESSION_ID and HIVEMIND_WEAVE_LIVE_PROJECT"
        )
    api_key = os.environ.get("WANDB_API_KEY")
    if not api_key:
        pytest.fail("live test requires WANDB_API_KEY")

    client = HiveMindClient()
    client.preflight()
    raw_session = next(
        (item for item in client.list_sessions(days=365) if item.get("id") == session_id),
        None,
    )
    if raw_session is None:
        pytest.fail("live session was not returned inside the 365-day authenticated-user window")
    source_session = Session.from_api(raw_session)
    expected = sanitize_mapped_conversation(
        map_atif(source_session, client.get_atif(source_session.id))
    )
    config = ImportConfig(
        days=365,
        project=project,
        idle_minutes=0,
        state_path=tmp_path / "live-state.sqlite3",
        session_ids=frozenset({session_id}),
    )
    first = run_import(config)
    assert first.ok, first.render()
    assert first.imported == len(expected.turns) >= 1, first.render()

    verifier = WeaveVerifier(project=project, api_key=api_key)
    remote_turns = verifier.conversation_turns(expected.conversation_id)
    assert remote_turns
    assert all(turn.get("agent_name") == expected.agent_name for turn in remote_turns)

    all_expected_trace_ids: set[str] = set()
    previous_started_at: datetime | None = None
    for expected_turn in expected.turns:
        matched = verifier.attribute_trace_matches(
            conversation_id=expected.conversation_id,
            turn_key=expected_turn.key,
            payload_sha256=expected_turn.payload_sha256,
        )
        assert matched.matches == 1
        assert len(matched.trace_ids) == 1
        trace_id = matched.trace_ids[0]
        all_expected_trace_ids.add(trace_id)
        assert verifier.trace_span_count(
            conversation_id=expected.conversation_id,
            trace_id=trace_id,
        ) == _span_count(expected_turn)
        remote_turn = next(item for item in remote_turns if item.get("trace_id") == trace_id)
        assert verifier._turn_signature(remote_turn) == expected_turn.verification_signature
        remote_attributes = _root_span_attributes(
            verifier,
            conversation_id=expected.conversation_id,
            trace_id=trace_id,
        )
        logical_attributes = restore_chunked_attributes(expected_turn.attributes)
        archival_keys = ARCHIVAL_ATTRIBUTE_KEYS.intersection(logical_attributes)
        assert archival_keys
        assert ATTRIBUTE_SPILL_MANIFEST_KEY in remote_attributes
        assert int(remote_attributes[ATTRIBUTE_SPILL_FRAGMENT_COUNT_KEY]) >= 1
        assert archival_keys.isdisjoint(remote_attributes)
        messages = remote_turn.get("messages", [])
        timestamps = [
            parsed
            for message in messages
            if isinstance(message, dict)
            and (parsed := parse_datetime(message.get("started_at"))) is not None
        ]
        assert timestamps == sorted(timestamps)
        if timestamps:
            assert previous_started_at is None or timestamps[0] >= previous_started_at
            previous_started_at = timestamps[0]
        if expected_turn.tools:
            assert any(message.get("tool_call") for message in messages)
        if any(llm.reasoning for llm in expected_turn.llms):
            assert any(
                isinstance((assistant := message.get("assistant_message")), dict)
                and assistant.get("reasoning_content")
                for message in messages
                if isinstance(message, dict)
            )

    assert all_expected_trace_ids.issubset(verifier.span_trace_ids(expected.conversation_id))
    if source_session.parent_session_id:
        parent_trace_ids = _root_attribute_trace_ids(
            verifier,
            conversation_id=expected.conversation_id,
            attribute="hivemind.parent_session_id",
            value=source_session.parent_session_id,
        )
        assert all_expected_trace_ids.issubset(parent_trace_ids)
    elif os.environ.get("HIVEMIND_WEAVE_LIVE_REQUIRE_PARENT") == "1":
        pytest.fail(
            "parent-link acceptance requested, but the selected live session is not a child"
        )

    second = run_import(config)
    assert second.ok, second.render()
    assert second.imported == 0, second.render()
    assert second.skipped == first.imported, second.render()
