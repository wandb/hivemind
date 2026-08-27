from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Callable
from dataclasses import asdict, replace
from datetime import timedelta
from typing import Any

import pytest

from hivemind_weave.atif import map_atif
from hivemind_weave.models import ChatMessage, MappedConversation, Session
from hivemind_weave.pii import redact_upload_data
from hivemind_weave.review_manifest import (
    MAX_REVIEW_CHUNK_BYTES,
    MAX_REVIEW_CHUNKS,
    MAX_REVIEW_OBJECT_NAME_CHARACTERS,
    REVIEW_INDEX_SCHEMA,
    REVIEW_MANIFEST_SCHEMA,
    REVIEW_PREVIEW_CHARACTERS,
    REVIEW_PREVIEW_SCHEMA,
    ReviewManifestError,
    _stable_preview_text,
    build_review_manifest,
    reconstruct_review_manifest,
)
from hivemind_weave.utils import canonical_json


def _conversation(
    session_payload: Callable[..., dict[str, Any]],
    atif_wrapper: Callable[..., dict[str, Any]],
    *,
    parent_session_id: str = "",
) -> MappedConversation:
    session = Session.from_api(session_payload(parent_session_id=parent_session_id))
    return map_atif(session, atif_wrapper())


def test_manifest_preserves_complete_turn_metadata_and_marked_previews(
    session_payload: Callable[..., dict[str, Any]],
    atif_wrapper: Callable[..., dict[str, Any]],
) -> None:
    parent_session_id = "22222222-2222-4222-8222-222222222222"
    conversation = _conversation(
        session_payload,
        atif_wrapper,
        parent_session_id=parent_session_id,
    )
    turn = conversation.turns[0]
    long_user = "[REDACTED] " + "🙂" * 5_000
    long_final_assistant = "final answer " * 500
    turn.messages[0] = replace(turn.messages[0], content=long_user)
    turn.output_messages[0] = replace(turn.output_messages[0], content=long_final_assistant)
    turn.llms[0] = replace(
        turn.llms[0],
        reasoning="Use the already-redacted credential [REDACTED].",
        usage={"input_tokens": 11, "output_tokens": 7, "reasoning_tokens": 3},
    )
    turn.attributes["hivemind.mapping_warnings"] = ["unmatched_tool_call:redacted-call"]
    source_payload_sha256 = "f" * 64
    turn.attributes["hivemind.source_payload_sha256"] = source_payload_sha256
    turn.finalize_hash()

    bundle = build_review_manifest(conversation, turn)
    payload = reconstruct_review_manifest(bundle)

    assert payload["schema"] == REVIEW_MANIFEST_SCHEMA
    assert payload["source_payload_sha256"] == source_payload_sha256
    assert bundle.source_payload_sha256 == source_payload_sha256
    assert payload["content_contract"] == {
        "input": "already-redacted-mapped-turn",
        "previews_are_complete": False,
        "turn_content": "complete",
    }
    assert payload["conversation"] == {
        "agent_id": conversation.agent_id,
        "agent_name": conversation.agent_name,
        "agent_version": conversation.agent_version,
        "atif_schema_version": conversation.schema_version,
        "conversation_id": conversation.conversation_id,
        "conversation_name": conversation.conversation_name,
        "model": conversation.model,
    }
    assert payload["session"]["session_id"] == turn.attributes["hivemind.session_id"]
    assert payload["session"]["agent_session_id"] == "agent-session-1"
    assert payload["session"]["parent_session_id"] == parent_session_id
    assert payload["session"]["is_subagent"] is True
    assert payload["session"]["repository"] == "wandb/hivemind"
    assert payload["session"]["branch"] == "codex/importer"
    assert "source_last_activity_at" not in payload["session"]
    assert payload["mapping_warnings"] == ["unmatched_tool_call:redacted-call"]

    serialized_turn = payload["turn"]
    expected_turn = json.loads(canonical_json(asdict(turn)))
    expected_turn["attributes"].pop("hivemind.atif_final_metrics", None)
    trajectory_metadata = json.loads(
        expected_turn["attributes"]["hivemind.atif_trajectory_metadata"]
    )
    trajectory_metadata.pop("final_metrics", None)
    expected_turn["attributes"]["hivemind.atif_trajectory_metadata"] = canonical_json(
        trajectory_metadata
    )
    assert serialized_turn == expected_turn
    assert serialized_turn["messages"][0]["content"] == long_user
    assert serialized_turn["output_messages"][0]["content"] == long_final_assistant
    assert serialized_turn["llms"][0]["reasoning"] == (
        "Use the already-redacted credential [REDACTED]."
    )
    assert serialized_turn["llms"][0]["usage"] == {
        "input_tokens": 11,
        "output_tokens": 7,
        "reasoning_tokens": 3,
    }
    assert serialized_turn["llms"][0]["started_at"] == "2026-08-01T12:00:02Z"
    assert serialized_turn["tools"][0]["arguments"] == {
        "content": "hello",
        "path": "hello.txt",
    }
    assert serialized_turn["tools"][0]["result"] == {"ok": True}
    assert serialized_turn["tools"][0]["started_at"] == "2026-08-01T12:00:02Z"
    assert serialized_turn["attributes"]["hivemind.parent_session_id"] == parent_session_id
    assert serialized_turn["attributes"]["hivemind.source_payload_sha256"] == source_payload_sha256
    assert serialized_turn["payload_sha256"] == turn.payload_sha256

    user_preview = payload["review_previews"]["user"]
    assert payload["review_previews"]["schema"] == REVIEW_PREVIEW_SCHEMA
    assert user_preview["kind"] == "preview"
    assert "USER MESSAGE PREVIEW" in user_preview["label"]
    assert user_preview["source_path"] == "turn.messages[0].content"
    assert user_preview["text"] == long_user[:REVIEW_PREVIEW_CHARACTERS]
    assert len(user_preview["text"]) == REVIEW_PREVIEW_CHARACTERS
    assert user_preview["preview_character_count"] == REVIEW_PREVIEW_CHARACTERS
    assert user_preview["original_character_count"] == len(long_user)
    assert user_preview["truncated"] is True

    assistant_preview = payload["review_previews"]["final_assistant"]
    assert "FINAL ASSISTANT MESSAGE PREVIEW" in assistant_preview["label"]
    assert assistant_preview["source_path"] == "turn.output_messages[0].content"
    assert assistant_preview["text"] == long_final_assistant[:REVIEW_PREVIEW_CHARACTERS]
    assert len(assistant_preview["text"]) == REVIEW_PREVIEW_CHARACTERS
    assert assistant_preview["truncated"] is True
    preview_bytes = json.dumps(
        payload["review_previews"],
        allow_nan=False,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    assert hashlib.sha256(preview_bytes).hexdigest() == bundle.preview_signature
    assert payload["preview_signature"] == bundle.preview_signature
    assert json.loads(bundle.manifest_json) == payload


def test_preview_redaction_expansion_stays_bounded_and_stable() -> None:
    source = " -> ".join(["Australia"] * 600)

    preview, source_character_count = _stable_preview_text(source)

    assert len(preview) <= REVIEW_PREVIEW_CHARACTERS
    assert source_character_count < REVIEW_PREVIEW_CHARACTERS
    assert "Australia" not in preview
    assert redact_upload_data(preview) == preview


def test_chunks_and_index_are_deterministic_content_addressed_and_utf8_safe(
    session_payload: Callable[..., dict[str, Any]],
    atif_wrapper: Callable[..., dict[str, Any]],
) -> None:
    conversation = _conversation(session_payload, atif_wrapper)
    turn = conversation.turns[0]
    turn.messages[0] = ChatMessage(role="user", content="prefix-" + "🙂é" * 100)
    turn.finalize_hash()

    first = build_review_manifest(
        conversation,
        turn,
        max_chunk_bytes=257,
    )
    second = build_review_manifest(
        conversation,
        turn,
        max_chunk_bytes=257,
    )

    assert first == second
    assert 1 < len(first.chunks) <= MAX_REVIEW_CHUNKS
    assert b"".join(chunk.content for chunk in first.chunks).decode("utf-8") == (
        first.manifest_json
    )
    assert any("🙂" in chunk.text for chunk in first.chunks)
    assert all(0 < chunk.byte_count <= 257 for chunk in first.chunks)
    assert all(len(chunk.content) == chunk.byte_count for chunk in first.chunks)
    assert all(
        chunk.content.decode("utf-8").encode("utf-8") == chunk.content for chunk in first.chunks
    )
    assert hashlib.sha256(first.manifest_json.encode("utf-8")).hexdigest() == (
        first.manifest_sha256
    )
    assert hashlib.sha256(first.index_json.encode("utf-8")).hexdigest() == first.index_sha256
    assert len(first.index_json.encode("utf-8")) == first.index_byte_count

    index = first.index_metadata
    assert index["schema"] == REVIEW_INDEX_SCHEMA
    assert index["manifest"] == {
        "byte_count": first.manifest_byte_count,
        "media_type": "application/json; charset=utf-8",
        "name": first.manifest_name,
        "preview_signature": first.preview_signature,
        "schema": REVIEW_MANIFEST_SCHEMA,
        "sha256": first.manifest_sha256,
        "source_payload_sha256": first.source_payload_sha256,
    }
    assert index["chunking"] == {
        "chunk_count": len(first.chunks),
        "encoding": "utf-8",
        "max_chunk_bytes": 257,
        "max_chunks": MAX_REVIEW_CHUNKS,
    }
    for chunk, metadata in zip(first.chunks, index["chunks"], strict=True):
        assert metadata == {
            "byte_count": chunk.byte_count,
            "index": chunk.index,
            "media_type": "text/plain; charset=utf-8",
            "name": chunk.name,
            "sha256": chunk.sha256,
        }
        assert first.manifest_sha256[:24] in chunk.name
        assert chunk.sha256 in chunk.name

    assert first.manifest_sha256 in first.manifest_name
    assert first.index_sha256 in first.index_name
    object_names = [
        first.manifest_name,
        first.index_name,
        *(chunk.name for chunk in first.chunks),
    ]
    assert all(len(name) <= MAX_REVIEW_OBJECT_NAME_CHARACTERS for name in object_names)
    assert all(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*", name) for name in object_names)
    assert reconstruct_review_manifest(first)["turn"]["messages"][0]["content"].endswith(
        "🙂é" * 100
    )


def test_existing_turn_bundle_ignores_later_session_activity(
    session_payload: Callable[..., dict[str, Any]],
    atif_wrapper: Callable[..., dict[str, Any]],
) -> None:
    conversation = _conversation(session_payload, atif_wrapper)
    turn = conversation.turns[0]
    first = build_review_manifest(conversation, turn)
    advanced = replace(
        conversation,
        source_last_activity_at=conversation.source_last_activity_at + timedelta(days=1),
    )

    second = build_review_manifest(advanced, turn)

    assert second == first
    assert "source_last_activity_at" not in reconstruct_review_manifest(second)["session"]


def test_existing_turn_bundle_ignores_mutable_session_final_metrics(
    session_payload: Callable[..., dict[str, Any]],
    atif_wrapper: Callable[..., dict[str, Any]],
) -> None:
    session = Session.from_api(session_payload())
    before_append = map_atif(
        session,
        atif_wrapper(final_metrics={"total_tokens": 10}),
    )
    after_append = map_atif(
        session,
        atif_wrapper(final_metrics={"total_tokens": 20}),
    )
    before_turn = before_append.turns[0]
    after_turn = after_append.turns[0]

    assert before_turn.payload_sha256 == after_turn.payload_sha256
    before_bundle = build_review_manifest(before_append, before_turn)
    after_bundle = build_review_manifest(after_append, after_turn)

    assert after_bundle == before_bundle
    serialized_turn = reconstruct_review_manifest(after_bundle)["turn"]
    assert "hivemind.atif_final_metrics" not in serialized_turn["attributes"]
    assert "final_metrics" not in json.loads(
        serialized_turn["attributes"]["hivemind.atif_trajectory_metadata"]
    )
    assert serialized_turn["llms"][0]["usage"] == {
        "input_tokens": 10,
        "output_tokens": 4,
        "reasoning_tokens": 1,
        "cache_creation_input_tokens": 0,
        "cache_read_input_tokens": 2,
    }


def test_reconstruction_rejects_modified_chunk_or_index(
    session_payload: Callable[..., dict[str, Any]],
    atif_wrapper: Callable[..., dict[str, Any]],
) -> None:
    conversation = _conversation(session_payload, atif_wrapper)
    bundle = build_review_manifest(
        conversation,
        conversation.turns[0],
        max_chunk_bytes=512,
    )

    original = bundle.chunks[0]
    replacement_byte = b"x" if original.content[:1] != b"x" else b"y"
    modified_chunk = replace(
        original,
        content=replacement_byte + original.content[1:],
    )
    modified_bundle = replace(
        bundle,
        chunks=(modified_chunk, *bundle.chunks[1:]),
    )
    with pytest.raises(
        ReviewManifestError,
        match="review chunk content does not match its hash",
    ):
        reconstruct_review_manifest(modified_bundle)

    modified_index = replace(bundle, index_json=bundle.index_json + " ")
    with pytest.raises(
        ReviewManifestError,
        match="review index metadata does not match the bundle",
    ):
        reconstruct_review_manifest(modified_index)


def test_preview_signature_changes_only_with_preview_payload(
    session_payload: Callable[..., dict[str, Any]],
    atif_wrapper: Callable[..., dict[str, Any]],
) -> None:
    conversation = _conversation(session_payload, atif_wrapper)
    turn = conversation.turns[0]
    original = build_review_manifest(conversation, turn)

    turn.llms[0] = replace(turn.llms[0], reasoning="Different redacted reasoning")
    turn.finalize_hash()
    reasoning_changed = build_review_manifest(conversation, turn)

    turn.messages[0] = replace(turn.messages[0], content="Different user request")
    turn.finalize_hash()
    preview_changed = build_review_manifest(conversation, turn)

    assert reasoning_changed.manifest_sha256 != original.manifest_sha256
    assert reasoning_changed.preview_signature == original.preview_signature
    assert preview_changed.preview_signature != reasoning_changed.preview_signature


def test_chunk_limits_fail_before_returning_a_partial_bundle(
    session_payload: Callable[..., dict[str, Any]],
    atif_wrapper: Callable[..., dict[str, Any]],
) -> None:
    conversation = _conversation(session_payload, atif_wrapper)
    turn = conversation.turns[0]

    with pytest.raises(
        ReviewManifestError,
        match="review manifest requires more than the allowed chunks",
    ):
        build_review_manifest(
            conversation,
            turn,
            max_chunk_bytes=128,
            max_chunks=1,
        )
    with pytest.raises(ReviewManifestError, match="between 1 byte and 8 MiB"):
        build_review_manifest(
            conversation,
            turn,
            max_chunk_bytes=MAX_REVIEW_CHUNK_BYTES + 1,
        )
    with pytest.raises(ReviewManifestError, match="between 1 and 64"):
        build_review_manifest(
            conversation,
            turn,
            max_chunks=MAX_REVIEW_CHUNKS + 1,
        )


@pytest.mark.parametrize(
    ("result", "message"),
    [
        ({"score": float("nan")}, "review manifest contains a non-JSON value"),
        ({"text": "\ud800"}, "review manifest contains invalid Unicode"),
    ],
    ids=["non-finite-number", "unpaired-surrogate"],
)
def test_noncanonical_json_values_are_rejected(
    session_payload: Callable[..., dict[str, Any]],
    atif_wrapper: Callable[..., dict[str, Any]],
    result: dict[str, Any],
    message: str,
) -> None:
    conversation = _conversation(session_payload, atif_wrapper)
    turn = conversation.turns[0]
    turn.tools[0] = replace(turn.tools[0], result=result)

    with pytest.raises(
        ReviewManifestError,
        match=message,
    ):
        build_review_manifest(conversation, turn)
