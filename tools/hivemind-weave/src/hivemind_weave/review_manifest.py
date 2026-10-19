"""Lossless, deterministic review manifests for already-redacted turns.

This module is deliberately transport-agnostic. It does not persist or upload
content: callers must pass the final already-redacted mapped conversation and
turn. Preview slicing is treated as a new PII-context boundary and stabilized
with the same local redactor. The resulting content-addressed bundle can be
reviewed or handed to a later storage layer without changing its canonical
bytes.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import asdict, dataclass, field
from datetime import datetime
from typing import Any

from .models import ChatMessage, MappedConversation, MappedTurn
from .utils import isoformat_z

REVIEW_MANIFEST_SCHEMA = "hivemind-review-turn-v1"
REVIEW_INDEX_SCHEMA = "hivemind-review-turn-index-v1"
REVIEW_PREVIEW_SCHEMA = "hivemind-review-preview-v1"
MAX_REVIEW_CHUNK_BYTES = 8 * 1024 * 1024
MAX_REVIEW_CHUNKS = 64
REVIEW_PREVIEW_CHARACTERS = 4096
MAX_REVIEW_OBJECT_NAME_CHARACTERS = 120
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_OBJECT_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,119}$")


class ReviewManifestError(ValueError):
    """A review manifest could not be represented or verified losslessly."""


@dataclass(frozen=True, slots=True)
class ReviewManifestChunk:
    """One independently verifiable UTF-8 fragment of canonical manifest JSON."""

    index: int
    name: str
    sha256: str
    byte_count: int
    content: bytes = field(repr=False)

    @property
    def text(self) -> str:
        """Decode the fragment, which is guaranteed to end at a UTF-8 boundary."""
        return self.content.decode("utf-8", errors="strict")


@dataclass(frozen=True, slots=True)
class ReviewManifestBundle:
    """Canonical manifest chunks and their content-addressed index."""

    manifest_name: str
    manifest_sha256: str
    source_payload_sha256: str
    preview_signature: str
    manifest_byte_count: int
    max_chunk_bytes: int
    max_chunks: int
    chunks: tuple[ReviewManifestChunk, ...]
    index_name: str
    index_sha256: str
    index_byte_count: int
    index_json: str = field(repr=False)

    @property
    def manifest_json(self) -> str:
        """Return the exact canonical JSON represented by the chunks."""
        return b"".join(chunk.content for chunk in self.chunks).decode("utf-8", errors="strict")

    @property
    def index_metadata(self) -> dict[str, Any]:
        """Return a detached parsed copy of the canonical index metadata."""
        parsed = json.loads(self.index_json)
        if not isinstance(parsed, dict):  # pragma: no cover - guarded during construction.
            raise ReviewManifestError("review index is not a JSON object")
        return parsed


def build_review_manifest(
    conversation: MappedConversation,
    turn: MappedTurn,
    *,
    max_chunk_bytes: int = MAX_REVIEW_CHUNK_BYTES,
    max_chunks: int = MAX_REVIEW_CHUNKS,
) -> ReviewManifestBundle:
    """Build and self-verify one canonical review bundle.

    ``conversation`` and ``turn`` must already have passed the importer's final
    redaction pass.  This function intentionally performs no redaction of its
    own, so the full remaining messages, reasoning, tools, usage, timestamps,
    warnings, and source metadata survive byte-for-byte in canonical JSON.

    Smaller limits may be supplied by tests or a future storage adapter, but
    neither limit may exceed the public 8 MiB / 64 chunk contract.
    """
    _validate_chunk_limits(max_chunk_bytes=max_chunk_bytes, max_chunks=max_chunks)
    manifest_payload = _manifest_payload(conversation, turn)
    manifest_bytes = _canonical_json_bytes(manifest_payload)
    if len(manifest_bytes) > max_chunk_bytes * max_chunks:
        raise ReviewManifestError("review manifest requires more than the allowed chunks")

    manifest_sha256 = _sha256(manifest_bytes)
    source_payload_sha256 = str(manifest_payload["source_payload_sha256"])
    preview_signature = str(manifest_payload["preview_signature"])
    manifest_name = _manifest_name(manifest_sha256)
    chunk_contents = _split_utf8(manifest_bytes, max_chunk_bytes=max_chunk_bytes)
    if len(chunk_contents) > max_chunks:
        raise ReviewManifestError("review manifest requires more than the allowed chunks")

    chunk_count = len(chunk_contents)
    chunks: list[ReviewManifestChunk] = []
    for index, content in enumerate(chunk_contents):
        chunk_sha256 = _sha256(content)
        chunks.append(
            ReviewManifestChunk(
                index=index,
                name=_chunk_name(
                    manifest_sha256=manifest_sha256,
                    chunk_sha256=chunk_sha256,
                    index=index,
                    chunk_count=chunk_count,
                ),
                sha256=chunk_sha256,
                byte_count=len(content),
                content=content,
            )
        )

    frozen_chunks = tuple(chunks)
    index_json = _canonical_json(
        _index_payload(
            manifest_name=manifest_name,
            manifest_sha256=manifest_sha256,
            source_payload_sha256=source_payload_sha256,
            preview_signature=preview_signature,
            manifest_byte_count=len(manifest_bytes),
            max_chunk_bytes=max_chunk_bytes,
            max_chunks=max_chunks,
            chunks=frozen_chunks,
        )
    )
    index_bytes = index_json.encode("utf-8")
    index_sha256 = _sha256(index_bytes)
    bundle = ReviewManifestBundle(
        manifest_name=manifest_name,
        manifest_sha256=manifest_sha256,
        source_payload_sha256=source_payload_sha256,
        preview_signature=preview_signature,
        manifest_byte_count=len(manifest_bytes),
        max_chunk_bytes=max_chunk_bytes,
        max_chunks=max_chunks,
        chunks=frozen_chunks,
        index_name=_index_name(index_sha256),
        index_sha256=index_sha256,
        index_byte_count=len(index_bytes),
        index_json=index_json,
    )
    reconstruct_review_manifest(bundle)
    return bundle


def reconstruct_review_manifest(bundle: ReviewManifestBundle) -> dict[str, Any]:
    """Verify every certificate and reconstruct the canonical manifest object.

    Any missing, reordered, renamed, oversized, non-UTF-8, or content-modified
    chunk fails before JSON is returned.  The canonical index and full-manifest
    hashes are independently checked as well.
    """
    _validate_chunk_limits(
        max_chunk_bytes=bundle.max_chunk_bytes,
        max_chunks=bundle.max_chunks,
    )
    if not bundle.chunks or len(bundle.chunks) > bundle.max_chunks:
        raise ReviewManifestError("review bundle has an invalid chunk count")
    if bundle.manifest_name != _manifest_name(bundle.manifest_sha256):
        raise ReviewManifestError("review manifest name does not match its hash")
    if not _SHA256.fullmatch(bundle.source_payload_sha256):
        raise ReviewManifestError("review bundle has an invalid source payload hash")
    if not _SHA256.fullmatch(bundle.preview_signature):
        raise ReviewManifestError("review bundle has an invalid preview signature")
    if bundle.index_name != _index_name(bundle.index_sha256):
        raise ReviewManifestError("review index name does not match its hash")

    chunk_count = len(bundle.chunks)
    for expected_index, chunk in enumerate(bundle.chunks):
        if chunk.index != expected_index:
            raise ReviewManifestError("review chunks are missing, duplicated, or reordered")
        if chunk.byte_count != len(chunk.content) or chunk.byte_count > bundle.max_chunk_bytes:
            raise ReviewManifestError("review chunk byte metadata is invalid")
        try:
            chunk.content.decode("utf-8", errors="strict")
        except UnicodeDecodeError as error:
            raise ReviewManifestError("review chunk does not end at a UTF-8 boundary") from error
        actual_chunk_sha256 = _sha256(chunk.content)
        if chunk.sha256 != actual_chunk_sha256:
            raise ReviewManifestError("review chunk content does not match its hash")
        expected_name = _chunk_name(
            manifest_sha256=bundle.manifest_sha256,
            chunk_sha256=chunk.sha256,
            index=expected_index,
            chunk_count=chunk_count,
        )
        if chunk.name != expected_name:
            raise ReviewManifestError("review chunk name does not match its metadata")

    expected_index_json = _canonical_json(
        _index_payload(
            manifest_name=bundle.manifest_name,
            manifest_sha256=bundle.manifest_sha256,
            source_payload_sha256=bundle.source_payload_sha256,
            preview_signature=bundle.preview_signature,
            manifest_byte_count=bundle.manifest_byte_count,
            max_chunk_bytes=bundle.max_chunk_bytes,
            max_chunks=bundle.max_chunks,
            chunks=bundle.chunks,
        )
    )
    if bundle.index_json != expected_index_json:
        raise ReviewManifestError("review index metadata does not match the bundle")
    index_bytes = bundle.index_json.encode("utf-8")
    if len(index_bytes) != bundle.index_byte_count:
        raise ReviewManifestError("review index byte count does not match its content")
    if _sha256(index_bytes) != bundle.index_sha256:
        raise ReviewManifestError("review index content does not match its hash")

    manifest_bytes = b"".join(chunk.content for chunk in bundle.chunks)
    if len(manifest_bytes) != bundle.manifest_byte_count:
        raise ReviewManifestError("review manifest byte count does not match its chunks")
    if _sha256(manifest_bytes) != bundle.manifest_sha256:
        raise ReviewManifestError("review manifest content does not match its hash")
    try:
        manifest_text = manifest_bytes.decode("utf-8", errors="strict")
        parsed = json.loads(manifest_text)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ReviewManifestError("review manifest is not valid UTF-8 JSON") from error
    if not isinstance(parsed, dict) or parsed.get("schema") != REVIEW_MANIFEST_SCHEMA:
        raise ReviewManifestError("review manifest has an unsupported schema")
    if _canonical_json_bytes(parsed) != manifest_bytes:
        raise ReviewManifestError("review manifest JSON is not canonical")
    _validate_reconstructed_shape(parsed)
    if parsed.get("source_payload_sha256") != bundle.source_payload_sha256:
        raise ReviewManifestError("review manifest source hash does not match the bundle")
    if parsed.get("preview_signature") != bundle.preview_signature:
        raise ReviewManifestError("review manifest preview signature does not match the bundle")
    if _sha256(_canonical_json_bytes(parsed["review_previews"])) != bundle.preview_signature:
        raise ReviewManifestError("review previews do not match their signature")
    return parsed


def _manifest_payload(
    conversation: MappedConversation,
    turn: MappedTurn,
) -> dict[str, Any]:
    attributes = turn.attributes
    session_id = attributes.get("hivemind.session_id")
    if not isinstance(session_id, str) or not session_id:
        raise ReviewManifestError("mapped turn is missing its session metadata")
    parent_session_id = attributes.get("hivemind.parent_session_id", "")
    if not isinstance(parent_session_id, str):
        raise ReviewManifestError("mapped turn has invalid parent-session metadata")
    mapping_warnings = attributes.get("hivemind.mapping_warnings", [])
    if not isinstance(mapping_warnings, list) or not all(
        isinstance(value, str) for value in mapping_warnings
    ):
        raise ReviewManifestError("mapped turn has invalid mapping warnings")
    source_payload_sha256 = str(
        attributes.get("hivemind.source_payload_sha256") or turn.payload_sha256
    )
    if not _SHA256.fullmatch(source_payload_sha256):
        raise ReviewManifestError("mapped turn is missing its source payload hash")

    review_previews = {
        "schema": REVIEW_PREVIEW_SCHEMA,
        "user": _message_preview(
            turn.messages,
            role="user",
            reverse=False,
            label="USER MESSAGE PREVIEW (full content remains in turn.messages)",
            collection_path="turn.messages",
        ),
        "final_assistant": _message_preview(
            turn.output_messages,
            role="assistant",
            reverse=True,
            label=(
                "FINAL ASSISTANT MESSAGE PREVIEW (full content remains in turn.output_messages)"
            ),
            collection_path="turn.output_messages",
        ),
    }
    preview_signature = _sha256(_canonical_json_bytes(review_previews))
    serialized_turn = _immutable_turn_payload(turn)

    return {
        "schema": REVIEW_MANIFEST_SCHEMA,
        "source_payload_sha256": source_payload_sha256,
        "preview_signature": preview_signature,
        "content_contract": {
            "input": "already-redacted-mapped-turn",
            "turn_content": "complete",
            "previews_are_complete": False,
        },
        "conversation": {
            "conversation_id": conversation.conversation_id,
            "conversation_name": conversation.conversation_name,
            "agent_name": conversation.agent_name,
            "model": conversation.model,
            "agent_id": conversation.agent_id,
            "agent_version": conversation.agent_version,
            "atif_schema_version": conversation.schema_version,
        },
        "session": {
            "session_id": session_id,
            "agent_session_id": attributes.get("hivemind.agent_session_id", ""),
            "parent_session_id": parent_session_id,
            "is_subagent": bool(attributes.get("hivemind.is_subagent", parent_session_id)),
            "repository": attributes.get("hivemind.repository", ""),
            "branch": attributes.get("hivemind.branch", ""),
        },
        "mapping_warnings": list(mapping_warnings),
        "turn": serialized_turn,
        "review_previews": review_previews,
    }


def _immutable_turn_payload(turn: MappedTurn) -> dict[str, Any]:
    """Remove the one known mutable session aggregate from a turn manifest.

    ATIF ``final_metrics`` describes the whole trajectory and legitimately
    changes when later turns are appended.  The mapper retains it as searchable
    session provenance, both directly and inside its lossless trajectory
    metadata copy, but it is not part of ``MappedTurn.payload_for_hash``.  A
    review manifest is an immutable per-turn certificate, so carrying that
    aggregate here would make an unchanged historical turn acquire a new wire
    digest.  Per-step usage remains present on every serialized LLM span.
    """
    payload = asdict(turn)
    attributes = payload.get("attributes")
    if not isinstance(attributes, dict):  # pragma: no cover - dataclass invariant.
        raise ReviewManifestError("mapped turn has invalid attributes")

    attributes.pop("hivemind.atif_final_metrics", None)
    trajectory_metadata = attributes.get("hivemind.atif_trajectory_metadata")
    if isinstance(trajectory_metadata, str) and trajectory_metadata:
        try:
            parsed_metadata = json.loads(trajectory_metadata)
        except json.JSONDecodeError as error:
            raise ReviewManifestError("mapped turn has invalid ATIF trajectory metadata") from error
        if not isinstance(parsed_metadata, dict):
            raise ReviewManifestError("mapped turn has invalid ATIF trajectory metadata")
        parsed_metadata.pop("final_metrics", None)
        attributes["hivemind.atif_trajectory_metadata"] = _canonical_json(parsed_metadata)
    return payload


def _message_preview(
    messages: list[ChatMessage],
    *,
    role: str,
    reverse: bool,
    label: str,
    collection_path: str,
) -> dict[str, Any]:
    indexes = range(len(messages) - 1, -1, -1) if reverse else range(len(messages))
    selected_index = next((index for index in indexes if messages[index].role == role), None)
    content = "" if selected_index is None else messages[selected_index].content
    return _preview_payload(
        content=content,
        selected_index=selected_index,
        label=label,
        collection_path=collection_path,
    )


def _preview_payload(
    *,
    content: str,
    selected_index: int | None,
    label: str,
    collection_path: str,
) -> dict[str, Any]:
    preview, source_character_count = _stable_preview_text(content)
    return {
        "kind": "preview",
        "label": label,
        "present": selected_index is not None,
        "source_path": (
            None if selected_index is None else f"{collection_path}[{selected_index}].content"
        ),
        "text": preview,
        "preview_character_count": len(preview),
        "original_character_count": len(content),
        "limit_characters": REVIEW_PREVIEW_CHARACTERS,
        "truncated": len(content) > source_character_count,
    }


def _stable_preview_text(content: str) -> tuple[str, int]:
    """Return a redacted fixed-point preview within the exact UI budget.

    Cutting text changes NER context, and typed replacements can be longer than
    their source phrase. Start with the largest permitted source prefix, debit
    any observed expansion, then halve only if that exact adjustment still does
    not fit. The loop is bounded by the 4,096-character source window.
    """
    from .pii import redact_upload_data

    source_character_count = min(len(content), REVIEW_PREVIEW_CHARACTERS)
    adjusted_for_expansion = False
    while True:
        try:
            preview = redact_upload_data(content[:source_character_count])
        except Exception as error:
            raise ReviewManifestError("review preview redaction failed") from error
        if not isinstance(preview, str):
            raise ReviewManifestError("review preview redaction changed the text type")
        if len(preview) <= REVIEW_PREVIEW_CHARACTERS:
            return preview, source_character_count
        if source_character_count == 0:  # pragma: no cover - empty text cannot expand.
            raise ReviewManifestError("review preview cannot fit its character budget")
        overflow = len(preview) - REVIEW_PREVIEW_CHARACTERS
        if not adjusted_for_expansion:
            source_character_count = max(0, source_character_count - max(1, overflow))
            adjusted_for_expansion = True
        else:
            source_character_count //= 2


def _split_utf8(content: bytes, *, max_chunk_bytes: int) -> tuple[bytes, ...]:
    chunks: list[bytes] = []
    start = 0
    while start < len(content):
        end = min(start + max_chunk_bytes, len(content))
        if end < len(content):
            while end > start and content[end] & 0xC0 == 0x80:
                end -= 1
        if end == start:
            raise ReviewManifestError(
                "review chunk byte limit cannot contain one complete UTF-8 character"
            )
        chunk = content[start:end]
        try:
            chunk.decode("utf-8", errors="strict")
        except UnicodeDecodeError as error:  # pragma: no cover - boundary loop is exhaustive.
            raise ReviewManifestError("review chunk is not independently valid UTF-8") from error
        chunks.append(chunk)
        start = end
    if not chunks:  # Canonical manifest objects are nonempty; retain a total helper.
        chunks.append(b"")
    return tuple(chunks)


def _index_payload(
    *,
    manifest_name: str,
    manifest_sha256: str,
    source_payload_sha256: str,
    preview_signature: str,
    manifest_byte_count: int,
    max_chunk_bytes: int,
    max_chunks: int,
    chunks: tuple[ReviewManifestChunk, ...],
) -> dict[str, Any]:
    return {
        "schema": REVIEW_INDEX_SCHEMA,
        "manifest": {
            "schema": REVIEW_MANIFEST_SCHEMA,
            "name": manifest_name,
            "sha256": manifest_sha256,
            "source_payload_sha256": source_payload_sha256,
            "preview_signature": preview_signature,
            "byte_count": manifest_byte_count,
            "media_type": "application/json; charset=utf-8",
        },
        "chunking": {
            "encoding": "utf-8",
            "max_chunk_bytes": max_chunk_bytes,
            "max_chunks": max_chunks,
            "chunk_count": len(chunks),
        },
        "chunks": [
            {
                "index": chunk.index,
                "name": chunk.name,
                "sha256": chunk.sha256,
                "byte_count": chunk.byte_count,
                "media_type": "text/plain; charset=utf-8",
            }
            for chunk in chunks
        ],
    }


def _validate_reconstructed_shape(payload: dict[str, Any]) -> None:
    required_objects = ("content_contract", "conversation", "session", "turn", "review_previews")
    if any(not isinstance(payload.get(key), dict) for key in required_objects):
        raise ReviewManifestError("review manifest is missing a required object")
    if payload["content_contract"] != {
        "input": "already-redacted-mapped-turn",
        "turn_content": "complete",
        "previews_are_complete": False,
    }:
        raise ReviewManifestError("review manifest has an invalid content contract")

    turn = payload["turn"]
    required_turn_fields = {
        "key",
        "messages",
        "output_messages",
        "system_instructions",
        "llms",
        "tools",
        "subagents",
        "started_at",
        "ended_at",
        "hash_context",
        "attributes",
        "payload_sha256",
        "verification_signature",
    }
    if not required_turn_fields.issubset(turn) or not isinstance(turn.get("attributes"), dict):
        raise ReviewManifestError("review manifest does not contain a complete mapped turn")
    attributes = turn["attributes"]
    warnings = payload.get("mapping_warnings")
    if not isinstance(warnings, list) or not all(isinstance(value, str) for value in warnings):
        raise ReviewManifestError("review manifest has invalid mapping warnings")
    if warnings != attributes.get("hivemind.mapping_warnings", []):
        raise ReviewManifestError("review manifest warnings do not match the mapped turn")

    source_payload_sha256 = attributes.get("hivemind.source_payload_sha256") or turn.get(
        "payload_sha256"
    )
    if (
        not isinstance(source_payload_sha256, str)
        or not _SHA256.fullmatch(source_payload_sha256)
        or payload.get("source_payload_sha256") != source_payload_sha256
    ):
        raise ReviewManifestError("review manifest has invalid source payload metadata")
    session = payload["session"]
    expected_session_values = {
        "session_id": attributes.get("hivemind.session_id"),
        "agent_session_id": attributes.get("hivemind.agent_session_id", ""),
        "parent_session_id": attributes.get("hivemind.parent_session_id", ""),
        "is_subagent": bool(
            attributes.get(
                "hivemind.is_subagent",
                attributes.get("hivemind.parent_session_id", ""),
            )
        ),
        "repository": attributes.get("hivemind.repository", ""),
        "branch": attributes.get("hivemind.branch", ""),
    }
    if session != expected_session_values:
        raise ReviewManifestError("review manifest session metadata does not match the mapped turn")

    previews = payload["review_previews"]
    if previews.get("schema") != REVIEW_PREVIEW_SCHEMA:
        raise ReviewManifestError("review manifest has an unsupported preview schema")
    expected_previews = {
        "schema": REVIEW_PREVIEW_SCHEMA,
        "user": _serialized_message_preview(
            turn.get("messages"),
            role="user",
            reverse=False,
            label="USER MESSAGE PREVIEW (full content remains in turn.messages)",
            collection_path="turn.messages",
        ),
        "final_assistant": _serialized_message_preview(
            turn.get("output_messages"),
            role="assistant",
            reverse=True,
            label=(
                "FINAL ASSISTANT MESSAGE PREVIEW (full content remains in turn.output_messages)"
            ),
            collection_path="turn.output_messages",
        ),
    }
    if previews != expected_previews:
        raise ReviewManifestError("review manifest previews do not match the complete turn")


def _serialized_message_preview(
    messages: Any,
    *,
    role: str,
    reverse: bool,
    label: str,
    collection_path: str,
) -> dict[str, Any]:
    if not isinstance(messages, list) or any(
        not isinstance(message, dict)
        or not isinstance(message.get("role"), str)
        or not isinstance(message.get("content"), str)
        for message in messages
    ):
        raise ReviewManifestError("review manifest has invalid mapped messages")
    indexes = range(len(messages) - 1, -1, -1) if reverse else range(len(messages))
    selected_index = next((index for index in indexes if messages[index]["role"] == role), None)
    content = "" if selected_index is None else messages[selected_index]["content"]
    return _preview_payload(
        content=content,
        selected_index=selected_index,
        label=label,
        collection_path=collection_path,
    )


def _validate_chunk_limits(*, max_chunk_bytes: int, max_chunks: int) -> None:
    if (
        isinstance(max_chunk_bytes, bool)
        or not isinstance(max_chunk_bytes, int)
        or not 1 <= max_chunk_bytes <= MAX_REVIEW_CHUNK_BYTES
    ):
        raise ReviewManifestError("review chunk size must be between 1 byte and 8 MiB")
    if (
        isinstance(max_chunks, bool)
        or not isinstance(max_chunks, int)
        or not 1 <= max_chunks <= MAX_REVIEW_CHUNKS
    ):
        raise ReviewManifestError("review chunk count must be between 1 and 64")


def _canonical_json(value: Any) -> str:
    try:
        return json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
            default=_json_default,
        )
    except (TypeError, ValueError) as error:
        raise ReviewManifestError("review manifest contains a non-JSON value") from error


def _canonical_json_bytes(value: Any) -> bytes:
    try:
        return _canonical_json(value).encode("utf-8", errors="strict")
    except UnicodeEncodeError as error:
        raise ReviewManifestError("review manifest contains invalid Unicode") from error


def _json_default(value: Any) -> str:
    if isinstance(value, datetime) and value.tzinfo is not None and value.utcoffset() is not None:
        return isoformat_z(value)
    raise TypeError(f"unsupported review-manifest value: {type(value).__name__}")


def _sha256(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def _manifest_name(manifest_sha256: str) -> str:
    return _object_name(f"{REVIEW_MANIFEST_SCHEMA}-{manifest_sha256}.json")


def _index_name(index_sha256: str) -> str:
    return _object_name(f"{REVIEW_INDEX_SCHEMA}-{index_sha256}.json")


def _chunk_name(
    *,
    manifest_sha256: str,
    chunk_sha256: str,
    index: int,
    chunk_count: int,
) -> str:
    return _object_name(
        f"hm-review-v1-{manifest_sha256[:24]}-"
        f"c{index + 1:02d}-of-{chunk_count:02d}-{chunk_sha256}.txt"
    )


def _object_name(value: str) -> str:
    if len(value) > MAX_REVIEW_OBJECT_NAME_CHARACTERS or not _OBJECT_NAME.fullmatch(value):
        raise ReviewManifestError("review object name exceeds its safe storage contract")
    return value
