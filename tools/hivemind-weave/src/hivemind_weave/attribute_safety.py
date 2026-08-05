"""Keep custom attributes below Weave Agents ingest limits without data loss."""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from .errors import ImporterError
from .utils import canonical_json

# Weave 0.53 accepts at most 256 Ki characters per typed custom-attribute
# value and 1,024 custom attributes per span. Stay comfortably below both
# boundaries so server-side truncation/drop behavior is never relied upon.
MAX_ATTRIBUTE_VALUE_CHARS = 240_000
MAX_CUSTOM_ATTRIBUTES = 900

# ``weave.conversation.log_turn`` copies custom attributes onto every child
# span. Keep that repeated payload small, then put archival data in dedicated
# Tool spans whose content is independently reconstructable. These budgets are
# deliberately expressed in JSON-escaped bytes because an innocuous-looking
# string of quotes or control characters can grow substantially on the wire.
MAX_ROOT_ATTRIBUTE_BYTES = 12 * 1_024
MAX_ROOT_ATTRIBUTES = 64
MAX_INLINE_TOOL_FIELD_JSON_BYTES = 20 * 1_024
MAX_SPILL_FRAGMENT_JSON_BYTES = 32 * 1_024

SPILL_SCHEMA = "hivemind.weave.spill/v1"
SPILL_TRANSPORT_ENCODING = "base64-utf8-sentinel-v1"
LEGACY_SPILL_TRANSPORT_ENCODING = "base64-utf8"
SPILL_CHUNK_PREFIX = "hivemind-b64-v1:"
SPILL_TOOL_NAME = "hivemind_transport_fragment"
SPILL_TOOL_TYPE = "hivemind_transport"
SPILL_PLACEHOLDER_KEY = "$hivemind_spill"
ATTRIBUTE_SPILL_MANIFEST_KEY = "hivemind.spill.attributes.manifest"
ATTRIBUTE_SPILL_FRAGMENT_COUNT_KEY = "hivemind.spill.attributes.fragment_count"

ROOT_CORRELATION_ATTRIBUTES = frozenset(
    {
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
    }
)

# These values are complete source archives or session-wide aggregates rather
# than useful root-span search facets. Always move them off the root, even when
# a particular instance happens to be small, so payload behavior is stable as
# a session grows.
ARCHIVAL_ATTRIBUTE_KEYS = frozenset(
    {
        "hivemind.atif_trajectory_extra",
        "hivemind.atif_agent_extra",
        "hivemind.atif_tool_definitions",
        "hivemind.atif_final_metrics",
        "hivemind.atif_wrapper_metadata",
        "hivemind.atif_wrapper_extra",
        "hivemind.atif_trajectory_metadata",
        "hivemind.preserved_step_data",
        "hivemind.trailing_copied_step_data",
        "hivemind.unreferenced_subagent_trajectories",
    }
)


class AttributeSafetyError(ImporterError):
    """A turn cannot fit losslessly inside the supported Weave limits."""


@dataclass(frozen=True)
class SpillManifest:
    """Compact metadata needed to find and validate one spilled value."""

    archive_id: str
    owner_kind: str
    field: str
    encoding: str
    transport_encoding: str
    sha256: str
    chunk_count: int
    utf8_bytes: int

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema": SPILL_SCHEMA,
            "archive_id": self.archive_id,
            "owner_kind": self.owner_kind,
            "field": self.field,
            "encoding": self.encoding,
            "transport_encoding": self.transport_encoding,
            "sha256": self.sha256,
            "chunk_count": self.chunk_count,
            "utf8_bytes": self.utf8_bytes,
        }

    @classmethod
    def from_dict(cls, value: Any) -> SpillManifest:
        if not isinstance(value, dict) or value.get("schema") != SPILL_SCHEMA:
            raise AttributeSafetyError("invalid spill manifest schema")
        archive_id = value.get("archive_id")
        owner_kind = value.get("owner_kind")
        field = value.get("field")
        encoding = value.get("encoding")
        transport_encoding = value.get("transport_encoding")
        digest = value.get("sha256")
        chunk_count = value.get("chunk_count")
        utf8_bytes = value.get("utf8_bytes")
        if (
            not isinstance(archive_id, str)
            or len(archive_id) != 64
            or not isinstance(owner_kind, str)
            or not owner_kind
            or not isinstance(field, str)
            or not field
            or encoding not in {"text", "canonical-json", "sdk-json"}
            or transport_encoding not in {SPILL_TRANSPORT_ENCODING, LEGACY_SPILL_TRANSPORT_ENCODING}
            or not isinstance(digest, str)
            or len(digest) != 64
            or isinstance(chunk_count, bool)
            or not isinstance(chunk_count, int)
            or chunk_count < 1
            or isinstance(utf8_bytes, bool)
            or not isinstance(utf8_bytes, int)
            or utf8_bytes < 0
        ):
            raise AttributeSafetyError("invalid spill manifest metadata")
        return cls(
            archive_id=archive_id,
            owner_kind=owner_kind,
            field=field,
            encoding=encoding,
            transport_encoding=transport_encoding,
            sha256=digest,
            chunk_count=chunk_count,
            utf8_bytes=utf8_bytes,
        )


@dataclass(frozen=True)
class SpillFragment:
    """One bounded physical Tool-span payload from a logical spilled value."""

    manifest: SpillManifest
    chunk_index: int
    content: str

    @property
    def chunk_sha256(self) -> str:
        return hashlib.sha256(self.content.encode("utf-8")).hexdigest()

    @property
    def arguments(self) -> dict[str, Any]:
        return {
            **self.manifest.as_dict(),
            "chunk_index": self.chunk_index,
            "chunk_sha256": self.chunk_sha256,
            "chunk_utf8_bytes": len(self.content.encode("utf-8")),
            "chunk_json_bytes": json_string_wire_bytes(self.content),
        }

    @property
    def tool_call_id(self) -> str:
        return f"hivemind-spill:{self.manifest.archive_id}:{self.chunk_index:04d}"


@dataclass(frozen=True)
class AttributeSpillPlan:
    root_attributes: dict[str, Any]
    fragments: tuple[SpillFragment, ...]


@dataclass(frozen=True)
class ToolSpillPlan:
    arguments: Any
    result: Any
    fragments: tuple[SpillFragment, ...]


def _serialized_value(value: Any) -> tuple[str, str]:
    if isinstance(value, str):
        return (value, "text")
    return (canonical_json(value), "canonical-json")


def json_string_wire_bytes(value: str) -> int:
    """Return the UTF-8 byte size of ``value`` as one JSON string token."""
    return len(json.dumps(value, ensure_ascii=False).encode("utf-8"))


def _json_character_bytes(value: str) -> int:
    codepoint = ord(value)
    if value in {'"', "\\"}:
        return 2
    if codepoint < 0x20:
        return 2 if value in "\b\t\n\f\r" else 6
    return len(value.encode("utf-8"))


def _split_json_string(value: str, *, prefix: str = "") -> tuple[str, ...]:
    """Split text at codepoint boundaries under the escaped wire budget."""
    if not value:
        return (prefix,)
    parts: list[str] = []
    start = 0
    used = json_string_wire_bytes(prefix)
    for index, character in enumerate(value):
        character_bytes = _json_character_bytes(character)
        if used + character_bytes > MAX_SPILL_FRAGMENT_JSON_BYTES and index > start:
            parts.append(prefix + value[start:index])
            start = index
            used = json_string_wire_bytes(prefix)
        used += character_bytes
    parts.append(prefix + value[start:])
    if any(json_string_wire_bytes(part) > MAX_SPILL_FRAGMENT_JSON_BYTES for part in parts):
        raise AttributeSafetyError("spill fragment exceeds its JSON wire budget")
    return tuple(parts)


def _spill_value(
    value: Any,
    *,
    owner_kind: str,
    owner_id: str,
    field: str,
) -> tuple[SpillManifest, tuple[SpillFragment, ...]]:
    serialized, encoding = _serialized_value(value)
    return _spill_serialized(
        serialized,
        encoding=encoding,
        owner_kind=owner_kind,
        owner_id=owner_id,
        field=field,
    )


def _spill_serialized(
    serialized: str,
    *,
    encoding: str,
    owner_kind: str,
    owner_id: str,
    field: str,
) -> tuple[SpillManifest, tuple[SpillFragment, ...]]:
    digest = hashlib.sha256(serialized.encode("utf-8")).hexdigest()
    archive_identity = canonical_json(
        {
            "schema": SPILL_SCHEMA,
            "owner_kind": owner_kind,
            "owner_id": owner_id,
            "field": field,
            "encoding": encoding,
            "transport_encoding": SPILL_TRANSPORT_ENCODING,
            "sha256": digest,
        }
    )
    archive_id = hashlib.sha256(archive_identity.encode("utf-8")).hexdigest()
    transport_value = base64.b64encode(serialized.encode("utf-8")).decode("ascii")
    # Prefix every physical chunk.  Weave's hosted ingest treats long bare
    # base64 strings as potential media and may replace one with a Content ref,
    # which would break lossless reconstruction.  The sentinel is outside the
    # base64 alphabet and therefore keeps every fragment inline.
    chunks = _split_json_string(transport_value, prefix=SPILL_CHUNK_PREFIX)
    manifest = SpillManifest(
        archive_id=archive_id,
        owner_kind=owner_kind,
        field=field,
        encoding=encoding,
        transport_encoding=SPILL_TRANSPORT_ENCODING,
        sha256=digest,
        chunk_count=len(chunks),
        utf8_bytes=len(serialized.encode("utf-8")),
    )
    return (
        manifest,
        tuple(
            SpillFragment(manifest=manifest, chunk_index=index, content=chunk)
            for index, chunk in enumerate(chunks)
        ),
    )


def _root_attribute_bytes(attributes: dict[str, Any]) -> int:
    return len(canonical_json(attributes).encode("utf-8"))


def _root_candidate_bytes(value: Any) -> int:
    return len(canonical_json(value).encode("utf-8"))


def plan_attribute_spill(
    attributes: dict[str, Any],
    *,
    owner_id: str,
) -> AttributeSpillPlan:
    """Move archival/root-heavy values into one deterministic fragment stream.

    Required reconciliation correlators always remain on the root. Additional
    values are spilled largest-first only when needed to enforce a small total
    root payload or attribute count.
    """
    spill_keys = {
        key
        for key, value in attributes.items()
        if key in ARCHIVAL_ATTRIBUTE_KEYS
        or key in {ATTRIBUTE_SPILL_MANIFEST_KEY, ATTRIBUTE_SPILL_FRAGMENT_COUNT_KEY}
        or json_string_wire_bytes(_serialized_value(value)[0]) > MAX_INLINE_TOOL_FIELD_JSON_BYTES
    }

    while True:
        root_attributes = {key: value for key, value in attributes.items() if key not in spill_keys}
        fragments: tuple[SpillFragment, ...] = ()
        if spill_keys:
            archive = {key: attributes[key] for key in sorted(spill_keys)}
            manifest, fragments = _spill_value(
                archive,
                owner_kind="turn_attributes",
                owner_id=owner_id,
                field="attributes",
            )
            root_attributes[ATTRIBUTE_SPILL_MANIFEST_KEY] = canonical_json(
                {
                    **manifest.as_dict(),
                    "attribute_count": len(archive),
                }
            )
            root_attributes[ATTRIBUTE_SPILL_FRAGMENT_COUNT_KEY] = len(fragments)

        within_count = len(root_attributes) <= MAX_ROOT_ATTRIBUTES
        within_bytes = _root_attribute_bytes(root_attributes) <= MAX_ROOT_ATTRIBUTE_BYTES
        if within_count and within_bytes:
            validate_upload_attributes(root_attributes)
            return AttributeSpillPlan(root_attributes, fragments)

        candidates = [
            key
            for key in root_attributes
            if key not in ROOT_CORRELATION_ATTRIBUTES
            and key not in {ATTRIBUTE_SPILL_MANIFEST_KEY, ATTRIBUTE_SPILL_FRAGMENT_COUNT_KEY}
        ]
        if not candidates:
            raise AttributeSafetyError(
                "required root correlators exceed the lossless transport budget"
            )
        candidate = sorted(
            candidates,
            key=lambda key: (-_root_candidate_bytes(attributes[key]), key),
        )[0]
        spill_keys.add(candidate)


def _sdk_tool_string(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    return json.dumps(value, ensure_ascii=False, default=str)


def plan_tool_spill(
    arguments: Any,
    result: Any,
    *,
    owner_id: str,
    serialized_redactor: Callable[[str], str] | None = None,
) -> ToolSpillPlan:
    """Replace oversized Tool fields with manifests plus bounded fragments.

    The optional redactor represents the Conversation SDK's destination pass.
    It is applied once to the complete SDK-serialized value before any split,
    preserving cross-boundary entity detection. Base64 then prevents the SDK's
    unavoidable per-physical-Tool pass from changing the archived text/hash.
    """
    uploaded: dict[str, Any] = {"arguments": arguments, "result": result}
    fragments: list[SpillFragment] = []
    for field in ("arguments", "result"):
        value = uploaded[field]
        serialized = _sdk_tool_string(value)
        if json_string_wire_bytes(serialized) <= MAX_INLINE_TOOL_FIELD_JSON_BYTES:
            continue
        if serialized_redactor is not None:
            serialized = serialized_redactor(serialized)
        manifest, field_fragments = _spill_serialized(
            serialized,
            encoding="text" if isinstance(value, str) else "sdk-json",
            owner_kind="tool",
            owner_id=owner_id,
            field=field,
        )
        uploaded[field] = {SPILL_PLACEHOLDER_KEY: manifest.as_dict()}
        fragments.extend(field_fragments)
    return ToolSpillPlan(uploaded["arguments"], uploaded["result"], tuple(fragments))


def _reconstruct_value(
    manifest: SpillManifest,
    fragments: tuple[SpillFragment, ...],
) -> Any:
    matching = [
        fragment for fragment in fragments if fragment.manifest.archive_id == manifest.archive_id
    ]
    matching.sort(key=lambda fragment: fragment.chunk_index)
    if len(matching) != manifest.chunk_count or [
        fragment.chunk_index for fragment in matching
    ] != list(range(manifest.chunk_count)):
        raise AttributeSafetyError("incomplete spill fragment sequence")
    for fragment in matching:
        if fragment.manifest != manifest:
            raise AttributeSafetyError("spill fragment manifest mismatch")
    transport_parts: list[str] = []
    for fragment in matching:
        content = fragment.content
        if manifest.transport_encoding == SPILL_TRANSPORT_ENCODING:
            if not content.startswith(SPILL_CHUNK_PREFIX):
                raise AttributeSafetyError("invalid spill fragment sentinel")
            content = content[len(SPILL_CHUNK_PREFIX) :]
        transport_parts.append(content)
    transport_value = "".join(transport_parts)
    try:
        serialized_bytes = base64.b64decode(transport_value, validate=True)
        serialized = serialized_bytes.decode("utf-8")
    except (binascii.Error, UnicodeDecodeError) as error:
        raise AttributeSafetyError("invalid base64-UTF8 spill content") from error
    if len(serialized_bytes) != manifest.utf8_bytes:
        raise AttributeSafetyError("spill fragment byte count mismatch")
    if hashlib.sha256(serialized.encode("utf-8")).hexdigest() != manifest.sha256:
        raise AttributeSafetyError("spill fragment hash mismatch")
    if manifest.encoding == "text":
        return serialized
    try:
        return json.loads(serialized)
    except (TypeError, ValueError) as error:
        raise AttributeSafetyError("invalid canonical JSON spill content") from error


def restore_spilled_attributes(
    root_attributes: dict[str, Any],
    fragments: tuple[SpillFragment, ...],
) -> dict[str, Any]:
    """Reconstruct the logical post-redaction attributes from a spill plan."""
    if ATTRIBUTE_SPILL_MANIFEST_KEY not in root_attributes:
        if fragments:
            raise AttributeSafetyError("orphaned attribute spill fragments")
        return dict(root_attributes)
    raw_manifest = root_attributes[ATTRIBUTE_SPILL_MANIFEST_KEY]
    if not isinstance(raw_manifest, str):
        raise AttributeSafetyError("invalid attribute spill manifest")
    try:
        manifest_value = json.loads(raw_manifest)
    except (TypeError, ValueError) as error:
        raise AttributeSafetyError("invalid attribute spill manifest") from error
    manifest = SpillManifest.from_dict(manifest_value)
    if manifest.owner_kind != "turn_attributes" or manifest.field != "attributes":
        raise AttributeSafetyError("invalid attribute spill owner")
    if root_attributes.get(ATTRIBUTE_SPILL_FRAGMENT_COUNT_KEY) != manifest.chunk_count:
        raise AttributeSafetyError("attribute spill fragment count mismatch")
    archive = _reconstruct_value(manifest, fragments)
    if not isinstance(archive, dict) or len(archive) != manifest_value.get("attribute_count"):
        raise AttributeSafetyError("invalid attribute spill archive")
    restored = dict(root_attributes)
    del restored[ATTRIBUTE_SPILL_MANIFEST_KEY]
    del restored[ATTRIBUTE_SPILL_FRAGMENT_COUNT_KEY]
    if any(key in restored for key in archive):
        raise AttributeSafetyError("attribute spill archive collides with root data")
    restored.update(archive)
    return restored


def _placeholder_manifest(value: Any) -> SpillManifest | None:
    candidate = value
    if isinstance(candidate, str):
        try:
            candidate = json.loads(candidate)
        except (TypeError, ValueError):
            return None
    if not isinstance(candidate, dict) or set(candidate) != {SPILL_PLACEHOLDER_KEY}:
        return None
    return SpillManifest.from_dict(candidate[SPILL_PLACEHOLDER_KEY])


def restore_spilled_tool(
    arguments: Any,
    result: Any,
    fragments: tuple[SpillFragment, ...],
) -> tuple[Any, Any]:
    """Reconstruct a logical Tool's exact post-redaction arguments and result."""
    restored: dict[str, Any] = {"arguments": arguments, "result": result}
    used_archive_ids: set[str] = set()
    for field in ("arguments", "result"):
        manifest = _placeholder_manifest(restored[field])
        if manifest is None:
            continue
        if manifest.owner_kind != "tool" or manifest.field != field:
            raise AttributeSafetyError("invalid tool spill owner")
        restored[field] = _reconstruct_value(manifest, fragments)
        used_archive_ids.add(manifest.archive_id)
    fragment_archive_ids = {fragment.manifest.archive_id for fragment in fragments}
    if fragment_archive_ids != used_archive_ids:
        raise AttributeSafetyError("orphaned tool spill fragments")
    return (restored["arguments"], restored["result"])


def chunk_large_attributes(attributes: dict[str, Any]) -> dict[str, Any]:
    """Split oversized values into deterministic, reconstructable attributes.

    Every value is first represented losslessly as either its original text or
    canonical JSON. Calling this function again is safe: if a prior chunk grew
    during a later redaction pass, that leaf receives its own chunk envelope.
    Consumers reconstruct such values from the deepest envelope outward.
    """
    chunked: dict[str, Any] = {}
    for key, value in attributes.items():
        serialized, encoding = _serialized_value(value)
        if len(serialized) <= MAX_ATTRIBUTE_VALUE_CHARS:
            chunked[key] = value
            continue

        parts = [
            serialized[index : index + MAX_ATTRIBUTE_VALUE_CHARS]
            for index in range(0, len(serialized), MAX_ATTRIBUTE_VALUE_CHARS)
        ]
        chunked[f"{key}.chunk_count"] = len(parts)
        chunked[f"{key}.encoding"] = encoding
        chunked[f"{key}.sha256"] = hashlib.sha256(serialized.encode("utf-8")).hexdigest()
        for index, part in enumerate(parts):
            chunked[f"{key}.chunk.{index:04d}"] = part

    validate_upload_attributes(chunked)
    return chunked


def restore_chunked_attributes(attributes: dict[str, Any]) -> dict[str, Any]:
    """Restore deterministic chunk envelopes to their original typed values.

    Nested envelopes are processed deepest-first. This matters when a later
    transform expanded an individual chunk and that chunk was itself split.
    Hashes are checked at every level so corrupt or incomplete transport data
    can never be mistaken for the original attribute.
    """
    restored = dict(attributes)
    suffix = ".chunk_count"
    bases = sorted(
        (key[: -len(suffix)] for key in restored if key.endswith(suffix)),
        key=len,
        reverse=True,
    )
    for base in bases:
        count_key = f"{base}.chunk_count"
        if count_key not in restored:
            continue
        encoding_key = f"{base}.encoding"
        digest_key = f"{base}.sha256"
        # A user attribute may legitimately end in `.chunk_count`. It is an
        # envelope only when the complete metadata triplet is present.
        if encoding_key not in restored and digest_key not in restored:
            continue
        count = restored[count_key]
        encoding = restored.get(encoding_key)
        digest = restored.get(digest_key)
        if isinstance(count, bool) or not isinstance(count, int) or count < 1:
            raise AttributeSafetyError(f"invalid chunk count for custom attribute {base!r}")
        if encoding not in {"text", "canonical-json"} or not isinstance(digest, str):
            raise AttributeSafetyError(f"invalid chunk metadata for custom attribute {base!r}")

        part_keys = [f"{base}.chunk.{index:04d}" for index in range(count)]
        if any(key not in restored or not isinstance(restored[key], str) for key in part_keys):
            raise AttributeSafetyError(f"incomplete chunk data for custom attribute {base!r}")
        serialized = "".join(restored[key] for key in part_keys)
        actual_digest = hashlib.sha256(serialized.encode("utf-8")).hexdigest()
        if actual_digest != digest:
            raise AttributeSafetyError(f"chunk hash mismatch for custom attribute {base!r}")
        if encoding == "canonical-json":
            try:
                value = json.loads(serialized)
            except (TypeError, ValueError) as error:
                raise AttributeSafetyError(
                    f"invalid canonical JSON chunks for custom attribute {base!r}"
                ) from error
        else:
            value = serialized

        del restored[count_key]
        del restored[encoding_key]
        del restored[digest_key]
        for key in part_keys:
            del restored[key]
        restored[base] = value
    return restored


def validate_upload_attributes(attributes: dict[str, Any]) -> None:
    """Fail before upload if Weave could truncate or drop a custom attribute."""
    if len(attributes) > MAX_CUSTOM_ATTRIBUTES:
        raise AttributeSafetyError(
            "turn requires too many custom attributes for a lossless Weave upload"
        )
    for value in attributes.values():
        serialized, _ = _serialized_value(value)
        if len(serialized) > MAX_ATTRIBUTE_VALUE_CHARS:
            raise AttributeSafetyError(
                "turn contains a custom attribute too large for a lossless Weave upload"
            )
