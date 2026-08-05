"""Fail closed when a turn cannot use Weave's ordinary inspected fields safely."""

from __future__ import annotations

import json
from typing import Any

from .errors import ImporterError
from .utils import canonical_json

# These are deliberately conservative. The importer no longer encodes oversized
# values into opaque fragments because doing so would make server-side content
# inspection ineffective. Until Weave offers an atomic, scan-preserving large-
# payload API, an oversized turn is rejected before ``weave.log_turn`` is called.
MAX_ATTRIBUTE_VALUE_CHARS = 240_000
MAX_CUSTOM_ATTRIBUTES = 64
MAX_ROOT_ATTRIBUTE_BYTES = 12 * 1_024
MAX_INLINE_FIELD_JSON_BYTES = 20 * 1_024
MAX_TURN_CONTENT_JSON_BYTES = 256 * 1_024


class AttributeSafetyError(ImporterError):
    """A turn cannot fit inside the reviewed inline Weave transport limits."""


def json_wire_bytes(value: Any) -> int:
    """Return the UTF-8 size of one compact JSON value."""
    return len(
        json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            default=str,
        ).encode("utf-8")
    )


def validate_inline_field(value: Any, *, field: str) -> None:
    """Reject a content-bearing field that would need an opaque side channel."""
    if json_wire_bytes(value) > MAX_INLINE_FIELD_JSON_BYTES:
        raise AttributeSafetyError(
            f"{field} exceeds the secure inline transport limit; "
            "the turn was not sent to Weave"
        )


def validate_upload_attributes(attributes: dict[str, Any]) -> None:
    """Reject attributes that Weave could truncate, drop, or repeat excessively."""
    if len(attributes) > MAX_CUSTOM_ATTRIBUTES:
        raise AttributeSafetyError(
            "turn requires too many custom attributes for a secure inline Weave upload"
        )
    if len(canonical_json(attributes).encode("utf-8")) > MAX_ROOT_ATTRIBUTE_BYTES:
        raise AttributeSafetyError(
            "turn attributes exceed the secure inline transport limit; "
            "the turn was not sent to Weave"
        )
    for value in attributes.values():
        serialized = value if isinstance(value, str) else canonical_json(value)
        if len(serialized) > MAX_ATTRIBUTE_VALUE_CHARS:
            raise AttributeSafetyError(
                "turn contains a custom attribute too large for a secure Weave upload"
            )


def validate_turn_payload(
    payload: dict[str, Any],
    *,
    repeated_attributes: dict[str, Any],
    span_count: int,
) -> None:
    """Bound a whole turn before the non-atomic SDK/exporter boundary is entered."""
    repeated_bytes = json_wire_bytes(repeated_attributes) * max(span_count - 1, 0)
    if json_wire_bytes(payload) + repeated_bytes > MAX_TURN_CONTENT_JSON_BYTES:
        raise AttributeSafetyError(
            "turn exceeds the secure aggregate transport limit; "
            "the turn was not sent to Weave"
        )
