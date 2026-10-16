from __future__ import annotations

import pytest

from hivemind_weave.attribute_safety import (
    MAX_CUSTOM_ATTRIBUTES,
    MAX_INLINE_FIELD_JSON_BYTES,
    MAX_ROOT_ATTRIBUTE_BYTES,
    MAX_TURN_CONTENT_JSON_BYTES,
    AttributeSafetyError,
    validate_inline_field,
    validate_turn_payload,
    validate_upload_attributes,
)


def test_attributes_within_reviewed_limits_are_accepted() -> None:
    validate_upload_attributes({"hivemind.session_id": "session-1", "ordinary": "value"})


def test_attributes_fail_closed_instead_of_being_fragmented() -> None:
    with pytest.raises(AttributeSafetyError, match="inline transport"):
        validate_upload_attributes({"oversized": "x" * MAX_ROOT_ATTRIBUTE_BYTES})
    with pytest.raises(AttributeSafetyError, match="too many"):
        validate_upload_attributes(
            {f"key-{index}": index for index in range(MAX_CUSTOM_ATTRIBUTES + 1)}
        )


def test_oversized_content_field_fails_closed() -> None:
    with pytest.raises(AttributeSafetyError, match="was not sent"):
        validate_inline_field("x" * MAX_INLINE_FIELD_JSON_BYTES, field="tool result")


def test_aggregate_turn_budget_accounts_for_repeated_root_attributes() -> None:
    with pytest.raises(AttributeSafetyError, match="aggregate"):
        validate_turn_payload(
            {"messages": "x" * (MAX_TURN_CONTENT_JSON_BYTES - 1_000)},
            repeated_attributes={"search": "y" * 1_000},
            span_count=4,
        )
