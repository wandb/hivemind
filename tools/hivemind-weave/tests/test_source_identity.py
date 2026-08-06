from __future__ import annotations

import pytest

from hivemind_weave.source_identity import is_opaque_source_coordinate


@pytest.mark.parametrize(
    "value",
    [
        "11111111-1111-4111-8111-111111111111",
        "11111111-1111-5111-8111-111111111111",
        "019f3df9-dc78-72c1-a9f0-60b9477a98db",
    ],
)
def test_review_source_coordinate_accepts_canonical_uuid_v4_v5_and_v7(value: str) -> None:
    assert is_opaque_source_coordinate(value)


@pytest.mark.parametrize(
    "value",
    [
        "AliceJohnson",
        "session-AliceJohnson",
        "child-JohnSmith",
        "alice@example.com",
        "review-user",
        "11111111-1111-1111-8111-111111111111",
        "11111111-1111-4111-7111-111111111111",
        "11111111-1111-4111-8111-11111111111A",
        "416c6963654a6f686e736f6e",
        "01ARZ3NDEKTSV4RRFFQ69G5FAV",
        " 11111111-1111-4111-8111-111111111111",
    ],
)
def test_review_source_coordinate_rejects_names_and_uncontracted_formats(value: object) -> None:
    assert not is_opaque_source_coordinate(value)
