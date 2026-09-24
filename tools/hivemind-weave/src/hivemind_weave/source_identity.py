"""Fail-closed validation for source coordinates retained by review state.

Review plans deliberately retain HiveMind's internal session coordinate. The
coordinate must therefore use a narrowly contracted machine-ID syntax, not a
username, email address, or label. UUIDv5 is name-derived and syntax alone does
not prove opacity, so review state remains sensitive and private. Account labels
are neither copied nor hashed into review state.
"""

from __future__ import annotations

import re

from .redaction import redact_string

_OPAQUE_SOURCE_COORDINATE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[457][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
)


def is_opaque_source_coordinate(value: object) -> bool:
    """Return whether *value* is a supported, credential-free source ID.

    Review v1 accepts only canonical lowercase RFC-variant UUIDv4/v5/v7 text.
    The intentionally narrow allowlist matches current HiveMind
    session coordinates while rejecting legacy slugs, plausible names, and
    account handles even when a general-purpose PII model misses them. New
    server ID formats must be documented and added explicitly instead of
    weakening this check.
    """
    if not isinstance(value, str) or not value or len(value) > 255:
        return False
    if value != value.strip() or redact_string(value) != value:
        return False
    return _OPAQUE_SOURCE_COORDINATE.fullmatch(value) is not None
