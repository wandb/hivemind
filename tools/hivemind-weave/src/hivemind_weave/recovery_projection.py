"""Fail-closed normalized span projections for recovery audits.

This module reproduces the Weave Agents read-side normalization used to compare
historical OpenTelemetry spans with locally reconstructed spans.  It exposes
only deterministic digests and non-content metadata to callers; validation
errors never interpolate span attributes or message content.

The implementation intentionally depends on Weave trace-server internals.  A
caller performing a mutation must validate an independently reviewed source
pin manifest before trusting the projections produced here.
"""

from __future__ import annotations

import inspect
import json
import math
import re
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass
from dataclasses import field as dataclass_field
from datetime import UTC, datetime
from hashlib import sha256
from pathlib import Path
from types import MappingProxyType
from typing import Any, Literal

from weave.trace_server.agents.semconv import KNOWN_KEYS
from weave.trace_server.agents.types import AgentSpanSchema
from weave.trace_server.base64_content_conversion import (
    AUTO_CONVERSION_MIN_SIZE,
    is_base64,
    is_data_uri,
)
from weave.trace_server.opentelemetry.genai_extraction import (
    redact_credentials_from_span,
)
from weave.trace_server.opentelemetry.helpers import expand_attributes
from weave.trace_server.opentelemetry.python_spans import Span, SpanKind

from .errors import VerificationError
from .utils import parse_datetime, sha256_json

PROJECTION_SCHEMA = "weave-0.53-normalized-child/v4"
RECOVERY_CHILD_KEY = "hivemind.recovery.child_key"
RECOVERY_SCHEMA_KEY = "hivemind.recovery.schema"
RECOVERY_SCHEMA = "hivemind.weave.partial-recovery/v1"

LEGACY_TOOL_COMPATIBILITY_SCHEMA = "hivemind.weave.legacy-tool-result/v2"
LEGACY_TOOL_COMPATIBILITY_POLICY = "exact-json-reviewed-placeholder-relations/v2"
LEGACY_TOOL_RESULT_MAX_CHARS = 128 * 1024 * 1024
LEGACY_TOOL_RESULT_MAX_DEPTH = 64
LEGACY_TOOL_RESULT_MAX_NODES = 1_000_000
LEGACY_TOOL_PLACEHOLDER_VOCABULARY = (
    "CREDIT_CARD",
    "CRYPTO",
    "EMAIL_ADDRESS",
    "ES_NIF",
    "FI_PERSONAL_IDENTITY_CODE",
    "IBAN_CODE",
    "IN_AADHAAR",
    "IN_PAN",
    "IP_ADDRESS",
    "LOCATION",
    "PERSON",
    "PHONE_NUMBER",
    "UK_NHS",
    "UK_NINO",
    "US_BANK_NUMBER",
    "US_DRIVER_LICENSE",
    "US_PASSPORT",
    "US_SSN",
)
LEGACY_TOOL_PLACEHOLDER_VOCABULARY_SHA256 = sha256_json(
    {
        "schema": LEGACY_TOOL_COMPATIBILITY_SCHEMA,
        "generic": ["[REDACTED]", "REDACTED"],
        "typed": list(LEGACY_TOOL_PLACEHOLDER_VOCABULARY),
    }
)
LEGACY_TOOL_COMPATIBILITY_POLICY_SHA256 = sha256_json(
    {
        "schema": LEGACY_TOOL_COMPATIBILITY_SCHEMA,
        "policy": LEGACY_TOOL_COMPATIBILITY_POLICY,
        "operation": "execute_tool",
        "representation": "legacy",
        "field": "tool_call_result",
        "constraints": [
            "strict-json-object-or-array",
            "exact-object-keys-and-container-topology",
            "exact-non-placeholder-content",
            "unchanged-placeholders-exact",
            "changed-placeholders-one-relation-class",
            "allow-generic-typed",
            "allow-distinct-known-typed-typed",
            "reject-generic-generic",
            "at-least-one-substitution",
            "exactly-one-changed-string-value-leaf",
        ],
        "vocabulary_sha256": LEGACY_TOOL_PLACEHOLDER_VOCABULARY_SHA256,
    }
)

STABLE_CUSTOM_KEYS = (
    "hivemind.session_id",
    "hivemind.turn_key",
    "hivemind.payload_sha256",
    "hivemind.source_payload_sha256",
    "hivemind.atif_schema_version",
    "hivemind.importer_version",
)
RECOVERY_CUSTOM_KEYS = (RECOVERY_CHILD_KEY, RECOVERY_SCHEMA_KEY)
SELECTED_CUSTOM_KEYS = (*STABLE_CUSTOM_KEYS, *RECOVERY_CUSTOM_KEYS)
CUSTOM_MAP_FIELDS = (
    "custom_attrs_string",
    "custom_attrs_int",
    "custom_attrs_float",
    "custom_attrs_bool",
)

_HEX_64 = re.compile(r"^[0-9a-f]{64}$")
_PLACEHOLDER = re.compile(
    r"(?P<generic>\[REDACTED\]|"
    r"(?<![A-Za-z0-9_])REDACTED(?![A-Za-z0-9_]))|"
    r"(?P<typed><(?:" + "|".join(LEGACY_TOOL_PLACEHOLDER_VOCABULARY) + r")>)"
)
_EXCLUDED_NORMALIZED_FIELDS = frozenset(
    {
        "project_id",
        "trace_id",
        "span_id",
        "parent_span_id",
        "span_name",
        "started_at",
        "ended_at",
        "created_at",
        *CUSTOM_MAP_FIELDS,
        "raw_span_dump",
        "wb_user_id",
        "wb_run_id",
        "wb_run_step",
        "wb_run_step_end",
        "expire_at",
    }
)
AGENT_SPAN_SCHEMA_FIELDS = frozenset(AgentSpanSchema.model_fields)
NORMALIZED_FIELDS = tuple(sorted(AGENT_SPAN_SCHEMA_FIELDS - _EXCLUDED_NORMALIZED_FIELDS))

Representation = Literal["legacy", "recovery"]

__all__ = [
    "AGENT_SPAN_SCHEMA_FIELDS",
    "CUSTOM_MAP_FIELDS",
    "LEGACY_TOOL_COMPATIBILITY_POLICY",
    "LEGACY_TOOL_COMPATIBILITY_POLICY_SHA256",
    "LEGACY_TOOL_COMPATIBILITY_SCHEMA",
    "LEGACY_TOOL_PLACEHOLDER_VOCABULARY",
    "LEGACY_TOOL_PLACEHOLDER_VOCABULARY_SHA256",
    "LEGACY_TOOL_RESULT_MAX_CHARS",
    "LEGACY_TOOL_RESULT_MAX_DEPTH",
    "LEGACY_TOOL_RESULT_MAX_NODES",
    "NORMALIZED_FIELDS",
    "PROJECTION_SCHEMA",
    "RECOVERY_CHILD_KEY",
    "RECOVERY_CUSTOM_KEYS",
    "RECOVERY_SCHEMA",
    "RECOVERY_SCHEMA_KEY",
    "SELECTED_CUSTOM_KEYS",
    "STABLE_CUSTOM_KEYS",
    "LegacyToolCompatibilityMatch",
    "LegacyToolCompatibilityProjection",
    "LegacyToolValueLeafEvidence",
    "LocalSpanCapture",
    "NormalizedSpanProjection",
    "ProjectionValidationError",
    "RootAttribution",
    "SelectedCustomAttributes",
    "SourcePin",
    "canonicalize_agent_span",
    "compare_legacy_tool_compatibility",
    "custom_attr_columns",
    "determine_root_attribution",
    "extract_local_row",
    "normalization_source_paths",
    "otlp_roundtrip_attributes",
    "otlp_roundtrip_value",
    "parse_selected_custom",
    "project_local_capture",
    "project_remote_span",
    "validate_pin_manifest",
]


class ProjectionValidationError(VerificationError):
    """A normalized projection could not be proven without ambiguity."""


@dataclass(frozen=True, repr=False)
class LegacyToolValueLeafEvidence:
    """Content-safe evidence for one typed JSON value leaf."""

    path_sha256: str
    value_type: str
    exact_sha256: str
    secondary_sha256: str
    marker_kinds: tuple[str, ...] = dataclass_field(repr=False)

    def __post_init__(self) -> None:
        if (
            any(
                not isinstance(value, str) or not _HEX_64.fullmatch(value)
                for value in (
                    self.path_sha256,
                    self.exact_sha256,
                    self.secondary_sha256,
                )
            )
            or self.value_type not in {"null", "bool", "int", "float", "string"}
            or any(
                marker not in {"generic:bracket", "generic:bare"}
                and (
                    not marker.startswith("typed:")
                    or marker.removeprefix("typed:") not in LEGACY_TOOL_PLACEHOLDER_VOCABULARY
                )
                for marker in self.marker_kinds
            )
        ):
            raise ProjectionValidationError("legacy tool value-leaf evidence was invalid")


@dataclass(frozen=True, repr=False)
class LegacyToolCompatibilityProjection:
    """Strict JSON evidence eligible for the narrow legacy-tool exception."""

    policy_sha256: str
    vocabulary_sha256: str
    context_sha256: str
    topology_sha256: str
    exact_json_sha256: str
    secondary_sha256: str
    value_leaf_evidence_sha256: str
    value_leaves: tuple[LegacyToolValueLeafEvidence, ...] = dataclass_field(repr=False)

    def __post_init__(self) -> None:
        if (
            self.policy_sha256 != LEGACY_TOOL_COMPATIBILITY_POLICY_SHA256
            or self.vocabulary_sha256 != LEGACY_TOOL_PLACEHOLDER_VOCABULARY_SHA256
            or any(
                not isinstance(value, str) or not _HEX_64.fullmatch(value)
                for value in (
                    self.context_sha256,
                    self.topology_sha256,
                    self.exact_json_sha256,
                    self.secondary_sha256,
                    self.value_leaf_evidence_sha256,
                )
            )
            or not isinstance(self.value_leaves, tuple)
            or len(self.value_leaves) > LEGACY_TOOL_RESULT_MAX_NODES
        ):
            raise ProjectionValidationError("legacy tool compatibility projection was invalid")


@dataclass(frozen=True, repr=False)
class LegacyToolCompatibilityMatch:
    """Safe proof of one reviewed non-exact placeholder-relation edge."""

    policy_sha256: str
    vocabulary_sha256: str
    context_sha256: str
    topology_sha256: str
    expected_exact_json_sha256: str
    remote_exact_json_sha256: str
    expected_secondary_sha256: str
    remote_secondary_sha256: str
    expected_value_leaf_evidence_sha256: str
    remote_value_leaf_evidence_sha256: str
    substitution_relation: Literal["generic_typed", "typed_typed"]
    substitution_count: int
    changed_leaf_count: int
    value_leaf_count: int
    evidence_sha256: str

    def __post_init__(self) -> None:
        digests = (
            self.policy_sha256,
            self.vocabulary_sha256,
            self.context_sha256,
            self.topology_sha256,
            self.expected_exact_json_sha256,
            self.remote_exact_json_sha256,
            self.expected_secondary_sha256,
            self.remote_secondary_sha256,
            self.expected_value_leaf_evidence_sha256,
            self.remote_value_leaf_evidence_sha256,
            self.evidence_sha256,
        )
        evidence = {
            "schema": LEGACY_TOOL_COMPATIBILITY_SCHEMA,
            "policy_sha256": self.policy_sha256,
            "vocabulary_sha256": self.vocabulary_sha256,
            "context_sha256": self.context_sha256,
            "topology_sha256": self.topology_sha256,
            "expected_exact_json_sha256": self.expected_exact_json_sha256,
            "remote_exact_json_sha256": self.remote_exact_json_sha256,
            "expected_secondary_sha256": self.expected_secondary_sha256,
            "remote_secondary_sha256": self.remote_secondary_sha256,
            "expected_value_leaf_evidence_sha256": (self.expected_value_leaf_evidence_sha256),
            "remote_value_leaf_evidence_sha256": (self.remote_value_leaf_evidence_sha256),
            "substitution_relation": self.substitution_relation,
            "substitution_count": self.substitution_count,
            "changed_leaf_count": self.changed_leaf_count,
            "value_leaf_count": self.value_leaf_count,
        }
        if (
            self.policy_sha256 != LEGACY_TOOL_COMPATIBILITY_POLICY_SHA256
            or self.vocabulary_sha256 != LEGACY_TOOL_PLACEHOLDER_VOCABULARY_SHA256
            or any(not isinstance(value, str) or not _HEX_64.fullmatch(value) for value in digests)
            or self.expected_exact_json_sha256 == self.remote_exact_json_sha256
            or self.expected_secondary_sha256 != self.remote_secondary_sha256
            or self.substitution_relation not in {"generic_typed", "typed_typed"}
            or isinstance(self.substitution_count, bool)
            or not isinstance(self.substitution_count, int)
            or self.substitution_count < 1
            or isinstance(self.changed_leaf_count, bool)
            or not isinstance(self.changed_leaf_count, int)
            or self.changed_leaf_count != 1
            or isinstance(self.value_leaf_count, bool)
            or not isinstance(self.value_leaf_count, int)
            or self.value_leaf_count < self.changed_leaf_count
            or self.evidence_sha256 != sha256_json(evidence)
        ):
            raise ProjectionValidationError("legacy tool compatibility match was invalid")


def _freeze(value: Any) -> Any:
    if isinstance(value, Mapping):
        return MappingProxyType(
            {
                str(key): _freeze(item)
                for key, item in sorted(value.items(), key=lambda item: str(item[0]))
            }
        )
    if isinstance(value, (list, tuple)):
        return tuple(_freeze(item) for item in value)
    if isinstance(value, set):
        return frozenset(_freeze(item) for item in value)
    return value


@dataclass(frozen=True, repr=False)
class LocalSpanCapture:
    """An immutable, in-memory source span used only for local normalization."""

    label: str
    span_name: str
    start_time_ns: int
    end_time_ns: int
    attributes: Mapping[str, Any]

    def __post_init__(self) -> None:
        if (
            not isinstance(self.label, str)
            or not self.label
            or not isinstance(self.span_name, str)
            or not self.span_name
            or isinstance(self.start_time_ns, bool)
            or not isinstance(self.start_time_ns, int)
            or isinstance(self.end_time_ns, bool)
            or not isinstance(self.end_time_ns, int)
            or self.start_time_ns < 0
            or self.end_time_ns < self.start_time_ns
            or not isinstance(self.attributes, Mapping)
            or any(not isinstance(key, str) for key in self.attributes)
        ):
            raise ProjectionValidationError("local span capture had an invalid shape")
        object.__setattr__(self, "attributes", _freeze(self.attributes))


@dataclass(frozen=True, repr=False)
class RootAttribution:
    """The atomic agent identity and independent conversation trace fallback."""

    agent_name: str
    agent_version: str
    agent_id: str
    conversation_id: str

    def __post_init__(self) -> None:
        if (
            not self.agent_name
            or any(
                not isinstance(value, str)
                for value in (
                    self.agent_name,
                    self.agent_version,
                    self.agent_id,
                    self.conversation_id,
                )
            )
            or not self.conversation_id
        ):
            raise ProjectionValidationError("root attribution had an invalid shape")

    @property
    def agent_identity(self) -> tuple[str, str, str]:
        return (self.agent_name, self.agent_version, self.agent_id)


@dataclass(frozen=True, repr=False)
class SelectedCustomAttributes:
    """Content-safe stable correlators and recovery representation markers."""

    values: tuple[tuple[str, str], ...]
    representation: Representation
    recovery_key: str | None

    def __post_init__(self) -> None:
        keys = [key for key, _value in self.values]
        if (
            len(keys) != len(set(keys))
            or any(
                key not in SELECTED_CUSTOM_KEYS or not isinstance(value, str)
                for key, value in self.values
            )
            or any(key not in keys for key in STABLE_CUSTOM_KEYS)
            or self.representation not in {"legacy", "recovery"}
        ):
            raise ProjectionValidationError("selected custom attributes were invalid")
        if self.representation == "legacy":
            if self.recovery_key is not None or any(key in keys for key in RECOVERY_CUSTOM_KEYS):
                raise ProjectionValidationError("legacy recovery markers were invalid")
        elif (
            self.recovery_key is None
            or not _HEX_64.fullmatch(self.recovery_key)
            or dict(self.values).get(RECOVERY_CHILD_KEY) != self.recovery_key
            or dict(self.values).get(RECOVERY_SCHEMA_KEY) != RECOVERY_SCHEMA
        ):
            raise ProjectionValidationError("recovery child markers were invalid")

    def as_dict(self) -> dict[str, str]:
        result = dict(self.values)
        result["representation"] = self.representation
        return result


@dataclass(frozen=True)
class NormalizedSpanProjection:
    """A content hash plus the safe metadata needed to classify a child span."""

    digest: str
    representation: Representation
    recovery_key: str | None
    operation_name: str
    legacy_tool_compatibility: LegacyToolCompatibilityProjection | None = dataclass_field(
        default=None,
        repr=False,
    )

    def __post_init__(self) -> None:
        if (
            not isinstance(self.digest, str)
            or not _HEX_64.fullmatch(self.digest)
            or self.representation not in {"legacy", "recovery"}
            or not isinstance(self.operation_name, str)
            or not self.operation_name
        ):
            raise ProjectionValidationError("normalized projection had an invalid shape")
        if self.representation == "legacy" and self.recovery_key is not None:
            raise ProjectionValidationError("legacy projection carried a recovery key")
        if self.representation == "recovery" and (
            not isinstance(self.recovery_key, str) or not _HEX_64.fullmatch(self.recovery_key)
        ):
            raise ProjectionValidationError("recovery projection lacked a valid key")
        if self.legacy_tool_compatibility is not None and (
            self.representation != "legacy" or self.operation_name != "execute_tool"
        ):
            raise ProjectionValidationError(
                "legacy tool compatibility evidence appeared on an ineligible span"
            )


@dataclass(frozen=True)
class SourcePin:
    """One reviewed source file and its expected SHA-256."""

    path: Path
    sha256: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "path", Path(self.path).expanduser().resolve())
        if not isinstance(self.sha256, str) or not _HEX_64.fullmatch(self.sha256):
            raise ProjectionValidationError("normalized projection source pin was invalid")


def custom_attr_columns() -> list[dict[str, str]]:
    """Return fresh query column descriptors for every selected attribute map."""

    return [
        {"source": source, "key": key}
        for source in CUSTOM_MAP_FIELDS
        for key in SELECTED_CUSTOM_KEYS
    ]


def otlp_roundtrip_value(value: Any) -> Any:
    """Model OTLP's conversion of in-process OTel tuple arrays into lists."""

    if isinstance(value, Mapping):
        return {str(key): otlp_roundtrip_value(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [otlp_roundtrip_value(item) for item in value]
    return value


def otlp_roundtrip_attributes(attributes: Mapping[str, Any]) -> dict[str, Any]:
    """Reproduce Weave's OTLP attribute decode and dotted-key expansion.

    The hosted path resolves protobuf values, expands dotted attribute keys,
    and JSON-decodes strings beginning with ``{`` or ``[``.  In particular,
    tool arguments/results are then serialized by the Agents extractor with
    standard JSON spacing.  Constructing a server ``Span`` directly from the
    in-process flat mapping would silently skip that transform.
    """

    try:
        expanded = expand_attributes(
            (key, otlp_roundtrip_value(value)) for key, value in attributes.items()
        )
    except Exception as error:
        raise ProjectionValidationError("local OTLP attribute expansion failed") from error
    if not isinstance(expanded, dict):
        raise ProjectionValidationError("local OTLP attribute expansion returned an invalid shape")
    return expanded


def _reject_storage_dependent_inline_blobs(value: Any) -> None:
    """Fail closed when hosted ingest could replace content with an object ref.

    Content refs depend on server-side storage.  They cannot be reconstructed
    from a local span without guessing.  The importer transport prefixes its
    own base64 chunks so they never enter this branch.
    """

    if isinstance(value, Mapping):
        for item in value.values():
            _reject_storage_dependent_inline_blobs(item)
        return
    if isinstance(value, (list, tuple)):
        for item in value:
            _reject_storage_dependent_inline_blobs(item)
        return
    if (
        isinstance(value, str)
        and len(value) > AUTO_CONVERSION_MIN_SIZE
        and (is_data_uri(value) or is_base64(value))
    ):
        raise ProjectionValidationError("local span contains storage-dependent inline content")


def _extract_genai_span() -> Callable[[Span, str], Any]:
    try:
        from weave.trace_server.opentelemetry.genai_extraction import (
            extract_genai_span,
        )
    except Exception as error:
        raise ProjectionValidationError("normalized projection runtime was unavailable") from error
    return extract_genai_span


def extract_local_row(
    capture: LocalSpanCapture,
    *,
    project: str,
) -> dict[str, Any]:
    """Run Weave's pinned GenAI extractor on one reconstructed local span."""

    if not isinstance(project, str) or not project:
        raise ProjectionValidationError("normalized projection project was invalid")
    selected_attributes = {
        key: value
        for key, value in capture.attributes.items()
        if key in KNOWN_KEYS or key in SELECTED_CUSTOM_KEYS
    }
    span = Span(
        resource=None,
        name=capture.span_name,
        trace_id="0" * 32,
        span_id="0" * 16,
        parent_id="0" * 16,
        start_time_unix_nano=capture.start_time_ns,
        end_time_unix_nano=capture.end_time_ns,
        attributes=otlp_roundtrip_attributes(selected_attributes),
        kind=SpanKind.INTERNAL,
    )
    try:
        # Hosted Agents ingest applies key-based credential redaction after
        # protobuf/JSON expansion and before normalized field extraction.
        redact_credentials_from_span(span)
        _reject_storage_dependent_inline_blobs(span.attributes)
        extracted = _extract_genai_span()(span, project)
        row = extracted.model_dump(mode="json")
    except ProjectionValidationError:
        raise
    except Exception as error:
        raise ProjectionValidationError("local span normalization failed") from error
    if not isinstance(row, dict):
        raise ProjectionValidationError("local span normalization returned an invalid row")
    return row


def determine_root_attribution(
    captures: Sequence[LocalSpanCapture],
    *,
    expected_conversation_id: str,
    project: str,
    root_label: str = "legacy:root",
) -> RootAttribution:
    """Reproduce deterministic Weave trace attribution for local projections."""

    if (
        not captures
        or not isinstance(expected_conversation_id, str)
        or not expected_conversation_id
        or not isinstance(root_label, str)
        or not root_label
        or len({capture.label for capture in captures}) != len(captures)
    ):
        raise ProjectionValidationError("local attribution inputs were ambiguous")

    candidates: list[tuple[str, int, tuple[str, str, str]]] = []
    conversation_ids: set[str] = set()
    for capture in captures:
        row = extract_local_row(capture, project=project)
        agent_name = row.get("agent_name")
        if isinstance(agent_name, str) and agent_name:
            identity = (agent_name, row.get("agent_version"), row.get("agent_id"))
            if any(not isinstance(value, str) for value in identity):
                raise ProjectionValidationError("local agent identity was mistyped")
            candidates.append((capture.label, capture.start_time_ns, identity))
        elif agent_name is not None and agent_name != "":
            raise ProjectionValidationError("local agent identity was mistyped")

        conversation_id = row.get("conversation_id")
        if isinstance(conversation_id, str) and conversation_id:
            conversation_ids.add(conversation_id)
        elif conversation_id is not None and conversation_id != "":
            raise ProjectionValidationError("local conversation identity was mistyped")

    roots = [item for item in candidates if item[0] == root_label]
    if len(roots) != 1:
        raise ProjectionValidationError("local root did not declare one agent identity")
    _label, root_started_at, root_identity = roots[0]
    for label, started_at, identity in candidates:
        if label == root_label:
            continue
        if started_at < root_started_at or (
            started_at == root_started_at and identity != root_identity
        ):
            raise ProjectionValidationError(
                "local root was not the deterministic trace agent fallback"
            )
    if conversation_ids != {expected_conversation_id}:
        raise ProjectionValidationError("local trace conversation attribution was ambiguous")
    return RootAttribution(*root_identity, expected_conversation_id)


def canonicalize_agent_span(
    row: Mapping[str, Any],
    *,
    attribution: RootAttribution,
    remote: bool,
) -> dict[str, Any]:
    """Validate and canonicalize exactly one Weave ``AgentSpanSchema`` row.

    Hosted rows must contain the exact current schema.  Local extractor rows
    may omit server-owned fields and receive only the read-time attribution
    that the hosted query would apply.  Hosted rows are never re-attributed.
    """

    if not isinstance(row, Mapping):
        raise ProjectionValidationError("normalized span row was not a mapping")
    if remote and frozenset(row) != AGENT_SPAN_SCHEMA_FIELDS:
        raise ProjectionValidationError("normalized response schema changed")
    candidate = {key: value for key, value in row.items() if key in AGENT_SPAN_SCHEMA_FIELDS}
    if not remote:
        if not candidate.get("agent_name"):
            (
                candidate["agent_name"],
                candidate["agent_version"],
                candidate["agent_id"],
            ) = attribution.agent_identity
        if not candidate.get("conversation_id"):
            candidate["conversation_id"] = attribution.conversation_id
    for field in CUSTOM_MAP_FIELDS:
        values = candidate.get(field)
        if not isinstance(values, Mapping):
            values = {}
        candidate[field] = {
            key: value for key, value in values.items() if key in SELECTED_CUSTOM_KEYS
        }
    try:
        canonical = AgentSpanSchema.model_validate(candidate).model_dump(mode="json")
    except Exception as error:
        raise ProjectionValidationError("normalized span row failed schema validation") from error
    if frozenset(canonical) != AGENT_SPAN_SCHEMA_FIELDS:
        raise ProjectionValidationError("canonical normalized schema changed")
    return canonical


def parse_selected_custom(row: Mapping[str, Any]) -> SelectedCustomAttributes:
    """Parse exact stable and recovery markers across all typed custom maps."""

    selected: list[tuple[str, str]] = []
    for key in SELECTED_CUSTOM_KEYS:
        matches: list[Any] = []
        for field in CUSTOM_MAP_FIELDS:
            values = row.get(field)
            if not isinstance(values, Mapping):
                raise ProjectionValidationError("custom attribute map was mistyped")
            if key in values:
                matches.append(values[key])
        if len(matches) > 1:
            raise ProjectionValidationError("selected custom attribute appeared in multiple maps")
        if key in STABLE_CUSTOM_KEYS:
            if len(matches) != 1 or not isinstance(matches[0], str):
                raise ProjectionValidationError("stable child correlator was absent or mistyped")
            selected.append((key, matches[0]))
        elif matches:
            if not isinstance(matches[0], str):
                raise ProjectionValidationError("recovery child marker was mistyped")
            selected.append((key, matches[0]))

    selected_dict = dict(selected)
    recovery_key = selected_dict.get(RECOVERY_CHILD_KEY)
    recovery_schema = selected_dict.get(RECOVERY_SCHEMA_KEY)
    if recovery_key is None and recovery_schema is None:
        representation: Representation = "legacy"
        parsed_key = None
    elif (
        isinstance(recovery_key, str)
        and _HEX_64.fullmatch(recovery_key)
        and recovery_schema == RECOVERY_SCHEMA
    ):
        representation = "recovery"
        parsed_key = recovery_key
    else:
        raise ProjectionValidationError("recovery child markers were partial or unknown")
    return SelectedCustomAttributes(tuple(selected), representation, parsed_key)


def _normal(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {
            str(key): _normal(item)
            for key, item in sorted(value.items(), key=lambda item: str(item[0]))
        }
    if isinstance(value, (list, tuple)):
        return [_normal(item) for item in value]
    if isinstance(value, datetime):
        if value.tzinfo is None:
            value = value.replace(tzinfo=UTC)
        return value.astimezone(UTC).isoformat().replace("+00:00", "Z")
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    return str(value)


def _strict_json_result(raw: str) -> dict[str, Any] | list[Any]:
    """Decode one bounded JSON result without permissive JSON extensions."""

    if not isinstance(raw, str) or len(raw) > LEGACY_TOOL_RESULT_MAX_CHARS:
        raise ProjectionValidationError("legacy tool result JSON exceeded its safe boundary")

    def reject_constant(_value: str) -> Any:
        raise ValueError

    def reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError
            result[key] = value
        return result

    try:
        decoded = json.loads(
            raw,
            object_pairs_hook=reject_duplicate_keys,
            parse_constant=reject_constant,
        )
    except (OverflowError, RecursionError, TypeError, ValueError, json.JSONDecodeError) as error:
        raise ProjectionValidationError("legacy tool result was not strict JSON") from error
    if not isinstance(decoded, (dict, list)):
        raise ProjectionValidationError("legacy tool result JSON was not an object or array")

    nodes = 0

    def validate(value: Any, depth: int) -> None:
        nonlocal nodes
        nodes += 1
        if nodes > LEGACY_TOOL_RESULT_MAX_NODES or depth > LEGACY_TOOL_RESULT_MAX_DEPTH:
            raise ProjectionValidationError("legacy tool result JSON exceeded structural bounds")
        if isinstance(value, dict):
            for key, item in value.items():
                if any(0xD800 <= ord(character) <= 0xDFFF for character in key):
                    raise ProjectionValidationError("legacy tool result JSON contained a surrogate")
                validate(item, depth + 1)
            return
        if isinstance(value, list):
            for item in value:
                validate(item, depth + 1)
            return
        if isinstance(value, str):
            if any(0xD800 <= ord(character) <= 0xDFFF for character in value):
                raise ProjectionValidationError("legacy tool result JSON contained a surrogate")
            return
        if isinstance(value, float) and not math.isfinite(value):
            raise ProjectionValidationError("legacy tool result JSON contained a non-finite number")
        if value is not None and not isinstance(value, (bool, int, float)):
            raise ProjectionValidationError("legacy tool result JSON contained an unknown value")

    validate(decoded, 0)
    return decoded


def _value_type(value: Any) -> str:
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "bool"
    if isinstance(value, int):
        return "int"
    if isinstance(value, float):
        return "float"
    if isinstance(value, str):
        return "string"
    raise ProjectionValidationError("legacy tool result JSON leaf type was invalid")


def _marker_evidence(value: str) -> tuple[tuple[str, ...], tuple[str, ...]]:
    markers: list[str] = []
    segments: list[str] = []
    position = 0
    for match in _PLACEHOLDER.finditer(value):
        segments.append(value[position : match.start()])
        token = match.group(0)
        if match.lastgroup == "typed":
            markers.append(f"typed:{token[1:-1]}")
        elif token == "[REDACTED]":
            markers.append("generic:bracket")
        else:
            markers.append("generic:bare")
        position = match.end()
    segments.append(value[position:])
    return tuple(markers), tuple(segments)


def _legacy_tool_result_evidence(
    raw: str,
) -> tuple[
    str,
    str,
    str,
    tuple[LegacyToolValueLeafEvidence, ...],
    str,
]:
    decoded = _strict_json_result(raw)
    leaves: list[LegacyToolValueLeafEvidence] = []

    def visit(value: Any, path: tuple[tuple[str, Any], ...], depth: int) -> Any:
        if depth > LEGACY_TOOL_RESULT_MAX_DEPTH:
            raise ProjectionValidationError("legacy tool result JSON exceeded structural bounds")
        if isinstance(value, dict):
            return {
                "object": [
                    [key, visit(value[key], (*path, ("key", key)), depth + 1)]
                    for key in sorted(value)
                ]
            }
        if isinstance(value, list):
            return {
                "array": [
                    visit(item, (*path, ("index", index)), depth + 1)
                    for index, item in enumerate(value)
                ]
            }
        value_type = _value_type(value)
        marker_kinds: tuple[str, ...] = ()
        secondary_value: Any = {"type": value_type, "value": value}
        if isinstance(value, str):
            marker_kinds, segments = _marker_evidence(value)
            secondary_value = {
                "type": value_type,
                "non_placeholder_segments": list(segments),
                "placeholder_count": len(marker_kinds),
            }
        leaf = LegacyToolValueLeafEvidence(
            path_sha256=sha256_json(
                {
                    "schema": LEGACY_TOOL_COMPATIBILITY_SCHEMA,
                    "typed_path": [[kind, item] for kind, item in path],
                }
            ),
            value_type=value_type,
            exact_sha256=sha256_json(
                {
                    "schema": LEGACY_TOOL_COMPATIBILITY_SCHEMA,
                    "type": value_type,
                    "value": value,
                }
            ),
            secondary_sha256=sha256_json(
                {
                    "schema": LEGACY_TOOL_COMPATIBILITY_SCHEMA,
                    "secondary": secondary_value,
                }
            ),
            marker_kinds=marker_kinds,
        )
        leaves.append(leaf)
        return {"value_type": value_type}

    topology = visit(decoded, (), 0)
    topology_sha256 = sha256_json(
        {"schema": LEGACY_TOOL_COMPATIBILITY_SCHEMA, "topology": topology}
    )
    exact_json_sha256 = sha256_json(
        {"schema": LEGACY_TOOL_COMPATIBILITY_SCHEMA, "typed_json": decoded}
    )
    secondary_sha256 = sha256_json(
        {
            "schema": LEGACY_TOOL_COMPATIBILITY_SCHEMA,
            "topology_sha256": topology_sha256,
            "value_leaves": [
                {
                    "path_sha256": leaf.path_sha256,
                    "value_type": leaf.value_type,
                    "secondary_sha256": leaf.secondary_sha256,
                    "placeholder_count": len(leaf.marker_kinds),
                }
                for leaf in leaves
            ],
        }
    )
    value_leaf_evidence_sha256 = sha256_json(
        {
            "schema": LEGACY_TOOL_COMPATIBILITY_SCHEMA,
            "value_leaves": [
                {
                    "path_sha256": leaf.path_sha256,
                    "value_type": leaf.value_type,
                    "exact_sha256": leaf.exact_sha256,
                    "secondary_sha256": leaf.secondary_sha256,
                    "marker_kinds": list(leaf.marker_kinds),
                }
                for leaf in leaves
            ],
        }
    )
    return (
        topology_sha256,
        exact_json_sha256,
        secondary_sha256,
        tuple(leaves),
        value_leaf_evidence_sha256,
    )


def _legacy_tool_compatibility_projection(
    *,
    row: Mapping[str, Any],
    selected: SelectedCustomAttributes,
    normalized: Mapping[str, Any],
    span_name: str,
    started_at_ms: int,
    ended_at_ms: int,
) -> LegacyToolCompatibilityProjection | None:
    if selected.representation != "legacy" or row.get("operation_name") != "execute_tool":
        return None
    raw_result = row.get("tool_call_result")
    if not isinstance(raw_result, str):
        return None
    try:
        (
            topology_sha256,
            exact_json_sha256,
            secondary_sha256,
            value_leaves,
            value_leaf_evidence_sha256,
        ) = _legacy_tool_result_evidence(raw_result)
    except ProjectionValidationError:
        return None
    exact_context = {key: value for key, value in normalized.items() if key != "tool_call_result"}
    context_sha256 = sha256_json(
        {
            "schema": PROJECTION_SCHEMA,
            "compatibility_schema": LEGACY_TOOL_COMPATIBILITY_SCHEMA,
            "span_name": span_name,
            "started_at_ms": started_at_ms,
            "ended_at_ms": ended_at_ms,
            "normalized_except_tool_call_result": exact_context,
            "selected_custom": selected.as_dict(),
        }
    )
    return LegacyToolCompatibilityProjection(
        policy_sha256=LEGACY_TOOL_COMPATIBILITY_POLICY_SHA256,
        vocabulary_sha256=LEGACY_TOOL_PLACEHOLDER_VOCABULARY_SHA256,
        context_sha256=context_sha256,
        topology_sha256=topology_sha256,
        exact_json_sha256=exact_json_sha256,
        secondary_sha256=secondary_sha256,
        value_leaf_evidence_sha256=value_leaf_evidence_sha256,
        value_leaves=value_leaves,
    )


def _is_generic_marker(marker: str) -> bool:
    return marker in {"generic:bracket", "generic:bare"}


def _is_typed_marker(marker: str) -> bool:
    return marker.startswith("typed:") and marker.removeprefix("typed:") in set(
        LEGACY_TOOL_PLACEHOLDER_VOCABULARY
    )


def compare_legacy_tool_compatibility(
    expected: NormalizedSpanProjection,
    remote: NormalizedSpanProjection,
) -> LegacyToolCompatibilityMatch | None:
    """Return proof only for one reviewed legacy execute-tool marker relation."""

    if (
        expected.representation != "legacy"
        or remote.representation != "legacy"
        or expected.operation_name != "execute_tool"
        or remote.operation_name != "execute_tool"
        or expected.digest == remote.digest
        or expected.legacy_tool_compatibility is None
        or remote.legacy_tool_compatibility is None
    ):
        return None
    left = expected.legacy_tool_compatibility
    right = remote.legacy_tool_compatibility
    if (
        left.policy_sha256 != right.policy_sha256
        or left.vocabulary_sha256 != right.vocabulary_sha256
        or left.context_sha256 != right.context_sha256
        or left.topology_sha256 != right.topology_sha256
        or left.secondary_sha256 != right.secondary_sha256
        or left.exact_json_sha256 == right.exact_json_sha256
        or len(left.value_leaves) != len(right.value_leaves)
    ):
        return None
    left_paths = tuple(leaf.path_sha256 for leaf in left.value_leaves)
    right_paths = tuple(leaf.path_sha256 for leaf in right.value_leaves)
    if len(set(left_paths)) != len(left_paths) or len(set(right_paths)) != len(
        right_paths
    ):
        return None

    substitutions = 0
    changed_leaves = 0
    substitution_relations: set[str] = set()
    for expected_leaf, remote_leaf in zip(left.value_leaves, right.value_leaves, strict=True):
        if (
            expected_leaf.path_sha256 != remote_leaf.path_sha256
            or expected_leaf.value_type != remote_leaf.value_type
        ):
            return None
        if expected_leaf.exact_sha256 == remote_leaf.exact_sha256:
            if (
                expected_leaf.secondary_sha256 != remote_leaf.secondary_sha256
                or expected_leaf.marker_kinds != remote_leaf.marker_kinds
            ):
                return None
            continue
        if (
            expected_leaf.value_type != "string"
            or expected_leaf.secondary_sha256 != remote_leaf.secondary_sha256
            or not expected_leaf.marker_kinds
            or len(expected_leaf.marker_kinds) != len(remote_leaf.marker_kinds)
        ):
            return None
        leaf_substitutions = 0
        for expected_marker, remote_marker in zip(
            expected_leaf.marker_kinds,
            remote_leaf.marker_kinds,
            strict=True,
        ):
            if expected_marker == remote_marker:
                continue
            expected_generic = _is_generic_marker(expected_marker)
            remote_generic = _is_generic_marker(remote_marker)
            expected_typed = _is_typed_marker(expected_marker)
            remote_typed = _is_typed_marker(remote_marker)
            if (expected_generic and remote_typed) or (expected_typed and remote_generic):
                substitution_relation = "generic_typed"
            elif expected_typed and remote_typed:
                # Equal labels were handled above, so this is a change between
                # two distinct labels in the exact reviewed vocabulary.
                substitution_relation = "typed_typed"
            else:
                # This rejects generic↔generic changes and unknown markers.
                return None
            substitution_relations.add(substitution_relation)
            if len(substitution_relations) > 1:
                return None
            leaf_substitutions += 1
        if leaf_substitutions < 1:
            return None
        substitutions += leaf_substitutions
        changed_leaves += 1
    if substitutions < 1 or changed_leaves != 1 or len(substitution_relations) != 1:
        return None
    substitution_relation = next(iter(substitution_relations))

    match_values = {
        "policy_sha256": left.policy_sha256,
        "vocabulary_sha256": left.vocabulary_sha256,
        "context_sha256": left.context_sha256,
        "topology_sha256": left.topology_sha256,
        "expected_exact_json_sha256": left.exact_json_sha256,
        "remote_exact_json_sha256": right.exact_json_sha256,
        "expected_secondary_sha256": left.secondary_sha256,
        "remote_secondary_sha256": right.secondary_sha256,
        "expected_value_leaf_evidence_sha256": left.value_leaf_evidence_sha256,
        "remote_value_leaf_evidence_sha256": right.value_leaf_evidence_sha256,
        "substitution_relation": substitution_relation,
        "substitution_count": substitutions,
        "changed_leaf_count": changed_leaves,
        "value_leaf_count": len(left.value_leaves),
    }
    return LegacyToolCompatibilityMatch(
        **match_values,
        evidence_sha256=sha256_json({"schema": LEGACY_TOOL_COMPATIBILITY_SCHEMA, **match_values}),
    )


def _projection_from_canonical(
    row: dict[str, Any],
    *,
    span_name: str,
    started_at_ms: int,
    ended_at_ms: int,
) -> NormalizedSpanProjection:
    selected = parse_selected_custom(row)
    operation_name = row.get("operation_name")
    if not isinstance(operation_name, str) or not operation_name:
        raise ProjectionValidationError("normalized span operation was invalid")
    normalized = {field: _normal(row[field]) for field in NORMALIZED_FIELDS}
    digest = sha256_json(
        {
            "schema": PROJECTION_SCHEMA,
            "span_name": span_name,
            "started_at_ms": started_at_ms,
            "ended_at_ms": ended_at_ms,
            "normalized": normalized,
            "selected_custom": selected.as_dict(),
        }
    )
    compatibility = _legacy_tool_compatibility_projection(
        row=row,
        selected=selected,
        normalized=normalized,
        span_name=span_name,
        started_at_ms=started_at_ms,
        ended_at_ms=ended_at_ms,
    )
    return NormalizedSpanProjection(
        digest=digest,
        representation=selected.representation,
        recovery_key=selected.recovery_key,
        operation_name=operation_name,
        legacy_tool_compatibility=compatibility,
    )


def project_local_capture(
    capture: LocalSpanCapture,
    *,
    attribution: RootAttribution,
    project: str,
) -> NormalizedSpanProjection:
    """Generate a normalized projection for one reconstructed local span."""

    extracted = extract_local_row(capture, project=project)
    canonical = canonicalize_agent_span(
        extracted,
        attribution=attribution,
        remote=False,
    )
    return _projection_from_canonical(
        canonical,
        span_name=capture.span_name,
        started_at_ms=capture.start_time_ns // 1_000_000,
        ended_at_ms=capture.end_time_ns // 1_000_000,
    )


def _datetime_to_unix_ms(value: datetime) -> int:
    delta = value.astimezone(UTC) - datetime(1970, 1, 1, tzinfo=UTC)
    return delta.days * 86_400_000 + delta.seconds * 1_000 + delta.microseconds // 1_000


def _weave_datetime_roundtrip_ms(value_ns: int) -> int:
    """Reproduce Weave's nanosecond-to-datetime normalization at millisecond precision."""

    value = datetime.fromtimestamp(value_ns / 1_000_000_000, UTC)
    return _datetime_to_unix_ms(value)


def project_remote_span(
    row: Mapping[str, Any],
    *,
    span_name: str,
    start_time_ns: int,
    end_time_ns: int,
    attribution: RootAttribution,
) -> NormalizedSpanProjection:
    """Generate a digest from an exact hosted row and independently parsed core.

    The supplied name/timestamps are expected to come from ``raw_span_dump``.
    Matching them to the normalized row prevents either representation from
    silently identifying a different physical span.
    """

    if (
        not isinstance(span_name, str)
        or not span_name
        or isinstance(start_time_ns, bool)
        or not isinstance(start_time_ns, int)
        or isinstance(end_time_ns, bool)
        or not isinstance(end_time_ns, int)
        or start_time_ns < 0
        or end_time_ns < start_time_ns
    ):
        raise ProjectionValidationError("raw span core fields were invalid")
    canonical = canonicalize_agent_span(row, attribution=attribution, remote=True)
    started_at = parse_datetime(canonical.get("started_at"))
    ended_at = parse_datetime(canonical.get("ended_at"))
    if started_at is None or ended_at is None:
        raise ProjectionValidationError("normalized span timestamps were invalid")
    started_at_ms = _datetime_to_unix_ms(started_at)
    ended_at_ms = _datetime_to_unix_ms(ended_at)
    try:
        raw_started_at_ms = _weave_datetime_roundtrip_ms(start_time_ns)
        raw_ended_at_ms = _weave_datetime_roundtrip_ms(end_time_ns)
    except (OSError, OverflowError, ValueError) as error:
        raise ProjectionValidationError("raw span core fields were invalid") from error
    if (
        canonical.get("span_name") != span_name
        or started_at_ms != raw_started_at_ms
        or ended_at_ms != raw_ended_at_ms
    ):
        raise ProjectionValidationError("normalized and raw span core fields disagreed")
    return _projection_from_canonical(
        canonical,
        span_name=span_name,
        # Local captures retain the client's historical float-based `_to_ns`
        # representation. Keep the digest on that same floor while validating
        # identity against the datetime value Weave actually stores and returns.
        started_at_ms=start_time_ns // 1_000_000,
        ended_at_ms=end_time_ns // 1_000_000,
    )


def normalization_source_paths() -> tuple[Path, ...]:
    """Return every Weave source file whose behavior the projection relies on."""

    types_path = Path(inspect.getfile(AgentSpanSchema)).resolve()
    agents_dir = types_path.parent
    trace_server_dir = agents_dir.parent
    return (
        trace_server_dir / "opentelemetry" / "genai_extraction.py",
        agents_dir / "schema.py",
        types_path,
        trace_server_dir / "opentelemetry" / "python_spans.py",
        trace_server_dir / "opentelemetry" / "helpers.py",
        trace_server_dir / "credential_redaction.py",
        trace_server_dir / "base64_content_conversion.py",
        trace_server_dir / "query_builder" / "agent_query_builder.py",
        trace_server_dir / "query_builder" / "agent_trace_attribution.py",
        agents_dir / "clickhouse.py",
        agents_dir / "helpers.py",
        agents_dir / "semconv.py",
    )


def validate_pin_manifest(
    pins: Iterable[SourcePin],
    *,
    required_paths: Iterable[Path] | None = None,
    read_bytes: Callable[[Path], bytes] | None = None,
) -> None:
    """Validate a reviewed source manifest without exposing file contents."""

    pin_list = tuple(pins)
    paths = [pin.path for pin in pin_list]
    if not pin_list or len(paths) != len(set(paths)):
        raise ProjectionValidationError("normalized projection source pins were ambiguous")
    if required_paths is not None:
        required = {Path(path).expanduser().resolve() for path in required_paths}
        if set(paths) != required:
            raise ProjectionValidationError("normalized projection source pins were incomplete")
    reader = read_bytes or Path.read_bytes
    for pin in pin_list:
        try:
            contents = reader(pin.path)
        except Exception as error:
            raise ProjectionValidationError(
                "normalized projection source pin could not be read"
            ) from error
        if not isinstance(contents, bytes) or sha256(contents).hexdigest() != pin.sha256:
            raise ProjectionValidationError("normalized projection source pin changed")
