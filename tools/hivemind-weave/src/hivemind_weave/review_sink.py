"""Hosted Weave publication boundary for reviewable, chunked chat archives.

The canonical :class:`HistoricalTurnSink` remains the lossless agent importer.
This module implements a separate review surface: immutable ``Content`` objects
hold the complete redacted archive, while one compact Agents turn links to the
objects.  The phases are intentionally explicit so an orchestrator can journal
verified object refs before attempting the root turn.
"""

from __future__ import annotations

import hashlib
import importlib
import importlib.util
import inspect
import json
import os
import re
import urllib.request
from base64 import b64encode, urlsafe_b64encode
from collections.abc import Callable, Mapping, Sequence
from contextlib import suppress
from dataclasses import dataclass, field, replace
from datetime import datetime
from importlib import metadata as importlib_metadata
from pathlib import Path, PurePosixPath
from typing import Any, Protocol

from . import __version__
from .attribute_safety import (
    AttributeSafetyError,
    validate_inline_field,
    validate_upload_attributes,
)
from .errors import (
    ReviewMirrorConflictError,
    ReviewMirrorError,
    ReviewMirrorUncertainError,
    WeaveImportError,
)
from .pii import (
    configure_weave_pii,
    redact_agent_name,
    redact_model_name,
    redact_provider_name,
    redact_source_coordinate,
    redact_upload_data,
)
from .redaction import redact_data, redact_string
from .review_manifest import (
    REVIEW_INDEX_SCHEMA,
    REVIEW_MANIFEST_SCHEMA,
    REVIEW_PREVIEW_SCHEMA,
    ReviewManifestBundle,
    ReviewManifestError,
    reconstruct_review_manifest,
)
from .review_state import review_logical_key
from .source_identity import is_opaque_source_coordinate
from .utils import canonical_json, isoformat_z, parse_datetime, sha256_json
from .verify import (
    WeaveVerifier,
    disabled_weave_error_reporting,
    enforce_weave_error_reporting_disabled,
    validate_live_transport_environment,
    validate_trace_server_url,
    validate_wandb_base_url,
)
from .weave_sink import (
    _assert_locked_weave_settings,
    _assert_no_preexisting_tracer_provider,
    _assert_owned_weave_transport,
    _bounded_otel_export_batch,
    _disable_weave_version_check,
    _is_real_weave_sdk,
    _pinned_weave_environment,
)

_PROJECT = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}/[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_COORDINATE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_TRACE_ID = re.compile(r"^[0-9a-f]{32}$")
_SPAN_ID = re.compile(r"^[0-9a-f]{16}$")
# Weave's object digest is its 43-character modified base64 SHA-256. A 64-char
# lowercase SHA-256 is retained for hosted deployments that expose the content
# hash directly. Nothing broader may become a URI, root attribute, or state key.
_OBJECT_DIGEST = re.compile(r"^(?:[A-Za-z0-9]{43}|[0-9a-f]{64})$")
_CERTIFIED_HASH_RUN = re.compile(r"[0-9a-f]{16,64}", re.IGNORECASE)
_EXTENSION = re.compile(r"^[a-z0-9][a-z0-9._-]{0,15}$")
_OBJECT_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,255}$")
_ALLOWED_MIMETYPES = frozenset({"text/plain; charset=utf-8", "application/json; charset=utf-8"})
_PRIVATE_PROJECT_ACCESS = frozenset({"PRIVATE", "RESTRICTED"})
_MAX_CHUNKS = 64
_MAX_CHUNK_BYTES = 8 * 1024 * 1024
_MAX_PREVIEW_CHARACTERS = 4_096
_USER_PREVIEW_MARKER = "[REVIEW PREVIEW — USER; FULL CONTENT IN LINKED MANIFEST]\n"
_ASSISTANT_PREVIEW_MARKER = "[REVIEW PREVIEW — FINAL ASSISTANT; FULL CONTENT IN LINKED MANIFEST]\n"
_PREVIEW_TRUNCATED_MARKER = "\n[PREVIEW SHORTENED FOR ROOT; FULL CONTENT IN LINKED MANIFEST]"
_ROOT_SCHEMA = "hivemind-hosted-review-root-v1"
_ROOT_MATCH_SCHEMA = "hivemind-hosted-review-match-v1"
_HOSTED_INDEX_SCHEMA = "hivemind-hosted-review-index-v1"
_REVIEW_AGENT_DESCRIPTION = "Hosted review of a redacted W&B HiveMind archive"
_REVIEW_PROJECT = "wandb/hivemind-chats-review"
_REVIEW_WEAVE_COMMIT = "eaf0a27beffd13f90d4ec64547c53a37df4bdb94"
_REVIEW_WEAVE_URL = "https://github.com/wandb/weave.git"
_WANDB_GRAPHQL_URL = "https://api.wandb.ai/graphql"
_HOSTED_TRACE_SERVER_URL = "https://trace.wandb.ai"
_HOSTED_WANDB_BASE_URL = "https://api.wandb.ai"


def _review_conversation_session_id(value: object) -> str | None:
    if not isinstance(value, str) or not value.startswith("hivemind:"):
        return None
    session_id = value.removeprefix("hivemind:")
    return session_id if is_opaque_source_coordinate(session_id) else None


_MAX_GRAPHQL_RESPONSE_BYTES = 1024 * 1024
_PROJECT_QUERY = """
query HivemindReviewProject($entity: String!, $project: String!) {
  project(name: $project, entityName: $entity) {
    id
    name
    entityName
    access
    readOnly
  }
}
""".strip()
_OWNED_ROOT_ATTRIBUTES = frozenset(
    {
        "hivemind.session_id",
        "hivemind.turn_key",
        "hivemind.payload_sha256",
        "hivemind.source_payload_sha256",
        "hivemind.review.schema",
        "hivemind.review.index_sha256",
        "hivemind.review.index_uri",
        "hivemind.review.chunk_count",
        "hivemind.review.content_bytes",
        "hivemind.review.object_refs_verified",
        "hivemind.review.manifest_sha256",
        "hivemind.review.preview_signature",
        "hivemind.review.source_turn_key",
        "hivemind.review.noncanonical",
        "hivemind.review.logical_key",
        "hivemind.review.match_sha256",
        "hivemind.review.planning_index_sha256",
        "hivemind.review.repository",
        "hivemind.review.branch",
        "hivemind.review.parent_session_id",
        "hivemind.review.is_subagent",
    }
)


class HostedReviewError(ReviewMirrorError):
    """The hosted review publication could not be proved safe and complete."""


class ReviewObjectPublicationError(HostedReviewError):
    """An immutable object phase failed and may be safely repeated."""

    retry_safe = True


class ReviewRootUncertainError(HostedReviewError, ReviewMirrorUncertainError):
    """The root may have been accepted and must never be blindly retried."""

    retry_safe = False


class ReviewRootConflictError(HostedReviewError, ReviewMirrorConflictError):
    """More than one root or incompatible root evidence was observed."""

    retry_safe = False


@dataclass(frozen=True)
class ProjectAccess:
    """Mutation-free destination preflight evidence.

    The hosted write remains the authoritative authorization check; this
    evidence only prevents an obviously absent, public, or read-only target
    from reaching that write boundary.
    """

    exists: bool
    visibility_scope: str
    can_read: bool
    can_write: bool
    canonical_entity: str
    canonical_project: str = ""


@dataclass(frozen=True)
class ReviewRuntime:
    """Credential-free handles for the exact locally installed review SDK."""

    weave: Any
    conversation_types: Any


class ProjectGuard(Protocol):
    """Injected hosted authorization/capabilities check."""

    def check(self, *, entity: str, project: str) -> ProjectAccess | Mapping[str, Any]: ...


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(
        self,
        req: Any,
        fp: Any,
        code: int,
        msg: str,
        headers: Any,
        newurl: str,
    ) -> None:
        return None


def _wandb_api_key() -> str:
    validate_live_transport_environment()
    api_key = os.environ.get("WANDB_API_KEY", "")
    if not api_key or len(api_key) > 4_096 or "\r" in api_key or "\n" in api_key:
        raise HostedReviewError("WANDB_API_KEY is required for hosted review")
    return api_key


def _no_redirect_graphql_transport(
    request: urllib.request.Request,
    timeout: float,
) -> bytes:
    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({}),
        _NoRedirectHandler(),
    )
    with opener.open(request, timeout=timeout) as response:
        if response.geturl() != _WANDB_GRAPHQL_URL or getattr(response, "status", 0) != 200:
            raise HostedReviewError("W&B project authorization request was not accepted")
        content_type = response.headers.get_content_type()
        if content_type != "application/json":
            raise HostedReviewError("W&B project authorization returned an invalid response")
        body = response.read(_MAX_GRAPHQL_RESPONSE_BYTES + 1)
    if len(body) > _MAX_GRAPHQL_RESPONSE_BYTES:
        raise HostedReviewError("W&B project authorization response exceeded its limit")
    return body


class HostedProjectGuard:
    """Read-only hosted GraphQL guard; it cannot create or probe-write a project."""

    def __init__(self, *, transport: Any = _no_redirect_graphql_transport) -> None:
        self.transport = transport

    def check(self, *, entity: str, project: str) -> ProjectAccess:
        if (
            not _COORDINATE.fullmatch(entity)
            or not _COORDINATE.fullmatch(project)
            or f"{entity}/{project}" != _REVIEW_PROJECT
        ):
            raise HostedReviewError("hosted review project authorization target is invalid")
        api_key = _wandb_api_key()
        token = b64encode(f"api:{api_key}".encode()).decode()
        body = json.dumps(
            {
                "operationName": "HivemindReviewProject",
                "query": _PROJECT_QUERY,
                "variables": {"entity": entity, "project": project},
            },
            separators=(",", ":"),
        ).encode("utf-8")
        request = urllib.request.Request(
            _WANDB_GRAPHQL_URL,
            data=body,
            headers={
                "Accept": "application/json",
                "Authorization": f"Basic {token}",
                "Content-Type": "application/json",
                "User-Agent": "hivemind-weave/hosted-review",
            },
            method="POST",
        )
        try:
            raw = self.transport(request, 15.0)
            response = json.loads(raw)
        except HostedReviewError:
            raise
        except Exception as error:
            raise HostedReviewError("W&B project authorization could not be established") from error
        if (
            not isinstance(response, Mapping)
            or response.get("errors")
            or not isinstance(response.get("data"), Mapping)
            or not isinstance(remote := response["data"].get("project"), Mapping)
            or not isinstance(remote.get("id"), str)
            or not remote["id"]
            or remote.get("name") != project
            or remote.get("entityName") != entity
            or remote.get("access") not in _PRIVATE_PROJECT_ACCESS
            or type(remote.get("readOnly")) is not bool
        ):
            raise HostedReviewError(
                "destination project privacy and effective access could not be proved"
            )
        return ProjectAccess(
            exists=True,
            visibility_scope="private",
            can_read=True,
            can_write=remote["readOnly"] is False,
            canonical_entity=entity,
            canonical_project=project,
        )


class RootVerifier(Protocol):
    """The query-only subset of :class:`WeaveVerifier` used by this sink."""

    def reconcile(
        self,
        *,
        conversation_id: str,
        expected_trace_ids: list[str],
        turn_key: str,
        payload_sha256: str,
        expected_span_count: int,
        expected_root_attributes: Mapping[str, str] | None = None,
        expected_started_at: datetime | None = None,
        expected_ended_at: datetime | None = None,
        timeout_seconds: float = 60.0,
    ) -> Any: ...


@dataclass(frozen=True)
class ReviewContent:
    """One complete, already-redacted archive object and its byte certificate."""

    data: bytes
    sha256: str
    mimetype: str = "application/json; charset=utf-8"
    extension: str = "json"
    name: str = ""

    def __post_init__(self) -> None:
        if not isinstance(self.data, bytes) or not self.data:
            raise ValueError("review content must contain non-empty immutable bytes")
        if not _SHA256.fullmatch(self.sha256):
            raise ValueError("review content must include a lowercase SHA-256 certificate")
        if hashlib.sha256(self.data).hexdigest() != self.sha256:
            raise ValueError("review content bytes do not match their SHA-256 certificate")
        if self.mimetype not in _ALLOWED_MIMETYPES:
            raise ValueError("review content has an unsupported MIME type")
        if not _EXTENSION.fullmatch(self.extension):
            raise ValueError("review content has an unsupported filename extension")
        if self.name and (not _OBJECT_NAME.fullmatch(self.name) or self.sha256 not in self.name):
            raise ValueError("review content name is not deterministically bound to its bytes")

    @classmethod
    def from_bytes(
        cls,
        data: bytes,
        *,
        mimetype: str = "application/json; charset=utf-8",
        extension: str = "json",
        name: str = "",
    ) -> ReviewContent:
        return cls(
            data=data,
            sha256=hashlib.sha256(data).hexdigest(),
            mimetype=mimetype,
            extension=extension,
            name=name,
        )


@dataclass(frozen=True)
class HostedReviewManifest:
    """Structurally small root metadata plus complete chunk and index bytes."""

    conversation_id: str
    conversation_name: str
    agent_name: str
    preview: str
    chunks: tuple[ReviewContent, ...]
    index: ReviewContent
    started_at: datetime
    ended_at: datetime
    model: str = ""
    agent_id: str = ""
    agent_version: str = ""
    session_id: str = ""
    attributes: Mapping[str, Any] = field(default_factory=dict)
    manifest_sha256: str = ""
    source_payload_sha256: str = ""
    preview_signature: str = ""
    source_turn_key: str = ""
    user_preview: str = ""
    final_assistant_preview: str = ""


@dataclass(frozen=True)
class ReviewBundlePreflight:
    """Credential-free proof that a canonical bundle is locally safe to publish."""

    manifest: HostedReviewManifest
    logical_key: str
    root_user_preview: str
    root_final_assistant_preview: str


@dataclass(frozen=True)
class PublishedContent:
    """One byte-verified immutable Weave object ref."""

    kind: str
    ordinal: int
    name: str
    content_sha256: str
    object_digest: str
    uri: str
    size: int
    mimetype: str


@dataclass(frozen=True)
class ObjectPublication:
    """Journal-safe evidence emitted before the root turn is attempted."""

    conversation_id: str
    manifest_sha256: str
    root_turn_key: str
    root_payload_sha256: str
    logical_key: str
    preview_signature: str
    planning_index_sha256: str
    started_at: datetime
    ended_at: datetime
    chunks: tuple[PublishedContent, ...]
    index: PublishedContent
    query_only: bool = False

    @property
    def chunk_refs(self) -> tuple[str, ...]:
        return tuple(item.uri for item in self.chunks)

    @property
    def chunk_hashes(self) -> tuple[str, ...]:
        return tuple(item.content_sha256 for item in self.chunks)

    @property
    def chunk_sizes(self) -> tuple[int, ...]:
        return tuple(item.size for item in self.chunks)

    @property
    def index_ref(self) -> str:
        return self.index.uri

    @property
    def index_sha256(self) -> str:
        return self.index.content_sha256

    @property
    def root_match_certificate(self) -> RootMatchCertificate:
        return RootMatchCertificate.build(
            conversation_id=self.conversation_id,
            logical_key=self.logical_key,
            index_ref=self.index.uri,
            preview_signature=self.preview_signature,
            started_at=self.started_at,
            ended_at=self.ended_at,
        )

    @classmethod
    def from_persisted_evidence(
        cls,
        *,
        conversation_id: str,
        manifest_sha256: str,
        logical_key: str,
        preview_signature: str,
        started_at: datetime,
        ended_at: datetime,
        chunk_refs: Sequence[str],
        chunk_hashes: Sequence[str],
        chunk_sizes: Sequence[int],
        index_ref: str,
        index_sha256: str,
        index_size: int = 0,
        planning_index_sha256: str = "",
    ) -> ObjectPublication:
        """Rebuild query-only evidence without loading source or archived content."""
        if not (
            len(chunk_refs) == len(chunk_hashes) == len(chunk_sizes)
            and 1 <= len(chunk_refs) <= _MAX_CHUNKS
        ):
            raise ReviewRootConflictError("persisted review chunk evidence is malformed")
        chunks = tuple(
            _published_from_persisted_ref(
                kind="chunk",
                ordinal=ordinal,
                uri=str(uri),
                content_sha256=str(digest),
                size=size,
                mimetype="text/plain; charset=utf-8",
            )
            for ordinal, (uri, digest, size) in enumerate(
                zip(chunk_refs, chunk_hashes, chunk_sizes, strict=True)
            )
        )
        index = _published_from_persisted_ref(
            kind="index",
            ordinal=len(chunks),
            uri=index_ref,
            content_sha256=index_sha256,
            size=index_size,
            mimetype="application/json; charset=utf-8",
        )
        match_certificate = RootMatchCertificate.build(
            conversation_id=conversation_id,
            logical_key=logical_key,
            index_ref=index.uri,
            preview_signature=preview_signature,
            started_at=started_at,
            ended_at=ended_at,
        )
        publication = cls(
            conversation_id=conversation_id,
            manifest_sha256=manifest_sha256,
            root_turn_key=f"review:{logical_key}",
            root_payload_sha256=match_certificate.sha256,
            logical_key=logical_key,
            preview_signature=preview_signature,
            planning_index_sha256=planning_index_sha256,
            started_at=started_at,
            ended_at=ended_at,
            chunks=chunks,
            index=index,
            query_only=True,
        )
        if not _SHA256.fullmatch(manifest_sha256) or (
            planning_index_sha256 and not _SHA256.fullmatch(planning_index_sha256)
        ):
            raise ReviewRootConflictError("persisted review manifest hash is malformed")
        return publication


@dataclass(frozen=True)
class RootMatchCertificate:
    """Exact query identity for one root and its zero-child span invariant."""

    conversation_id: str
    logical_key: str
    index_ref: str
    preview_signature: str
    started_at: datetime
    ended_at: datetime
    sha256: str

    @classmethod
    def build(
        cls,
        *,
        conversation_id: str,
        logical_key: str,
        index_ref: str,
        preview_signature: str,
        started_at: datetime,
        ended_at: datetime,
    ) -> RootMatchCertificate:
        _validate_root_match_fields(
            conversation_id=conversation_id,
            logical_key=logical_key,
            index_ref=index_ref,
            preview_signature=preview_signature,
            started_at=started_at,
            ended_at=ended_at,
        )
        certificate = {
            "schema": _ROOT_MATCH_SCHEMA,
            "conversation_id": conversation_id,
            "logical_key": logical_key,
            "index_ref": index_ref,
            "preview_signature": preview_signature,
            "started_at": isoformat_z(started_at),
            "ended_at": isoformat_z(ended_at),
            "expected_root_count": 1,
            "expected_span_count": 1,
            "expected_child_span_count": 0,
        }
        return cls(
            conversation_id=conversation_id,
            logical_key=logical_key,
            index_ref=index_ref,
            preview_signature=preview_signature,
            started_at=started_at,
            ended_at=ended_at,
            sha256=sha256_json(certificate),
        )

    @property
    def expected_root_attributes(self) -> dict[str, str]:
        """Return independently queryable fields bound by this certificate."""
        return {
            "hivemind.turn_key": f"review:{self.logical_key}",
            "hivemind.payload_sha256": self.sha256,
            "hivemind.review.schema": _ROOT_SCHEMA,
            "hivemind.review.logical_key": self.logical_key,
            "hivemind.review.index_uri": self.index_ref,
            "hivemind.review.preview_signature": self.preview_signature,
            "hivemind.review.match_sha256": self.sha256,
        }


@dataclass(frozen=True)
class RootSubmission:
    """Content-free acknowledgement from exactly one root submission attempt."""

    manifest_sha256: str
    attempted: bool
    acknowledged: bool
    trace_ids: tuple[str, ...] = ()
    root_span_ids: tuple[str, ...] = ()
    error_code: str = ""

    @property
    def trace_id(self) -> str:
        return self.trace_ids[0] if len(self.trace_ids) == 1 else ""

    @property
    def root_span_id(self) -> str:
        return self.root_span_ids[0] if len(self.root_span_ids) == 1 else ""


@dataclass(frozen=True)
class RootQueryResult:
    """Query-only root evidence; it never authorizes an automatic submission."""

    matches: int
    trace_ids: tuple[str, ...] = ()
    root_span_ids: tuple[str, ...] = ()
    span_count: int = 0


def _validated_root_query_result(result: Any) -> RootQueryResult:
    matches = getattr(result, "matches", None)
    span_count = getattr(result, "span_count", None)
    raw_trace_ids = getattr(result, "trace_ids", ())
    raw_root_span_ids = getattr(result, "root_span_ids", ())
    if (
        type(matches) is not int
        or matches < 0
        or type(span_count) is not int
        or span_count < 0
        or not isinstance(raw_trace_ids, Sequence)
        or isinstance(raw_trace_ids, (str, bytes, bytearray))
        or not all(isinstance(value, str) for value in raw_trace_ids)
        or not isinstance(raw_root_span_ids, Sequence)
        or isinstance(raw_root_span_ids, (str, bytes, bytearray))
        or not all(isinstance(value, str) for value in raw_root_span_ids)
    ):
        raise ReviewRootUncertainError("hosted review root query returned malformed evidence")
    trace_ids = tuple(raw_trace_ids)
    root_span_ids = tuple(raw_root_span_ids)
    if any(not _valid_w3c_trace_id(value) for value in trace_ids) or any(
        not _valid_w3c_span_id(value) for value in root_span_ids
    ):
        raise ReviewRootConflictError(
            "hosted review root query returned invalid W3C identity evidence"
        )
    if matches == 0 and (span_count or trace_ids or root_span_ids):
        raise ReviewRootConflictError(
            "absent hosted review root returned contradictory remote evidence"
        )
    if matches == 1 and (span_count != 1 or len(trace_ids) != 1 or len(root_span_ids) != 1):
        raise ReviewRootConflictError(
            "hosted review root evidence was incomplete or internally inconsistent"
        )
    return RootQueryResult(
        matches=matches,
        trace_ids=trace_ids,
        root_span_ids=root_span_ids,
        span_count=span_count,
    )


@dataclass(frozen=True)
class HostedReviewOutcome:
    """Exactly-one visible root and all immutable object refs."""

    publication: ObjectPublication
    trace_id: str
    root_span_id: str


def _valid_w3c_trace_id(value: Any) -> bool:
    return isinstance(value, str) and bool(_TRACE_ID.fullmatch(value) and value != "0" * 32)


def _valid_w3c_span_id(value: Any) -> bool:
    return isinstance(value, str) and bool(_SPAN_ID.fullmatch(value) and value != "0" * 16)


def _immutable_ref_fields(uri: str) -> tuple[str, str]:
    prefix = f"weave:///{_REVIEW_PROJECT}/object/"
    if not isinstance(uri, str) or not uri.startswith(prefix) or ":" not in uri:
        raise ReviewRootConflictError("persisted review object reference is malformed")
    name, object_digest = uri[len(prefix) :].rsplit(":", 1)
    redaction_probe = _CERTIFIED_HASH_RUN.sub("certifiedhash", name)
    if (
        not _OBJECT_NAME.fullmatch(name)
        or not _OBJECT_DIGEST.fullmatch(object_digest)
        or redact_string(redaction_probe) != redaction_probe
    ):
        raise ReviewRootConflictError("persisted review object reference is mutable")
    return name, object_digest


def _published_from_persisted_ref(
    *,
    kind: str,
    ordinal: int,
    uri: str,
    content_sha256: str,
    size: int,
    mimetype: str,
) -> PublishedContent:
    name, object_digest = _immutable_ref_fields(uri)
    if (
        kind not in {"chunk", "index"}
        or type(ordinal) is not int
        or ordinal < 0
        or not _SHA256.fullmatch(content_sha256)
        or content_sha256 not in name
        or type(size) is not int
        or size < 0
        or (kind == "chunk" and size == 0)
        or size > _MAX_CHUNK_BYTES
        or mimetype not in _ALLOWED_MIMETYPES
    ):
        raise ReviewRootConflictError("persisted review object evidence is malformed")
    return PublishedContent(
        kind=kind,
        ordinal=ordinal,
        name=name,
        content_sha256=content_sha256,
        object_digest=object_digest,
        uri=uri,
        size=size,
        mimetype=mimetype,
    )


def _validate_root_match_fields(
    *,
    conversation_id: str,
    logical_key: str,
    index_ref: str,
    preview_signature: str,
    started_at: datetime,
    ended_at: datetime,
) -> None:
    _immutable_ref_fields(index_ref)
    if (
        _review_conversation_session_id(conversation_id) is None
        or not _SHA256.fullmatch(logical_key)
        or not _SHA256.fullmatch(preview_signature)
        or not isinstance(started_at, datetime)
        or started_at.tzinfo is None
        or not isinstance(ended_at, datetime)
        or ended_at.tzinfo is None
        or ended_at < started_at
    ):
        raise ReviewRootConflictError("hosted review root matching certificate is malformed")


def _marked_root_preview(value: str, *, marker: str) -> str:
    remaining = _MAX_PREVIEW_CHARACTERS - len(marker)
    if len(value) <= remaining:
        return f"{marker}{value}"
    content_limit = remaining - len(_PREVIEW_TRUNCATED_MARKER)
    if content_limit < 0:  # pragma: no cover - constants are reviewed together.
        raise HostedReviewError("hosted review preview marker exceeds its root budget")
    return f"{marker}{value[:content_limit]}{_PREVIEW_TRUNCATED_MARKER}"


def _item(value: Any, name: str, default: Any = None) -> Any:
    if isinstance(value, Mapping):
        return value.get(name, default)
    return getattr(value, name, default)


def _as_content(value: Any) -> ReviewContent:
    if isinstance(value, ReviewContent):
        return value
    data = _item(value, "data")
    digest = _item(value, "sha256", _item(value, "digest", ""))
    mimetype = _item(
        value,
        "mimetype",
        _item(value, "mime_type", "application/json; charset=utf-8"),
    )
    extension = _item(value, "extension", "json")
    name = _item(value, "name", "")
    return ReviewContent(
        data=data,
        sha256=digest,
        mimetype=mimetype,
        extension=extension,
        name=name,
    )


def _bundle_previews(payload: Mapping[str, Any]) -> tuple[str, str]:
    previews = payload.get("review_previews")
    if not isinstance(previews, Mapping):
        raise ValueError("hosted review bundle is missing its certified previews")
    user = previews.get("user")
    assistant = previews.get("final_assistant")
    if not isinstance(user, Mapping) or not isinstance(assistant, Mapping):
        raise ValueError("hosted review bundle has malformed certified previews")
    user_text = user.get("text")
    assistant_text = assistant.get("text")
    if (
        not isinstance(user_text, str)
        or not isinstance(assistant_text, str)
        or len(user_text) > _MAX_PREVIEW_CHARACTERS
        or len(assistant_text) > _MAX_PREVIEW_CHARACTERS
    ):
        raise ValueError("hosted review bundle contains an oversized certified preview")
    return user_text, assistant_text


def _manifest_from_bundle(
    bundle: ReviewManifestBundle,
    *,
    payload: Mapping[str, Any] | None = None,
) -> HostedReviewManifest:
    if payload is None:
        try:
            payload = reconstruct_review_manifest(bundle)
        except ReviewManifestError as error:
            raise ValueError("hosted review bundle failed canonical reconstruction") from error
    conversation = payload["conversation"]
    session = payload["session"]
    turn = payload["turn"]
    if not all(isinstance(value, Mapping) for value in (conversation, session, turn)):
        raise ValueError("hosted review bundle has malformed root metadata")
    started_at = parse_datetime(turn.get("started_at"))
    ended_at = parse_datetime(turn.get("ended_at"))
    if started_at is None or ended_at is None:
        raise ValueError("hosted review bundle has malformed turn timestamps")
    turn_attributes = turn.get("attributes")
    if not isinstance(turn_attributes, Mapping):
        raise ValueError("hosted review bundle has malformed turn attributes")
    safe_attribute_names = (
        "hivemind.agent_session_id",
        "hivemind.repository",
        "hivemind.branch",
        "hivemind.parent_session_id",
        "hivemind.is_subagent",
        "hivemind.atif_schema_version",
        "hivemind.importer_version",
        "hivemind.timestamp_inferred",
    )
    attributes = {
        key: turn_attributes[key] for key in safe_attribute_names if key in turn_attributes
    }
    chunks = tuple(
        ReviewContent(
            data=chunk.content,
            sha256=chunk.sha256,
            mimetype="text/plain; charset=utf-8",
            extension="txt",
            name=chunk.name,
        )
        for chunk in bundle.chunks
    )
    user_preview, final_assistant_preview = _bundle_previews(payload)
    return HostedReviewManifest(
        conversation_id=str(conversation.get("conversation_id", "")),
        conversation_name=str(conversation.get("conversation_name", "")),
        agent_name=str(conversation.get("agent_name", "")),
        model=str(conversation.get("model", "")),
        agent_id=str(conversation.get("agent_id", "")),
        agent_version=str(conversation.get("agent_version", "")),
        preview=user_preview,
        chunks=chunks,
        index=ReviewContent(
            data=bundle.index_json.encode("utf-8"),
            sha256=bundle.index_sha256,
            mimetype="application/json; charset=utf-8",
            extension="json",
            name=bundle.index_name,
        ),
        started_at=started_at,
        ended_at=ended_at,
        session_id=str(session.get("session_id", "")),
        attributes=attributes,
        manifest_sha256=bundle.manifest_sha256,
        source_payload_sha256=bundle.source_payload_sha256,
        preview_signature=bundle.preview_signature,
        source_turn_key=str(turn.get("key", "")),
        user_preview=user_preview,
        final_assistant_preview=final_assistant_preview,
    )


def _as_manifest(value: Any) -> HostedReviewManifest:
    if isinstance(value, ReviewManifestBundle):
        manifest = _manifest_from_bundle(value)
    elif isinstance(value, HostedReviewManifest):
        manifest = value
    else:
        chunks = _item(value, "chunks")
        if not isinstance(chunks, Sequence) or isinstance(chunks, (str, bytes, bytearray)):
            raise ValueError("hosted review manifest is missing its ordered chunks")
        attributes = _item(value, "attributes", {})
        if not isinstance(attributes, Mapping):
            raise ValueError("hosted review manifest attributes must be a mapping")
        manifest = HostedReviewManifest(
            conversation_id=_item(value, "conversation_id", ""),
            conversation_name=_item(value, "conversation_name", ""),
            agent_name=_item(value, "agent_name", ""),
            preview=_item(value, "preview", _item(value, "preview_text", "")),
            chunks=tuple(_as_content(item) for item in chunks),
            index=_as_content(_item(value, "index")),
            started_at=_item(value, "started_at"),
            ended_at=_item(value, "ended_at"),
            model=_item(value, "model", ""),
            agent_id=_item(value, "agent_id", ""),
            agent_version=_item(value, "agent_version", ""),
            session_id=_item(value, "session_id", ""),
            attributes=dict(attributes),
            manifest_sha256=_item(value, "manifest_sha256", ""),
            source_payload_sha256=_item(value, "source_payload_sha256", ""),
            preview_signature=_item(value, "preview_signature", ""),
            source_turn_key=_item(value, "source_turn_key", _item(value, "turn_key", "")),
            user_preview=_item(value, "user_preview", ""),
            final_assistant_preview=_item(
                value,
                "final_assistant_preview",
                _item(value, "assistant_preview", ""),
            ),
        )
    conversation_session_id = _review_conversation_session_id(manifest.conversation_id)
    if conversation_session_id is None:
        raise ValueError("hosted review conversation ID is malformed")
    if not 1 <= len(manifest.chunks) <= _MAX_CHUNKS:
        raise ValueError("hosted review manifest has an invalid chunk count")
    if any(len(item.data) > _MAX_CHUNK_BYTES for item in (*manifest.chunks, manifest.index)):
        raise ValueError("hosted review content exceeds the 8 MiB object limit")
    if not all(
        isinstance(value, str)
        for value in (
            manifest.preview,
            manifest.user_preview,
            manifest.final_assistant_preview,
        )
    ):
        raise ValueError("hosted review previews must be text")
    if (
        len(manifest.user_preview or manifest.preview) > _MAX_PREVIEW_CHARACTERS
        or len(manifest.final_assistant_preview) > _MAX_PREVIEW_CHARACTERS
    ):
        raise ValueError("hosted review preview exceeds 4096 characters")
    for timestamp in (manifest.started_at, manifest.ended_at):
        if not isinstance(timestamp, datetime) or timestamp.tzinfo is None:
            raise ValueError("hosted review timestamps must be timezone-aware")
    if manifest.ended_at < manifest.started_at:
        raise ValueError("hosted review end timestamp precedes its start")
    if manifest.session_id and not is_opaque_source_coordinate(manifest.session_id):
        raise ValueError("hosted review session ID is malformed")
    if manifest.session_id and manifest.session_id != conversation_session_id:
        raise ValueError("hosted review session and conversation IDs disagree")
    for digest, label in (
        (manifest.manifest_sha256, "manifest"),
        (manifest.source_payload_sha256, "source payload"),
        (manifest.preview_signature, "preview signature"),
    ):
        if not _SHA256.fullmatch(digest):
            raise ValueError(f"hosted review {label} hash is malformed")
    if (
        not _COORDINATE.fullmatch(manifest.source_turn_key)
        or redact_string(manifest.source_turn_key) != manifest.source_turn_key
    ):
        raise ValueError("hosted review source turn key is malformed")
    return manifest


def _hosted_index_content(
    manifest: HostedReviewManifest,
    chunks: tuple[PublishedContent, ...],
    *,
    logical_key: str,
) -> ReviewContent:
    payload = {
        "schema": _HOSTED_INDEX_SCHEMA,
        "importer_version": __version__,
        "project": _REVIEW_PROJECT,
        "conversation_id": manifest.conversation_id,
        "logical_key": logical_key,
        "source_turn_key": manifest.source_turn_key,
        "manifest": {
            "schema": REVIEW_MANIFEST_SCHEMA,
            "sha256": manifest.manifest_sha256,
            "source_payload_sha256": manifest.source_payload_sha256,
            "preview_signature": manifest.preview_signature,
            "byte_count": sum(item.size for item in chunks),
        },
        "planning_index": {
            "schema": REVIEW_INDEX_SCHEMA,
            "name": manifest.index.name,
            "sha256": manifest.index.sha256,
            "byte_count": len(manifest.index.data),
        },
        "chunks": [
            {
                "ordinal": item.ordinal,
                "name": item.name,
                "sha256": item.content_sha256,
                "byte_count": item.size,
                "media_type": item.mimetype,
                "object_digest": item.object_digest,
                "uri": item.uri,
            }
            for item in chunks
        ],
    }
    data = canonical_json(payload).encode("utf-8")
    if len(data) > _MAX_CHUNK_BYTES:
        raise ReviewObjectPublicationError(
            "hosted review reconstruction index exceeds the 8 MiB object limit"
        )
    digest = hashlib.sha256(data).hexdigest()
    return ReviewContent(
        data=data,
        sha256=digest,
        mimetype="application/json; charset=utf-8",
        extension="json",
        name=f"{_HOSTED_INDEX_SCHEMA}-{digest}.json",
    )


def _redact_or_error(redactor: Callable[[Any], Any], value: Any) -> Any:
    try:
        return redactor(value)
    except Exception as error:
        raise HostedReviewError("required hosted review redaction failed") from error


def _content_bearing_fixed_point_payload(payload: dict[str, Any]) -> dict[str, Any]:
    """Remove only certified protocol coordinates before content redaction.

    Presidio's general-purpose recognizers classify UUIDs as payment/banking
    values and version suffixes as government IDs when they are analyzed out
    of context. Those protocol values are generated or independently validated,
    not transcript content. Everything that can carry source/user text remains
    in this payload and must be an exact active-redactor fixed point.
    """
    if payload.pop("schema", None) != REVIEW_MANIFEST_SCHEMA:
        raise HostedReviewError("canonical review bundle has an invalid schema coordinate")
    conversation = payload.get("conversation")
    previews = payload.get("review_previews")
    turn = payload.get("turn")
    if not all(isinstance(value, dict) for value in (conversation, previews, turn)):
        raise HostedReviewError("canonical review bundle has malformed protocol coordinates")
    assert isinstance(conversation, dict)
    assert isinstance(previews, dict)
    assert isinstance(turn, dict)
    conversation_id = conversation.pop("conversation_id", None)
    if (
        _review_conversation_session_id(conversation_id) is None
        or previews.pop("schema", None) != REVIEW_PREVIEW_SCHEMA
        or not _SHA256.fullmatch(str(turn.pop("payload_sha256", "")))
    ):
        raise HostedReviewError("canonical review bundle has unsafe protocol coordinates")
    hash_context = turn.get("hash_context")
    if (
        not isinstance(hash_context, dict)
        or hash_context.pop("conversation_id", None) != conversation_id
    ):
        raise HostedReviewError("canonical review bundle has inconsistent protocol coordinates")

    def mask_typed_field(
        owner: dict[str, Any],
        key: str,
        sanitizer: Callable[[str], str],
    ) -> None:
        value = owner.get(key)
        if not isinstance(value, str) or sanitizer(value) != value:
            raise HostedReviewError("canonical review bundle has unsafe typed metadata")
        # The field-specific sanitizer has already proved this protocol value.
        # Remove it from the context-free content pass, where names such as the
        # source agent enum ``claude`` must be treated as possible user PII.
        owner[key] = ""

    mask_typed_field(conversation, "agent_name", redact_agent_name)
    mask_typed_field(conversation, "model", redact_model_name)
    for key, sanitizer in (
        ("agent_name", redact_agent_name),
        ("model", redact_model_name),
    ):
        if key in hash_context:
            mask_typed_field(hash_context, key, sanitizer)
    llms = turn.get("llms")
    subagents = turn.get("subagents")
    if not isinstance(llms, list) or not isinstance(subagents, list):
        raise HostedReviewError("canonical review bundle has malformed typed metadata")
    for item in llms:
        if not isinstance(item, dict):
            raise HostedReviewError("canonical review bundle has malformed typed metadata")
        mask_typed_field(item, "model", redact_model_name)
        mask_typed_field(item, "provider", redact_provider_name)
    for item in subagents:
        if not isinstance(item, dict):
            raise HostedReviewError("canonical review bundle has malformed typed metadata")
        mask_typed_field(item, "model", redact_model_name)

    def mask_sha256_values(value: Any) -> None:
        if isinstance(value, dict):
            for key, child in value.items():
                if isinstance(child, str) and _SHA256.fullmatch(child):
                    value[key] = "trace:certified-sha256"
                else:
                    mask_sha256_values(child)
        elif isinstance(value, list):
            for index, child in enumerate(value):
                if isinstance(child, str) and _SHA256.fullmatch(child):
                    value[index] = "trace:certified-sha256"
                else:
                    mask_sha256_values(child)

    # Presidio can assign a PERSON label to a random lowercase digest. Digest
    # values are post-redaction content certificates, not source text or PII.
    mask_sha256_values(payload)
    return payload


def _assert_bundle_redaction_fixed_point(
    payload: dict[str, Any],
    *,
    redactor: Callable[[Any], Any],
) -> None:
    content_payload = _content_bearing_fixed_point_payload(payload)
    redacted = _redact_or_error(redactor, content_payload)
    if canonical_json(redacted) != canonical_json(content_payload):
        raise HostedReviewError(
            "canonical review bundle is not a fixed point of the active redactor"
        )


def _safe_identity_material(
    manifest: HostedReviewManifest,
    *,
    redactor: Callable[[Any], Any],
) -> HostedReviewManifest:
    raw = {
        "conversation_name": manifest.conversation_name,
        "agent_name": manifest.agent_name,
        "model": manifest.model,
        "agent_id": manifest.agent_id,
        "agent_version": manifest.agent_version,
    }
    if any(not isinstance(value, str) for value in raw.values()):
        raise HostedReviewError("hosted review root identity fields must be text")
    safe = {
        "conversation_name": _redact_or_error(redactor, raw["conversation_name"]),
        "agent_name": redact_agent_name(raw["agent_name"]),
        "model": redact_model_name(raw["model"]),
        "agent_id": redact_source_coordinate(raw["agent_id"]),
        "agent_version": _redact_or_error(redactor, raw["agent_version"]),
    }
    for field_name, value in safe.items():
        if not isinstance(value, str):
            raise HostedReviewError("hosted review identity redaction returned invalid text")
        try:
            validate_inline_field(value, field=field_name.replace("_", " "))
        except AttributeSafetyError as error:
            raise HostedReviewError(str(error)) from error
    return replace(manifest, **safe)


def _safe_root_material(
    manifest: HostedReviewManifest,
    *,
    chunks: tuple[PublishedContent, ...],
    index: PublishedContent,
    logical_key: str,
    redactor: Callable[[Any], Any],
) -> tuple[str, str, dict[str, Any]]:
    redacted_user_preview = _redact_or_error(
        redactor,
        manifest.user_preview or manifest.preview,
    )
    redacted_assistant_preview = _redact_or_error(
        redactor,
        manifest.final_assistant_preview,
    )
    if not isinstance(redacted_user_preview, str) or not isinstance(
        redacted_assistant_preview, str
    ):
        raise HostedReviewError("hosted review preview redaction returned invalid text")
    user_preview = _marked_root_preview(
        redacted_user_preview,
        marker=_USER_PREVIEW_MARKER,
    )
    final_assistant_preview = _marked_root_preview(
        redacted_assistant_preview,
        marker=_ASSISTANT_PREVIEW_MARKER,
    )
    for preview, label in (
        (user_preview, "hosted review user preview"),
        (final_assistant_preview, "hosted review final-assistant preview"),
    ):
        if len(preview) > _MAX_PREVIEW_CHARACTERS:
            raise HostedReviewError(f"{label} exceeds 4096 characters")
        try:
            validate_inline_field(preview, field=label)
        except AttributeSafetyError as error:
            raise HostedReviewError(str(error)) from error
    attributes = _redact_or_error(redactor, dict(manifest.attributes))
    if not isinstance(attributes, dict) or any(not isinstance(key, str) for key in attributes):
        raise HostedReviewError("hosted review root attributes are malformed")
    if any(
        key in _OWNED_ROOT_ATTRIBUTES or key.startswith("gen_ai.") or key.startswith("weave.")
        for key in attributes
    ):
        raise HostedReviewError("hosted review root attributes use a reserved name")

    conversation_session_id = _review_conversation_session_id(manifest.conversation_id)
    session_id = manifest.session_id or conversation_session_id
    if (
        conversation_session_id is None
        or not is_opaque_source_coordinate(session_id)
        or session_id != conversation_session_id
    ):
        raise HostedReviewError("hosted review session ID is malformed")
    repository = attributes.get("hivemind.repository", "")
    branch = attributes.get("hivemind.branch", "")
    parent_session_id = attributes.get("hivemind.parent_session_id", "")
    is_subagent = attributes.get("hivemind.is_subagent", False)
    if (
        not isinstance(repository, str)
        or not isinstance(branch, str)
        or not isinstance(parent_session_id, str)
        or type(is_subagent) is not bool
        or (parent_session_id and not is_opaque_source_coordinate(parent_session_id))
    ):
        raise HostedReviewError("hosted review linkage attributes are malformed")
    match_certificate = RootMatchCertificate.build(
        conversation_id=manifest.conversation_id,
        logical_key=logical_key,
        index_ref=index.uri,
        preview_signature=manifest.preview_signature,
        started_at=manifest.started_at,
        ended_at=manifest.ended_at,
    )
    base_attributes = {
        **attributes,
        "hivemind.session_id": session_id,
        "hivemind.review.schema": _ROOT_SCHEMA,
        "hivemind.review.index_sha256": index.content_sha256,
        "hivemind.review.index_uri": index.uri,
        "hivemind.review.chunk_count": len(chunks),
        "hivemind.review.content_bytes": index.size + sum(item.size for item in chunks),
        "hivemind.review.object_refs_verified": True,
        "hivemind.review.noncanonical": True,
        "hivemind.review.manifest_sha256": manifest.manifest_sha256,
        "hivemind.review.preview_signature": manifest.preview_signature,
        "hivemind.review.source_turn_key": manifest.source_turn_key,
        "hivemind.review.logical_key": logical_key,
        "hivemind.review.match_sha256": match_certificate.sha256,
        "hivemind.review.planning_index_sha256": manifest.index.sha256,
        "hivemind.review.repository": repository,
        "hivemind.review.branch": branch,
        "hivemind.review.parent_session_id": parent_session_id,
        "hivemind.review.is_subagent": is_subagent,
    }
    root_attributes = {
        **base_attributes,
        "hivemind.turn_key": f"review:{logical_key}",
        "hivemind.payload_sha256": match_certificate.sha256,
        "hivemind.source_payload_sha256": manifest.source_payload_sha256,
    }
    try:
        validate_upload_attributes(root_attributes)
    except AttributeSafetyError as error:
        raise HostedReviewError(str(error)) from error
    return user_preview, final_assistant_preview, root_attributes


def _placeholder_publication(
    content: ReviewContent,
    *,
    kind: str,
    ordinal: int,
) -> PublishedContent:
    name = content.name or f"hivemind-review-{kind}-{content.sha256}"
    # Use the longest digest accepted at the hosted boundary. The real immutable
    # digest is unknown until publication, so preflighting the maximum-length URI
    # proves that every accepted final reference fits the compact root/index.
    object_digest = hashlib.sha256(
        f"preflight:{kind}:{ordinal}:{name}:{content.sha256}".encode()
    ).hexdigest()
    return PublishedContent(
        kind=kind,
        ordinal=ordinal,
        name=name,
        content_sha256=content.sha256,
        object_digest=object_digest,
        uri=f"weave:///{_REVIEW_PROJECT}/object/{name}:{object_digest}",
        size=len(content.data),
        mimetype=content.mimetype,
    )


def _preflight_content_objects(
    weave_module: Any,
    contents: Sequence[ReviewContent],
) -> None:
    """Construct every publishable Content value locally without network I/O."""
    content_type = getattr(weave_module, "Content", None)
    from_bytes = getattr(content_type, "from_bytes", None)
    if not callable(from_bytes):
        raise HostedReviewError("installed Weave cannot prepare review content")
    for content in contents:
        try:
            local = from_bytes(
                content.data,
                mimetype=content.mimetype,
                extension=content.extension,
            )
            data = getattr(local, "data", None)
            if isinstance(data, bytearray | memoryview):
                data = bytes(data)
            if (
                data != content.data
                or getattr(local, "digest", None) != content.sha256
                or getattr(local, "size", None) != len(content.data)
                or getattr(local, "mimetype", None) != content.mimetype
            ):
                raise TypeError("Content construction changed certified bytes")
        except Exception:
            raise HostedReviewError("pinned Weave rejected prepared review content") from None


def _build_sdk_root_turn(
    conversation_types: Any,
    manifest: HostedReviewManifest,
    *,
    user_preview: str,
    final_assistant_preview: str,
    contents: Sequence[PublishedContent],
) -> Any:
    """Construct the exact pinned-SDK model later passed to ``log_turn``."""
    try:
        parts = [conversation_types.TextPart(content=user_preview)]
        parts.extend(
            conversation_types.UriPart(
                uri=item.uri,
                mime_type=item.mimetype,
                modality="document",
            )
            for item in contents
        )
        messages = [
            conversation_types.Message(
                role="user",
                content="",
                parts=parts,
            )
        ]
        output_messages = [
            conversation_types.Message(
                role="assistant",
                content="",
                parts=[conversation_types.TextPart(content=final_assistant_preview)],
            )
        ]
        turn = conversation_types.Turn(
            agent_name=manifest.agent_name,
            model=manifest.model,
            agent_id=manifest.agent_id,
            agent_description=_REVIEW_AGENT_DESCRIPTION,
            agent_version=manifest.agent_version,
            system_instructions=[],
            messages=messages,
            output_messages=output_messages,
            spans=[],
            continue_parent_trace=False,
            started_at=manifest.started_at,
            ended_at=manifest.ended_at,
        )
    except Exception:
        # Pydantic validation errors may echo source-bearing previews.  Keep the
        # public failure content-free while still rejecting the complete session.
        raise HostedReviewError("pinned Weave rejected the prepared review root") from None
    if (
        getattr(turn, "spans", None) != []
        or getattr(turn, "started_at", None) != manifest.started_at
        or getattr(turn, "ended_at", None) != manifest.ended_at
    ):
        raise HostedReviewError("pinned Weave changed the prepared review root")
    return turn


def _root_log_turn_kwargs(
    turn: Any,
    *,
    conversation_id: str,
    conversation_name: str,
    attributes: Mapping[str, Any],
) -> dict[str, Any]:
    """Return the one shared argument set used by preflight and submission."""
    return {
        "conversation_id": conversation_id,
        "conversation_name": conversation_name,
        "agent_name": turn.agent_name,
        "model": turn.model,
        "agent_id": turn.agent_id,
        "agent_description": turn.agent_description,
        "agent_version": turn.agent_version,
        "messages": turn.messages,
        "output_messages": turn.output_messages,
        "system_instructions": turn.system_instructions,
        "spans": turn.spans,
        "started_at": turn.started_at,
        "ended_at": turn.ended_at,
        "include_content": True,
        "continue_parent_trace": turn.continue_parent_trace,
        "attributes": attributes,
    }


def _validate_sdk_root_wire(
    weave_module: Any,
    turn: Any,
    *,
    conversation_id: str,
    conversation_name: str,
    attributes: Mapping[str, Any],
) -> None:
    """Exercise pinned Weave and OTel encoding paths without starting telemetry."""
    build_attrs = getattr(turn, "_build_attrs", None)
    if not callable(build_attrs):
        raise HostedReviewError("installed Weave cannot preflight a review root")
    try:
        kwargs = _root_log_turn_kwargs(
            turn,
            conversation_id=conversation_id,
            conversation_name=conversation_name,
            attributes=attributes,
        )
        inspect.signature(weave_module.log_turn).bind(**kwargs)
        wire_attributes = build_attrs(
            conversation_id=conversation_id,
            conversation_name=conversation_name,
            include_content=True,
        )
        if not isinstance(wire_attributes, dict):
            raise TypeError("invalid root attributes")
        wire_attributes.update(attributes)
        otel_attributes = importlib.import_module("opentelemetry.attributes")
        cleaner = getattr(otel_attributes, "_clean_attribute", None)
        if not callable(cleaner):
            raise TypeError("missing OTel attribute encoder")
        cleaned_attributes: dict[str, Any] = {}
        for key, value in wire_attributes.items():
            cleaned = cleaner(key, value, None)
            if cleaned is None:
                raise TypeError("OTel rejected a root attribute")
            cleaned_attributes[key] = cleaned
        # The pinned SDK hands this exact attribute structure to OTel. Prove the
        # cleaner preserves it and that it has a deterministic byte form.
        serialized = canonical_json(cleaned_attributes).encode("utf-8")
        if serialized != canonical_json(wire_attributes).encode("utf-8"):
            raise TypeError("OTel changed a root attribute")
        if not serialized:
            raise TypeError("empty root serialization")
    except Exception:
        raise HostedReviewError("pinned Weave could not serialize the review root") from None


def _preflight_manifest(
    manifest: HostedReviewManifest,
    *,
    redactor: Callable[[Any], Any],
    runtime: ReviewRuntime | None = None,
) -> ReviewBundlePreflight:
    logical_key = review_logical_key(
        _REVIEW_PROJECT,
        manifest.conversation_id,
        manifest.source_turn_key,
    )
    safe_manifest = _safe_identity_material(manifest, redactor=redactor)
    safe_user_preview = _redact_or_error(
        redactor,
        safe_manifest.user_preview or safe_manifest.preview,
    )
    safe_assistant_preview = _redact_or_error(
        redactor,
        safe_manifest.final_assistant_preview,
    )
    safe_attributes = _redact_or_error(redactor, dict(safe_manifest.attributes))
    if (
        not isinstance(safe_user_preview, str)
        or not isinstance(safe_assistant_preview, str)
        or not isinstance(safe_attributes, dict)
    ):
        raise HostedReviewError("hosted review preflight redaction returned malformed data")
    safe_manifest = replace(
        safe_manifest,
        preview=safe_user_preview,
        user_preview=safe_user_preview,
        final_assistant_preview=safe_assistant_preview,
        attributes=safe_attributes,
    )
    placeholder_chunks = tuple(
        _placeholder_publication(content, kind="chunk", ordinal=ordinal)
        for ordinal, content in enumerate(safe_manifest.chunks)
    )
    placeholder_index_content = _hosted_index_content(
        safe_manifest,
        placeholder_chunks,
        logical_key=logical_key,
    )
    placeholder_index = _placeholder_publication(
        placeholder_index_content,
        kind="index",
        ordinal=len(placeholder_chunks),
    )
    root_user_preview, root_final_assistant_preview, attributes = _safe_root_material(
        safe_manifest,
        chunks=placeholder_chunks,
        index=placeholder_index,
        logical_key=logical_key,
        redactor=redactor,
    )
    runtime = runtime or preflight_review_runtime()
    _preflight_content_objects(
        runtime.weave,
        (*safe_manifest.chunks, placeholder_index_content),
    )
    root = _build_sdk_root_turn(
        runtime.conversation_types,
        safe_manifest,
        user_preview=root_user_preview,
        final_assistant_preview=root_final_assistant_preview,
        contents=(placeholder_index, *placeholder_chunks),
    )
    _validate_sdk_root_wire(
        runtime.weave,
        root,
        conversation_id=safe_manifest.conversation_id,
        conversation_name=safe_manifest.conversation_name,
        attributes=attributes,
    )
    return ReviewBundlePreflight(
        manifest=safe_manifest,
        logical_key=logical_key,
        root_user_preview=root_user_preview,
        root_final_assistant_preview=root_final_assistant_preview,
    )


def preflight_review_bundle(
    bundle: ReviewManifestBundle,
    *,
    redactor: Callable[[Any], Any] = redact_upload_data,
    _runtime: ReviewRuntime | None = None,
) -> ReviewBundlePreflight:
    """Validate a canonical bundle locally before credentials or writes exist."""
    if not isinstance(bundle, ReviewManifestBundle):
        raise TypeError("hosted review preflight requires a canonical ReviewManifestBundle")
    try:
        payload = reconstruct_review_manifest(bundle)
        manifest = _as_manifest(_manifest_from_bundle(bundle, payload=payload))
    except (ReviewManifestError, ValueError) as error:
        raise HostedReviewError("hosted review bundle failed canonical preflight") from error
    _assert_bundle_redaction_fixed_point(payload, redactor=redactor)
    return _preflight_manifest(manifest, redactor=redactor, runtime=_runtime)


def _access_result(value: ProjectAccess | Mapping[str, Any]) -> ProjectAccess:
    if isinstance(value, ProjectAccess):
        return value
    if not isinstance(value, Mapping):
        raise HostedReviewError("destination authorization returned invalid evidence")
    try:
        return ProjectAccess(
            exists=value["exists"],
            visibility_scope=value["visibility_scope"],
            can_read=value["can_read"],
            can_write=value["can_write"],
            canonical_entity=value["canonical_entity"],
            canonical_project=value.get("canonical_project", ""),
        )
    except KeyError as error:
        raise HostedReviewError("destination authorization evidence was incomplete") from error


def _assert_pinned_weave_distribution() -> Any:
    """Return the one distribution claiming the reviewed Git provenance."""
    try:
        distributions = list(importlib_metadata.distributions(name="weave"))
        if len(distributions) != 1:
            raise TypeError("ambiguous Weave distributions")
        distribution = distributions[0]
        direct_url_text = distribution.read_text("direct_url.json")
        direct_url = json.loads(direct_url_text) if direct_url_text is not None else None
    except Exception:
        raise HostedReviewError(
            "installed Weave lacks readable PEP 610 source provenance"
        ) from None
    if not isinstance(direct_url, Mapping):
        raise HostedReviewError("installed Weave lacks PEP 610 source provenance")
    vcs_info = direct_url.get("vcs_info")
    if (
        direct_url.get("url") != _REVIEW_WEAVE_URL
        or not isinstance(vcs_info, Mapping)
        or vcs_info.get("vcs") != "git"
        or vcs_info.get("commit_id") != _REVIEW_WEAVE_COMMIT
        or vcs_info.get("requested_revision") != _REVIEW_WEAVE_COMMIT
        or "archive_info" in direct_url
        or "dir_info" in direct_url
        or "subdirectory" in direct_url
    ):
        raise HostedReviewError("installed Weave is not the exact reviewed companion Git commit")
    return distribution


def _verified_weave_record(distribution: Any) -> dict[str, Path]:
    """Verify every installed Weave package file against wheel RECORD hashes."""
    try:
        root = Path(distribution.locate_file("")).resolve(strict=True)
        raw_files = distribution.files
        if raw_files is None:
            raise TypeError("missing RECORD")
        verified: dict[str, Path] = {}
        for record in raw_files:
            relative = PurePosixPath(str(record))
            if not relative.parts or relative.parts[0] != "weave":
                continue
            if relative.is_absolute() or ".." in relative.parts:
                raise TypeError("unsafe RECORD entry")
            name = relative.as_posix()
            if name in verified:
                raise TypeError("duplicate RECORD entry")
            record_hash = getattr(record, "hash", None)
            expected_size = getattr(record, "size", None)
            if (
                record_hash is None
                or getattr(record_hash, "mode", None) != "sha256"
                or not isinstance(getattr(record_hash, "value", None), str)
                or type(expected_size) is not int
                or expected_size < 0
            ):
                raise TypeError("incomplete RECORD entry")
            candidate = Path(distribution.locate_file(record))
            resolved = candidate.resolve(strict=True)
            expected = root.joinpath(*relative.parts).resolve(strict=True)
            resolved.relative_to(root)
            if (
                resolved != expected
                or not candidate.is_file()
                or candidate.stat().st_size != expected_size
            ):
                raise TypeError("installed file size mismatch")
            with candidate.open("rb") as source:
                digest = hashlib.file_digest(source, "sha256").digest()
            encoded = urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
            if encoded != record_hash.value:
                raise TypeError("installed file hash mismatch")
            verified[name] = resolved
        if not verified:
            raise TypeError("empty Weave RECORD")
        return verified
    except Exception:
        raise HostedReviewError(
            "installed Weave files do not match their installation record"
        ) from None


def _assert_preimport_weave_origin(recorded: Mapping[str, Path]) -> None:
    """Reject a shadow import before any Weave package code can execute."""
    expected = recorded.get("weave/__init__.py")
    if expected is None:
        raise HostedReviewError("installed Weave record lacks its package initializer")
    try:
        spec = importlib.util.find_spec("weave")
        origin = getattr(spec, "origin", None)
        locations = getattr(spec, "submodule_search_locations", None)
        if (
            spec is None
            or getattr(spec, "name", None) != "weave"
            or not isinstance(origin, str)
            or locations is None
        ):
            raise TypeError("missing package import spec")
        resolved_origin = Path(origin).resolve(strict=True)
        resolved_locations = tuple(Path(value).resolve(strict=True) for value in locations)
        if resolved_origin != expected or resolved_locations != (expected.parent,):
            raise TypeError("shadow package import")
    except Exception:
        raise HostedReviewError(
            "Weave import resolution does not match the pinned distribution"
        ) from None


def _module_origin(module: Any, *, name: str) -> Path:
    try:
        if getattr(module, "__name__", None) != name:
            raise TypeError("unexpected module name")
        module_file = getattr(module, "__file__", None)
        spec_origin = getattr(getattr(module, "__spec__", None), "origin", None)
        if not isinstance(module_file, str) or not isinstance(spec_origin, str):
            raise TypeError("missing module origin")
        resolved_file = Path(module_file).resolve(strict=True)
        resolved_origin = Path(spec_origin).resolve(strict=True)
        if resolved_file != resolved_origin:
            raise TypeError("module origin mismatch")
        return resolved_file
    except Exception:
        raise HostedReviewError("imported Weave modules are not distribution-bound") from None


def _assert_pinned_weave_runtime(
    weave_module: Any,
    conversation_types: Any,
) -> None:
    """Bind imported modules and their bytes to the one pinned distribution."""
    distribution = _assert_pinned_weave_distribution()
    recorded = _verified_weave_record(distribution)
    expected_weave = recorded.get("weave/__init__.py")
    expected_conversation = recorded.get("weave/conversation/__init__.py")
    if expected_weave is None or expected_conversation is None:
        raise HostedReviewError("installed Weave record lacks required review modules")
    try:
        matches = (
            _module_origin(weave_module, name="weave") == expected_weave
            and _module_origin(conversation_types, name="weave.conversation")
            == expected_conversation
            and getattr(weave_module, "conversation", None) is conversation_types
        )
    except HostedReviewError:
        matches = False
    if not matches:
        raise HostedReviewError("imported Weave modules do not match the pinned distribution")


def preflight_review_runtime() -> ReviewRuntime:
    """Validate the pinned local SDK without credentials or network access."""
    try:
        # Inspect and hash the installed distribution before importing it.  A
        # shadow package must not get an opportunity to execute merely so that
        # the post-import origin check can reject it.
        distribution = _assert_pinned_weave_distribution()
        recorded = _verified_weave_record(distribution)
        _assert_preimport_weave_origin(recorded)
        # Weave configures optional error telemetry at import time. Own that
        # boundary even for preview, which never initializes a sink.
        with disabled_weave_error_reporting():
            weave_module = importlib.import_module("weave")
            conversation_types = importlib.import_module("weave.conversation")
            enforce_weave_error_reporting_disabled()
        _assert_pinned_weave_runtime(weave_module, conversation_types)
        for method_name in ("init", "publish", "ref", "log_turn", "finish"):
            if not callable(getattr(weave_module, method_name, None)):
                raise TypeError("missing Weave method")
        content_type = getattr(weave_module, "Content", None)
        if not callable(getattr(content_type, "from_bytes", None)):
            raise TypeError("missing Content.from_bytes")
        for type_name in ("Message", "TextPart", "UriPart", "Turn"):
            if not callable(getattr(conversation_types, type_name, None)):
                raise TypeError("missing conversation type")
        init_parameters = inspect.signature(weave_module.init).parameters
        log_turn_parameters = inspect.signature(weave_module.log_turn).parameters
        if "ensure_project_exists" not in init_parameters or not {
            "conversation_id",
            "conversation_name",
            "agent_name",
            "model",
            "agent_id",
            "agent_description",
            "agent_version",
            "messages",
            "output_messages",
            "system_instructions",
            "spans",
            "started_at",
            "ended_at",
            "include_content",
            "continue_parent_trace",
            "attributes",
        }.issubset(log_turn_parameters):
            raise TypeError("incompatible review interfaces")
    except HostedReviewError:
        raise
    except Exception:
        raise HostedReviewError("installed Weave interfaces do not support hosted review") from None
    return ReviewRuntime(
        weave=weave_module,
        conversation_types=conversation_types,
    )


class HostedReviewSink:
    """Publish verified objects, then at most one compact review root."""

    def __init__(
        self,
        *,
        project_guard: ProjectGuard | None = None,
        root_verifier: RootVerifier | None = None,
        weave_module: Any | None = None,
        conversation_module: Any | None = None,
        require_pii_dependencies: bool = True,
        upload_redactor: Any | None = None,
        object_publish_attempts: int = 2,
        trace_server_url: str = "https://trace.wandb.ai",
        wandb_base_url: str = "https://api.wandb.ai",
    ) -> None:
        if not 1 <= object_publish_attempts <= 5:
            raise ValueError("object publication attempts must be between one and five")
        self.project_guard = project_guard
        self.root_verifier = root_verifier
        self.weave = weave_module
        self.conversation_types = conversation_module
        self.require_pii_dependencies = require_pii_dependencies
        self.upload_redactor = upload_redactor
        self.object_publish_attempts = object_publish_attempts
        self.trace_server_url = validate_trace_server_url(trace_server_url)
        self.wandb_base_url = validate_wandb_base_url(wandb_base_url)
        if (
            self.trace_server_url != _HOSTED_TRACE_SERVER_URL
            or self.wandb_base_url != _HOSTED_WANDB_BASE_URL
        ):
            raise HostedReviewError("custom hosted-review endpoints are forbidden")
        self.project = ""
        self.started = False
        self._root_attempts: set[str] = set()
        self._real_weave_sdk = False
        self._real_weave_initialized_once = False
        self._query_authorized = False
        self._read_only_started = False

    @staticmethod
    def _require_callable(value: Any, name: str) -> Any:
        candidate = getattr(value, name, None)
        if not callable(candidate):
            raise HostedReviewError("installed Weave interfaces do not support hosted review")
        return candidate

    def _close_after_failed_init(self) -> None:
        with suppress(Exception):
            if self.weave is not None:
                self.weave.finish()
        self.started = False
        self.project = ""
        self._real_weave_sdk = False
        self._query_authorized = False

    def _authorize_project(self, project: str, *, require_write: bool) -> None:
        if not _PROJECT.fullmatch(project) or redact_string(project) != project:
            raise HostedReviewError("hosted review project must be a safe entity/project slug")
        if project != _REVIEW_PROJECT:
            raise HostedReviewError(f"hosted review publication is restricted to {_REVIEW_PROJECT}")
        if self.project_guard is None:
            self.project_guard = HostedProjectGuard()
        entity, project_name = project.split("/", 1)
        try:
            access = _access_result(self.project_guard.check(entity=entity, project=project_name))
        except HostedReviewError:
            raise
        except Exception as error:
            raise HostedReviewError("destination authorization could not be established") from error
        if (
            type(access.exists) is not bool
            or type(access.can_read) is not bool
            or type(access.can_write) is not bool
            or access.exists is not True
            or access.can_read is not True
            or (require_write and access.can_write is not True)
            or str(access.visibility_scope).lower() != "private"
            or access.canonical_entity != entity
            or (access.canonical_project and access.canonical_project != project_name)
        ):
            permission = "read/write" if require_write else "read"
            raise HostedReviewError(
                "destination must already exist, be private, and grant effective "
                f"{permission} access"
            )

    def _validate_verifier_binding(self, project: str) -> None:
        if self.root_verifier is None:
            self.root_verifier = WeaveVerifier(
                project=project,
                api_key=_wandb_api_key(),
                base_url=self.trace_server_url,
            )
        verifier_project = getattr(self.root_verifier, "project", None)
        verifier_base_url = getattr(self.root_verifier, "base_url", None)
        if verifier_project is not None and verifier_project != project:
            raise HostedReviewError("root verifier is bound to a different project")
        if verifier_base_url is not None and verifier_base_url != self.trace_server_url:
            raise HostedReviewError("root verifier is bound to an unreviewed endpoint")

    def start_read_only(self, project: str) -> None:
        """Authorize exact reconciliation without initializing any write transport."""
        if self.started:
            raise HostedReviewError("write-mode hosted review sink is already initialized")
        if self._read_only_started:
            if project != self.project:
                raise HostedReviewError("an initialized review sink cannot change projects")
            return
        try:
            validate_live_transport_environment()
        except Exception as error:
            raise HostedReviewError("hosted review query transport is unsafe") from error
        self._authorize_project(project, require_write=False)
        self._validate_verifier_binding(project)
        self.project = project
        self._read_only_started = True
        self._query_authorized = True

    def start(self, project: str) -> None:
        """Authorize an existing private project and initialize without creation."""
        if self.started:
            if project != self.project:
                raise HostedReviewError("an initialized review sink cannot change projects")
            return
        if self._read_only_started:
            raise HostedReviewError("read-only hosted review sink is already initialized")
        if self.weave is None:
            runtime = preflight_review_runtime()
            self.weave = runtime.weave
            if self.conversation_types is not None and (
                self.conversation_types is not runtime.conversation_types
            ):
                raise HostedReviewError(
                    "injected conversation types do not match the pinned Weave runtime"
                )
            self.conversation_types = runtime.conversation_types
        try:
            validate_live_transport_environment()
        except Exception as error:
            raise HostedReviewError("hosted review write transport is unsafe") from error
        self._authorize_project(project, require_write=True)
        self._validate_verifier_binding(project)

        try:
            if self.require_pii_dependencies:
                importlib.import_module("presidio_analyzer")
                importlib.import_module("presidio_anonymizer")
        except Exception as error:
            if isinstance(error, WeaveImportError):
                raise HostedReviewError(str(error)) from error
            raise HostedReviewError("hosted review prerequisites are unavailable") from error

        init_attempted = False
        try:
            with (
                disabled_weave_error_reporting(),
                _pinned_weave_environment(self.trace_server_url, self.wandb_base_url),
                _bounded_otel_export_batch(),
            ):
                if self.weave is None:
                    self.weave = importlib.import_module("weave")
                if self.conversation_types is None:
                    self.conversation_types = importlib.import_module("weave.conversation")
                for method in ("init", "publish", "ref", "log_turn", "finish"):
                    self._require_callable(self.weave, method)
                content_type = getattr(self.weave, "Content", None)
                self._require_callable(content_type, "from_bytes")
                for type_name in ("Message", "TextPart", "UriPart", "Turn"):
                    self._require_callable(self.conversation_types, type_name)

                self._real_weave_sdk = _is_real_weave_sdk(self.weave)
                if self._real_weave_sdk:
                    assert self.conversation_types is not None
                    _assert_pinned_weave_runtime(self.weave, self.conversation_types)
                    enforce_weave_error_reporting_disabled()
                    if not self._real_weave_initialized_once:
                        _assert_no_preexisting_tracer_provider()
                    _disable_weave_version_check()
                if self.require_pii_dependencies:
                    configure_weave_pii()
                    self.upload_redactor = self.upload_redactor or redact_upload_data
                else:
                    self.upload_redactor = self.upload_redactor or redact_data
                init_attempted = True
                # This keyword is an intentional compatibility boundary. A Weave
                # build without no-create initialization is unsafe for this sink.
                self.weave.init(
                    project,
                    ensure_project_exists=False,
                    settings={
                        "redact_pii": True,
                        "redact_pii_fields": [],
                        "redact_pii_exclude_fields": [],
                        "use_server_cache": False,
                        "enable_disk_fallback": False,
                        "enable_wal": False,
                        "capture_code": False,
                        "capture_client_info": False,
                        "capture_system_info": False,
                        "implicitly_patch_integrations": False,
                        "print_call_link": False,
                        "log_level": "WARNING",
                        "retry_max_attempts": 1,
                        "use_stainless_server": False,
                        "allow_unsafe_custom_obj_decode": False,
                    },
                )
                if self._real_weave_sdk:
                    enforce_weave_error_reporting_disabled()
                    _disable_weave_version_check()
                    _assert_locked_weave_settings()
                    _assert_owned_weave_transport(self.trace_server_url)
                    self._real_weave_initialized_once = True
        except Exception as error:
            if init_attempted:
                self._close_after_failed_init()
            if isinstance(error, HostedReviewError):
                raise
            raise HostedReviewError(
                "could not initialize the no-create hosted review transport"
            ) from error
        self.project = project
        self.started = True
        self._query_authorized = True

    def _redact(self, value: Any) -> Any:
        if self.upload_redactor is None:
            raise HostedReviewError("hosted review redaction was not initialized")
        try:
            return self.upload_redactor(value)
        except Exception as error:
            raise HostedReviewError("required hosted review redaction failed") from error

    def _assert_redacted_bundle_fixed_point(self, bundle: ReviewManifestBundle) -> None:
        try:
            payload = reconstruct_review_manifest(bundle)
        except Exception as error:
            if isinstance(error, HostedReviewError):
                raise
            raise HostedReviewError(
                "canonical review bundle could not be checked by the active redactor"
            ) from error
        _assert_bundle_redaction_fixed_point(payload, redactor=self._redact)

    @staticmethod
    def _object_name(kind: str, content: ReviewContent) -> str:
        if content.name:
            return content.name
        return f"hivemind-review-{kind}-{content.sha256}"

    @staticmethod
    def _ref_fields(ref: Any, *, expected_name: str) -> tuple[str, str]:
        name = getattr(ref, "name", None)
        digest = getattr(ref, "digest", None)
        uri = getattr(ref, "uri", None)
        try:
            parsed_name, parsed_digest = _immutable_ref_fields(uri)
        except ReviewRootConflictError:
            raise ReviewObjectPublicationError(
                "Weave returned a mutable or malformed review object reference"
            ) from None
        if name != expected_name or parsed_name != expected_name or digest != parsed_digest:
            raise ReviewObjectPublicationError(
                "Weave returned a mutable or malformed review object reference"
            )
        return uri, parsed_digest

    @staticmethod
    def _readback_bytes(value: Any) -> tuple[bytes, str, int, str]:
        if isinstance(value, Mapping):
            data = value.get("data")
            digest = value.get("digest")
            size = value.get("size")
            mimetype = value.get("mimetype")
        else:
            data = getattr(value, "data", None)
            digest = getattr(value, "digest", None)
            size = getattr(value, "size", None)
            mimetype = getattr(value, "mimetype", None)
        if isinstance(data, bytearray | memoryview):
            data = bytes(data)
        if not isinstance(data, bytes):
            raise ReviewObjectPublicationError(
                "published review object did not read back as immutable bytes"
            )
        if not isinstance(digest, str) or type(size) is not int or not isinstance(mimetype, str):
            raise ReviewObjectPublicationError(
                "published review object returned malformed byte metadata"
            )
        return data, digest, size, mimetype

    def _resolve_and_verify(
        self,
        content: ReviewContent,
        *,
        kind: str,
        ordinal: int,
        expected_name: str,
        ref: Any,
    ) -> PublishedContent:
        assert self.weave is not None
        uri, object_digest = self._ref_fields(ref, expected_name=expected_name)
        resolved = self.weave.ref(uri)
        resolved_uri, resolved_digest = self._ref_fields(
            resolved,
            expected_name=expected_name,
        )
        if resolved_uri != uri or resolved_digest != object_digest:
            raise ReviewObjectPublicationError(
                "immutable review object identity changed during resolution"
            )
        get = self._require_callable(resolved, "get")
        returned, digest, size, mimetype = self._readback_bytes(get())
        if (
            returned != content.data
            or hashlib.sha256(returned).hexdigest() != content.sha256
            or digest != content.sha256
            or size != len(content.data)
            or mimetype != content.mimetype
        ):
            raise ReviewObjectPublicationError(
                "published review object failed byte-for-byte readback verification"
            )
        return PublishedContent(
            kind=kind,
            ordinal=ordinal,
            name=expected_name,
            content_sha256=content.sha256,
            object_digest=object_digest,
            uri=uri,
            size=size,
            mimetype=mimetype,
        )

    def _publish_content(
        self,
        content: ReviewContent,
        *,
        kind: str,
        ordinal: int,
    ) -> PublishedContent:
        if not self.started or self.weave is None:
            raise HostedReviewError("hosted review sink was not initialized")
        expected_name = self._object_name(kind, content)
        content_type = self.weave.Content
        try:
            local = content_type.from_bytes(
                content.data,
                mimetype=content.mimetype,
                extension=content.extension,
            )
            local_bytes, local_digest, local_size, local_mimetype = self._readback_bytes(local)
        except ReviewObjectPublicationError:
            raise
        except Exception as error:
            raise ReviewObjectPublicationError(
                "could not construct a deterministic Weave Content object"
            ) from error
        if (
            local_bytes != content.data
            or local_digest != content.sha256
            or local_size != len(content.data)
            or local_mimetype != content.mimetype
        ):
            raise ReviewObjectPublicationError(
                "local Weave Content construction changed the certified bytes"
            )

        last_error: Exception | None = None
        for _attempt in range(self.object_publish_attempts):
            try:
                ref = self.weave.publish(local, name=expected_name)
                return self._resolve_and_verify(
                    content,
                    kind=kind,
                    ordinal=ordinal,
                    expected_name=expected_name,
                    ref=ref,
                )
            except Exception as error:
                last_error = error
        assert last_error is not None
        raise ReviewObjectPublicationError(
            "immutable review object publication failed after safe content-addressed retry"
        ) from last_error

    def _safe_root_material(
        self,
        manifest: HostedReviewManifest,
        *,
        chunks: tuple[PublishedContent, ...],
        index: PublishedContent,
        logical_key: str,
    ) -> tuple[str, str, dict[str, Any]]:
        return _safe_root_material(
            manifest,
            chunks=chunks,
            index=index,
            logical_key=logical_key,
            redactor=self._redact,
        )

    def publish_objects(self, manifest: HostedReviewManifest | Any) -> ObjectPublication:
        """Publish and read back every chunk, then the index, without a root write."""
        if not self.started:
            raise HostedReviewError("hosted review sink was not initialized")
        if self.require_pii_dependencies and not isinstance(manifest, ReviewManifestBundle):
            raise HostedReviewError(
                "live hosted review accepts only a canonical ReviewManifestBundle"
            )
        if self.weave is None or self.conversation_types is None:
            raise HostedReviewError("hosted review runtime disappeared before publication")
        runtime = ReviewRuntime(
            weave=self.weave,
            conversation_types=self.conversation_types,
        )
        if isinstance(manifest, ReviewManifestBundle):
            preflight = preflight_review_bundle(
                manifest,
                redactor=self._redact,
                _runtime=runtime,
            )
        else:
            preflight = _preflight_manifest(
                _as_manifest(manifest),
                redactor=self._redact,
                runtime=runtime,
            )
        normalized = preflight.manifest
        logical_key = preflight.logical_key
        published_chunks = tuple(
            self._publish_content(content, kind="chunk", ordinal=ordinal)
            for ordinal, content in enumerate(normalized.chunks)
        )
        hosted_index = _hosted_index_content(
            normalized,
            published_chunks,
            logical_key=logical_key,
        )
        published_index = self._publish_content(
            hosted_index,
            kind="index",
            ordinal=len(published_chunks),
        )
        _user_preview, _final_assistant_preview, attributes = self._safe_root_material(
            normalized,
            chunks=published_chunks,
            index=published_index,
            logical_key=logical_key,
        )
        manifest_sha256 = str(attributes["hivemind.payload_sha256"])
        return ObjectPublication(
            conversation_id=normalized.conversation_id,
            manifest_sha256=normalized.manifest_sha256 or manifest_sha256,
            root_turn_key=str(attributes["hivemind.turn_key"]),
            root_payload_sha256=manifest_sha256,
            logical_key=logical_key,
            preview_signature=normalized.preview_signature,
            planning_index_sha256=normalized.index.sha256,
            started_at=normalized.started_at,
            ended_at=normalized.ended_at,
            chunks=published_chunks,
            index=published_index,
        )

    def _verify_publication(
        self,
        manifest: HostedReviewManifest,
        publication: ObjectPublication,
    ) -> tuple[str, str, dict[str, Any]]:
        if publication.query_only:
            raise HostedReviewError("query-only object evidence cannot submit a review root")
        if publication.conversation_id != manifest.conversation_id:
            raise HostedReviewError("hosted review publication belongs to another conversation")
        expected_logical_key = review_logical_key(
            _REVIEW_PROJECT,
            manifest.conversation_id,
            manifest.source_turn_key,
        )
        if publication.logical_key != expected_logical_key:
            raise HostedReviewError("hosted review logical key changed after object verification")
        if len(manifest.chunks) != len(publication.chunks):
            raise HostedReviewError("hosted review publication object count changed")
        for content, published in zip(manifest.chunks, publication.chunks, strict=True):
            if content.sha256 != published.content_sha256 or len(content.data) != published.size:
                raise HostedReviewError("hosted review publication certificate changed")
            assert self.weave is not None
            resolved = self.weave.ref(published.uri)
            verified = self._resolve_and_verify(
                content,
                kind=published.kind,
                ordinal=published.ordinal,
                expected_name=published.name,
                ref=resolved,
            )
            if verified != published:
                raise HostedReviewError("hosted review immutable object evidence changed")
        hosted_index = _hosted_index_content(
            manifest,
            publication.chunks,
            logical_key=publication.logical_key,
        )
        if (
            hosted_index.sha256 != publication.index.content_sha256
            or len(hosted_index.data) != publication.index.size
            or publication.planning_index_sha256 != manifest.index.sha256
        ):
            raise HostedReviewError("hosted review reconstruction index certificate changed")
        assert self.weave is not None
        verified_index = self._resolve_and_verify(
            hosted_index,
            kind="index",
            ordinal=len(publication.chunks),
            expected_name=hosted_index.name,
            ref=self.weave.ref(publication.index.uri),
        )
        if verified_index != publication.index:
            raise HostedReviewError("hosted review reconstruction index evidence changed")
        user_preview, final_assistant_preview, attributes = self._safe_root_material(
            manifest,
            chunks=publication.chunks,
            index=publication.index,
            logical_key=publication.logical_key,
        )
        if (
            attributes["hivemind.turn_key"] != publication.root_turn_key
            or attributes["hivemind.payload_sha256"] != publication.root_payload_sha256
            or publication.manifest_sha256 != manifest.manifest_sha256
            or publication.preview_signature != manifest.preview_signature
            or publication.started_at != manifest.started_at
            or publication.ended_at != manifest.ended_at
        ):
            raise HostedReviewError("hosted review root certificate changed before submission")
        return user_preview, final_assistant_preview, attributes

    def submit_root(
        self,
        manifest_or_conversation: HostedReviewManifest | ReviewManifestBundle | Any,
        publication_or_turn: ObjectPublication | Any,
        bundle: ReviewManifestBundle | Any | None = None,
        publication: ObjectPublication | None = None,
        *,
        logical_key: str = "",
    ) -> RootSubmission:
        """Attempt the root exactly once; ambiguity is returned, never retried."""
        if not self.started or self.weave is None or self.conversation_types is None:
            raise HostedReviewError("hosted review sink was not initialized")
        if bundle is None and publication is None:
            normalized = _as_manifest(manifest_or_conversation)
            if not isinstance(publication_or_turn, ObjectPublication):
                raise TypeError("hosted review root requires verified object publication evidence")
            publication = publication_or_turn
        elif bundle is not None and publication is not None:
            normalized = _as_manifest(bundle)
            source_conversation_id = str(_item(manifest_or_conversation, "conversation_id", ""))
            source_turn_key = str(_item(publication_or_turn, "key", ""))
            if (
                source_conversation_id != normalized.conversation_id
                or source_turn_key != normalized.source_turn_key
            ):
                raise ReviewRootConflictError(
                    "hosted review root inputs do not match the certified manifest"
                )
        else:
            raise TypeError("hosted review root arguments are incomplete")
        if logical_key and logical_key != publication.logical_key:
            raise ReviewRootConflictError(
                "hosted review logical key changed after object verification"
            )
        user_preview, final_assistant_preview, attributes = self._verify_publication(
            normalized,
            publication,
        )
        if publication.root_turn_key in self._root_attempts:
            raise ReviewRootUncertainError(
                "hosted review root was already attempted; query exact evidence before any retry"
            )

        safe_identity = _safe_identity_material(normalized, redactor=self._redact)

        root = _build_sdk_root_turn(
            self.conversation_types,
            safe_identity,
            user_preview=user_preview,
            final_assistant_preview=final_assistant_preview,
            contents=(publication.index, *publication.chunks),
        )

        self._root_attempts.add(publication.root_turn_key)
        try:
            result = self.weave.log_turn(
                **_root_log_turn_kwargs(
                    root,
                    conversation_id=normalized.conversation_id,
                    conversation_name=safe_identity.conversation_name,
                    attributes=attributes,
                )
            )
        except Exception:
            return RootSubmission(
                manifest_sha256=publication.manifest_sha256,
                attempted=True,
                acknowledged=False,
                error_code="root_transport_uncertain",
            )

        raw_trace_ids = getattr(result, "trace_ids", [])
        raw_root_span_ids = getattr(result, "root_span_ids", [])
        identity_lists_valid = (
            isinstance(raw_trace_ids, Sequence)
            and not isinstance(raw_trace_ids, (str, bytes, bytearray))
            and all(isinstance(value, str) for value in raw_trace_ids)
            and isinstance(raw_root_span_ids, Sequence)
            and not isinstance(raw_root_span_ids, (str, bytes, bytearray))
            and all(isinstance(value, str) for value in raw_root_span_ids)
        )
        trace_ids = tuple(raw_trace_ids) if identity_lists_valid else ()
        root_span_ids = tuple(raw_root_span_ids) if identity_lists_valid else ()
        span_count = getattr(result, "span_count", 0)
        acknowledged = (
            len(trace_ids) == 1
            and len(root_span_ids) == 1
            and _valid_w3c_trace_id(trace_ids[0])
            and _valid_w3c_span_id(root_span_ids[0])
            and type(span_count) is int
            and span_count == 1
        )
        return RootSubmission(
            manifest_sha256=publication.manifest_sha256,
            attempted=True,
            acknowledged=acknowledged,
            trace_ids=trace_ids if acknowledged else (),
            root_span_ids=root_span_ids if acknowledged else (),
            error_code="" if acknowledged else "root_acknowledgement_invalid",
        )

    def finish(self) -> None:
        """Flush the single root and close Weave before remote verification."""
        if self._read_only_started:
            self._read_only_started = False
            self._query_authorized = False
            self.project = ""
            return
        if not self.started or self.weave is None:
            return
        try:
            self.weave.finish()
        except Exception as error:
            raise ReviewRootUncertainError(
                "hosted review root flush was not acknowledged; query exact evidence"
            ) from error
        finally:
            self.started = False
            self._real_weave_sdk = False

    def query_root(
        self,
        publication: ObjectPublication,
        *,
        expected_trace_ids: Sequence[str] = (),
        timeout_seconds: float = 60.0,
    ) -> RootQueryResult:
        """Poll exact root attributes without creating or retrying any object."""
        if timeout_seconds <= 0:
            raise ValueError("root query timeout must be positive")
        if not self._query_authorized:
            raise ReviewRootUncertainError(
                "hosted review query was not authorized for the private destination"
            )
        if self.root_verifier is None:
            raise ReviewRootUncertainError(
                "an exact query-only root verifier is required for hosted review"
            )
        certificate = publication.root_match_certificate
        if (
            publication.root_turn_key != f"review:{publication.logical_key}"
            or publication.root_payload_sha256 != certificate.sha256
        ):
            raise ReviewRootConflictError(
                "hosted review publication does not match its exact root certificate"
            )
        if any(not _valid_w3c_trace_id(value) for value in expected_trace_ids):
            raise ReviewRootConflictError(
                "hosted review submission returned invalid W3C trace identity evidence"
            )
        try:
            result = self.root_verifier.reconcile(
                conversation_id=publication.conversation_id,
                expected_trace_ids=list(expected_trace_ids),
                turn_key=publication.root_turn_key,
                payload_sha256=certificate.sha256,
                expected_span_count=1,
                expected_root_attributes=certificate.expected_root_attributes,
                expected_started_at=certificate.started_at,
                expected_ended_at=certificate.ended_at,
                timeout_seconds=timeout_seconds,
            )
        except Exception as error:
            raise ReviewRootUncertainError(
                "hosted review root query could not establish exact remote evidence"
            ) from error
        return _validated_root_query_result(result)

    def find_roots(
        self,
        *,
        conversation_id: str,
        logical_key: str,
        manifest_ref: str,
        preview_signature: str,
        started_at: datetime,
        ended_at: datetime,
        timeout_seconds: float = 60.0,
    ) -> RootQueryResult:
        """Query a journaled root certificate without publishing or resubmitting."""
        if not self._query_authorized:
            raise ReviewRootUncertainError(
                "hosted review query was not authorized for the private destination"
            )
        if self.root_verifier is None:
            raise ReviewRootUncertainError(
                "an exact query-only root verifier is required for hosted review"
            )
        if timeout_seconds <= 0:
            raise ValueError("root query timeout must be positive")
        certificate = RootMatchCertificate.build(
            conversation_id=conversation_id,
            logical_key=logical_key,
            index_ref=manifest_ref,
            preview_signature=preview_signature,
            started_at=started_at,
            ended_at=ended_at,
        )
        try:
            result = self.root_verifier.reconcile(
                conversation_id=conversation_id,
                expected_trace_ids=[],
                turn_key=f"review:{logical_key}",
                payload_sha256=certificate.sha256,
                expected_span_count=1,
                expected_root_attributes=certificate.expected_root_attributes,
                expected_started_at=certificate.started_at,
                expected_ended_at=certificate.ended_at,
                timeout_seconds=timeout_seconds,
            )
        except Exception as error:
            raise ReviewRootUncertainError(
                "hosted review root query could not establish exact remote evidence"
            ) from error
        return _validated_root_query_result(result)

    def verify_root(
        self,
        publication: ObjectPublication,
        submission: RootSubmission | None = None,
        *,
        timeout_seconds: float = 60.0,
    ) -> HostedReviewOutcome:
        """Require exactly one visible one-span root after :meth:`finish`."""
        if self.started:
            raise ReviewRootUncertainError(
                "finish the hosted review transport before verifying its root"
            )
        if submission is not None and submission.manifest_sha256 != publication.manifest_sha256:
            raise ReviewRootConflictError("hosted review submission identity changed")
        expected = submission.trace_ids if submission is not None else ()
        evidence = self.query_root(
            publication,
            expected_trace_ids=expected,
            timeout_seconds=timeout_seconds,
        )
        if evidence.matches == 0:
            raise ReviewRootUncertainError(
                "hosted review root is not conclusively visible; it was not retried"
            )
        if evidence.matches != 1:
            raise ReviewRootConflictError(
                "multiple hosted review roots matched the immutable publication"
            )
        return HostedReviewOutcome(
            publication=publication,
            trace_id=evidence.trace_ids[0],
            root_span_id=evidence.root_span_ids[0],
        )
