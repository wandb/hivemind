"""Post-ingestion verification through the documented Weave Agents API."""

from __future__ import annotations

import base64
import json
import os
import time
import urllib.error
import urllib.request
from collections.abc import Callable, Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, TypeVar
from urllib.parse import urlsplit

from . import __version__
from .errors import VerificationError
from .utils import first_present, parse_datetime, sha256_json

Transport = Callable[[str, dict[str, Any], dict[str, str], float], dict[str, Any]]
ItemT = TypeVar("ItemT")

_VERIFICATION_FILTER_BATCH_SIZE = 100
_VERIFICATION_QUERY_PAGE_SIZE = 1_000
_MEDIA_MESSAGE_PART_TYPES = {"uri", "blob", "file"}
_HOSTED_TRACE_SERVER_URL = "https://trace.wandb.ai"
_HOSTED_WANDB_BASE_URL = "https://api.wandb.ai"
_UNSAFE_TRANSPORT_ENV_VARS = (
    "OTEL_EXPORTER_OTLP_ENDPOINT",
    "OTEL_EXPORTER_OTLP_TRACES_ENDPOINT",
    "OTEL_EXPORTER_OTLP_HEADERS",
    "OTEL_EXPORTER_OTLP_TRACES_HEADERS",
    "OTEL_EXPORTER_OTLP_CERTIFICATE",
    "OTEL_EXPORTER_OTLP_TRACES_CERTIFICATE",
    "OTEL_EXPORTER_OTLP_CLIENT_CERTIFICATE",
    "OTEL_EXPORTER_OTLP_TRACES_CLIENT_CERTIFICATE",
    "OTEL_EXPORTER_OTLP_CLIENT_KEY",
    "OTEL_EXPORTER_OTLP_TRACES_CLIENT_KEY",
    "OTEL_EXPORTER_OTLP_INSECURE",
    "OTEL_EXPORTER_OTLP_TRACES_INSECURE",
    "OTEL_PYTHON_TRACER_PROVIDER",
    "OTEL_PYTHON_EXPORTER_OTLP_HTTP_CREDENTIAL_PROVIDER",
    "OTEL_PYTHON_EXPORTER_OTLP_HTTP_TRACES_CREDENTIAL_PROVIDER",
    "REQUESTS_CA_BUNDLE",
    "CURL_CA_BUNDLE",
    "SSL_CERT_FILE",
    "SSL_CERT_DIR",
    "WEAVE_DEBUG_HTTP",
    "WEAVE_REDACT_PII_FIELDS",
    "WEAVE_REDACT_PII_EXCLUDE_FIELDS",
    "WEAVE_ENABLE_DISK_FALLBACK",
    "WEAVE_USE_SERVER_CACHE",
    "WEAVE_SERVER_CACHE_DIR",
    "WEAVE_SERVER_CACHE_SIZE_LIMIT",
    "WEAVE_ENABLE_WAL",
    "WEAVE_DISABLE_WAL_SENDER",
    "WEAVE_CAPTURE_CODE",
    "WEAVE_CAPTURE_CLIENT_INFO",
    "WEAVE_CAPTURE_SYSTEM_INFO",
    "WEAVE_IMPLICITLY_PATCH_INTEGRATIONS",
    "WEAVE_PRINT_CALL_LINK",
    "WEAVE_USE_STAINLESS_SERVER",
    "WEAVE_ALLOW_UNSAFE_CUSTOM_OBJ_DECODE",
    "WEAVE_LOG_LEVEL",
    "OTEL_RESOURCE_ATTRIBUTES",
    "OTEL_EXPERIMENTAL_RESOURCE_DETECTORS",
    "OTEL_ATTRIBUTE_COUNT_LIMIT",
    "OTEL_SPAN_ATTRIBUTE_COUNT_LIMIT",
    "OTEL_ATTRIBUTE_VALUE_LENGTH_LIMIT",
    "OTEL_SPAN_ATTRIBUTE_VALUE_LENGTH_LIMIT",
    "OTEL_SDK_DISABLED",
    "OTEL_TRACES_SAMPLER",
    "OTEL_TRACES_SAMPLER_ARG",
    "SSLKEYLOGFILE",
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "ALL_PROXY",
    "NO_PROXY",
    "http_proxy",
    "https_proxy",
    "all_proxy",
    "no_proxy",
)


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Do not forward the W&B Authorization header across redirects."""

    def redirect_request(self, *_args: Any, **_kwargs: Any) -> None:
        return None


def _open_no_redirect(request: urllib.request.Request, *, timeout: float) -> Any:
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirectHandler())
    return opener.open(request, timeout=timeout)


@contextmanager
def disabled_weave_error_reporting() -> Iterator[None]:
    """Disable SDK error telemetry before the first Weave import and for the live run."""
    variable = "WANDB_ERROR_REPORTING"
    original_present = variable in os.environ
    original_value = os.environ.get(variable)
    os.environ[variable] = "false"
    try:
        yield
    finally:
        if original_present:
            assert original_value is not None
            os.environ[variable] = original_value
        else:
            os.environ.pop(variable, None)


def enforce_weave_error_reporting_disabled() -> None:
    """Disable an already-imported Weave Sentry client without flushing it."""
    try:
        from weave.telemetry import trace_sentry
    except ImportError as error:  # pragma: no cover - required live dependency.
        raise VerificationError("the pinned Weave SDK is unavailable") from error
    sentry = getattr(trace_sentry, "global_trace_sentry", None)
    if sentry is None:
        raise VerificationError("Weave error reporting state is unavailable")
    sentry._disabled = True
    sentry.scope = None
    if getattr(sentry, "_disabled", None) is not True or getattr(sentry, "scope", 1) is not None:
        raise VerificationError("Weave error reporting could not be disabled")


def validate_trace_server_url(url: str) -> str:
    """Return a normalized HTTPS trace endpoint or fail before credentials are used."""
    if not url or any(ord(character) < 0x21 or ord(character) > 0x7E for character in url):
        raise VerificationError("Weave trace endpoint must use visible ASCII characters")
    try:
        parsed = urlsplit(url)
        _ = parsed.port
    except ValueError as error:
        raise VerificationError("Weave trace endpoint is invalid") from error
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
    ):
        raise VerificationError(
            "Weave trace endpoint must be HTTPS and contain no credentials, query, or fragment"
        )
    return url.rstrip("/")


def validate_wandb_base_url(url: str) -> str:
    """Return a normalized HTTPS W&B API origin or fail before auth is used."""
    normalized = validate_trace_server_url(url)
    parsed = urlsplit(normalized)
    if parsed.path not in {"", "/"}:
        raise VerificationError("W&B API endpoint must be an HTTPS origin without a path")
    return normalized


def validate_live_transport_environment() -> None:
    """Reject ambient settings that can bypass the reviewed authenticated transport."""
    insecure = os.environ.get("WEAVE_INSECURE_DISABLE_SSL", "").strip().lower()
    if insecure in {"1", "on", "true", "yes"}:
        raise VerificationError("WEAVE_INSECURE_DISABLE_SSL is forbidden for live imports")
    configured_overrides = [name for name in _UNSAFE_TRANSPORT_ENV_VARS if name in os.environ]
    if configured_overrides:
        raise VerificationError(
            f"{configured_overrides[0]} is forbidden for live imports; "
            "remove ambient diagnostic, OpenTelemetry, and TLS transport overrides"
        )


def _equals(field: str, value: str) -> dict[str, Any]:
    return {
        "$eq": [
            {"$getField": field},
            {"$literal": value},
        ]
    }


def _one_of(field: str, values: list[str]) -> dict[str, Any]:
    if not values:
        raise ValueError("membership filters require at least one value")
    return {
        "$in": [
            {"$getField": field},
            [{"$literal": value} for value in values],
        ]
    }


def _chunks(items: list[ItemT], size: int) -> list[list[ItemT]]:
    return [items[index : index + size] for index in range(0, len(items), size)]


def _message_display_text(content: str) -> str:
    """Canonicalize an Agents API message to the text shown in chat.

    The Agents service stores current SDK messages as a JSON-serialized parts
    array in ``content`` while legacy producers stored plain text directly.
    Match the service chat view: concatenate visible text parts, exclude
    reasoning/media parts that render elsewhere, and preserve malformed or
    non-parts content verbatim.
    """
    if not content or not content.startswith("["):
        return content
    try:
        parts = json.loads(content)
    except (json.JSONDecodeError, TypeError):
        return content
    if not isinstance(parts, list):
        return content
    texts: list[str] = []
    for part in parts:
        if isinstance(part, dict):
            part_type = part.get("type")
            if part_type == "reasoning" or part_type in _MEDIA_MESSAGE_PART_TYPES:
                continue
            if isinstance(part.get("content"), str):
                texts.append(part["content"])
            elif isinstance(part.get("text"), str):
                texts.append(part["text"])
        elif isinstance(part, str):
            texts.append(part)
    return "\n".join(texts)


def _post_json(
    url: str,
    payload: dict[str, Any],
    headers: dict[str, str],
    timeout: float,
) -> dict[str, Any]:
    validate_trace_server_url(url)
    request = urllib.request.Request(
        url,
        data=json.dumps(payload).encode("utf-8"),
        headers=headers,
        method="POST",
    )
    try:
        response_context = _open_no_redirect(request, timeout=timeout)
        with response_context as response:
            body = response.read()
    except urllib.error.HTTPError as error:
        raise VerificationError(f"Weave verification API returned HTTP {error.code}") from error
    except urllib.error.URLError as error:
        raise VerificationError("could not reach the Weave verification API") from error
    except OSError as error:
        raise VerificationError("Weave verification transport failed") from error
    try:
        decoded = json.loads(body)
    except (json.JSONDecodeError, UnicodeDecodeError) as error:
        raise VerificationError("Weave verification API returned invalid JSON") from error
    if not isinstance(decoded, dict):
        raise VerificationError("Weave verification API returned an unexpected JSON shape")
    return decoded


@dataclass(frozen=True)
class ReconcileResult:
    matches: int
    trace_ids: list[str]
    root_span_ids: list[str] = field(default_factory=list)
    span_count: int = 0


@dataclass(frozen=True)
class VerificationExpectation:
    turn_key: str
    payload_sha256: str
    trace_ids: tuple[str, ...]
    verification_signature: str = ""
    span_count: int = 0


@dataclass(frozen=True)
class BatchVerificationResult:
    verified: frozenset[str]
    conflicts: frozenset[str]
    missing: frozenset[str]
    last_error: str = ""


@dataclass(frozen=True)
class _RootSignatureEvidence:
    span_id: str
    signature: str | None
    metadata_state: str = "unused"


def _trace_server_url() -> str:
    """Resolve the endpoint exactly as the pinned Weave SDK would."""
    try:
        from weave.trace.env import weave_trace_server_url
    except ImportError:  # pragma: no cover - Weave is a required live dependency.
        explicit = os.environ.get("WF_TRACE_SERVER_URL", "").strip()
        if explicit:
            return explicit
        public_base = os.environ.get("WANDB_PUBLIC_BASE_URL", "").strip()
        wandb_base = os.environ.get("WANDB_BASE_URL", "https://api.wandb.ai").strip()
        base = (public_base or wandb_base).rstrip("/")
        if base and base != "https://api.wandb.ai":
            return f"{base}/traces"
        return "https://trace.wandb.ai"
    return weave_trace_server_url()


def _wandb_base_url() -> str:
    try:
        from weave.trace.env import wandb_base_url
    except ImportError as error:  # pragma: no cover - required live dependency.
        raise VerificationError("the pinned Weave SDK is unavailable") from error

    return wandb_base_url()


def resolve_trace_server_url() -> str:
    """Resolve and require the reviewed hosted trace endpoint."""
    resolved = validate_trace_server_url(_trace_server_url())
    if resolved != _HOSTED_TRACE_SERVER_URL:
        raise VerificationError(
            "custom Weave trace endpoints are not supported by this review prototype"
        )
    return resolved


def resolve_wandb_base_url() -> str:
    """Resolve and require the reviewed hosted W&B control-plane endpoint."""
    resolved = validate_wandb_base_url(_wandb_base_url())
    if resolved != _HOSTED_WANDB_BASE_URL:
        raise VerificationError(
            "custom W&B API endpoints are not supported by this review prototype"
        )
    return resolved


class WeaveVerifier:
    def __init__(
        self,
        *,
        project: str,
        api_key: str,
        base_url: str | None = None,
        transport: Transport = _post_json,
        sleep: Callable[[float], None] = time.sleep,
        monotonic: Callable[[], float] = time.monotonic,
    ) -> None:
        self.project = project
        self.base_url = validate_trace_server_url(base_url or _trace_server_url())
        self.transport = transport
        self.sleep = sleep
        self.monotonic = monotonic
        auth_token = base64.b64encode(f"api:{api_key}".encode()).decode()
        self.headers = {
            "Authorization": f"Basic {auth_token}",
            "Content-Type": "application/json",
            "User-Agent": f"hivemind-weave/{__version__}",
        }

    def _post(
        self,
        path: str,
        payload: dict[str, Any],
        *,
        timeout: float = 30.0,
    ) -> dict[str, Any]:
        return self.transport(f"{self.base_url}{path}", payload, self.headers, timeout)

    def conversation_turns(
        self,
        conversation_id: str,
        *,
        request_timeout: float = 30.0,
    ) -> list[dict[str, Any]]:
        turns: list[dict[str, Any]] = []
        offset = 0
        while True:
            payload = self._post(
                "/agents/conversations/chat",
                {
                    "project_id": self.project,
                    "conversation_id": conversation_id,
                    "limit": 50,
                    "offset": offset,
                    "include_feedback": False,
                },
                timeout=request_timeout,
            )
            page = payload.get("turns")
            if not isinstance(page, list):
                raise VerificationError("Weave conversation response is missing turns")
            page_turns = [item for item in page if isinstance(item, dict)]
            # offset=0 is the newest chunk; subsequent chunks are older.
            turns = [*page_turns, *turns]
            has_more = payload.get("has_more", False)
            if not has_more:
                break
            if not page:
                raise VerificationError(
                    "Weave returned an empty conversation page with has_more=true"
                )
            offset += len(page)
        return turns

    def span_trace_ids(
        self,
        conversation_id: str,
        *,
        request_timeout: float = 30.0,
    ) -> set[str]:
        payload = self._post(
            "/agents/conversations/spans",
            {
                "project_id": self.project,
                "conversation_ids": [conversation_id],
            },
            timeout=request_timeout,
        )
        conversations = payload.get("conversations")
        if not isinstance(conversations, list):
            raise VerificationError("Weave spans response is missing conversations")
        trace_ids: set[str] = set()
        for conversation in conversations:
            if not isinstance(conversation, dict):
                continue
            if conversation.get("conversation_id") != conversation_id:
                continue
            spans = conversation.get("spans", [])
            if not isinstance(spans, list):
                continue
            for span in spans:
                if isinstance(span, dict) and isinstance(span.get("trace_id"), str):
                    trace_ids.add(span["trace_id"])
        return trace_ids

    def trace_span_count(
        self,
        *,
        conversation_id: str,
        trace_id: str,
        request_timeout: float = 30.0,
    ) -> int:
        """Return the complete remote span count for one imported trace."""

        def equals(field: str, value: str) -> dict[str, Any]:
            return {
                "$eq": [
                    {"$getField": field},
                    {"$literal": value},
                ]
            }

        payload = self._post(
            "/agents/spans/query",
            {
                "project_id": self.project,
                "query": {
                    "$expr": {
                        "$and": [
                            equals("conversation_id", conversation_id),
                            equals("trace_id", trace_id),
                        ]
                    }
                },
                "group_by": [{"source": "field", "key": "trace_id", "alias": "trace_id"}],
                "limit": 2,
                "offset": 0,
            },
            timeout=request_timeout,
        )
        groups = payload.get("groups")
        total_count = payload.get("total_count")
        if not isinstance(groups, list) or not isinstance(total_count, int):
            raise VerificationError("Weave trace span-count query returned an invalid response")
        matching = [
            group
            for group in groups
            if isinstance(group, dict)
            and isinstance(group.get("group_keys"), dict)
            and group["group_keys"].get("trace_id") == trace_id
        ]
        if not matching:
            return 0
        if len(matching) != 1 or total_count != 1:
            raise VerificationError("Weave trace span-count query returned duplicate groups")
        count = matching[0].get("span_count")
        if isinstance(count, bool) or not isinstance(count, int) or count < 1:
            raise VerificationError("Weave trace span-count query omitted a valid span_count")
        return count

    def trace_span_counts_many(
        self,
        *,
        conversation_id: str,
        trace_ids: list[str],
        request_timeout: float = 30.0,
    ) -> dict[str, int]:
        """Return complete span counts using one grouped query per bounded batch."""
        unique_trace_ids = list(dict.fromkeys(trace_ids))
        counts = {trace_id: 0 for trace_id in unique_trace_ids}
        for trace_id_batch in _chunks(
            unique_trace_ids,
            _VERIFICATION_FILTER_BATCH_SIZE,
        ):
            payload = self._post(
                "/agents/spans/query",
                {
                    "project_id": self.project,
                    "query": {
                        "$expr": {
                            "$and": [
                                _equals("conversation_id", conversation_id),
                                _one_of("trace_id", trace_id_batch),
                            ]
                        }
                    },
                    "group_by": [{"source": "field", "key": "trace_id", "alias": "trace_id"}],
                    # A trace id produces at most one group, so the bounded
                    # filter also guarantees the complete response fits here.
                    "limit": len(trace_id_batch),
                    "offset": 0,
                },
                timeout=request_timeout,
            )
            groups = payload.get("groups")
            total_count = payload.get("total_count")
            if (
                not isinstance(groups, list)
                or isinstance(total_count, bool)
                or not isinstance(total_count, int)
                or total_count < 0
            ):
                raise VerificationError(
                    "Weave batched trace span-count query returned an invalid response"
                )
            if total_count != len(groups) or total_count > len(trace_id_batch):
                raise VerificationError(
                    "Weave batched trace span-count query returned incomplete groups"
                )
            requested = set(trace_id_batch)
            seen: set[str] = set()
            for group in groups:
                if not isinstance(group, dict) or not isinstance(
                    group_keys := group.get("group_keys"), dict
                ):
                    raise VerificationError(
                        "Weave batched trace span-count query returned an invalid group"
                    )
                trace_id = group_keys.get("trace_id")
                span_count = group.get("span_count")
                if (
                    not isinstance(trace_id, str)
                    or trace_id not in requested
                    or trace_id in seen
                    or isinstance(span_count, bool)
                    or not isinstance(span_count, int)
                    or span_count < 1
                ):
                    raise VerificationError(
                        "Weave batched trace span-count query returned an invalid group"
                    )
                seen.add(trace_id)
                counts[trace_id] = span_count
        return counts

    @staticmethod
    def _root_span_signature(span: dict[str, Any]) -> str | None:
        """Hash only canonical root-turn fields, never child/chat aggregates."""
        started_at = parse_datetime(span.get("started_at"))
        input_messages = span.get("input_messages")
        output_messages = span.get("output_messages")
        if (
            started_at is None
            or not isinstance(input_messages, list)
            or not isinstance(output_messages, list)
        ):
            return None

        def message_content(
            messages: list[Any],
            *,
            role: str,
            reverse: bool = False,
        ) -> tuple[bool, str]:
            ordered = reversed(messages) if reverse else iter(messages)
            for message in ordered:
                if not isinstance(message, dict) or message.get("role") != role:
                    continue
                content = message.get("content")
                if not isinstance(content, str):
                    return (False, "")
                return (True, _message_display_text(content))
            # A synthetic/orphan turn may legitimately have no user message,
            # and a turn may legitimately have no final assistant output.
            return (True, "")

        valid_user, first_user = message_content(input_messages, role="user")
        valid_assistant, last_assistant = message_content(
            output_messages,
            role="assistant",
            reverse=True,
        )
        if not valid_user or not valid_assistant:
            return None
        return sha256_json(
            {
                "started_at_ms": int(started_at.timestamp() * 1000),
                "first_user": first_user,
                "last_assistant": last_assistant,
            }
        )

    @staticmethod
    def _root_metadata_state(
        span: dict[str, Any],
        *,
        expected_root_attributes: Mapping[str, str] | None,
        expected_started_at: datetime | None,
        expected_ended_at: datetime | None,
    ) -> str:
        """Classify independently read root metadata as exact, missing, or mismatched."""
        if expected_root_attributes is None:
            return "unused"
        attributes = span.get("custom_attrs_string")
        started_at = parse_datetime(span.get("started_at"))
        ended_at = parse_datetime(span.get("ended_at"))
        if (
            not isinstance(attributes, dict)
            or any(key not in attributes for key in expected_root_attributes)
            or started_at is None
            or ended_at is None
        ):
            # Detail/custom-attribute indexes can lag the root-key index. Keep
            # polling when required evidence is absent, but never accept it.
            return "missing"
        if (
            any(attributes.get(key) != value for key, value in expected_root_attributes.items())
            or started_at != expected_started_at
            or ended_at != expected_ended_at
        ):
            return "mismatch"
        return "exact"

    def root_span_signatures_many(
        self,
        *,
        conversation_id: str,
        trace_ids: list[str],
        expected_root_attributes: Mapping[str, str] | None = None,
        expected_started_at: datetime | None = None,
        expected_ended_at: datetime | None = None,
        request_timeout: float = 30.0,
    ) -> dict[str, list[_RootSignatureEvidence]]:
        """Read canonical root messages for many traces in bounded queries.

        Conversation chat intentionally is not used for content matching: it
        aggregates child LLM/tool messages and therefore does not preserve the
        exact root ``input_messages``/``output_messages`` pair.  Only hashes are
        retained here, so transcript content cannot escape through diagnostics.
        """
        unique_trace_ids = list(dict.fromkeys(trace_ids))
        evidence = {trace_id: [] for trace_id in unique_trace_ids}
        for trace_id_batch in _chunks(
            unique_trace_ids,
            _VERIFICATION_FILTER_BATCH_SIZE,
        ):
            offset = 0
            expected_total: int | None = None
            seen_span_ids: set[tuple[str, str]] = set()
            while True:
                request: dict[str, Any] = {
                    "project_id": self.project,
                    "query": {
                        "$expr": {
                            "$and": [
                                _equals("conversation_id", conversation_id),
                                _equals("parent_span_id", ""),
                                _one_of("trace_id", trace_id_batch),
                            ]
                        }
                    },
                    "include_details": True,
                    "limit": _VERIFICATION_QUERY_PAGE_SIZE,
                    "offset": offset,
                }
                if expected_root_attributes is not None:
                    request["custom_attr_columns"] = [
                        {"source": "custom_attrs_string", "key": key}
                        for key in sorted(expected_root_attributes)
                    ]
                payload = self._post(
                    "/agents/spans/query",
                    request,
                    timeout=request_timeout,
                )
                spans = payload.get("spans")
                total_count = payload.get("total_count")
                if not isinstance(spans, list) or not isinstance(total_count, int):
                    raise VerificationError(
                        "Weave batched root-signature query returned an invalid response"
                    )
                if expected_total is None:
                    expected_total = total_count
                elif total_count != expected_total:
                    raise VerificationError(
                        "Weave batched root-signature query changed during pagination"
                    )
                if offset + len(spans) > total_count:
                    raise VerificationError(
                        "Weave batched root-signature query returned too many spans"
                    )
                for span in spans:
                    if not isinstance(span, dict):
                        raise VerificationError(
                            "Weave batched root-signature query returned an invalid span"
                        )
                    trace_id = span.get("trace_id")
                    span_id = span.get("span_id")
                    if (
                        not isinstance(trace_id, str)
                        or trace_id not in evidence
                        or trace_id not in trace_id_batch
                        or not isinstance(span_id, str)
                        or not span_id
                        or (trace_id, span_id) in seen_span_ids
                    ):
                        raise VerificationError(
                            "Weave batched root-signature query returned an invalid span"
                        )
                    seen_span_ids.add((trace_id, span_id))
                    evidence[trace_id].append(
                        _RootSignatureEvidence(
                            span_id=span_id,
                            signature=self._root_span_signature(span),
                            metadata_state=self._root_metadata_state(
                                span,
                                expected_root_attributes=expected_root_attributes,
                                expected_started_at=expected_started_at,
                                expected_ended_at=expected_ended_at,
                            ),
                        )
                    )
                offset += len(spans)
                if offset >= total_count:
                    break
                if not spans:
                    raise VerificationError(
                        "Weave batched root-signature query returned an empty page"
                    )
        return evidence

    @staticmethod
    def _matching_root_traces(
        evidence: dict[str, list[_RootSignatureEvidence]],
        *,
        trace_ids: set[str],
        verification_signatures: set[str],
    ) -> list[str]:
        return [
            trace_id
            for trace_id in trace_ids
            for root in evidence.get(trace_id, [])
            if root.signature in verification_signatures
        ]

    @staticmethod
    def _turn_signature(turn: dict[str, Any]) -> str | None:
        messages = turn.get("messages")
        if not isinstance(messages, list):
            return None
        started = []
        first_user = ""
        last_assistant = ""
        for message in messages:
            if not isinstance(message, dict):
                continue
            if (parsed := parse_datetime(message.get("started_at"))) is not None:
                started.append(parsed)
            user_message = message.get("user_message")
            if not first_user and isinstance(user_message, dict):
                first_user = str(
                    first_present(user_message, "text", "content", "message", default="")
                )
            assistant_message = message.get("assistant_message")
            if isinstance(assistant_message, dict):
                candidate = str(
                    first_present(
                        assistant_message,
                        "text",
                        "content",
                        "message",
                        default="",
                    )
                )
                if candidate:
                    last_assistant = candidate
        if not started:
            return None
        return sha256_json(
            {
                "started_at_ms": int(min(started).timestamp() * 1000),
                "first_user": first_user,
                "last_assistant": last_assistant,
            }
        )

    @classmethod
    def _matching_chat_traces(
        cls,
        turns: list[dict[str, Any]],
        *,
        trace_ids: set[str],
        verification_signature: str,
    ) -> list[str]:
        return [
            trace_id
            for turn in turns
            if isinstance((raw_trace_id := turn.get("trace_id")), str)
            and (trace_id := str(raw_trace_id)) in trace_ids
            and cls._turn_signature(turn) == verification_signature
        ]

    def attribute_trace_matches(
        self,
        *,
        conversation_id: str,
        turn_key: str,
        payload_sha256: str,
        request_timeout: float = 30.0,
    ) -> ReconcileResult:
        def equals(field: str, value: str) -> dict[str, Any]:
            return {
                "$eq": [
                    {"$getField": field},
                    {"$literal": value},
                ]
            }

        payload = self._post(
            "/agents/spans/query",
            {
                "project_id": self.project,
                "query": {
                    "$expr": {
                        "$and": [
                            equals("conversation_id", conversation_id),
                            equals("operation_name", "invoke_agent"),
                            # SubAgent children are also invoke_agent spans and
                            # inherit every custom attribute. Restrict this to
                            # the trace root so a delegation is not counted as
                            # a duplicate imported turn.
                            equals("parent_span_id", ""),
                            equals("custom_attrs_string.hivemind.turn_key", turn_key),
                            equals(
                                "custom_attrs_string.hivemind.payload_sha256",
                                payload_sha256,
                            ),
                        ]
                    }
                },
                "group_by": [
                    {"source": "field", "key": "trace_id", "alias": "trace_id"},
                    {"source": "field", "key": "span_id", "alias": "span_id"},
                ],
                "limit": 2,
                "offset": 0,
            },
            timeout=request_timeout,
        )
        groups = payload.get("groups")
        total_count = payload.get("total_count")
        if not isinstance(groups, list) or not isinstance(total_count, int):
            raise VerificationError("Weave spans query returned an invalid grouped response")
        trace_ids = {
            group_keys.get("trace_id")
            for group in groups
            if isinstance(group, dict)
            and isinstance((group_keys := group.get("group_keys")), dict)
            and isinstance(group_keys.get("trace_id"), str)
            and group_keys.get("trace_id")
        }
        root_span_ids = {
            group_keys.get("span_id")
            for group in groups
            if isinstance(group, dict)
            and isinstance((group_keys := group.get("group_keys")), dict)
            and isinstance(group_keys.get("span_id"), str)
            and group_keys.get("span_id")
        }
        if total_count == 1 and len(trace_ids) != 1:
            raise VerificationError("Weave spans query omitted its sole trace id")
        return ReconcileResult(
            matches=total_count,
            trace_ids=sorted(str(item) for item in trace_ids),
            root_span_ids=sorted(str(item) for item in root_span_ids),
        )

    def attribute_trace_matches_many(
        self,
        *,
        conversation_id: str,
        expected_hashes: dict[str, str],
        request_timeout: float = 30.0,
    ) -> dict[str, ReconcileResult]:
        """Find root spans for many exact turn-key/payload-hash pairs.

        Filters are bounded to keep request payloads predictable. The two
        attributes are projected on otherwise-lightweight root rows, which
        lets the client validate each exact pair without issuing a query for
        every turn.
        """
        matches: dict[str, list[tuple[str, str]]] = {turn_key: [] for turn_key in expected_hashes}
        expected_items = list(expected_hashes.items())
        for expected_batch in _chunks(
            expected_items,
            _VERIFICATION_FILTER_BATCH_SIZE,
        ):
            batch_hashes = dict(expected_batch)
            turn_keys = list(batch_hashes)
            payload_hashes = list(dict.fromkeys(batch_hashes.values()))
            offset = 0
            expected_total: int | None = None
            while True:
                payload = self._post(
                    "/agents/spans/query",
                    {
                        "project_id": self.project,
                        "query": {
                            "$expr": {
                                "$and": [
                                    _equals("conversation_id", conversation_id),
                                    _equals("operation_name", "invoke_agent"),
                                    # Delegated SubAgent spans inherit the root
                                    # attrs, so only the trace root is eligible.
                                    _equals("parent_span_id", ""),
                                    _one_of(
                                        "custom_attrs_string.hivemind.turn_key",
                                        turn_keys,
                                    ),
                                    _one_of(
                                        "custom_attrs_string.hivemind.payload_sha256",
                                        payload_hashes,
                                    ),
                                ]
                            }
                        },
                        "custom_attr_columns": [
                            {
                                "source": "custom_attrs_string",
                                "key": "hivemind.turn_key",
                            },
                            {
                                "source": "custom_attrs_string",
                                "key": "hivemind.payload_sha256",
                            },
                        ],
                        "include_details": False,
                        "limit": _VERIFICATION_QUERY_PAGE_SIZE,
                        "offset": offset,
                    },
                    timeout=request_timeout,
                )
                spans = payload.get("spans")
                total_count = payload.get("total_count")
                if not isinstance(spans, list) or not isinstance(total_count, int):
                    raise VerificationError(
                        "Weave batched root-span query returned an invalid response"
                    )
                if expected_total is None:
                    expected_total = total_count
                elif total_count != expected_total:
                    raise VerificationError(
                        "Weave batched root-span query changed during pagination"
                    )
                if offset + len(spans) > total_count:
                    raise VerificationError("Weave batched root-span query returned too many spans")
                for span in spans:
                    if not isinstance(span, dict) or not isinstance(
                        custom_attrs := span.get("custom_attrs_string"), dict
                    ):
                        raise VerificationError(
                            "Weave batched root-span query returned an invalid span"
                        )
                    turn_key = custom_attrs.get("hivemind.turn_key")
                    payload_sha256 = custom_attrs.get("hivemind.payload_sha256")
                    trace_id = span.get("trace_id")
                    span_id = span.get("span_id")
                    if not all(
                        isinstance(value, str)
                        for value in (turn_key, payload_sha256, trace_id, span_id)
                    ):
                        raise VerificationError(
                            "Weave batched root-span query returned an invalid span"
                        )
                    # The independent $in filters can admit a cross-pair. Only
                    # an exact key/hash pair is evidence for that turn.
                    if batch_hashes.get(turn_key) == payload_sha256:
                        matches[turn_key].append((trace_id, span_id))
                offset += len(spans)
                if offset >= total_count:
                    break
                if not spans:
                    raise VerificationError("Weave batched root-span query returned an empty page")

        return {
            turn_key: ReconcileResult(
                matches=len(rows),
                trace_ids=sorted({trace_id for trace_id, _ in rows}),
                root_span_ids=sorted({span_id for _, span_id in rows}),
            )
            for turn_key, rows in matches.items()
        }

    def attribute_span_presence(
        self,
        *,
        conversation_id: str,
        turn_key: str,
        payload_sha256: str,
        request_timeout: float = 30.0,
    ) -> ReconcileResult:
        """Find every trace containing any span with the exact import attrs.

        A failed OTLP request can leave child LLM/tool spans remotely visible
        without their root.  Those children inherit the turn key and payload
        hash, so root-only absence is not sufficient evidence for a safe
        replay.  Grouping by trace avoids treating each child as a duplicate
        upload while still surfacing multiple partial traces as a conflict.
        """
        offset = 0
        expected_total: int | None = None
        trace_ids: set[str] = set()
        span_count = 0
        while True:
            payload = self._post(
                "/agents/spans/query",
                {
                    "project_id": self.project,
                    "query": {
                        "$expr": {
                            "$and": [
                                _equals("conversation_id", conversation_id),
                                _equals(
                                    "custom_attrs_string.hivemind.turn_key",
                                    turn_key,
                                ),
                                _equals(
                                    "custom_attrs_string.hivemind.payload_sha256",
                                    payload_sha256,
                                ),
                            ]
                        }
                    },
                    "group_by": [{"source": "field", "key": "trace_id", "alias": "trace_id"}],
                    "limit": _VERIFICATION_QUERY_PAGE_SIZE,
                    "offset": offset,
                },
                timeout=request_timeout,
            )
            groups = payload.get("groups")
            total_count = payload.get("total_count")
            if (
                not isinstance(groups, list)
                or isinstance(total_count, bool)
                or not isinstance(total_count, int)
                or total_count < 0
            ):
                raise VerificationError(
                    "Weave all-span presence query returned an invalid response"
                )
            if expected_total is None:
                expected_total = total_count
            elif total_count != expected_total:
                raise VerificationError("Weave all-span presence query changed during pagination")
            if offset + len(groups) > total_count:
                raise VerificationError("Weave all-span presence query returned too many groups")
            for group in groups:
                if not isinstance(group, dict) or not isinstance(
                    group_keys := group.get("group_keys"), dict
                ):
                    raise VerificationError(
                        "Weave all-span presence query returned an invalid group"
                    )
                trace_id = group_keys.get("trace_id")
                group_span_count = group.get("span_count")
                if (
                    not isinstance(trace_id, str)
                    or not trace_id
                    or trace_id in trace_ids
                    or isinstance(group_span_count, bool)
                    or not isinstance(group_span_count, int)
                    or group_span_count < 1
                ):
                    raise VerificationError(
                        "Weave all-span presence query returned an invalid group"
                    )
                trace_ids.add(trace_id)
                span_count += group_span_count
            offset += len(groups)
            if offset >= total_count:
                break
            if not groups:
                raise VerificationError("Weave all-span presence query returned an empty page")
        return ReconcileResult(
            matches=len(trace_ids),
            trace_ids=sorted(trace_ids),
            span_count=span_count,
        )

    def reconcile(
        self,
        *,
        conversation_id: str,
        expected_trace_ids: list[str],
        turn_key: str,
        payload_sha256: str,
        verification_signature: str = "",
        alternate_verification_signatures: tuple[str, ...] = (),
        expected_span_count: int = 0,
        expected_root_attributes: Mapping[str, str] | None = None,
        expected_started_at: datetime | None = None,
        expected_ended_at: datetime | None = None,
        timeout_seconds: float = 60.0,
    ) -> ReconcileResult:
        expects_root_metadata = any(
            value is not None
            for value in (
                expected_root_attributes,
                expected_started_at,
                expected_ended_at,
            )
        )
        if expects_root_metadata:
            if (
                not isinstance(expected_root_attributes, Mapping)
                or not expected_root_attributes
                or any(
                    not isinstance(key, str) or not key or not isinstance(value, str)
                    for key, value in expected_root_attributes.items()
                )
                or not isinstance(expected_started_at, datetime)
                or expected_started_at.tzinfo is None
                or expected_started_at.utcoffset() is None
                or not isinstance(expected_ended_at, datetime)
                or expected_ended_at.tzinfo is None
                or expected_ended_at.utcoffset() is None
                or expected_ended_at < expected_started_at
            ):
                raise VerificationError("exact root metadata expectation is malformed")
            expected_root_attributes = dict(expected_root_attributes)

        def metadata_matches(
            evidence: dict[str, list[_RootSignatureEvidence]],
            *,
            trace_ids: set[str],
            expected_root_span_ids: set[str] | None = None,
        ) -> tuple[list[str], bool]:
            if not expects_root_metadata:
                return sorted(trace_ids), False
            exact: list[str] = []
            mismatch = False
            for trace_id in trace_ids:
                roots = evidence.get(trace_id, [])
                if len(roots) != 1:
                    continue
                root = roots[0]
                if root.metadata_state == "mismatch":
                    mismatch = True
                    continue
                if (
                    expected_root_span_ids is not None
                    and root.span_id not in expected_root_span_ids
                ):
                    mismatch = True
                    continue
                if root.metadata_state == "exact":
                    exact.append(trace_id)
            return sorted(exact), mismatch

        deadline = self.monotonic() + timeout_seconds
        verification_signatures = {
            item for item in (verification_signature, *alternate_verification_signatures) if item
        }
        last_error: VerificationError | None = None
        last_poll_absent = False
        saw_incomplete_match: ReconcileResult | None = None
        while True:
            try:
                # Absence is safe evidence for re-upload only when it came
                # from the latest complete poll. A later transport failure
                # makes remote state unknown again.
                last_poll_absent = False
                matched = self.attribute_trace_matches(
                    conversation_id=conversation_id,
                    turn_key=turn_key,
                    payload_sha256=payload_sha256,
                    request_timeout=min(
                        30.0,
                        max(0.1, deadline - self.monotonic()),
                    ),
                )
                all_span_presence: ReconcileResult | None = None
                if matched.matches:
                    if expected_trace_ids and not set(expected_trace_ids).issubset(
                        matched.trace_ids
                    ):
                        return ReconcileResult(
                            matches=max(2, matched.matches),
                            trace_ids=matched.trace_ids,
                            root_span_ids=matched.root_span_ids,
                        )
                    if matched.matches > 1:
                        return matched
                    matched_ids = set(matched.trace_ids)
                    remaining = max(0.1, deadline - self.monotonic())
                    remote_span_count = (
                        sum(
                            self.trace_span_count(
                                conversation_id=conversation_id,
                                trace_id=trace_id,
                                request_timeout=min(30.0, remaining),
                            )
                            for trace_id in matched.trace_ids
                        )
                        if expected_span_count
                        else 0
                    )
                    candidate = ReconcileResult(
                        matches=matched.matches,
                        trace_ids=matched.trace_ids,
                        root_span_ids=matched.root_span_ids,
                        span_count=remote_span_count,
                    )
                    if expected_span_count and remote_span_count > expected_span_count:
                        return ReconcileResult(
                            matches=2,
                            trace_ids=matched.trace_ids,
                            root_span_ids=matched.root_span_ids,
                            span_count=remote_span_count,
                        )
                    turns = self.conversation_turns(
                        conversation_id,
                        request_timeout=min(30.0, remaining),
                    )
                    chat_ids = {
                        str(turn["trace_id"])
                        for turn in turns
                        if isinstance(turn.get("trace_id"), str)
                    }
                    # The conversation-spans endpoint is a capped UI minimap
                    # (200 newest spans in Weave 0.53). Poll it as required,
                    # but use the untruncated grouped query above for exact
                    # trace completeness so old turns in large backfills do
                    # not become false conflicts.
                    self.span_trace_ids(
                        conversation_id,
                        request_timeout=min(30.0, remaining),
                    )
                    root_evidence = (
                        self.root_span_signatures_many(
                            conversation_id=conversation_id,
                            trace_ids=sorted(matched_ids),
                            expected_root_attributes=expected_root_attributes,
                            expected_started_at=expected_started_at,
                            expected_ended_at=expected_ended_at,
                            request_timeout=min(30.0, remaining),
                        )
                        if verification_signatures or expects_root_metadata
                        else {}
                    )
                    if any(len(root_evidence.get(trace_id, [])) > 1 for trace_id in matched_ids):
                        return ReconcileResult(
                            matches=2,
                            trace_ids=matched.trace_ids,
                            root_span_ids=sorted(
                                {
                                    root.span_id
                                    for trace_id in matched_ids
                                    for root in root_evidence.get(trace_id, [])
                                }
                            ),
                            span_count=remote_span_count,
                        )
                    metadata_trace_matches, metadata_mismatch = metadata_matches(
                        root_evidence,
                        trace_ids=matched_ids,
                        expected_root_span_ids=set(matched.root_span_ids),
                    )
                    if metadata_mismatch:
                        return ReconcileResult(
                            matches=2,
                            trace_ids=matched.trace_ids,
                            root_span_ids=sorted(
                                {
                                    root.span_id
                                    for trace_id in matched_ids
                                    for root in root_evidence.get(trace_id, [])
                                }
                            ),
                            span_count=remote_span_count,
                        )
                    signature_matches = (
                        self._matching_root_traces(
                            root_evidence,
                            trace_ids=matched_ids,
                            verification_signatures=verification_signatures,
                        )
                        if verification_signatures
                        else sorted(matched_ids)
                    )
                    if len(signature_matches) > 1:
                        return ReconcileResult(
                            matches=2,
                            trace_ids=matched.trace_ids,
                            root_span_ids=matched.root_span_ids,
                            span_count=remote_span_count,
                        )
                    complete_count = (
                        not expected_span_count or remote_span_count == expected_span_count
                    )
                    if (
                        complete_count
                        and matched_ids.issubset(chat_ids)
                        and len(signature_matches) == 1
                        and len(metadata_trace_matches) == 1
                    ):
                        return candidate
                    saw_incomplete_match = candidate
                elif expected_trace_ids:
                    # If the process crashed after recording returned IDs, those
                    # IDs plus canonical root content, Agents-chat visibility,
                    # and an exact trace count prove the upload exists even while
                    # the custom-attribute index is lagging. Never re-upload
                    # solely because that secondary index missed the deadline.
                    expected_ids = set(expected_trace_ids)
                    remaining = max(0.1, deadline - self.monotonic())
                    turns = self.conversation_turns(
                        conversation_id,
                        request_timeout=min(30.0, remaining),
                    )
                    self.span_trace_ids(
                        conversation_id,
                        request_timeout=min(30.0, remaining),
                    )
                    chat_ids = {
                        str(turn["trace_id"])
                        for turn in turns
                        if isinstance(turn.get("trace_id"), str)
                    }
                    root_evidence = (
                        self.root_span_signatures_many(
                            conversation_id=conversation_id,
                            trace_ids=sorted(expected_ids),
                            expected_root_attributes=expected_root_attributes,
                            expected_started_at=expected_started_at,
                            expected_ended_at=expected_ended_at,
                            request_timeout=min(30.0, remaining),
                        )
                        if verification_signatures or expects_root_metadata
                        else {}
                    )
                    remote_span_count = (
                        sum(
                            self.trace_span_count(
                                conversation_id=conversation_id,
                                trace_id=trace_id,
                                request_timeout=min(30.0, remaining),
                            )
                            for trace_id in expected_ids
                        )
                        if expected_span_count
                        else 0
                    )
                    signature_matches = (
                        self._matching_root_traces(
                            root_evidence,
                            trace_ids=expected_ids,
                            verification_signatures=verification_signatures,
                        )
                        if verification_signatures
                        else sorted(expected_ids)
                    )
                    root_span_ids = sorted(
                        {
                            root.span_id
                            for trace_id in expected_ids
                            for root in root_evidence.get(trace_id, [])
                        }
                    )
                    if any(len(root_evidence.get(trace_id, [])) > 1 for trace_id in expected_ids):
                        return ReconcileResult(
                            matches=2,
                            trace_ids=sorted(expected_ids),
                            root_span_ids=root_span_ids,
                        )
                    metadata_trace_matches, metadata_mismatch = metadata_matches(
                        root_evidence,
                        trace_ids=expected_ids,
                    )
                    if metadata_mismatch:
                        return ReconcileResult(
                            matches=2,
                            trace_ids=sorted(expected_ids),
                            root_span_ids=root_span_ids,
                            span_count=remote_span_count,
                        )
                    candidate = ReconcileResult(
                        matches=1,
                        trace_ids=sorted(expected_ids),
                        root_span_ids=root_span_ids,
                        span_count=remote_span_count,
                    )
                    if len(signature_matches) > 1 or (
                        expected_span_count and remote_span_count > expected_span_count
                    ):
                        return ReconcileResult(
                            matches=2,
                            trace_ids=sorted(expected_ids),
                            span_count=remote_span_count,
                        )
                    complete_count = (
                        not expected_span_count or remote_span_count == expected_span_count
                    )
                    if (
                        expected_ids.issubset(chat_ids)
                        and len(signature_matches) == 1
                        and len(metadata_trace_matches) == 1
                        and complete_count
                    ):
                        return candidate
                    if (
                        expected_ids.intersection(chat_ids)
                        or remote_span_count
                        or any(root_evidence.values())
                    ):
                        saw_incomplete_match = candidate
                else:
                    all_span_presence = self.attribute_span_presence(
                        conversation_id=conversation_id,
                        turn_key=turn_key,
                        payload_sha256=payload_sha256,
                        request_timeout=min(
                            30.0,
                            max(0.1, deadline - self.monotonic()),
                        ),
                    )
                    if all_span_presence.matches > 1:
                        return all_span_presence
                    if all_span_presence.matches:
                        saw_incomplete_match = all_span_presence
                last_poll_absent = not matched.matches and (
                    all_span_presence is None or not all_span_presence.matches
                )
            except VerificationError as error:
                last_poll_absent = False
                last_error = error
            if self.monotonic() >= deadline:
                if saw_incomplete_match is not None:
                    return ReconcileResult(
                        matches=2,
                        trace_ids=saw_incomplete_match.trace_ids,
                        root_span_ids=saw_incomplete_match.root_span_ids,
                        span_count=saw_incomplete_match.span_count,
                    )
                if last_poll_absent:
                    return ReconcileResult(matches=0, trace_ids=[])
                if last_error is not None:
                    raise last_error
                raise VerificationError(
                    "Weave reconciliation ended without a conclusive remote state"
                )
            self.sleep(min(2.0, max(0.0, deadline - self.monotonic())))

    def verify(
        self,
        *,
        conversation_id: str,
        expected_trace_ids: list[str],
        turn_key: str,
        payload_sha256: str,
        verification_signature: str = "",
        expected_span_count: int = 0,
        timeout_seconds: float = 60.0,
    ) -> None:
        result = self.verify_many(
            conversation_id=conversation_id,
            expectations=[
                VerificationExpectation(
                    turn_key=turn_key,
                    payload_sha256=payload_sha256,
                    trace_ids=tuple(expected_trace_ids),
                    verification_signature=verification_signature,
                    span_count=expected_span_count,
                )
            ],
            timeout_seconds=timeout_seconds,
        )
        if turn_key in result.verified:
            return
        if turn_key in result.conflicts:
            raise VerificationError("turn matched multiple remote Weave traces")
        suffix = f": {result.last_error}" if result.last_error else ""
        raise VerificationError(
            f"turn did not become visible in Weave within {timeout_seconds:g}s{suffix}"
        )

    def verify_many(
        self,
        *,
        conversation_id: str,
        expectations: list[VerificationExpectation],
        timeout_seconds: float = 60.0,
    ) -> BatchVerificationResult:
        """Verify a conversation batch while paging summaries once per poll."""
        by_key = {item.turn_key: item for item in expectations}
        if len(by_key) != len(expectations):
            raise VerificationError("verification batch contains duplicate turn keys")
        remaining = set(by_key)
        verified: set[str] = set()
        conflicts: set[str] = set()
        deadline = self.monotonic() + timeout_seconds
        last_error: VerificationError | None = None
        while remaining:
            try:
                turns = self.conversation_turns(
                    conversation_id,
                    request_timeout=min(30.0, max(0.1, deadline - self.monotonic())),
                )
                chat_ids = {
                    str(turn.get("trace_id"))
                    for turn in turns
                    if isinstance(turn.get("trace_id"), str)
                }
                # This endpoint confirms the Agents conversation index is
                # queryable, but its 200-span cap cannot be a per-turn gate.
                self.span_trace_ids(
                    conversation_id,
                    request_timeout=min(30.0, max(0.1, deadline - self.monotonic())),
                )
                candidates = {
                    key: by_key[key]
                    for key in remaining
                    if by_key[key].trace_ids and set(by_key[key].trace_ids).issubset(chat_ids)
                }
                matched_by_key = self.attribute_trace_matches_many(
                    conversation_id=conversation_id,
                    expected_hashes={
                        key: expectation.payload_sha256 for key, expectation in candidates.items()
                    },
                    request_timeout=min(
                        30.0,
                        max(0.1, deadline - self.monotonic()),
                    ),
                )
                count_candidates: dict[str, set[str]] = {}
                signature_candidates: dict[str, set[str]] = {}
                for key, expectation in candidates.items():
                    expected = set(expectation.trace_ids)
                    matched = matched_by_key[key]
                    matched_ids = set(matched.trace_ids)
                    if matched.matches > 1:
                        conflicts.add(key)
                        remaining.remove(key)
                    elif matched.matches == 1 and expected.issubset(matched_ids):
                        if expectation.verification_signature:
                            signature_candidates[key] = expected
                        elif not expectation.span_count:
                            verified.add(key)
                            remaining.remove(key)
                        else:
                            count_candidates[key] = expected

                root_evidence = self.root_span_signatures_many(
                    conversation_id=conversation_id,
                    trace_ids=sorted(
                        {
                            trace_id
                            for trace_ids in signature_candidates.values()
                            for trace_id in trace_ids
                        }
                    ),
                    request_timeout=min(
                        30.0,
                        max(0.1, deadline - self.monotonic()),
                    ),
                )
                for key, expected in signature_candidates.items():
                    expectation = by_key[key]
                    if any(len(root_evidence.get(trace_id, [])) > 1 for trace_id in expected):
                        conflicts.add(key)
                        remaining.remove(key)
                        continue
                    signature_matches = self._matching_root_traces(
                        root_evidence,
                        trace_ids=expected,
                        verification_signatures={expectation.verification_signature},
                    )
                    if len(signature_matches) > 1:
                        conflicts.add(key)
                        remaining.remove(key)
                        continue
                    if len(signature_matches) != 1:
                        continue
                    if not expectation.span_count:
                        verified.add(key)
                        remaining.remove(key)
                        continue
                    count_candidates[key] = expected

                trace_counts = self.trace_span_counts_many(
                    conversation_id=conversation_id,
                    trace_ids=sorted(
                        {
                            trace_id
                            for trace_ids in count_candidates.values()
                            for trace_id in trace_ids
                        }
                    ),
                    request_timeout=min(
                        30.0,
                        max(0.1, deadline - self.monotonic()),
                    ),
                )
                for key, expected in count_candidates.items():
                    expectation = by_key[key]
                    remote_span_count = sum(trace_counts[trace_id] for trace_id in expected)
                    if key not in remaining:
                        continue
                    if remote_span_count > expectation.span_count:
                        conflicts.add(key)
                        remaining.remove(key)
                        continue
                    if remote_span_count != expectation.span_count:
                        continue
                    verified.add(key)
                    remaining.remove(key)
            except VerificationError as error:
                last_error = error
            if remaining and self.monotonic() >= deadline:
                break
            if not remaining:
                break
            self.sleep(min(2.0, max(0.0, deadline - self.monotonic())))
        return BatchVerificationResult(
            verified=frozenset(verified),
            conflicts=frozenset(conflicts),
            missing=frozenset(remaining),
            last_error=str(last_error) if last_error is not None else "",
        )
