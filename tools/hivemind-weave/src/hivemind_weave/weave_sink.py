"""Weave Conversation SDK adapter, imported lazily for fast dry runs and tests."""

from __future__ import annotations

import importlib
import os
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from .attribute_safety import (
    AttributeSafetyError,
    validate_inline_field,
    validate_turn_payload,
    validate_upload_attributes,
)
from .errors import WeaveImportError
from .models import (
    ChatMessage,
    MappedConversation,
    MappedLLM,
    MappedSubAgent,
    MappedTool,
    MappedTurn,
)
from .pii import (
    configure_weave_pii,
    redact_agent_name,
    redact_model_name,
    redact_provider_name,
    redact_upload_data,
)
from .redaction import redact_data
from .verify import (
    enforce_weave_error_reporting_disabled,
    validate_live_transport_environment,
    validate_trace_server_url,
    validate_wandb_base_url,
)

UploadRedactor = Callable[[Any], Any]

_OTEL_EXPORT_BATCH_ENV = "OTEL_BSP_MAX_EXPORT_BATCH_SIZE"
_OTEL_QUEUE_ENV = "OTEL_BSP_MAX_QUEUE_SIZE"
_DEFAULT_OTEL_EXPORT_BATCH_SPANS = 4

# These identifiers are opaque machine correlators and must remain byte-stable
# for reconciliation. Other pinned/searchable root fields keep their final
# redacted values; copying their source form here could reintroduce PII.
_STABLE_MACHINE_CORRELATION_ATTRIBUTES = frozenset(
    {
        "hivemind.session_id",
        "hivemind.turn_key",
        "hivemind.payload_sha256",
        "hivemind.source_payload_sha256",
        "hivemind.atif_schema_version",
        "hivemind.importer_version",
    }
)


def _is_real_weave_sdk(module: Any) -> bool:
    """Return whether ``module`` is the pinned SDK rather than a test adapter."""
    return getattr(module, "__name__", "") == "weave"


def _assert_no_preexisting_tracer_provider() -> None:
    """Refuse a process whose global provider could reroute conversation spans."""
    trace = importlib.import_module("opentelemetry.trace")
    if getattr(trace, "_TRACER_PROVIDER", None) is not None:
        raise WeaveImportError(
            "a pre-existing OpenTelemetry tracer provider is forbidden for live imports"
        )


def _assert_weave_error_reporting_disabled() -> None:
    """Disable SDK error telemetry that could capture transcript-bearing locals."""
    try:
        enforce_weave_error_reporting_disabled()
    except Exception as error:
        raise WeaveImportError(str(error)) from error


def _disabled_weave_version_check() -> None:
    """Replace Weave's unconditional third-party PyPI request with a no-op."""


def _disable_weave_version_check() -> None:
    init_message = importlib.import_module("weave.trace.init_message")
    init_message._print_version_check = _disabled_weave_version_check
    if init_message._print_version_check is not _disabled_weave_version_check:
        raise WeaveImportError("Weave's third-party version check could not be disabled")


def _assert_locked_weave_settings() -> None:
    """Prove no environment overlay re-enabled persistence or content capture."""
    settings = importlib.import_module("weave.trace.settings")
    unsafe = {
        "PII redaction disabled": not settings.should_redact_pii(),
        "custom PII fields": bool(settings.redact_pii_fields()),
        "excluded PII fields": bool(settings.redact_pii_exclude_fields()),
        "server disk cache": settings.use_server_cache(),
        "disk fallback": settings.should_enable_disk_fallback(),
        "write-ahead log": settings.should_enable_wal(),
        "code capture": settings.should_capture_code(),
        "client info capture": settings.should_capture_client_info(),
        "system info capture": settings.should_capture_system_info(),
        "implicit integration patching": settings.should_implicitly_patch_integrations(),
        "call-link printing": settings.should_print_call_link(),
        "alternate HTTP client": settings.should_use_stainless_server(),
        "unsafe custom object decoding": settings.should_allow_unsafe_custom_obj_decode(),
    }
    enabled = [name for name, value in unsafe.items() if value]
    if enabled or settings.log_level() != "WARNING":
        detail = enabled[0] if enabled else "unexpected log level"
        raise WeaveImportError(f"Weave retained an unsafe live-import setting: {detail}")


def _assert_owned_weave_transport(trace_server_url: str) -> None:
    """Prove Weave owns the exact TLS-verifying exporter created for this import."""
    trace = importlib.import_module("opentelemetry.trace")
    weave_init = importlib.import_module("weave.trace.weave_init")
    weave_urls = importlib.import_module("weave.trace.urls")
    provider = getattr(weave_init, "_conversation_tracer_provider", None)
    exporter = getattr(weave_init, "_conversation_span_exporter", None)
    if provider is None or exporter is None or trace.get_tracer_provider() is not provider:
        raise WeaveImportError(
            "Weave did not retain exclusive ownership of the live-import tracer provider"
        )
    expected_endpoint = weave_urls.otel_traces_endpoint(trace_server_url)
    if getattr(exporter, "_endpoint", None) != expected_endpoint:
        raise WeaveImportError("Weave initialized an unexpected OpenTelemetry endpoint")
    if getattr(exporter, "_certificate_file", None) is not True:
        raise WeaveImportError(
            "Weave OpenTelemetry exporter did not retain system TLS certificate verification"
        )
    if any(
        getattr(exporter, attribute, None) is not None
        for attribute in (
            "_client_key_file",
            "_client_certificate_file",
            "_client_cert",
        )
    ):
        raise WeaveImportError(
            "custom OpenTelemetry client credentials are forbidden for live imports"
        )
    session = getattr(exporter, "_session", None)
    if (
        session is None
        or not hasattr(session, "trust_env")
        or not hasattr(session, "max_redirects")
    ):
        raise WeaveImportError(
            "Weave OpenTelemetry exporter did not expose a reviewable HTTP session"
        )
    session.trust_env = False
    session.max_redirects = 0
    if session.trust_env is not False or session.max_redirects != 0:
        raise WeaveImportError(
            "Weave OpenTelemetry exporter retained ambient HTTP or redirect behavior"
        )


@contextmanager
def _bounded_otel_export_batch() -> Iterator[None]:
    """Bound OTLP requests while preserving an explicit operator setting.

    Weave constructs OpenTelemetry's ``BatchSpanProcessor`` without explicit
    queue or batch arguments. The processor reads these standard environment
    variables synchronously in its constructor, which runs inside
    ``weave.init``. A temporary default therefore configures this sink's
    processor without leaving a process-global override behind.
    """
    original_present = _OTEL_EXPORT_BATCH_ENV in os.environ
    original_value = os.environ.get(_OTEL_EXPORT_BATCH_ENV)
    if original_value is not None and original_value.strip():
        try:
            explicit_limit = int(original_value)
        except ValueError as error:
            raise WeaveImportError(
                "OTEL_BSP_MAX_EXPORT_BATCH_SIZE must be an integer no greater than 4"
            ) from error
        if not 1 <= explicit_limit <= _DEFAULT_OTEL_EXPORT_BATCH_SPANS:
            raise WeaveImportError(
                "OTEL_BSP_MAX_EXPORT_BATCH_SIZE exceeds the reviewed live-import limit of 4"
            )
        yield
        return

    effective_limit = _DEFAULT_OTEL_EXPORT_BATCH_SPANS
    queue_value = os.environ.get(_OTEL_QUEUE_ENV, "").strip()
    try:
        explicit_queue_limit = int(queue_value)
    except ValueError:
        explicit_queue_limit = 0
    if explicit_queue_limit > 0:
        # BatchSpanProcessor requires max_export_batch_size <= max_queue_size.
        effective_limit = min(effective_limit, explicit_queue_limit)

    os.environ[_OTEL_EXPORT_BATCH_ENV] = str(effective_limit)
    try:
        yield
    finally:
        if original_present:
            assert original_value is not None
            os.environ[_OTEL_EXPORT_BATCH_ENV] = original_value
        else:
            os.environ.pop(_OTEL_EXPORT_BATCH_ENV, None)


@contextmanager
def _pinned_weave_environment(
    trace_server_url: str,
    wandb_base_url: str,
) -> Iterator[None]:
    """Pin both authenticated endpoints and disable SDK error telemetry."""
    pinned = {
        "WF_TRACE_SERVER_URL": trace_server_url,
        "WANDB_BASE_URL": wandb_base_url,
        "WANDB_ERROR_REPORTING": "false",
    }
    originals = {key: (key in os.environ, os.environ.get(key)) for key in pinned}
    os.environ.update(pinned)
    try:
        yield
    finally:
        for key, (was_present, original_value) in originals.items():
            if was_present:
                assert original_value is not None
                os.environ[key] = original_value
            else:
                os.environ.pop(key, None)


@dataclass(frozen=True)
class LogOutcome:
    trace_ids: list[str]
    root_span_ids: list[str]
    span_count: int
    logical_key: str = ""
    wire_sha256: str = ""
    commit_id: str = ""
    reference_count: int = 0
    capability_version: str = ""


def expected_turn_span_count(turn: MappedTurn) -> int:
    """Return the deterministic number of physical spans for reconciliation."""
    return 1 + len(turn.llms) + len(turn.tools) + len(turn.subagents)


class WeaveSink:
    def __init__(
        self,
        *,
        weave_module: Any | None = None,
        conversation_module: Any | None = None,
        require_pii_dependencies: bool = True,
        flush_span_limit: int = 512,
        max_single_turn_spans: int = 1_024,
        upload_redactor: UploadRedactor | None = None,
        trace_server_url: str = "https://trace.wandb.ai",
        wandb_base_url: str = "https://api.wandb.ai",
    ) -> None:
        self.weave = weave_module
        self.conversation_types: Any | None = conversation_module
        self.require_pii_dependencies = require_pii_dependencies
        self.flush_span_limit = flush_span_limit
        self.max_single_turn_spans = max_single_turn_spans
        self.upload_redactor = upload_redactor
        self.trace_server_url = validate_trace_server_url(trace_server_url)
        self.wandb_base_url = validate_wandb_base_url(wandb_base_url)
        self.pending_span_count = 0
        self.started = False

    def start(self, project: str) -> None:
        try:
            validate_live_transport_environment()
        except Exception as error:
            raise WeaveImportError(str(error)) from error
        if self.require_pii_dependencies:
            redact_override = os.environ.get("WEAVE_REDACT_PII", "").strip()
            if redact_override and redact_override.lower() not in {"1", "on", "true", "yes"}:
                raise WeaveImportError(
                    "WEAVE_REDACT_PII disables required destination-side PII redaction; "
                    "unset it or set it to true"
                )
            try:
                importlib.import_module("presidio_analyzer")
                importlib.import_module("presidio_anonymizer")
            except ImportError as error:
                raise WeaveImportError(
                    "PII redaction dependencies are unavailable; install with "
                    "the package's locked dependencies under Python 3.11 or 3.12"
                ) from error
        try:
            with (
                _pinned_weave_environment(
                    self.trace_server_url,
                    self.wandb_base_url,
                ),
                _bounded_otel_export_batch(),
            ):
                if self.weave is None:
                    self.weave = importlib.import_module("weave")
                if self.conversation_types is None:
                    self.conversation_types = importlib.import_module("weave.conversation")
                real_weave_sdk = _is_real_weave_sdk(self.weave)
                if real_weave_sdk:
                    _assert_weave_error_reporting_disabled()
                    _assert_no_preexisting_tracer_provider()
                    _disable_weave_version_check()
                if self.require_pii_dependencies:
                    configure_weave_pii()
                    if self.upload_redactor is None:
                        self.upload_redactor = redact_upload_data
                elif self.upload_redactor is None:
                    self.upload_redactor = redact_data
                self.weave.init(
                    project,
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
                        "use_stainless_server": False,
                        "allow_unsafe_custom_obj_decode": False,
                    },
                )
                if real_weave_sdk:
                    _disable_weave_version_check()
                    _assert_locked_weave_settings()
                    _assert_owned_weave_transport(self.trace_server_url)
        except WeaveImportError:
            raise
        except Exception as error:
            raise WeaveImportError(
                f"could not initialize Weave ({error.__class__.__name__}); "
                "credential-bearing SDK diagnostics were suppressed"
            ) from error
        self.started = True
        self.pending_span_count = 0

    def _message(self, item: ChatMessage) -> Any:
        assert self.conversation_types is not None
        return self.conversation_types.Message(
            role=item.role,
            content=self._safe_field(item.content, field="message content"),
        )

    def _redact(self, value: Any) -> Any:
        if self.upload_redactor is None:
            raise WeaveImportError("Weave sink redaction was not initialized")
        try:
            return self.upload_redactor(value)
        except Exception as error:
            raise WeaveImportError(
                "required local PII redaction failed "
                f"({error.__class__.__name__}); source content was suppressed"
            ) from error

    def _safe_field(self, value: Any, *, field: str) -> Any:
        redacted = self._redact(value)
        try:
            validate_inline_field(redacted, field=field)
        except AttributeSafetyError as error:
            raise WeaveImportError(str(error)) from error
        return redacted

    def _llm(self, item: MappedLLM) -> Any:
        assert self.conversation_types is not None
        model = redact_model_name(item.model)
        provider = redact_provider_name(item.provider)
        validate_inline_field(model, field="LLM model")
        validate_inline_field(provider, field="LLM provider")
        return self.conversation_types.LLM(
            model=model,
            provider_name=provider,
            system_instructions=self._safe_field(
                item.system_instructions, field="LLM system instructions"
            ),
            usage=self.conversation_types.Usage(**item.usage),
            reasoning=self.conversation_types.Reasoning(
                content=self._safe_field(item.reasoning, field="LLM reasoning")
            ),
            finish_reasons=self._safe_field(item.finish_reasons, field="LLM finish reasons"),
            input_messages=[self._message(message) for message in item.input_messages],
            output_messages=[self._message(message) for message in item.output_messages],
            started_at=item.started_at,
            ended_at=item.ended_at,
        )

    def _tool(self, item: MappedTool) -> Any:
        assert self.conversation_types is not None
        return self.conversation_types.Tool(
            name=self._safe_field(item.name, field="tool name"),
            arguments=self._safe_field(item.arguments, field="tool arguments"),
            result=self._safe_field(item.result, field="tool result"),
            tool_call_id=self._safe_field(item.tool_call_id, field="tool call id"),
            tool_type=self._safe_field(item.tool_type, field="tool type"),
            tool_description=self._safe_field(item.description, field="tool description"),
            started_at=item.started_at,
            ended_at=item.ended_at,
        )

    def _subagent(self, item: MappedSubAgent) -> Any:
        assert self.conversation_types is not None
        model = redact_model_name(item.model)
        validate_inline_field(model, field="subagent model")
        return self.conversation_types.SubAgent(
            name=self._safe_field(item.name, field="subagent name"),
            model=model,
            agent_id=self._safe_field(item.agent_id, field="subagent id"),
            agent_description=self._safe_field(item.description, field="subagent description"),
            agent_version=self._safe_field(item.version, field="subagent version"),
            system_instructions=self._safe_field(
                item.system_instructions, field="subagent system instructions"
            ),
            started_at=item.started_at,
            ended_at=item.ended_at,
        )

    def log_turn(
        self,
        conversation: MappedConversation,
        turn: MappedTurn,
    ) -> LogOutcome:
        if not self.started or self.weave is None:
            raise WeaveImportError("Weave sink was not initialized")
        attributes = self._redact(turn.attributes)
        if not isinstance(attributes, dict):
            raise WeaveImportError("turn attributes could not be safely redacted")
        # These opaque machine correlators are required for state reconciliation
        # and contain HiveMind identifiers rather than transcript content.
        for key in _STABLE_MACHINE_CORRELATION_ATTRIBUTES:
            if key in turn.attributes:
                attributes[key] = turn.attributes[key]
        try:
            validate_upload_attributes(attributes)
        except AttributeSafetyError as error:
            raise WeaveImportError(str(error)) from error
        spans: list[tuple[datetime, int, Any]] = []
        spans.extend((item.started_at, 0, self._llm(item)) for item in turn.llms)
        spans.extend((item.started_at, 1, self._tool(item)) for item in turn.tools)
        spans.extend((item.started_at, 2, self._subagent(item)) for item in turn.subagents)
        spans.sort(key=lambda item: (item[0], item[1]))
        estimated_span_count = 1 + len(spans)
        if estimated_span_count > self.max_single_turn_spans:
            raise WeaveImportError(
                f"turn {turn.key} contains {estimated_span_count} spans, exceeding the "
                f"lossless per-turn safety limit of {self.max_single_turn_spans}"
            )
        try:
            preview = self._redact(turn.payload_for_hash())
            if not isinstance(preview, dict):
                raise AttributeSafetyError("turn preview had an invalid shape")
            validate_turn_payload(
                preview,
                repeated_attributes=attributes,
                span_count=estimated_span_count,
            )
        except AttributeSafetyError as error:
            raise WeaveImportError(str(error)) from error
        if (
            self.pending_span_count
            and self.pending_span_count + estimated_span_count > self.flush_span_limit
        ):
            self.flush()
        conversation_name = self._safe_field(
            conversation.conversation_name, field="conversation name"
        )
        agent_name = redact_agent_name(conversation.agent_name)
        model = redact_model_name(conversation.model)
        validate_inline_field(agent_name, field="agent name")
        validate_inline_field(model, field="agent model")
        agent_id = self._safe_field(conversation.agent_id, field="agent id")
        agent_version = self._safe_field(conversation.agent_version, field="agent version")
        messages = [self._message(message) for message in turn.messages]
        output_messages = [self._message(message) for message in turn.output_messages]
        system_instructions = self._safe_field(
            turn.system_instructions, field="turn system instructions"
        )
        try:
            result = self.weave.log_turn(
                conversation_id=conversation.conversation_id,
                conversation_name=conversation_name,
                agent_name=agent_name,
                model=model,
                agent_id=agent_id,
                agent_description="Imported from W&B HiveMind",
                agent_version=agent_version,
                messages=messages,
                output_messages=output_messages,
                system_instructions=system_instructions,
                spans=[item[2] for item in spans],
                started_at=turn.started_at,
                ended_at=turn.ended_at,
                include_content=True,
                attributes=attributes,
            )
        except Exception as error:
            raise WeaveImportError(
                f"Weave rejected turn {turn.key} ({error.__class__.__name__}); "
                "transcript-bearing SDK diagnostics were suppressed"
            ) from error
        trace_ids = [str(item) for item in getattr(result, "trace_ids", [])]
        root_span_ids = [str(item) for item in getattr(result, "root_span_ids", [])]
        span_count = int(getattr(result, "span_count", 0) or 0)
        if not trace_ids or not root_span_ids or span_count <= 0:
            raise WeaveImportError(
                f"Weave emitted no trace for turn {turn.key}; check SDK and OTel configuration"
            )
        if span_count != estimated_span_count:
            raise WeaveImportError(
                f"Weave reported {span_count} spans for turn {turn.key}, but the lossless "
                f"mapping requires {estimated_span_count}"
            )
        self.pending_span_count += span_count
        if self.pending_span_count >= self.flush_span_limit:
            self.flush()
        return LogOutcome(
            trace_ids=trace_ids,
            root_span_ids=root_span_ids,
            span_count=span_count,
        )

    def _force_flush(self) -> None:
        try:
            trace = importlib.import_module("opentelemetry.trace")
        except ImportError:
            return
        provider = trace.get_tracer_provider()
        force_flush = getattr(provider, "force_flush", None)
        if callable(force_flush):
            flushed = force_flush()
            if flushed is False:
                raise TimeoutError("OpenTelemetry force_flush timed out")

    def flush(self) -> None:
        """Apply bounded backpressure without shutting down the Weave client."""
        if not self.started or not self.pending_span_count:
            return
        try:
            self._force_flush()
        except Exception as error:
            raise WeaveImportError(
                f"could not flush Weave ({error.__class__.__name__}); "
                "SDK diagnostics were suppressed"
            ) from error
        self.pending_span_count = 0

    def finish(self) -> None:
        if not self.started or self.weave is None:
            return
        failure: Exception | None = None
        try:
            self.flush()
        except Exception as error:
            failure = error
        try:
            self.weave.finish()
        except Exception as error:
            if failure is None:
                failure = error
        finally:
            self.started = False
            self.pending_span_count = 0
        if failure is not None:
            raise WeaveImportError(
                f"could not flush Weave ({failure.__class__.__name__}); "
                "SDK diagnostics were suppressed"
            ) from failure
