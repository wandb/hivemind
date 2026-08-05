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
    SPILL_TOOL_NAME,
    SPILL_TOOL_TYPE,
    AttributeSafetyError,
    SpillFragment,
    plan_attribute_spill,
    plan_tool_spill,
    restore_chunked_attributes,
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

UploadRedactor = Callable[[Any], Any]
StringRedactor = Callable[[str], str]

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


@dataclass(frozen=True)
class LogOutcome:
    trace_ids: list[str]
    root_span_ids: list[str]
    span_count: int


def expected_turn_span_count(turn: MappedTurn) -> int:
    """Return the deterministic number of physical spans for reconciliation."""
    logical_attributes = restore_chunked_attributes(turn.attributes)
    attribute_plan = plan_attribute_spill(logical_attributes, owner_id=turn.key)
    count = 1 + len(turn.llms) + len(turn.tools) + len(turn.subagents)
    count += len(attribute_plan.fragments)
    for index, item in enumerate(turn.tools):
        tool_plan = plan_tool_spill(
            item.arguments,
            item.result,
            owner_id=f"{turn.key}:tool:{index}",
        )
        count += len(tool_plan.fragments)
    return count


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
        destination_string_redactor: StringRedactor | None = None,
    ) -> None:
        self.weave = weave_module
        self.conversation_types: Any | None = conversation_module
        self.require_pii_dependencies = require_pii_dependencies
        self.flush_span_limit = flush_span_limit
        self.max_single_turn_spans = max_single_turn_spans
        self.upload_redactor = upload_redactor
        self.destination_string_redactor = destination_string_redactor
        self._transport_tool_type: Any | None = None
        self.pending_span_count = 0
        self.started = False

    def start(self, project: str) -> None:
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
                    "pip install 'weave[presidio]>=0.53.4,<0.54' under Python 3.11 or 3.12"
                ) from error
        try:
            if self.weave is None:
                self.weave = importlib.import_module("weave")
            if self.conversation_types is None:
                self.conversation_types = importlib.import_module("weave.conversation")
            if self.require_pii_dependencies:
                configure_weave_pii()
                if self.upload_redactor is None:
                    self.upload_redactor = redact_upload_data
                if self.destination_string_redactor is None:
                    pii_redaction = importlib.import_module("weave.utils.pii_redaction")
                    configured_redactor = getattr(pii_redaction, "redact_pii_string", None)
                    if not callable(configured_redactor):
                        raise RuntimeError("Weave PII string redactor is unavailable")
                    self.destination_string_redactor = configured_redactor
            elif self.upload_redactor is None:
                self.upload_redactor = redact_data
            if self.destination_string_redactor is None:
                self.destination_string_redactor = lambda value: value
            with _bounded_otel_export_batch():
                self.weave.init(
                    project,
                    settings={
                        "redact_pii": True,
                        "capture_code": False,
                        "implicitly_patch_integrations": False,
                        "print_call_link": False,
                    },
                )
            if self.require_pii_dependencies:
                settings = importlib.import_module("weave.trace.settings")
                if not settings.should_redact_pii():
                    raise RuntimeError("Weave PII redaction did not remain enabled")
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
            content=self._redact(item.content),
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

    def _destination_redact_string(self, value: str) -> str:
        if self.destination_string_redactor is None:
            raise WeaveImportError("Weave sink destination redaction was not initialized")
        try:
            redacted = self.destination_string_redactor(value)
        except Exception as error:
            raise WeaveImportError(
                "required destination PII redaction failed "
                f"({error.__class__.__name__}); source content was suppressed"
            ) from error
        if not isinstance(redacted, str):
            raise WeaveImportError("required destination PII redaction returned invalid content")
        return redacted

    def _llm(self, item: MappedLLM) -> Any:
        assert self.conversation_types is not None
        return self.conversation_types.LLM(
            model=redact_model_name(item.model),
            provider_name=redact_provider_name(item.provider),
            system_instructions=self._redact(item.system_instructions),
            usage=self.conversation_types.Usage(**item.usage),
            reasoning=self.conversation_types.Reasoning(content=self._redact(item.reasoning)),
            finish_reasons=self._redact(item.finish_reasons),
            input_messages=[self._message(message) for message in item.input_messages],
            output_messages=[self._message(message) for message in item.output_messages],
            started_at=item.started_at,
            ended_at=item.ended_at,
        )

    def _spill_tool(
        self,
        fragment: SpillFragment,
        *,
        started_at: datetime,
        ended_at: datetime,
    ) -> Any:
        """Build an already-redacted fragment without redacting it a second time."""
        assert self.conversation_types is not None
        tool_type = self._pre_redacted_transport_tool_type()
        return tool_type(
            name=SPILL_TOOL_NAME,
            arguments=fragment.arguments,
            result=fragment.content,
            tool_call_id=fragment.tool_call_id,
            tool_type=SPILL_TOOL_TYPE,
            tool_description=(
                "Lossless HiveMind transport fragment; reconstruct with its manifest and hash"
            ),
            started_at=started_at,
            ended_at=ended_at,
        )

    def _pre_redacted_transport_tool_type(self) -> Any:
        """Return an SDK Tool subtype that preserves encoded fragment bytes.

        Weave's ordinary Tool applies destination PII redaction to arguments
        and results in ``_build_attrs``. Fragment source was already redacted as
        one complete value and then base64-encoded; running Presidio on arbitrary
        encoded chunks can produce false positives and invalidate their hashes.
        The locked SDK routes Tool subtypes through this override in both batch
        and streaming paths.
        """
        assert self.conversation_types is not None
        base_type = self.conversation_types.Tool
        if not base_type.__module__.startswith("weave.conversation"):
            return base_type
        if self._transport_tool_type is not None:
            return self._transport_tool_type

        conversation_impl = importlib.import_module("weave.conversation.conversation")
        execute_tool_attributes = conversation_impl.execute_tool_attributes
        capture_info_attributes = conversation_impl._capture_info_attrs

        def _build_attrs(
            instance: Any,
            *,
            conversation_id: str,
            include_content: bool,
        ) -> dict[str, Any]:
            arguments = instance.arguments if include_content else ""
            result = instance.result if include_content else ""
            attributes = execute_tool_attributes(
                tool_name=instance.name,
                conversation_id=conversation_id,
                tool_call_arguments=arguments,
                tool_call_result=result,
                tool_call_id=instance.tool_call_id,
                tool_type=instance.tool_type,
                tool_description=instance.tool_description,
                tool_definitions=instance.tool_definitions,
            )
            attributes.update(capture_info_attributes())
            return attributes

        self._transport_tool_type = type(
            "HiveMindPreRedactedTransportTool",
            (base_type,),
            {
                "__module__": __name__,
                "_build_attrs": _build_attrs,
            },
        )
        return self._transport_tool_type

    def _tool(self, item: MappedTool, *, owner_id: str) -> tuple[Any, list[Any]]:
        assert self.conversation_types is not None
        # Analyze complete fields once, before splitting. Fragment content is
        # already at the final local-redaction boundary and must not be fed back
        # through an entity detector one arbitrary chunk at a time.
        arguments = self._redact(item.arguments)
        result = self._redact(item.result)
        plan = plan_tool_spill(
            arguments,
            result,
            owner_id=owner_id,
            serialized_redactor=self._destination_redact_string,
        )
        logical_tool = self.conversation_types.Tool(
            name=self._redact(item.name),
            arguments=plan.arguments,
            result=plan.result,
            tool_call_id=self._redact(item.tool_call_id),
            tool_type=self._redact(item.tool_type),
            tool_description=self._redact(item.description),
            started_at=item.started_at,
            ended_at=item.ended_at,
        )
        fragments = [
            self._spill_tool(
                fragment,
                started_at=item.started_at,
                ended_at=item.ended_at,
            )
            for fragment in plan.fragments
        ]
        return (logical_tool, fragments)

    def _subagent(self, item: MappedSubAgent) -> Any:
        assert self.conversation_types is not None
        return self.conversation_types.SubAgent(
            name=self._redact(item.name),
            model=redact_model_name(item.model),
            agent_id=self._redact(item.agent_id),
            agent_description=self._redact(item.description),
            agent_version=self._redact(item.version),
            system_instructions=self._redact(item.system_instructions),
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
        try:
            # Sanitization may already have chunked a large logical value. Put
            # it back together before the defense-in-depth redaction pass so
            # entity detection sees complete JSON/text rather than arbitrary
            # fragments. The exact final redacted value is spilled below.
            logical_attributes = restore_chunked_attributes(turn.attributes)
        except AttributeSafetyError as error:
            raise WeaveImportError(str(error)) from error
        attributes = self._redact(logical_attributes)
        if not isinstance(attributes, dict):
            raise WeaveImportError("turn attributes could not be safely redacted")
        # These opaque machine correlators are required for state reconciliation
        # and contain HiveMind identifiers rather than transcript content.
        for key in _STABLE_MACHINE_CORRELATION_ATTRIBUTES:
            if key in turn.attributes:
                attributes[key] = turn.attributes[key]
        try:
            # Build a compact root manifest and move exact post-redaction
            # archival values into bounded Tool fragments. This transport-only
            # plan deliberately does not mutate the turn or its payload hash.
            attribute_plan = plan_attribute_spill(attributes, owner_id=turn.key)
            attributes = attribute_plan.root_attributes
            validate_upload_attributes(attributes)
        except AttributeSafetyError as error:
            raise WeaveImportError(str(error)) from error
        spans: list[tuple[datetime, int, Any]] = []
        spans.extend((item.started_at, 0, self._llm(item)) for item in turn.llms)
        try:
            for index, item in enumerate(turn.tools):
                tool, fragments = self._tool(
                    item,
                    owner_id=f"{turn.key}:tool:{index}",
                )
                spans.append((item.started_at, 1, tool))
                spans.extend((item.started_at, 1, fragment) for fragment in fragments)
        except AttributeSafetyError as error:
            raise WeaveImportError(str(error)) from error
        spans.extend((item.started_at, 2, self._subagent(item)) for item in turn.subagents)
        spans.extend(
            (
                turn.ended_at,
                3,
                self._spill_tool(
                    fragment,
                    started_at=turn.ended_at,
                    ended_at=turn.ended_at,
                ),
            )
            for fragment in attribute_plan.fragments
        )
        spans.sort(key=lambda item: (item[0], item[1]))
        estimated_span_count = 1 + len(spans)
        if estimated_span_count > self.max_single_turn_spans:
            raise WeaveImportError(
                f"turn {turn.key} contains {estimated_span_count} spans, exceeding the "
                f"lossless per-turn safety limit of {self.max_single_turn_spans}"
            )
        if (
            self.pending_span_count
            and self.pending_span_count + estimated_span_count > self.flush_span_limit
        ):
            self.flush()
        try:
            result = self.weave.log_turn(
                conversation_id=conversation.conversation_id,
                conversation_name=self._redact(conversation.conversation_name),
                agent_name=redact_agent_name(conversation.agent_name),
                model=redact_model_name(conversation.model),
                agent_id=self._redact(conversation.agent_id),
                agent_description="Imported from W&B HiveMind",
                agent_version=self._redact(conversation.agent_version),
                messages=[self._message(message) for message in turn.messages],
                output_messages=[self._message(message) for message in turn.output_messages],
                system_instructions=self._redact(turn.system_instructions),
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
