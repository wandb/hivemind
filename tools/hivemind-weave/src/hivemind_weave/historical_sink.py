"""Atomic Weave historical-turn adapter.

This is deliberately separate from :mod:`weave_sink`.  The latter exercises
Weave's best-effort OpenTelemetry ``log_turn`` API; live HiveMind imports use
only the atomic prepare/upsert/status contract defined here.
"""

from __future__ import annotations

import importlib
import re
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from .attribute_safety import AttributeSafetyError, validate_upload_attributes
from .errors import (
    HistoricalTurnConflictError,
    HistoricalTurnUncertainError,
    WeaveImportError,
)
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
    disabled_weave_error_reporting,
    enforce_weave_error_reporting_disabled,
    validate_live_transport_environment,
    validate_trace_server_url,
)
from .weave_sink import (
    _STABLE_MACHINE_CORRELATION_ATTRIBUTES,
    LogOutcome,
    _assert_locked_weave_settings,
    _disable_weave_version_check,
    _pinned_weave_environment,
    expected_turn_span_count,
)

UploadRedactor = Callable[[Any], Any]
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_SUCCESS_STATUSES = frozenset({"committed", "replayed"})


def _required_capability_limit(capabilities: Any, *names: str) -> int:
    for name in names:
        value = getattr(capabilities, name, None)
        if type(value) is int and value > 0:
            return value
    raise WeaveImportError(
        "destination did not advertise every required historical-turn byte/count limit"
    )


@dataclass(frozen=True)
class PreparedOutcome:
    """Content-free metadata for one exact SDK-prepared turn."""

    logical_key: str
    wire_sha256: str
    span_count: int
    compressed_bytes: int
    uncompressed_bytes: int
    reference_count: int
    capability_version: str
    sdk_prepared: Any


class HistoricalTurnSink:
    """Prepare and atomically upsert fully formed historical agent turns."""

    # The importer uses this marker to distinguish safe server-idempotent
    # replay from the legacy OTLP path, where retrying an ambiguous pending
    # journal row can duplicate a partial trace.
    supports_atomic_replay = True

    def __init__(
        self,
        *,
        weave_module: Any | None = None,
        conversation_module: Any | None = None,
        require_pii_dependencies: bool = True,
        upload_redactor: UploadRedactor | None = None,
        trace_server_url: str = "https://trace.wandb.ai",
        wandb_base_url: str = "https://api.wandb.ai",
    ) -> None:
        self.weave = weave_module
        self.conversation_types = conversation_module
        self.require_pii_dependencies = require_pii_dependencies
        self.upload_redactor = upload_redactor
        self.trace_server_url = validate_trace_server_url(trace_server_url)
        self.wandb_base_url = wandb_base_url
        self.project = ""
        self.started = False
        self.capabilities: Any | None = None
        self.capability_version = ""
        self._prepared: dict[tuple[str, str, str], PreparedOutcome] = {}
        self._real_weave_sdk = False

    def _enforce_error_reporting_disabled(self) -> None:
        if self._real_weave_sdk:
            enforce_weave_error_reporting_disabled()

    def _redact(self, value: Any) -> Any:
        if self.upload_redactor is None:
            raise WeaveImportError("historical-turn redaction was not initialized")
        try:
            return self.upload_redactor(value)
        except Exception as error:
            raise WeaveImportError(
                "required local PII redaction failed "
                f"({error.__class__.__name__}); source content was suppressed"
            ) from error

    @staticmethod
    def _required_callable(module: Any, name: str) -> Callable[..., Any]:
        value = getattr(module, name, None)
        if not callable(value):
            raise WeaveImportError(
                "installed Weave SDK does not support atomic historical-turn "
                f"imports (missing {name})"
            )
        return value

    def _close_unaccepted_sdk(self) -> None:
        """Best-effort teardown after init but before capability acceptance."""
        try:
            if self.weave is not None:
                self.weave.finish()
        except Exception:
            # The capability rejection is authoritative and content-free. SDK
            # shutdown diagnostics must not replace it or leak internal state.
            pass
        self.capabilities = None
        self.capability_version = ""
        self._prepared.clear()
        self._real_weave_sdk = False

    def _reject_initialized_sdk(self, message: str) -> None:
        """Close an initialized client before rejecting its capability contract."""
        self._close_unaccepted_sdk()
        raise WeaveImportError(message)

    def start(self, project: str) -> None:
        """Initialize the SDK and prove the destination supports atomic turns."""
        if self.started:
            if project != self.project:
                raise WeaveImportError(
                    "an initialized historical-turn sink cannot change destination projects"
                )
            # Applying a sealed plan deliberately keeps one initialized client
            # alive between exact re-preparation and submission.  Reusing it
            # preserves the capability snapshot and the cached SDK-prepared
            # envelopes that were just compared with the plan certificates.
            return
        init_attempted = False
        try:
            validate_live_transport_environment()
            if self.require_pii_dependencies:
                importlib.import_module("presidio_analyzer")
                importlib.import_module("presidio_anonymizer")
        except Exception as error:
            if isinstance(error, WeaveImportError):
                raise
            raise WeaveImportError(
                f"atomic historical-turn prerequisites are unavailable ({error.__class__.__name__})"
            ) from error

        try:
            with (
                disabled_weave_error_reporting(),
                _pinned_weave_environment(self.trace_server_url, self.wandb_base_url),
            ):
                if self.weave is None:
                    self.weave = importlib.import_module("weave")
                if self.conversation_types is None:
                    self.conversation_types = importlib.import_module("weave.conversation")
                real_weave_sdk = getattr(self.weave, "__name__", "") == "weave"
                self._real_weave_sdk = real_weave_sdk
                if real_weave_sdk:
                    enforce_weave_error_reporting_disabled()
                    _disable_weave_version_check()
                if self.require_pii_dependencies:
                    configure_weave_pii()
                    self.upload_redactor = self.upload_redactor or redact_upload_data
                else:
                    self.upload_redactor = self.upload_redactor or redact_data

                prepare = self._required_callable(self.weave, "prepare_turn")
                del prepare
                self._required_callable(self.weave, "upsert_turn")
                self._required_callable(self.weave, "get_turn_status")
                capabilities_fn = self._required_callable(self.weave, "get_turn_capabilities")
                init_attempted = True
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
                    enforce_weave_error_reporting_disabled()
                    _disable_weave_version_check()
                    _assert_locked_weave_settings()
                self.capabilities = capabilities_fn()
        except WeaveImportError:
            if init_attempted:
                self._close_unaccepted_sdk()
            raise
        except Exception as error:
            if init_attempted:
                self._close_unaccepted_sdk()
            raise WeaveImportError(
                "could not initialize atomic Weave historical-turn transport "
                f"({error.__class__.__name__}); SDK diagnostics were suppressed"
            ) from error

        supported = bool(getattr(self.capabilities, "supported", False))
        atomic = bool(getattr(self.capabilities, "atomic_turn_commit", False))
        durable = bool(getattr(self.capabilities, "durable_idempotency", False))
        status_support = bool(getattr(self.capabilities, "status_lookup", False))
        capability_version = str(getattr(self.capabilities, "capability_version", ""))
        transport_encoding = str(getattr(self.capabilities, "transport_encoding", ""))
        content_encoding = str(getattr(self.capabilities, "content_encoding", ""))
        content_refs = str(getattr(self.capabilities, "content_refs", ""))
        if not supported or not atomic or not durable or not status_support:
            self._reject_initialized_sdk(
                "destination did not advertise atomic turn commits, durable idempotency, "
                "and status reconciliation"
            )
        if not capability_version:
            self._reject_initialized_sdk(
                "destination did not advertise a historical-turn capability version"
            )
        if (
            transport_encoding != "protobuf"
            or content_encoding != "gzip"
            or content_refs != "immutable"
        ):
            self._reject_initialized_sdk(
                "destination does not support the required gzipped protobuf transport "
                "and immutable authenticated text references"
            )
        try:
            _required_capability_limit(
                self.capabilities,
                "max_turn_compressed_bytes",
                "max_compressed_bytes",
                "max_request_compressed_bytes",
            )
            _required_capability_limit(
                self.capabilities,
                "max_turn_uncompressed_bytes",
                "max_uncompressed_bytes",
                "max_decompressed_bytes",
                "max_envelope_bytes",
            )
            _required_capability_limit(
                self.capabilities,
                "max_turn_span_count",
                "max_span_count",
                "max_spans",
            )
            _required_capability_limit(
                self.capabilities,
                "max_turn_reference_count",
                "max_reference_count",
                "max_references",
            )
        except WeaveImportError as error:
            self._reject_initialized_sdk(str(error))
        self.project = project
        self.capability_version = capability_version
        self._prepared.clear()
        self.started = True

    def _message(self, item: ChatMessage) -> Any:
        assert self.conversation_types is not None
        return self.conversation_types.Message(
            role=item.role,
            content=str(self._redact(item.content)),
        )

    def _llm(self, item: MappedLLM) -> Any:
        assert self.conversation_types is not None
        return self.conversation_types.LLM(
            model=redact_model_name(item.model),
            provider_name=redact_provider_name(item.provider),
            system_instructions=[str(self._redact(value)) for value in item.system_instructions],
            usage=self.conversation_types.Usage(**item.usage),
            reasoning=self.conversation_types.Reasoning(content=str(self._redact(item.reasoning))),
            finish_reasons=self._redact(item.finish_reasons),
            input_messages=[self._message(message) for message in item.input_messages],
            output_messages=[self._message(message) for message in item.output_messages],
            started_at=item.started_at,
            ended_at=item.ended_at,
        )

    def _tool(self, item: MappedTool) -> Any:
        assert self.conversation_types is not None
        return self.conversation_types.Tool(
            name=str(self._redact(item.name)),
            arguments=self._redact(item.arguments),
            result=self._redact(item.result),
            tool_call_id=str(self._redact(item.tool_call_id)),
            tool_type=str(self._redact(item.tool_type)),
            tool_description=str(self._redact(item.description)),
            started_at=item.started_at,
            ended_at=item.ended_at,
        )

    def _subagent(self, item: MappedSubAgent) -> Any:
        assert self.conversation_types is not None
        return self.conversation_types.SubAgent(
            name=str(self._redact(item.name)),
            model=redact_model_name(item.model),
            agent_id=str(self._redact(item.agent_id)),
            agent_description=str(self._redact(item.description)),
            agent_version=str(self._redact(item.version)),
            system_instructions=[str(self._redact(value)) for value in item.system_instructions],
            started_at=item.started_at,
            ended_at=item.ended_at,
        )

    def prepare_turn(
        self,
        conversation: MappedConversation,
        turn: MappedTurn,
    ) -> PreparedOutcome:
        if not self.started or self.weave is None:
            raise WeaveImportError("atomic Weave historical-turn sink was not initialized")

        cache_key = (conversation.conversation_id, turn.key, turn.payload_sha256)
        cached = self._prepared.get(cache_key)
        if cached is not None:
            return cached

        attributes = self._redact(turn.attributes)
        if not isinstance(attributes, dict):
            raise WeaveImportError("turn attributes could not be safely redacted")
        for key in _STABLE_MACHINE_CORRELATION_ATTRIBUTES:
            if key in turn.attributes:
                attributes[key] = turn.attributes[key]
        try:
            validate_upload_attributes(attributes)
        except AttributeSafetyError as error:
            raise WeaveImportError(str(error)) from error

        spans: list[tuple[Any, int, Any]] = []
        spans.extend((item.started_at, 0, self._llm(item)) for item in turn.llms)
        spans.extend((item.started_at, 1, self._tool(item)) for item in turn.tools)
        spans.extend((item.started_at, 2, self._subagent(item)) for item in turn.subagents)
        spans.sort(key=lambda item: (item[0], item[1]))
        source_hash = str(
            turn.attributes.get("hivemind.source_payload_sha256") or turn.payload_sha256
        )
        try:
            self._enforce_error_reporting_disabled()
            prepared = self.weave.prepare_turn(
                conversation_id=conversation.conversation_id,
                conversation_name=str(self._redact(conversation.conversation_name)),
                agent_name=redact_agent_name(conversation.agent_name),
                model=redact_model_name(conversation.model),
                agent_id=str(self._redact(conversation.agent_id)),
                agent_description="Imported from W&B HiveMind",
                agent_version=str(self._redact(conversation.agent_version)),
                messages=[self._message(message) for message in turn.messages],
                output_messages=[self._message(message) for message in turn.output_messages],
                system_instructions=[
                    str(self._redact(value)) for value in turn.system_instructions
                ],
                spans=[item[2] for item in spans],
                started_at=turn.started_at,
                ended_at=turn.ended_at,
                include_content=True,
                attributes=attributes,
                turn_key=turn.key,
                source_payload_sha256=source_hash,
            )
        except Exception as error:
            raise WeaveImportError(
                f"Weave could not prepare turn {turn.key} ({error.__class__.__name__}); "
                "transcript-bearing diagnostics were suppressed"
            ) from error

        logical_key = str(getattr(prepared, "logical_key", ""))
        wire_hash = str(getattr(prepared, "wire_sha256", ""))
        prepared_capability_version = str(getattr(prepared, "capability_version", ""))
        span_count = int(getattr(prepared, "span_count", 0) or 0)
        expected = expected_turn_span_count(turn)
        if not _SHA256.fullmatch(logical_key) or not _SHA256.fullmatch(wire_hash):
            raise WeaveImportError("Weave returned malformed historical-turn identity metadata")
        if prepared_capability_version != self.capability_version:
            raise WeaveImportError("Weave prepared the turn under a different capability version")
        if span_count != expected:
            raise WeaveImportError(
                f"Weave prepared {span_count} spans for turn {turn.key}, expected {expected}"
            )
        outcome = PreparedOutcome(
            logical_key=logical_key,
            wire_sha256=wire_hash,
            span_count=span_count,
            compressed_bytes=int(getattr(prepared, "compressed_bytes", 0) or 0),
            uncompressed_bytes=int(getattr(prepared, "uncompressed_bytes", 0) or 0),
            reference_count=int(getattr(prepared, "reference_count", 0) or 0),
            capability_version=prepared_capability_version,
            sdk_prepared=prepared,
        )
        self._prepared[cache_key] = outcome
        return outcome

    def log_turn(
        self,
        conversation: MappedConversation,
        turn: MappedTurn,
    ) -> LogOutcome:
        prepared = self.prepare_turn(conversation, turn)
        assert self.weave is not None
        try:
            self._enforce_error_reporting_disabled()
            result = self.weave.upsert_turn(prepared.sdk_prepared)
        except Exception as error:
            raise HistoricalTurnUncertainError(
                f"atomic upload for turn {turn.key} was not acknowledged "
                f"({error.__class__.__name__}); reconcile its logical key before retrying"
            ) from error
        status = str(getattr(result, "status", ""))
        trace_ids = [str(value) for value in getattr(result, "trace_ids", [])]
        root_span_ids = [str(value) for value in getattr(result, "root_span_ids", [])]
        span_count = int(getattr(result, "span_count", 0) or 0)
        commit_id = str(getattr(result, "commit_id", ""))
        if status == "conflict":
            raise HistoricalTurnConflictError(
                f"atomic upload for turn {turn.key} conflicts with existing content"
            )
        if status not in _SUCCESS_STATUSES:
            raise HistoricalTurnUncertainError(
                f"atomic upload for turn {turn.key} returned unresolved status {status!r}"
            )
        if not trace_ids or not root_span_ids or span_count != prepared.span_count:
            raise HistoricalTurnUncertainError(
                f"atomic upload for turn {turn.key} returned incomplete commit evidence"
            )
        status_result = self.get_status(prepared.logical_key)
        reconciled = self._outcome_from_status(prepared, status_result)
        if reconciled is None or (
            reconciled.trace_ids != trace_ids
            or reconciled.root_span_ids != root_span_ids
            or reconciled.span_count != span_count
            or not commit_id
            or reconciled.commit_id != commit_id
        ):
            raise HistoricalTurnUncertainError(
                f"atomic status lookup for turn {turn.key} did not match its acknowledgement"
            )
        return reconciled

    def reconcile_prepared(self, prepared: PreparedOutcome) -> LogOutcome | None:
        """Resolve a prior submission by exact key before deciding to replay it."""
        return self._outcome_from_status(
            prepared,
            self.get_status(prepared.logical_key),
        )

    def _outcome_from_status(
        self,
        prepared: PreparedOutcome,
        status_result: Any,
    ) -> LogOutcome | None:
        status = str(getattr(status_result, "status", ""))
        if status == "absent":
            return None
        if status == "committing":
            raise HistoricalTurnUncertainError(
                "historical turn is still committing; retry status reconciliation later"
            )
        if status != "committed":
            raise HistoricalTurnConflictError(
                "historical turn status is incompatible with the prepared logical key"
            )
        logical_key = str(getattr(status_result, "logical_key", ""))
        wire_sha256 = str(getattr(status_result, "wire_sha256", ""))
        span_count = int(getattr(status_result, "span_count", 0) or 0)
        trace_ids = [str(value) for value in getattr(status_result, "trace_ids", [])]
        root_span_ids = [str(value) for value in getattr(status_result, "root_span_ids", [])]
        commit_id = str(getattr(status_result, "commit_id", ""))
        if (
            logical_key != prepared.logical_key
            or wire_sha256 != prepared.wire_sha256
            or span_count != prepared.span_count
            or not trace_ids
            or not root_span_ids
            or not commit_id
        ):
            raise HistoricalTurnConflictError(
                "historical turn status evidence does not match the prepared envelope"
            )
        return LogOutcome(
            trace_ids=trace_ids,
            root_span_ids=root_span_ids,
            span_count=span_count,
            logical_key=logical_key,
            wire_sha256=wire_sha256,
            commit_id=commit_id,
            reference_count=prepared.reference_count,
            capability_version=prepared.capability_version,
        )

    def get_status(self, logical_key: str) -> Any:
        if not self.started or self.weave is None or not _SHA256.fullmatch(logical_key):
            raise WeaveImportError("cannot reconcile an invalid historical-turn logical key")
        try:
            self._enforce_error_reporting_disabled()
            return self.weave.get_turn_status(logical_key)
        except Exception as error:
            raise HistoricalTurnUncertainError(
                "could not reconcile historical turn "
                f"({error.__class__.__name__}); diagnostics were suppressed"
            ) from error

    def flush(self) -> None:
        """Atomic upserts are synchronous; no exporter queue exists."""

    def finish(self) -> None:
        if not self.started or self.weave is None:
            return
        try:
            self.weave.finish()
        except Exception as error:
            raise WeaveImportError(
                f"could not finish Weave ({error.__class__.__name__}); diagnostics were suppressed"
            ) from error
        finally:
            self.started = False
            self.capability_version = ""
            self._prepared.clear()
            self._real_weave_sdk = False
