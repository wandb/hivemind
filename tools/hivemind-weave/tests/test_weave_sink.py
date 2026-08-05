from __future__ import annotations

import json
import os
from collections.abc import Callable
from dataclasses import replace
from types import SimpleNamespace
from typing import Any

import pytest

from hivemind_weave import weave_sink as weave_sink_module
from hivemind_weave.atif import map_atif
from hivemind_weave.attribute_safety import (
    MAX_INLINE_FIELD_JSON_BYTES,
    MAX_ROOT_ATTRIBUTE_BYTES,
    MAX_TURN_CONTENT_JSON_BYTES,
)
from hivemind_weave.errors import WeaveImportError
from hivemind_weave.models import MappedSubAgent, Session
from hivemind_weave.pii import configure_weave_pii, redact_upload_data
from hivemind_weave.weave_sink import WeaveSink, expected_turn_span_count


class Box:
    def __init__(self, **values: Any) -> None:
        self.__dict__.update(values)


class FakeConversationModule:
    Message = Box
    Usage = Box
    Reasoning = Box
    LLM = Box
    Tool = Box
    SubAgent = Box


class FakeWeave:
    def __init__(self, *, empty: bool = False) -> None:
        self.empty = empty
        self.initialized: tuple[str, dict[str, Any]] | None = None
        self.otel_export_batch_at_init: str | None = None
        self.trace_server_at_init: str | None = None
        self.wandb_base_at_init: str | None = None
        self.error_reporting_at_init: str | None = None
        self.logged: list[dict[str, Any]] = []
        self.finished = False

    def init(self, project: str, *, settings: dict[str, Any]) -> None:
        self.otel_export_batch_at_init = os.environ.get("OTEL_BSP_MAX_EXPORT_BATCH_SIZE")
        self.trace_server_at_init = os.environ.get("WF_TRACE_SERVER_URL")
        self.wandb_base_at_init = os.environ.get("WANDB_BASE_URL")
        self.error_reporting_at_init = os.environ.get("WANDB_ERROR_REPORTING")
        self.initialized = (project, settings)

    def log_turn(self, **payload: Any) -> SimpleNamespace:
        self.logged.append(payload)
        if self.empty:
            return SimpleNamespace(trace_ids=[], root_span_ids=[], span_count=0)
        return SimpleNamespace(
            trace_ids=["trace-1"],
            root_span_ids=["root-1"],
            span_count=1 + len(payload["spans"]),
        )

    def finish(self) -> None:
        self.finished = True


def _sink(fake: FakeWeave, **kwargs: Any) -> WeaveSink:
    return WeaveSink(
        weave_module=fake,
        conversation_module=FakeConversationModule,
        require_pii_dependencies=False,
        **kwargs,
    )


def test_sink_builds_batch_sdk_objects_and_flushes(
    session_payload: Callable[..., dict[str, Any]],
    atif_wrapper: Callable[..., dict[str, Any]],
) -> None:
    conversation = map_atif(Session.from_api(session_payload()), atif_wrapper())
    fake = FakeWeave()
    sink = _sink(fake)
    sink.start("wandb/hivemind-chats")
    outcome = sink.log_turn(conversation, conversation.turns[0])
    sink.finish()

    assert fake.initialized is not None
    assert fake.initialized[1] == {
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
    }
    assert fake.trace_server_at_init == "https://trace.wandb.ai"
    assert fake.wandb_base_at_init == "https://api.wandb.ai"
    assert fake.error_reporting_at_init == "false"
    payload = fake.logged[0]
    assert payload["conversation_id"].startswith("hivemind:")
    assert payload["output_messages"][0].content == "Created hello.txt."
    assert payload["include_content"] is True
    expected_spans = expected_turn_span_count(conversation.turns[0])
    assert all(type(span).__name__ == "Box" for span in payload["spans"])
    assert len(payload["spans"]) == expected_spans - 1
    assert outcome.trace_ids == ["trace-1"]
    assert outcome.span_count == expected_spans
    assert fake.finished is True


def test_sink_bounds_otel_export_batches_during_weave_init(monkeypatch: Any) -> None:
    monkeypatch.delenv("OTEL_BSP_MAX_EXPORT_BATCH_SIZE", raising=False)
    monkeypatch.delenv("OTEL_BSP_MAX_QUEUE_SIZE", raising=False)
    fake = FakeWeave()
    _sink(fake).start("wandb/hivemind-chats")
    assert fake.otel_export_batch_at_init == "4"
    assert "OTEL_BSP_MAX_EXPORT_BATCH_SIZE" not in os.environ


def test_sink_accepts_only_reviewed_explicit_otel_batch_sizes(monkeypatch: Any) -> None:
    monkeypatch.setenv("OTEL_BSP_MAX_EXPORT_BATCH_SIZE", "4")
    fake = FakeWeave()
    _sink(fake).start("wandb/hivemind-chats")
    assert fake.otel_export_batch_at_init == "4"

    monkeypatch.setenv("OTEL_BSP_MAX_EXPORT_BATCH_SIZE", "7")
    with pytest.raises(WeaveImportError, match="exceeds"):
        _sink(FakeWeave()).start("wandb/hivemind-chats")


def test_sink_clamps_automatic_export_batch_to_explicit_queue(monkeypatch: Any) -> None:
    monkeypatch.delenv("OTEL_BSP_MAX_EXPORT_BATCH_SIZE", raising=False)
    monkeypatch.setenv("OTEL_BSP_MAX_QUEUE_SIZE", "2")
    fake = FakeWeave()
    _sink(fake).start("wandb/hivemind-chats")
    assert fake.otel_export_batch_at_init == "2"
    assert "OTEL_BSP_MAX_EXPORT_BATCH_SIZE" not in os.environ


def test_sink_restores_endpoint_and_blank_batch_environment(monkeypatch: Any) -> None:
    monkeypatch.setenv("OTEL_BSP_MAX_EXPORT_BATCH_SIZE", "  ")
    monkeypatch.setenv("WF_TRACE_SERVER_URL", "https://trace.wandb.ai")
    monkeypatch.setenv("WANDB_BASE_URL", "https://original.example")
    monkeypatch.setenv("WANDB_ERROR_REPORTING", "true")
    fake = FakeWeave()
    _sink(fake).start("wandb/hivemind-chats")
    assert fake.otel_export_batch_at_init == "4"
    assert os.environ["OTEL_BSP_MAX_EXPORT_BATCH_SIZE"] == "  "
    assert os.environ["WF_TRACE_SERVER_URL"] == "https://trace.wandb.ai"
    assert os.environ["WANDB_BASE_URL"] == "https://original.example"
    assert os.environ["WANDB_ERROR_REPORTING"] == "true"


def test_sink_rejects_insecure_transport_environment(monkeypatch: Any) -> None:
    monkeypatch.setenv("WEAVE_INSECURE_DISABLE_SSL", "true")
    with pytest.raises(WeaveImportError, match="INSECURE"):
        _sink(FakeWeave()).start("wandb/hivemind-chats")


def test_real_sink_rejects_a_preexisting_tracer_provider(monkeypatch: Any) -> None:
    fake = FakeWeave()
    fake.__name__ = "weave"
    monkeypatch.setattr(
        weave_sink_module,
        "_assert_weave_error_reporting_disabled",
        lambda: None,
    )
    monkeypatch.setattr(
        weave_sink_module,
        "_assert_no_preexisting_tracer_provider",
        lambda: (_ for _ in ()).throw(
            WeaveImportError("a pre-existing OpenTelemetry tracer provider is forbidden")
        ),
    )
    with pytest.raises(WeaveImportError, match="pre-existing"):
        _sink(fake).start("wandb/hivemind-chats")
    assert fake.initialized is None


def test_real_sink_checks_owned_exporter_after_init(monkeypatch: Any) -> None:
    fake = FakeWeave()
    fake.__name__ = "weave"
    checked: list[str] = []
    monkeypatch.setattr(
        weave_sink_module,
        "_assert_no_preexisting_tracer_provider",
        lambda: None,
    )
    monkeypatch.setattr(
        weave_sink_module,
        "_assert_weave_error_reporting_disabled",
        lambda: None,
    )
    monkeypatch.setattr(
        weave_sink_module,
        "_assert_locked_weave_settings",
        lambda: None,
    )
    version_check_disables: list[None] = []
    monkeypatch.setattr(
        weave_sink_module,
        "_disable_weave_version_check",
        lambda: version_check_disables.append(None),
    )
    monkeypatch.setattr(
        weave_sink_module,
        "_assert_owned_weave_transport",
        checked.append,
    )

    _sink(fake, trace_server_url="https://trace.example").start("wandb/hivemind-chats")

    assert checked == ["https://trace.example"]
    assert version_check_disables == [None, None]
    assert fake.initialized is not None


def test_weave_pypi_version_check_is_replaced_with_a_noop(monkeypatch: Any) -> None:
    def original() -> str:
        return "network request"

    init_message = SimpleNamespace(_print_version_check=original)
    monkeypatch.setattr(
        weave_sink_module.importlib,
        "import_module",
        lambda _name: init_message,
    )

    weave_sink_module._disable_weave_version_check()

    assert init_message._print_version_check is weave_sink_module._disabled_weave_version_check
    assert init_message._print_version_check() is None


def test_weave_error_reporting_must_already_be_disabled(monkeypatch: Any) -> None:
    monkeypatch.setattr(
        weave_sink_module,
        "enforce_weave_error_reporting_disabled",
        lambda: None,
    )
    weave_sink_module._assert_weave_error_reporting_disabled()

    monkeypatch.setattr(
        weave_sink_module,
        "enforce_weave_error_reporting_disabled",
        lambda: (_ for _ in ()).throw(RuntimeError("error reporting enabled")),
    )
    with pytest.raises(WeaveImportError, match="error reporting"):
        weave_sink_module._assert_weave_error_reporting_disabled()


def test_locked_weave_settings_reject_local_persistence(monkeypatch: Any) -> None:
    settings = SimpleNamespace(
        should_redact_pii=lambda: True,
        redact_pii_fields=lambda: [],
        redact_pii_exclude_fields=lambda: [],
        use_server_cache=lambda: False,
        should_enable_disk_fallback=lambda: False,
        should_enable_wal=lambda: False,
        should_capture_code=lambda: False,
        should_capture_client_info=lambda: False,
        should_capture_system_info=lambda: False,
        should_implicitly_patch_integrations=lambda: False,
        should_print_call_link=lambda: False,
        should_use_stainless_server=lambda: False,
        should_allow_unsafe_custom_obj_decode=lambda: False,
        log_level=lambda: "WARNING",
    )
    monkeypatch.setattr(
        weave_sink_module.importlib,
        "import_module",
        lambda _name: settings,
    )
    weave_sink_module._assert_locked_weave_settings()

    settings.use_server_cache = lambda: True
    with pytest.raises(WeaveImportError, match="server disk cache"):
        weave_sink_module._assert_locked_weave_settings()


def test_owned_exporter_disables_ambient_requests_environment(monkeypatch: Any) -> None:
    provider = object()
    session = SimpleNamespace(trust_env=True, max_redirects=30)
    exporter = SimpleNamespace(
        _endpoint="https://trace.example/agents/otel/v1/traces",
        _certificate_file=True,
        _client_key_file=None,
        _client_certificate_file=None,
        _client_cert=None,
        _session=session,
    )
    modules = {
        "opentelemetry.trace": SimpleNamespace(
            get_tracer_provider=lambda: provider,
        ),
        "weave.trace.weave_init": SimpleNamespace(
            _conversation_tracer_provider=provider,
            _conversation_span_exporter=exporter,
        ),
        "weave.trace.urls": SimpleNamespace(
            otel_traces_endpoint=lambda base: f"{base}/agents/otel/v1/traces",
        ),
    }
    monkeypatch.setattr(
        weave_sink_module.importlib,
        "import_module",
        lambda name: modules[name],
    )

    weave_sink_module._assert_owned_weave_transport("https://trace.example")

    assert session.trust_env is False
    assert session.max_redirects == 0


@pytest.mark.parametrize(
    ("attribute", "value", "message"),
    [
        ("_endpoint", "https://unexpected.example/v1/traces", "unexpected"),
        ("_certificate_file", False, "certificate verification"),
        ("_client_key_file", "client.key", "client credentials"),
        ("_session", None, "reviewable HTTP session"),
    ],
)
def test_owned_exporter_rejects_unreviewed_transport(
    monkeypatch: Any,
    attribute: str,
    value: Any,
    message: str,
) -> None:
    provider = object()
    exporter = SimpleNamespace(
        _endpoint="https://trace.example/agents/otel/v1/traces",
        _certificate_file=True,
        _client_key_file=None,
        _client_certificate_file=None,
        _client_cert=None,
        _session=SimpleNamespace(trust_env=True, max_redirects=30),
    )
    setattr(exporter, attribute, value)
    modules = {
        "opentelemetry.trace": SimpleNamespace(
            get_tracer_provider=lambda: provider,
        ),
        "weave.trace.weave_init": SimpleNamespace(
            _conversation_tracer_provider=provider,
            _conversation_span_exporter=exporter,
        ),
        "weave.trace.urls": SimpleNamespace(
            otel_traces_endpoint=lambda base: f"{base}/agents/otel/v1/traces",
        ),
    }
    monkeypatch.setattr(
        weave_sink_module.importlib,
        "import_module",
        lambda name: modules[name],
    )

    with pytest.raises(WeaveImportError, match=message):
        weave_sink_module._assert_owned_weave_transport("https://trace.example")


def test_empty_log_result_is_a_failure(
    session_payload: Callable[..., dict[str, Any]],
    atif_wrapper: Callable[..., dict[str, Any]],
) -> None:
    conversation = map_atif(Session.from_api(session_payload()), atif_wrapper())
    sink = _sink(FakeWeave(empty=True))
    sink.start("wandb/hivemind-chats")
    with pytest.raises(WeaveImportError, match="emitted no trace"):
        sink.log_turn(conversation, conversation.turns[0])


def test_real_weave_0534_conversation_models_accept_mapped_payload(
    session_payload: Callable[..., dict[str, Any]],
    atif_wrapper: Callable[..., dict[str, Any]],
) -> None:
    conversation_types = pytest.importorskip("weave.conversation")
    conversation = map_atif(Session.from_api(session_payload()), atif_wrapper())
    turn = conversation.turns[0]
    turn.subagents.append(
        MappedSubAgent(
            name="reviewer",
            model="o3",
            agent_id="child-1",
            description="explicit delegation",
            version="1",
            system_instructions=[],
            started_at=turn.started_at,
            ended_at=turn.ended_at,
            timestamp_inferred=True,
        )
    )
    fake = FakeWeave()
    sink = WeaveSink(
        weave_module=fake,
        conversation_module=conversation_types,
        require_pii_dependencies=False,
    )
    sink.start("wandb/hivemind-chats")
    sink.log_turn(conversation, turn)
    spans = fake.logged[0]["spans"]
    assert sum(isinstance(span, conversation_types.LLM) for span in spans) == len(turn.llms)
    assert sum(isinstance(span, conversation_types.Tool) for span in spans) == len(turn.tools)
    assert sum(isinstance(span, conversation_types.SubAgent) for span in spans) == 1


def test_sink_applies_backpressure_before_the_otel_queue_can_fill(
    monkeypatch: Any,
    session_payload: Callable[..., dict[str, Any]],
    atif_wrapper: Callable[..., dict[str, Any]],
) -> None:
    conversation = map_atif(Session.from_api(session_payload()), atif_wrapper())
    sink = _sink(FakeWeave(), flush_span_limit=3)
    flushes: list[int] = []
    monkeypatch.setattr(sink, "_force_flush", lambda: flushes.append(1))
    sink.start("wandb/hivemind-chats")
    sink.log_turn(conversation, conversation.turns[0])
    assert flushes == [1]
    assert sink.pending_span_count == 0


def test_sink_rejects_a_single_turn_with_too_many_spans(
    session_payload: Callable[..., dict[str, Any]],
    atif_wrapper: Callable[..., dict[str, Any]],
) -> None:
    conversation = map_atif(Session.from_api(session_payload()), atif_wrapper())
    fake = FakeWeave()
    sink = _sink(fake, max_single_turn_spans=3)
    sink.start("wandb/hivemind-chats")
    with pytest.raises(WeaveImportError, match="per-turn safety limit"):
        sink.log_turn(conversation, conversation.turns[0])
    assert fake.logged == []


def test_sink_rejects_oversized_attributes_before_upload(
    session_payload: Callable[..., dict[str, Any]],
    atif_wrapper: Callable[..., dict[str, Any]],
) -> None:
    conversation = map_atif(Session.from_api(session_payload()), atif_wrapper())
    conversation.turns[0].attributes["oversized"] = "x" * MAX_ROOT_ATTRIBUTE_BYTES
    fake = FakeWeave()
    sink = _sink(fake)
    sink.start("wandb/hivemind-chats")
    with pytest.raises(WeaveImportError, match="was not sent"):
        sink.log_turn(conversation, conversation.turns[0])
    assert fake.logged == []


def test_sink_rejects_oversized_tool_fields_before_upload(
    session_payload: Callable[..., dict[str, Any]],
    atif_wrapper: Callable[..., dict[str, Any]],
) -> None:
    conversation = map_atif(Session.from_api(session_payload()), atif_wrapper())
    turn = conversation.turns[0]
    turn.tools[0] = replace(turn.tools[0], result="x" * MAX_INLINE_FIELD_JSON_BYTES)
    fake = FakeWeave()
    sink = _sink(fake)
    sink.start("wandb/hivemind-chats")
    with pytest.raises(WeaveImportError, match="tool result"):
        sink.log_turn(conversation, turn)
    assert fake.logged == []


def test_sink_rejects_oversized_aggregate_turn_before_upload(
    session_payload: Callable[..., dict[str, Any]],
    atif_wrapper: Callable[..., dict[str, Any]],
) -> None:
    conversation = map_atif(Session.from_api(session_payload()), atif_wrapper())
    turn = conversation.turns[0]
    # Many individually small fields can still exceed the aggregate budget.
    turn.system_instructions = ["x" * 10_000] * (MAX_TURN_CONTENT_JSON_BYTES // 10_000)
    fake = FakeWeave()
    sink = _sink(fake)
    sink.start("wandb/hivemind-chats")
    with pytest.raises(WeaveImportError, match="aggregate"):
        sink.log_turn(conversation, turn)
    assert fake.logged == []


def test_sink_fails_closed_when_weave_pii_is_disabled(monkeypatch: Any) -> None:
    monkeypatch.setenv("WEAVE_REDACT_PII", "false")
    sink = WeaveSink(weave_module=FakeWeave(), conversation_module=FakeConversationModule)
    with pytest.raises(WeaveImportError, match="disables required"):
        sink.start("wandb/hivemind-chats")


def test_exact_mocked_sdk_payload_has_local_pii_redaction(
    session_payload: Callable[..., dict[str, Any]],
    atif_wrapper: Callable[..., dict[str, Any]],
) -> None:
    ordinary_code = "class Washington:\n    pass"
    opaque_token = "plainopaquecredentialvalue1234567890"
    token_key = "sk-proj-abcdefghijklmnopqrstuvwxyz1234567890"
    wrapper = atif_wrapper(
        agent={
            "name": "Alice Johnson",
            "version": "Alice Johnson version",
            "model_name": "alice@example.com",
            "provider_name": "Alice Johnson",
        }
    )
    wrapper["metadata"] = {"reviewer": "Alice Johnson in New York", token_key: "value"}
    wrapper["trajectory"]["steps"][1]["message"] = (
        "Ask Alice Johnson in New York via alice@example.com"
    )
    call = wrapper["trajectory"]["steps"][2]["tool_calls"][0]
    call["tool_call_id"] = "Alice Johnson"
    call["arguments"]["content"] = ordinary_code
    call["arguments"]["token"] = opaque_token
    wrapper["trajectory"]["steps"][2]["observation"]["results"][0]["source_call_id"] = (
        "Alice Johnson"
    )
    conversation = map_atif(
        Session.from_api(
            session_payload(
                title="Alice Johnson project in New York",
                agent_type="Alice Johnson",
                agent_session_id="/Users/Alice Johnson/session",
            )
        ),
        wrapper,
    )
    turn = conversation.turns[0]
    turn.subagents.append(
        MappedSubAgent(
            name="reviewer",
            model="alice@example.com",
            agent_id="/Users/Alice Johnson/project/child.json",
            description="delegated in New York",
            version="Alice Johnson version",
            system_instructions=[],
            started_at=turn.started_at,
            ended_at=turn.ended_at,
            timestamp_inferred=True,
        )
    )
    fake = FakeWeave()
    configure_weave_pii()
    sink = _sink(fake, upload_redactor=redact_upload_data)
    sink.start("wandb/hivemind-chats")
    sink.log_turn(conversation, turn)

    serialized = json.dumps(
        fake.logged[0],
        default=lambda value: getattr(value, "__dict__", str(value)),
        sort_keys=True,
    )
    for private_value in (
        "Alice Johnson",
        "New York",
        "alice@example.com",
        "/Users/Alice Johnson",
        opaque_token,
        token_key,
    ):
        assert private_value not in serialized
    assert any(
        getattr(span, "arguments", {}).get("content") == ordinary_code
        for span in fake.logged[0]["spans"]
    )
    assert fake.logged[0]["agent_name"] != "alice johnson"
    attributes = fake.logged[0]["attributes"]
    assert attributes["hivemind.turn_key"] == conversation.turns[0].key
    assert attributes["hivemind.session_id"] == conversation.conversation_id.removeprefix(
        "hivemind:"
    )
