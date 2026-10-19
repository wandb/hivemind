from __future__ import annotations

import os
from collections.abc import Callable
from dataclasses import replace
from types import SimpleNamespace
from typing import Any

import pytest

from hivemind_weave.atif import map_atif
from hivemind_weave.errors import HistoricalTurnConflictError, WeaveImportError
from hivemind_weave.historical_sink import HistoricalTurnSink
from hivemind_weave.models import Session
from hivemind_weave.weave_sink import expected_turn_span_count


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


class FakeAtomicWeave:
    def __init__(self) -> None:
        self.init_calls = 0
        self.prepared_payloads: list[dict[str, Any]] = []
        self.upserted: list[Any] = []
        self.finished = False
        self.result_status = "committed"
        self.status_status = "committed"
        self.last_prepared: Any | None = None
        self.capabilities = SimpleNamespace(
            supported=True,
            atomic_turn_commit=True,
            durable_idempotency=True,
            status_lookup=True,
            content_refs="immutable",
            capability_version="historical-turn-v1",
            transport_encoding="protobuf",
            content_encoding="gzip",
            max_turn_compressed_bytes=1_000_000,
            max_turn_uncompressed_bytes=2_000_000,
            max_turn_span_count=100,
            max_turn_reference_count=100,
        )

    def init(self, project: str, *, settings: dict[str, Any]) -> None:
        self.init_calls += 1
        self.error_reporting_during_init = os.environ.get("WANDB_ERROR_REPORTING")
        self.project = project
        self.settings = settings

    def get_turn_capabilities(self) -> Any:
        return self.capabilities

    def prepare_turn(self, **payload: Any) -> Any:
        self.prepared_payloads.append(payload)
        prepared = SimpleNamespace(
            logical_key="a" * 64,
            wire_sha256="b" * 64,
            span_count=1 + len(payload["spans"]),
            compressed_bytes=321,
            uncompressed_bytes=654,
            reference_count=0,
            capability_version="historical-turn-v1",
        )
        self.last_prepared = prepared
        return prepared

    def upsert_turn(self, prepared: Any) -> Any:
        self.upserted.append(prepared)
        return SimpleNamespace(
            status=self.result_status,
            trace_ids=["1" * 32],
            root_span_ids=["2" * 16],
            span_count=prepared.span_count,
            commit_id="commit-1",
        )

    def get_turn_status(self, logical_key: str) -> Any:
        prepared = self.upserted[-1] if self.upserted else self.last_prepared
        assert prepared is not None
        return SimpleNamespace(
            status=self.status_status,
            logical_key=logical_key,
            wire_sha256=prepared.wire_sha256,
            trace_ids=["1" * 32],
            root_span_ids=["2" * 16],
            span_count=prepared.span_count,
            commit_id="commit-1",
        )

    def finish(self) -> None:
        self.finished = True


def _sink(fake: Any) -> HistoricalTurnSink:
    return HistoricalTurnSink(
        weave_module=fake,
        conversation_module=FakeConversationModule,
        require_pii_dependencies=False,
    )


def test_atomic_sink_prepares_and_upserts_without_log_turn(
    session_payload: Callable[..., dict[str, Any]],
    atif_wrapper: Callable[..., dict[str, Any]],
) -> None:
    conversation = map_atif(Session.from_api(session_payload()), atif_wrapper())
    fake = FakeAtomicWeave()
    sink = _sink(fake)

    sink.start("wandb/hivemind-chats-v2")
    prepared = sink.prepare_turn(conversation, conversation.turns[0])
    outcome = sink.log_turn(conversation, conversation.turns[0])
    sink.finish()

    assert fake.project == "wandb/hivemind-chats-v2"
    assert fake.error_reporting_during_init == "false"
    assert not hasattr(fake, "log_turn")
    assert prepared.logical_key == "a" * 64
    assert prepared.wire_sha256 == "b" * 64
    assert prepared.compressed_bytes == 321
    assert fake.prepared_payloads[0]["turn_key"] == conversation.turns[0].key
    assert fake.prepared_payloads[0]["source_payload_sha256"]
    assert len(fake.prepared_payloads) == 1
    assert outcome.span_count == expected_turn_span_count(conversation.turns[0])
    assert outcome.logical_key == "a" * 64
    assert outcome.wire_sha256 == "b" * 64
    assert outcome.commit_id == "commit-1"
    assert outcome.capability_version == "historical-turn-v1"
    assert fake.finished is True


def test_atomic_sink_reuses_one_capability_snapshot_and_prepared_envelope(
    session_payload: Callable[..., dict[str, Any]],
    atif_wrapper: Callable[..., dict[str, Any]],
) -> None:
    conversation = map_atif(Session.from_api(session_payload()), atif_wrapper())
    fake = FakeAtomicWeave()
    sink = _sink(fake)

    sink.start("wandb/hivemind-chats-v2")
    first = sink.prepare_turn(conversation, conversation.turns[0])
    sink.start("wandb/hivemind-chats-v2")
    second = sink.prepare_turn(conversation, conversation.turns[0])

    assert first is second
    assert fake.init_calls == 1
    assert len(fake.prepared_payloads) == 1
    with pytest.raises(WeaveImportError, match="cannot change destination"):
        sink.start("wandb/a-different-project")


def test_atomic_sink_passes_complete_large_text_to_sdk_without_local_truncation(
    session_payload: Callable[..., dict[str, Any]],
    atif_wrapper: Callable[..., dict[str, Any]],
) -> None:
    conversation = map_atif(Session.from_api(session_payload()), atif_wrapper())
    large = "ordinary code and conversation text " * 20_000
    turn = conversation.turns[0]
    turn.messages[0] = replace(turn.messages[0], content=large)
    fake = FakeAtomicWeave()
    sink = _sink(fake)
    sink.start("wandb/hivemind-chats-v2")

    sink.prepare_turn(conversation, turn)

    assert fake.prepared_payloads[0]["messages"][0].content == large


def test_atomic_sink_scrubs_credential_holes_before_sdk_prepare(
    session_payload: Callable[..., dict[str, Any]],
    atif_wrapper: Callable[..., dict[str, Any]],
) -> None:
    conversation = map_atif(Session.from_api(session_payload()), atif_wrapper())
    turn = conversation.turns[0]
    turn.messages[0] = replace(
        turn.messages[0],
        content=(
            "connect postgres://alice:supersecret@db.internal/app\n"
            "-----BEGIN OPENSSH PRIVATE KEY-----\ntruncated-secret"
        ),
    )
    turn.attributes["database_url"] = "postgres://alice:supersecret@db.internal/app"
    turn.attributes["passphrase"] = "correct horse battery staple"
    fake = FakeAtomicWeave()
    sink = _sink(fake)
    sink.start("wandb/hivemind-chats-v2")

    sink.prepare_turn(conversation, turn)

    payload = fake.prepared_payloads[0]
    serialized = repr(payload)
    for secret in (
        "alice",
        "supersecret",
        "truncated-secret",
        "correct horse battery staple",
    ):
        assert secret not in serialized
    assert payload["attributes"]["database_url"] == "[REDACTED]"
    assert payload["attributes"]["passphrase"] == "[REDACTED]"


def test_atomic_sink_fails_closed_without_capability() -> None:
    fake = FakeAtomicWeave()
    fake.capabilities = SimpleNamespace(
        supported=True,
        atomic_turn_commit=False,
        durable_idempotency=True,
        status_lookup=True,
        capability_version="historical-turn-v1",
        transport_encoding="protobuf",
        content_encoding="gzip",
        content_refs="immutable",
    )
    with pytest.raises(WeaveImportError, match="atomic turn commits"):
        _sink(fake).start("wandb/hivemind-chats-v2")


def test_atomic_sink_rejects_nonproduction_transport_capability() -> None:
    fake = FakeAtomicWeave()
    fake.capabilities = SimpleNamespace(
        supported=True,
        atomic_turn_commit=True,
        durable_idempotency=True,
        status_lookup=True,
        capability_version="historical-turn-v1",
        transport_encoding="canonical-json",
        content_encoding="identity",
        content_refs="unsupported",
    )
    with pytest.raises(WeaveImportError, match="gzipped protobuf"):
        _sink(fake).start("wandb/hivemind-chats-v2")


def test_atomic_sink_rejects_missing_hard_limits() -> None:
    fake = FakeAtomicWeave()
    del fake.capabilities.max_turn_reference_count

    with pytest.raises(WeaveImportError, match="byte/count limit"):
        _sink(fake).start("wandb/hivemind-chats-v2")
    assert fake.finished is True


def test_atomic_sink_rejects_nonpositive_hard_limits() -> None:
    fake = FakeAtomicWeave()
    fake.capabilities.max_turn_span_count = 0

    with pytest.raises(WeaveImportError, match="byte/count limit"):
        _sink(fake).start("wandb/hivemind-chats-v2")
    assert fake.finished is True


def test_atomic_sink_tears_down_when_post_init_capability_lookup_fails() -> None:
    fake = FakeAtomicWeave()

    def fail_capabilities() -> Any:
        raise RuntimeError("private backend detail")

    fake.get_turn_capabilities = fail_capabilities  # type: ignore[method-assign]
    with pytest.raises(WeaveImportError, match="diagnostics were suppressed"):
        _sink(fake).start("wandb/hivemind-chats-v2")

    assert fake.init_calls == 1
    assert fake.finished is True


def test_atomic_sink_fails_closed_without_new_sdk_api() -> None:
    class LegacyWeave:
        def init(self, project: str, *, settings: dict[str, Any]) -> None:
            del project, settings

    with pytest.raises(WeaveImportError, match="missing prepare_turn"):
        _sink(LegacyWeave()).start("wandb/hivemind-chats-v2")


def test_atomic_sink_rejects_unresolved_upsert(
    session_payload: Callable[..., dict[str, Any]],
    atif_wrapper: Callable[..., dict[str, Any]],
) -> None:
    conversation = map_atif(Session.from_api(session_payload()), atif_wrapper())
    fake = FakeAtomicWeave()
    fake.result_status = "preparing"
    sink = _sink(fake)
    sink.start("wandb/hivemind-chats-v2")
    with pytest.raises(WeaveImportError, match="unresolved status"):
        sink.log_turn(conversation, conversation.turns[0])


def test_atomic_sink_surfaces_content_conflict(
    session_payload: Callable[..., dict[str, Any]],
    atif_wrapper: Callable[..., dict[str, Any]],
) -> None:
    conversation = map_atif(Session.from_api(session_payload()), atif_wrapper())
    fake = FakeAtomicWeave()
    fake.result_status = "conflict"
    sink = _sink(fake)
    sink.start("wandb/hivemind-chats-v2")
    with pytest.raises(HistoricalTurnConflictError, match="existing content"):
        sink.log_turn(conversation, conversation.turns[0])


def test_atomic_sink_reconciles_absence_without_reupload(
    session_payload: Callable[..., dict[str, Any]],
    atif_wrapper: Callable[..., dict[str, Any]],
) -> None:
    conversation = map_atif(Session.from_api(session_payload()), atif_wrapper())
    fake = FakeAtomicWeave()
    fake.status_status = "absent"
    sink = _sink(fake)
    sink.start("wandb/hivemind-chats-v2")
    prepared = sink.prepare_turn(conversation, conversation.turns[0])

    assert sink.reconcile_prepared(prepared) is None
    assert fake.upserted == []
