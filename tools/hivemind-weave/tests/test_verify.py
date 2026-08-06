from __future__ import annotations

import os
import sys
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from types import ModuleType, SimpleNamespace
from typing import Any

import pytest

from hivemind_weave.atif import map_atif
from hivemind_weave.errors import VerificationError
from hivemind_weave.models import Session
from hivemind_weave.pii import (
    configure_weave_pii,
    redact_upload_data,
    sanitize_mapped_conversation,
)
from hivemind_weave.utils import sha256_json
from hivemind_weave.verify import (
    _UNSAFE_TRANSPORT_ENV_VARS,
    ReconcileResult,
    VerificationExpectation,
    WeaveVerifier,
    _post_json,
    disabled_weave_error_reporting,
    enforce_weave_error_reporting_disabled,
    resolve_trace_server_url,
    resolve_wandb_base_url,
    validate_live_transport_environment,
    validate_wandb_base_url,
)


def _remote_turn(trace_id: str = "trace-1") -> dict[str, Any]:
    return {
        "trace_id": trace_id,
        "messages": [
            {
                "span_id": "root-1",
                "started_at": "2026-08-01T12:00:00Z",
                "user_message": {"text": "hello"},
            },
            {
                "span_id": "llm-1",
                "started_at": "2026-08-01T12:00:01Z",
                "assistant_message": {"text": "world"},
            },
        ],
    }


def _remote_signature() -> str:
    return sha256_json(
        {
            "started_at_ms": 1785585600000,
            "first_user": "hello",
            "last_assistant": "world",
        }
    )


def _remote_root(
    trace_id: str = "trace-1",
    *,
    span_id: str = "root-1",
    first_user: str = "hello",
    last_assistant: str = "world",
    started_at: str = "2026-08-01T12:00:00Z",
    ended_at: str = "2026-08-01T12:00:02Z",
    custom_attributes: dict[str, str] | None = None,
) -> dict[str, Any]:
    result = {
        "trace_id": trace_id,
        "span_id": span_id,
        "started_at": started_at,
        "ended_at": ended_at,
        "input_messages": [
            {"role": "system", "content": "system"},
            {"role": "user", "content": first_user},
        ],
        "output_messages": [{"role": "assistant", "content": last_assistant}],
    }
    if custom_attributes is not None:
        result["custom_attrs_string"] = custom_attributes
    return result


def test_conversation_pagination_uses_offsets() -> None:
    seen_payloads: list[dict[str, Any]] = []

    def transport(
        url: str, payload: dict[str, Any], headers: dict[str, str], timeout: float
    ) -> dict[str, Any]:
        seen_payloads.append(payload)
        if payload["offset"] == 0:
            return {"turns": [_remote_turn("new")], "has_more": True}
        return {"turns": [_remote_turn("old")], "has_more": False}

    verifier = WeaveVerifier(project="e/p", api_key="secret", transport=transport)
    turns = verifier.conversation_turns("hivemind:s")
    assert [item["trace_id"] for item in turns] == ["old", "new"]
    assert [payload["offset"] for payload in seen_payloads] == [0, 1]


def test_reconcile_by_stable_custom_attributes() -> None:
    seen_query: list[dict[str, Any]] = []

    def transport(
        url: str, payload: dict[str, Any], headers: dict[str, str], timeout: float
    ) -> dict[str, Any]:
        seen_query.append(payload)
        if url.endswith("/chat"):
            return {"turns": [_remote_turn()], "has_more": False}
        if url.endswith("/conversations/spans"):
            return {
                "conversations": [
                    {
                        "conversation_id": "hivemind:s",
                        "spans": [{"trace_id": "trace-1"}],
                    }
                ]
            }
        if payload.get("include_details") is True:
            return {"spans": [_remote_root()], "total_count": 1}
        if "custom_attrs_string.hivemind.turn_key" not in str(payload):
            return {
                "groups": [{"group_keys": {"trace_id": "trace-1"}, "span_count": 3}],
                "total_count": 1,
            }
        return {
            "spans": [],
            "groups": [
                {
                    "group_keys": {"trace_id": "trace-1", "span_id": "root-1"},
                    "span_count": 3,
                }
            ],
            "total_count": 1,
        }

    verifier = WeaveVerifier(project="e/p", api_key="secret", transport=transport)
    result = verifier.reconcile(
        conversation_id="hivemind:s",
        expected_trace_ids=["trace-1"],
        turn_key="atif:step:1",
        payload_sha256="a" * 64,
        verification_signature=_remote_signature(),
        expected_span_count=3,
        timeout_seconds=1,
    )
    assert result.matches == 1
    assert result.trace_ids == ["trace-1"]
    assert result.root_span_ids == ["root-1"]
    serialized = str(seen_query[0])
    assert "custom_attrs_string.hivemind.turn_key" in serialized
    assert "custom_attrs_string.hivemind.payload_sha256" in serialized
    assert "parent_span_id" in serialized
    assert seen_query[0]["group_by"][1]["key"] == "span_id"


@pytest.mark.parametrize(
    "mismatch",
    [None, "attribute", "started_at", "ended_at", "missing_attribute"],
)
def test_review_reconcile_independently_compares_root_attributes_and_timestamps(
    mismatch: str | None,
) -> None:
    trace_id = "1" * 32
    root_span_id = "2" * 16
    started_at = datetime(2026, 8, 1, 12, tzinfo=UTC)
    ended_at = started_at + timedelta(seconds=2)
    expected_attributes = {
        "hivemind.turn_key": f"review:{'a' * 64}",
        "hivemind.payload_sha256": "b" * 64,
        "hivemind.review.index_uri": "weave:///wandb/project/object/index:version",
        "hivemind.review.logical_key": "a" * 64,
        "hivemind.review.match_sha256": "b" * 64,
        "hivemind.review.preview_signature": "c" * 64,
        "hivemind.review.schema": "hivemind-hosted-review-root-v1",
    }
    remote_attributes = dict(expected_attributes)
    remote_started_at = "2026-08-01T12:00:00Z"
    remote_ended_at = "2026-08-01T12:00:02Z"
    if mismatch == "attribute":
        remote_attributes["hivemind.review.index_uri"] = "weave:///wrong:index"
    elif mismatch == "started_at":
        remote_started_at = "2026-08-01T11:59:59Z"
    elif mismatch == "ended_at":
        remote_ended_at = "2026-08-01T12:00:03Z"
    elif mismatch == "missing_attribute":
        remote_attributes.pop("hivemind.review.preview_signature")

    seen_detail_queries: list[dict[str, Any]] = []

    def transport(
        url: str, payload: dict[str, Any], headers: dict[str, str], timeout: float
    ) -> dict[str, Any]:
        del headers, timeout
        if url.endswith("/chat"):
            return {"turns": [_remote_turn(trace_id)], "has_more": False}
        if url.endswith("/conversations/spans"):
            return {
                "conversations": [
                    {
                        "conversation_id": "hivemind:s",
                        "spans": [{"trace_id": trace_id}],
                    }
                ]
            }
        if payload.get("include_details") is True:
            seen_detail_queries.append(payload)
            return {
                "spans": [
                    _remote_root(
                        trace_id,
                        span_id=root_span_id,
                        started_at=remote_started_at,
                        ended_at=remote_ended_at,
                        custom_attributes=remote_attributes,
                    )
                ],
                "total_count": 1,
            }
        if "custom_attrs_string.hivemind.turn_key" in str(payload):
            return {
                "groups": [
                    {
                        "group_keys": {"trace_id": trace_id, "span_id": root_span_id},
                        "span_count": 1,
                    }
                ],
                "total_count": 1,
            }
        return {
            "groups": [{"group_keys": {"trace_id": trace_id}, "span_count": 1}],
            "total_count": 1,
        }

    verifier = WeaveVerifier(project="e/p", api_key="secret", transport=transport)
    result = verifier.reconcile(
        conversation_id="hivemind:s",
        expected_trace_ids=[trace_id],
        turn_key=f"review:{'a' * 64}",
        payload_sha256="b" * 64,
        expected_span_count=1,
        expected_root_attributes=expected_attributes,
        expected_started_at=started_at,
        expected_ended_at=ended_at,
        timeout_seconds=0,
    )

    assert len(seen_detail_queries) == 1
    requested_columns = {item["key"] for item in seen_detail_queries[0]["custom_attr_columns"]}
    assert requested_columns == set(expected_attributes)
    if mismatch is None:
        assert result.matches == 1
        assert result.trace_ids == [trace_id]
        assert result.root_span_ids == [root_span_id]
    else:
        assert result.matches > 1


def test_verify_polls_until_chat_and_spans_are_visible() -> None:
    calls = 0

    def transport(
        url: str, payload: dict[str, Any], headers: dict[str, str], timeout: float
    ) -> dict[str, Any]:
        nonlocal calls
        calls += 1
        visible = calls > 2
        if url.endswith("/chat"):
            return {"turns": [_remote_turn()] if visible else [], "has_more": False}
        if url.endswith("/spans/query"):
            if payload.get("include_details") is True:
                return {
                    "spans": [_remote_root()] if visible else [],
                    "total_count": 1 if visible else 0,
                }
            if payload.get("custom_attr_columns"):
                return {
                    "spans": (
                        [
                            {
                                "trace_id": "trace-1",
                                "span_id": "root-1",
                                "custom_attrs_string": {
                                    "hivemind.turn_key": "atif:step:1",
                                    "hivemind.payload_sha256": "a" * 64,
                                },
                            }
                        ]
                        if visible
                        else []
                    ),
                    "total_count": 1 if visible else 0,
                }
            return {
                "groups": (
                    [
                        {
                            "group_keys": {"trace_id": "trace-1"},
                            "span_count": 3,
                        }
                    ]
                    if visible
                    else []
                ),
                "total_count": 1 if visible else 0,
            }
        return {
            "conversations": [
                {
                    "conversation_id": "hivemind:s",
                    "spans": [{"trace_id": "trace-1"}] if visible else [],
                }
            ]
        }

    verifier = WeaveVerifier(
        project="e/p",
        api_key="secret",
        transport=transport,
        sleep=lambda _: None,
    )
    verifier.verify(
        conversation_id="hivemind:s",
        expected_trace_ids=["trace-1"],
        turn_key="atif:step:1",
        payload_sha256="a" * 64,
        verification_signature=_remote_signature(),
        expected_span_count=3,
        timeout_seconds=1,
    )
    assert calls >= 4


def test_verify_times_out_cleanly() -> None:
    now = 0.0

    def monotonic() -> float:
        return now

    def sleep(seconds: float) -> None:
        nonlocal now
        now += seconds

    def transport(
        url: str, payload: dict[str, Any], headers: dict[str, str], timeout: float
    ) -> dict[str, Any]:
        if url.endswith("/chat"):
            return {"turns": [], "has_more": False}
        if url.endswith("/spans/query"):
            return {"groups": [], "total_count": 0}
        return {"conversations": []}

    verifier = WeaveVerifier(
        project="e/p",
        api_key="secret",
        transport=transport,
        sleep=sleep,
        monotonic=monotonic,
    )
    with pytest.raises(VerificationError, match="within 1s"):
        verifier.verify(
            conversation_id="hivemind:s",
            expected_trace_ids=["trace-1"],
            turn_key="atif:step:1",
            payload_sha256="a" * 64,
            timeout_seconds=1,
        )


def test_verifier_resolves_the_same_custom_trace_endpoint_as_weave(
    monkeypatch: Any,
) -> None:
    monkeypatch.delenv("WF_TRACE_SERVER_URL", raising=False)
    monkeypatch.delenv("WANDB_PUBLIC_BASE_URL", raising=False)
    monkeypatch.setenv("WANDB_BASE_URL", "https://wandb.internal.example/")
    verifier = WeaveVerifier(project="e/p", api_key="secret")
    assert verifier.base_url == "https://wandb.internal.example/traces"

    monkeypatch.setenv("WF_TRACE_SERVER_URL", "https://trace.internal.example/custom/")
    explicit = WeaveVerifier(project="e/p", api_key="secret")
    assert explicit.base_url == "https://trace.internal.example/custom"
    assert explicit.headers["Authorization"] == "Basic YXBpOnNlY3JldA=="
    assert "secret" not in explicit.headers["Authorization"]

    monkeypatch.delenv("WF_TRACE_SERVER_URL")
    monkeypatch.setattr(
        "weave.trace.env.weave_trace_server_url",
        lambda: "https://settings.example/traces",
    )
    configured = WeaveVerifier(project="e/p", api_key="secret")
    assert configured.base_url == "https://settings.example/traces"


def test_transport_os_errors_and_invalid_utf8_are_domain_failures(monkeypatch: Any) -> None:
    def fail_transport(*_: object, **__: object) -> None:
        raise TimeoutError("private transport detail")

    monkeypatch.setattr("hivemind_weave.verify._open_no_redirect", fail_transport)
    with pytest.raises(VerificationError, match="transport failed"):
        _post_json("https://trace.example/test", {}, {}, 1)

    class InvalidResponse:
        def __enter__(self) -> InvalidResponse:
            return self

        def __exit__(self, *_: object) -> None:
            return None

        def read(self) -> bytes:
            return b"\xff"

    monkeypatch.setattr(
        "hivemind_weave.verify._open_no_redirect",
        lambda *_args, **_kwargs: InvalidResponse(),
    )
    with pytest.raises(VerificationError, match="invalid JSON"):
        _post_json("https://trace.example/test", {}, {}, 1)


def test_transport_rejects_insecure_ssl_setting_and_plain_http(monkeypatch: Any) -> None:
    monkeypatch.setenv("WEAVE_INSECURE_DISABLE_SSL", "true")
    with pytest.raises(VerificationError, match="forbidden"):
        validate_live_transport_environment()
    with pytest.raises(VerificationError, match="must be HTTPS"):
        _post_json("http://trace.example/test", {}, {}, 1)
    with pytest.raises(VerificationError, match="credentials"):
        WeaveVerifier(project="e/p", api_key="secret", base_url="https://user@trace.example")


@pytest.mark.parametrize("variable", _UNSAFE_TRANSPORT_ENV_VARS)
def test_live_transport_rejects_every_ambient_override_even_when_blank(
    monkeypatch: Any,
    variable: str,
) -> None:
    monkeypatch.delenv("WEAVE_INSECURE_DISABLE_SSL", raising=False)
    monkeypatch.setenv(variable, "")
    with pytest.raises(VerificationError, match=variable):
        validate_live_transport_environment()


def test_live_endpoint_resolution_is_hosted_only(monkeypatch: Any) -> None:
    monkeypatch.setattr(
        "hivemind_weave.verify._trace_server_url",
        lambda: "https://trace.internal.example/custom/",
    )
    with pytest.raises(VerificationError, match="not supported"):
        resolve_trace_server_url()

    monkeypatch.setattr(
        "hivemind_weave.verify._trace_server_url",
        lambda: "https://trace.wandb.ai/",
    )
    assert resolve_trace_server_url() == "https://trace.wandb.ai"

    monkeypatch.setattr(
        "hivemind_weave.verify._wandb_base_url",
        lambda: "https://api.internal.example/",
    )
    with pytest.raises(VerificationError, match="not supported"):
        resolve_wandb_base_url()

    monkeypatch.setattr(
        "hivemind_weave.verify._wandb_base_url",
        lambda: "https://api.wandb.ai/",
    )
    assert resolve_wandb_base_url() == "https://api.wandb.ai"


def test_wandb_base_url_must_be_an_https_origin() -> None:
    with pytest.raises(VerificationError, match="without a path"):
        validate_wandb_base_url("https://api.wandb.ai/graphql")
    with pytest.raises(VerificationError, match="HTTPS"):
        validate_wandb_base_url("http://api.wandb.ai")


def test_error_reporting_is_pinned_and_restored(monkeypatch: Any) -> None:
    monkeypatch.setenv("WANDB_ERROR_REPORTING", "true")
    with disabled_weave_error_reporting():
        assert os.environ["WANDB_ERROR_REPORTING"] == "false"
    assert os.environ["WANDB_ERROR_REPORTING"] == "true"


def test_existing_weave_error_reporting_client_is_disabled(monkeypatch: Any) -> None:
    from weave.telemetry import trace_sentry

    sentry = SimpleNamespace(_disabled=False, scope=object())
    monkeypatch.setattr(trace_sentry, "global_trace_sentry", sentry)

    enforce_weave_error_reporting_disabled()

    assert sentry._disabled is True
    assert sentry.scope is None


def test_batch_verification_pages_conversation_once_for_multiple_turns() -> None:
    endpoints: list[str] = []

    def transport(
        url: str, payload: dict[str, Any], headers: dict[str, str], timeout: float
    ) -> dict[str, Any]:
        del headers, timeout
        endpoints.append(url)
        if url.endswith("/chat"):
            return {
                "turns": [_remote_turn("trace-1"), _remote_turn("trace-2")],
                "has_more": False,
            }
        if url.endswith("/spans/query"):
            if payload.get("include_details") is True:
                return {
                    "spans": [
                        _remote_root("trace-1", span_id="root-1"),
                        _remote_root("trace-2", span_id="root-2"),
                    ],
                    "total_count": 2,
                }
            if payload.get("custom_attr_columns"):
                return {
                    "spans": [
                        {
                            "trace_id": "trace-1",
                            "span_id": "root-1",
                            "custom_attrs_string": {
                                "hivemind.turn_key": "atif:step:1",
                                "hivemind.payload_sha256": "a" * 64,
                            },
                        },
                        {
                            "trace_id": "trace-2",
                            "span_id": "root-2",
                            "custom_attrs_string": {
                                "hivemind.turn_key": "atif:step:2",
                                "hivemind.payload_sha256": "b" * 64,
                            },
                        },
                    ],
                    "total_count": 2,
                }
            return {
                "groups": [
                    {"group_keys": {"trace_id": "trace-1"}, "span_count": 3},
                    {"group_keys": {"trace_id": "trace-2"}, "span_count": 3},
                ],
                "total_count": 2,
            }
        return {
            "conversations": [
                {
                    "conversation_id": "hivemind:s",
                    # The minimap is capped and may omit an older trace even
                    # while chat and the grouped spans query remain complete.
                    "spans": [{"trace_id": "trace-2"}],
                }
            ]
        }

    verifier = WeaveVerifier(project="e/p", api_key="secret", transport=transport)
    result = verifier.verify_many(
        conversation_id="hivemind:s",
        expectations=[
            VerificationExpectation("atif:step:1", "a" * 64, ("trace-1",), _remote_signature(), 3),
            VerificationExpectation("atif:step:2", "b" * 64, ("trace-2",), _remote_signature(), 3),
        ],
        timeout_seconds=1,
    )
    assert result.verified == {"atif:step:1", "atif:step:2"}
    assert sum(url.endswith("/chat") for url in endpoints) == 1
    assert sum(url.endswith("/conversations/spans") for url in endpoints) == 1
    assert sum(url.endswith("/spans/query") for url in endpoints) == 3


def test_batch_verification_uses_root_messages_when_chat_is_cumulative() -> None:
    cumulative_chat = _remote_turn()
    cumulative_chat["messages"].append(
        {
            "span_id": "tool-1",
            "started_at": "2026-08-01T12:00:02Z",
            "assistant_message": {"text": "child aggregate, not the root output"},
        }
    )

    def transport(
        url: str, payload: dict[str, Any], headers: dict[str, str], timeout: float
    ) -> dict[str, Any]:
        del headers, timeout
        if url.endswith("/chat"):
            return {"turns": [cumulative_chat], "has_more": False}
        if url.endswith("/conversations/spans"):
            return {
                "conversations": [
                    {"conversation_id": "hivemind:s", "spans": [{"trace_id": "trace-1"}]}
                ]
            }
        if payload.get("include_details") is True:
            return {"spans": [_remote_root()], "total_count": 1}
        if payload.get("custom_attr_columns"):
            return {
                "spans": [
                    {
                        "trace_id": "trace-1",
                        "span_id": "root-1",
                        "custom_attrs_string": {
                            "hivemind.turn_key": "atif:step:1",
                            "hivemind.payload_sha256": "a" * 64,
                        },
                    }
                ],
                "total_count": 1,
            }
        return {
            "groups": [{"group_keys": {"trace_id": "trace-1"}, "span_count": 3}],
            "total_count": 1,
        }

    verifier = WeaveVerifier(project="e/p", api_key="secret", transport=transport)
    assert verifier._turn_signature(cumulative_chat) != _remote_signature()
    result = verifier.verify_many(
        conversation_id="hivemind:s",
        expectations=[
            VerificationExpectation(
                "atif:step:1",
                "a" * 64,
                ("trace-1",),
                _remote_signature(),
                3,
            )
        ],
        timeout_seconds=0,
    )
    assert result.verified == {"atif:step:1"}


def test_batch_verification_requires_conversation_chat_visibility() -> None:
    queried_root_details = False

    def transport(
        url: str, payload: dict[str, Any], headers: dict[str, str], timeout: float
    ) -> dict[str, Any]:
        nonlocal queried_root_details
        del headers, timeout
        if url.endswith("/chat"):
            return {"turns": [], "has_more": False}
        if url.endswith("/conversations/spans"):
            return {
                "conversations": [
                    {"conversation_id": "hivemind:s", "spans": [{"trace_id": "trace-1"}]}
                ]
            }
        if payload.get("include_details") is True:
            queried_root_details = True
            return {"spans": [_remote_root()], "total_count": 1}
        raise AssertionError("chat-invisible turns must not advance to exact root verification")

    verifier = WeaveVerifier(project="e/p", api_key="secret", transport=transport)
    result = verifier.verify_many(
        conversation_id="hivemind:s",
        expectations=[
            VerificationExpectation(
                "atif:step:1",
                "a" * 64,
                ("trace-1",),
                _remote_signature(),
                3,
            )
        ],
        timeout_seconds=0,
    )
    assert result.missing == {"atif:step:1"}
    assert queried_root_details is False


def test_root_signature_query_batches_expected_trace_ids_without_returning_content() -> None:
    batch_sizes: list[int] = []

    def transport(
        url: str, payload: dict[str, Any], headers: dict[str, str], timeout: float
    ) -> dict[str, Any]:
        del url, headers, timeout
        trace_filter = payload["query"]["$expr"]["$and"][2]
        trace_ids = [item["$literal"] for item in trace_filter["$in"][1]]
        batch_sizes.append(len(trace_ids))
        return {
            "spans": [_remote_root(trace_id, span_id=f"root-{trace_id}") for trace_id in trace_ids],
            "total_count": len(trace_ids),
        }

    verifier = WeaveVerifier(project="e/p", api_key="secret", transport=transport)
    evidence = verifier.root_span_signatures_many(
        conversation_id="hivemind:s",
        trace_ids=[f"trace-{index}" for index in range(101)],
    )
    assert batch_sizes == [100, 1]
    assert len(evidence) == 101
    assert all(
        [item.signature for item in rows] == [_remote_signature()] for rows in evidence.values()
    )
    assert "hello" not in repr(evidence)
    assert "world" not in repr(evidence)


@pytest.mark.parametrize(
    ("remote_content", "canonical_content"),
    [
        ("legacy flat text", "legacy flat text"),
        ('[{"type":"text","content":"first"},{"type":"text","text":"second"}]', "first\nsecond"),
        ("[]", ""),
        ('[{"type":"text","content":"[{\\"literal\\":true}]"}]', '[{"literal":true}]'),
        ("[malformed", "[malformed"),
        (
            '[{"type":"reasoning","content":"hidden"},'
            '{"type":"uri","content":"media"},'
            '{"type":"text","content":"visible"}]',
            "visible",
        ),
    ],
)
def test_root_signature_canonicalizes_agents_message_parts(
    remote_content: str,
    canonical_content: str,
) -> None:
    root = _remote_root(first_user=remote_content)

    assert WeaveVerifier._root_span_signature(root) == sha256_json(
        {
            "started_at_ms": 1785585600000,
            "first_user": canonical_content,
            "last_assistant": "world",
        }
    )


def test_sanitized_signature_matches_real_sdk_and_server_root_shape(
    monkeypatch: Any,
    session_payload: Callable[..., dict[str, Any]],
    atif_wrapper: Callable[..., dict[str, Any]],
) -> None:
    """Exercise the exact SDK dict-redaction and server parts-normalization path."""
    monkeypatch.setenv("WEAVE_REDACT_PII", "true")
    configure_weave_pii()
    technical_output = "class Washington:\n    pass\n" * 128
    source = map_atif(
        Session.from_api(session_payload()),
        atif_wrapper(
            steps=[
                {
                    "step_id": 1,
                    "timestamp": "2026-08-01T12:00:00Z",
                    "source": "agent",
                    "message": technical_output,
                }
            ]
        ),
    )
    conversation = sanitize_mapped_conversation(source)
    turn = conversation.turns[0]
    assert turn.messages == []
    assert len(turn.output_messages) == 1

    from weave import conversation as conversation_types
    from weave.trace.settings import override_settings

    # The client-only Weave extra omits the SQL dependency of its server query
    # builder. The normalizer imports only these numeric helpers from it; stub
    # that unrelated module so this regression can execute the installed
    # server normalization function without expanding runtime dependencies.
    agent_query_builder = ModuleType("weave.trace_server.query_builder.agent_query_builder")
    agent_query_builder.safe_float = float  # type: ignore[attr-defined]
    agent_query_builder.safe_int = int  # type: ignore[attr-defined]
    monkeypatch.setitem(
        sys.modules,
        "weave.trace_server.query_builder.agent_query_builder",
        agent_query_builder,
    )
    from weave.trace_server.opentelemetry.genai_extraction import _normalize_raw_messages

    from hivemind_weave.weave_sink import WeaveSink

    sink = WeaveSink(
        conversation_module=conversation_types,
        require_pii_dependencies=False,
        upload_redactor=redact_upload_data,
    )
    root_turn = conversation_types.Turn(
        agent_name=conversation.agent_name,
        model=conversation.model,
        messages=[sink._message(message) for message in turn.messages],
        output_messages=[sink._message(message) for message in turn.output_messages],
        system_instructions=turn.system_instructions,
        started_at=turn.started_at,
        ended_at=turn.ended_at,
    )
    with override_settings(redact_pii=True):
        attributes = root_turn._build_attrs(
            conversation_id=conversation.conversation_id,
            conversation_name=conversation.conversation_name,
            include_content=True,
        )

    input_messages = _normalize_raw_messages(
        attributes.get("gen_ai.input.messages"),
        default_role="user",
    )
    output_messages = _normalize_raw_messages(
        attributes.get("gen_ai.output.messages"),
        default_role="assistant",
    )
    assert input_messages == []
    assert len(output_messages) == 1
    assert output_messages[0].content != turn.output_messages[0].content
    remote_root = {
        "started_at": turn.started_at,
        "input_messages": [message.model_dump() for message in input_messages],
        "output_messages": [message.model_dump() for message in output_messages],
    }

    assert WeaveVerifier._root_span_signature(remote_root) == turn.verification_signature


def test_batch_verification_reports_duplicate_and_missing_roots() -> None:
    span_queries = 0

    def transport(
        url: str, payload: dict[str, Any], headers: dict[str, str], timeout: float
    ) -> dict[str, Any]:
        nonlocal span_queries
        del headers, timeout
        if url.endswith("/chat"):
            return {
                "turns": [
                    _remote_turn("trace-1"),
                    _remote_turn("trace-2"),
                    _remote_turn("trace-3"),
                ],
                "has_more": False,
            }
        if url.endswith("/spans/query"):
            span_queries += 1
            if payload.get("custom_attr_columns"):
                return {
                    "spans": [
                        {
                            "trace_id": "trace-1",
                            "span_id": "root-1",
                            "custom_attrs_string": {
                                "hivemind.turn_key": "atif:step:1",
                                "hivemind.payload_sha256": "a" * 64,
                            },
                        },
                        {
                            "trace_id": "trace-2",
                            "span_id": "root-2a",
                            "custom_attrs_string": {
                                "hivemind.turn_key": "atif:step:2",
                                "hivemind.payload_sha256": "b" * 64,
                            },
                        },
                        {
                            "trace_id": "trace-2-copy",
                            "span_id": "root-2b",
                            "custom_attrs_string": {
                                "hivemind.turn_key": "atif:step:2",
                                "hivemind.payload_sha256": "b" * 64,
                            },
                        },
                    ],
                    "total_count": 3,
                }
            return {
                "groups": [{"group_keys": {"trace_id": "trace-1"}, "span_count": 3}],
                "total_count": 1,
            }
        return {"conversations": [{"conversation_id": "hivemind:s", "spans": []}]}

    verifier = WeaveVerifier(project="e/p", api_key="secret", transport=transport)
    result = verifier.verify_many(
        conversation_id="hivemind:s",
        expectations=[
            VerificationExpectation("atif:step:1", "a" * 64, ("trace-1",), "", 3),
            VerificationExpectation("atif:step:2", "b" * 64, ("trace-2",), "", 3),
            VerificationExpectation("atif:step:3", "c" * 64, ("trace-3",), "", 3),
        ],
        timeout_seconds=0,
    )
    assert result.verified == {"atif:step:1"}
    assert result.conflicts == {"atif:step:2"}
    assert result.missing == {"atif:step:3"}
    assert span_queries == 2


def test_batch_verification_bounds_filter_size() -> None:
    span_query_sizes: list[int] = []

    def literal_values(operation: dict[str, Any]) -> list[str]:
        return [item["$literal"] for item in operation["$in"][1]]

    def transport(
        url: str, payload: dict[str, Any], headers: dict[str, str], timeout: float
    ) -> dict[str, Any]:
        del headers, timeout
        if url.endswith("/chat"):
            return {
                "turns": [_remote_turn(f"trace-{index}") for index in range(101)],
                "has_more": False,
            }
        if url.endswith("/spans/query"):
            operations = payload["query"]["$expr"]["$and"]
            if payload.get("custom_attr_columns"):
                turn_keys = literal_values(operations[3])
                span_query_sizes.append(len(turn_keys))
                return {
                    "spans": [
                        {
                            "trace_id": f"trace-{turn_key.rsplit(':', 1)[1]}",
                            "span_id": f"root-{turn_key.rsplit(':', 1)[1]}",
                            "custom_attrs_string": {
                                "hivemind.turn_key": turn_key,
                                "hivemind.payload_sha256": "a" * 64,
                            },
                        }
                        for turn_key in turn_keys
                    ],
                    "total_count": len(turn_keys),
                }
            trace_ids = literal_values(operations[1])
            span_query_sizes.append(len(trace_ids))
            return {
                "groups": [
                    {"group_keys": {"trace_id": trace_id}, "span_count": 3}
                    for trace_id in trace_ids
                ],
                "total_count": len(trace_ids),
            }
        return {"conversations": [{"conversation_id": "hivemind:s", "spans": []}]}

    verifier = WeaveVerifier(project="e/p", api_key="secret", transport=transport)
    result = verifier.verify_many(
        conversation_id="hivemind:s",
        expectations=[
            VerificationExpectation(
                f"atif:step:{index}",
                "a" * 64,
                (f"trace-{index}",),
                "",
                3,
            )
            for index in range(101)
        ],
        timeout_seconds=1,
    )
    assert len(result.verified) == 101
    assert result.conflicts == set()
    assert result.missing == set()
    assert span_query_sizes == [100, 1, 100, 1]


@pytest.mark.parametrize(
    ("remote_span_count", "signature"),
    [(1, _remote_signature()), (3, "f" * 64)],
)
def test_reconcile_never_treats_partial_or_wrong_content_as_absent(
    remote_span_count: int,
    signature: str,
) -> None:
    now = 0.0

    def monotonic() -> float:
        return now

    def sleep(seconds: float) -> None:
        nonlocal now
        now += seconds

    def transport(
        url: str, payload: dict[str, Any], headers: dict[str, str], timeout: float
    ) -> dict[str, Any]:
        del headers, timeout
        if url.endswith("/chat"):
            return {"turns": [_remote_turn()], "has_more": False}
        if url.endswith("/conversations/spans"):
            return {
                "conversations": [
                    {
                        "conversation_id": "hivemind:s",
                        "spans": [{"trace_id": "trace-1"}],
                    }
                ]
            }
        if payload.get("include_details") is True:
            return {"spans": [_remote_root()], "total_count": 1}
        if "custom_attrs_string.hivemind.turn_key" in str(payload):
            return {
                "groups": [
                    {
                        "group_keys": {"trace_id": "trace-1", "span_id": "root-1"},
                        "span_count": 1,
                    }
                ],
                "total_count": 1,
            }
        return {
            "groups": [
                {
                    "group_keys": {"trace_id": "trace-1"},
                    "span_count": remote_span_count,
                }
            ],
            "total_count": 1,
        }

    verifier = WeaveVerifier(
        project="e/p",
        api_key="secret",
        transport=transport,
        sleep=sleep,
        monotonic=monotonic,
    )
    result = verifier.reconcile(
        conversation_id="hivemind:s",
        expected_trace_ids=["trace-1"],
        turn_key="atif:step:1",
        payload_sha256="a" * 64,
        verification_signature=signature,
        expected_span_count=3,
        timeout_seconds=1,
    )
    assert result.matches > 1
    assert result.trace_ids == ["trace-1"]


def test_reconcile_uses_recorded_trace_id_when_attribute_index_lags() -> None:
    def transport(
        url: str, payload: dict[str, Any], headers: dict[str, str], timeout: float
    ) -> dict[str, Any]:
        del headers, timeout
        if url.endswith("/chat"):
            return {"turns": [_remote_turn()], "has_more": False}
        if url.endswith("/conversations/spans"):
            return {"conversations": [{"conversation_id": "hivemind:s", "spans": []}]}
        if payload.get("include_details") is True:
            return {"spans": [_remote_root()], "total_count": 1}
        if "custom_attrs_string.hivemind.turn_key" in str(payload):
            return {"groups": [], "total_count": 0}
        return {
            "groups": [{"group_keys": {"trace_id": "trace-1"}, "span_count": 3}],
            "total_count": 1,
        }

    verifier = WeaveVerifier(project="e/p", api_key="secret", transport=transport)
    result = verifier.reconcile(
        conversation_id="hivemind:s",
        expected_trace_ids=["trace-1"],
        turn_key="atif:step:1",
        payload_sha256="a" * 64,
        verification_signature=_remote_signature(),
        expected_span_count=3,
        timeout_seconds=1,
    )
    assert result.matches == 1
    assert result.trace_ids == ["trace-1"]
    assert result.span_count == 3


def test_reconcile_accepts_fresh_exact_root_signature_for_legacy_pending_row() -> None:
    cumulative_chat = _remote_turn()
    cumulative_chat["messages"].append(
        {
            "started_at": "2026-08-01T12:00:02Z",
            "assistant_message": {"text": "aggregated child output"},
        }
    )

    def transport(
        url: str, payload: dict[str, Any], headers: dict[str, str], timeout: float
    ) -> dict[str, Any]:
        del headers, timeout
        if url.endswith("/chat"):
            return {"turns": [cumulative_chat], "has_more": False}
        if url.endswith("/conversations/spans"):
            return {"conversations": [{"conversation_id": "hivemind:s", "spans": []}]}
        if payload.get("include_details") is True:
            return {"spans": [_remote_root()], "total_count": 1}
        if "custom_attrs_string.hivemind.turn_key" in str(payload):
            return {
                "groups": [
                    {
                        "group_keys": {"trace_id": "trace-1", "span_id": "root-1"},
                        "span_count": 1,
                    }
                ],
                "total_count": 1,
            }
        return {
            "groups": [{"group_keys": {"trace_id": "trace-1"}, "span_count": 3}],
            "total_count": 1,
        }

    verifier = WeaveVerifier(project="e/p", api_key="secret", transport=transport)
    result = verifier.reconcile(
        conversation_id="hivemind:s",
        expected_trace_ids=["trace-1"],
        turn_key="atif:step:1",
        payload_sha256="a" * 64,
        verification_signature="legacy-second-pass-signature",
        alternate_verification_signatures=(_remote_signature(),),
        expected_span_count=3,
        timeout_seconds=0,
    )
    assert result.matches == 1
    assert result.trace_ids == ["trace-1"]
    assert result.root_span_ids == ["root-1"]


def test_reconcile_does_not_fall_back_to_matching_aggregated_chat_content() -> None:
    def transport(
        url: str, payload: dict[str, Any], headers: dict[str, str], timeout: float
    ) -> dict[str, Any]:
        del headers, timeout
        if url.endswith("/chat"):
            # This old signal matches, but the canonical root below does not.
            return {"turns": [_remote_turn()], "has_more": False}
        if url.endswith("/conversations/spans"):
            return {"conversations": [{"conversation_id": "hivemind:s", "spans": []}]}
        if payload.get("include_details") is True:
            return {
                "spans": [_remote_root(last_assistant="different root output")],
                "total_count": 1,
            }
        if "custom_attrs_string.hivemind.turn_key" in str(payload):
            return {
                "groups": [
                    {
                        "group_keys": {"trace_id": "trace-1", "span_id": "root-1"},
                        "span_count": 1,
                    }
                ],
                "total_count": 1,
            }
        return {
            "groups": [{"group_keys": {"trace_id": "trace-1"}, "span_count": 3}],
            "total_count": 1,
        }

    verifier = WeaveVerifier(project="e/p", api_key="secret", transport=transport)
    result = verifier.reconcile(
        conversation_id="hivemind:s",
        expected_trace_ids=["trace-1"],
        turn_key="atif:step:1",
        payload_sha256="a" * 64,
        verification_signature=_remote_signature(),
        expected_span_count=3,
        timeout_seconds=0,
    )
    assert result.matches > 1
    assert result.trace_ids == ["trace-1"]


def test_reconcile_treats_child_only_remote_span_as_incomplete_without_local_ids() -> None:
    queries: list[dict[str, Any]] = []

    def transport(
        url: str, payload: dict[str, Any], headers: dict[str, str], timeout: float
    ) -> dict[str, Any]:
        del url, headers, timeout
        queries.append(payload)
        if "parent_span_id" in str(payload):
            return {"groups": [], "total_count": 0}
        return {
            "groups": [
                {
                    "group_keys": {"trace_id": "orphan-trace"},
                    "span_count": 19,
                }
            ],
            "total_count": 1,
        }

    verifier = WeaveVerifier(project="e/p", api_key="secret", transport=transport)
    result = verifier.reconcile(
        conversation_id="hivemind:s",
        expected_trace_ids=[],
        turn_key="atif:step:97",
        payload_sha256="a" * 64,
        timeout_seconds=0,
    )

    assert result.matches > 1
    assert result.trace_ids == ["orphan-trace"]
    assert result.span_count == 19
    assert len(queries) == 2
    all_span_query = queries[1]
    serialized = str(all_span_query)
    assert "custom_attrs_string.hivemind.turn_key" in serialized
    assert "custom_attrs_string.hivemind.payload_sha256" in serialized
    assert "parent_span_id" not in serialized
    assert "operation_name" not in serialized
    assert all_span_query["group_by"] == [
        {"source": "field", "key": "trace_id", "alias": "trace_id"}
    ]


def test_all_span_presence_preserves_multiple_partial_trace_conflict() -> None:
    def transport(
        url: str, payload: dict[str, Any], headers: dict[str, str], timeout: float
    ) -> dict[str, Any]:
        del url, payload, headers, timeout
        return {
            "groups": [
                {"group_keys": {"trace_id": "trace-b"}, "span_count": 2},
                {"group_keys": {"trace_id": "trace-a"}, "span_count": 3},
            ],
            "total_count": 2,
        }

    verifier = WeaveVerifier(project="e/p", api_key="secret", transport=transport)
    result = verifier.attribute_span_presence(
        conversation_id="hivemind:s",
        turn_key="atif:step:97",
        payload_sha256="a" * 64,
    )
    assert result.matches == 2
    assert result.trace_ids == ["trace-a", "trace-b"]
    assert result.span_count == 5


def test_all_span_presence_paginates_grouped_traces() -> None:
    groups = [
        {"group_keys": {"trace_id": f"trace-{index:04d}"}, "span_count": index + 1}
        for index in range(1001)
    ]
    offsets: list[int] = []

    def transport(
        url: str, payload: dict[str, Any], headers: dict[str, str], timeout: float
    ) -> dict[str, Any]:
        del url, headers, timeout
        offset = payload["offset"]
        limit = payload["limit"]
        offsets.append(offset)
        return {
            "groups": groups[offset : offset + limit],
            "total_count": len(groups),
        }

    verifier = WeaveVerifier(project="e/p", api_key="secret", transport=transport)
    result = verifier.attribute_span_presence(
        conversation_id="hivemind:s",
        turn_key="atif:step:97",
        payload_sha256="a" * 64,
    )
    assert offsets == [0, 1000]
    assert result.matches == 1001
    assert result.trace_ids[0] == "trace-0000"
    assert result.trace_ids[-1] == "trace-1000"
    assert result.span_count == sum(range(1, 1002))


@pytest.mark.parametrize(
    "response",
    [
        {"groups": "not-a-list", "total_count": 0},
        {"groups": [], "total_count": True},
        {
            "groups": [{"group_keys": {"trace_id": "trace-1"}, "span_count": 0}],
            "total_count": 1,
        },
        {
            "groups": [
                {"group_keys": {"trace_id": "trace-1"}, "span_count": 1},
                {"group_keys": {"trace_id": "trace-1"}, "span_count": 1},
            ],
            "total_count": 2,
        },
    ],
)
def test_all_span_presence_rejects_invalid_schema(response: dict[str, Any]) -> None:
    def transport(
        url: str, payload: dict[str, Any], headers: dict[str, str], timeout: float
    ) -> dict[str, Any]:
        del url, payload, headers, timeout
        return response

    verifier = WeaveVerifier(project="e/p", api_key="secret", transport=transport)
    with pytest.raises(VerificationError, match="all-span presence query"):
        verifier.attribute_span_presence(
            conversation_id="hivemind:s",
            turn_key="atif:step:97",
            payload_sha256="a" * 64,
        )


def test_reconcile_proves_true_absence_across_root_and_all_span_queries() -> None:
    queries: list[dict[str, Any]] = []

    def transport(
        url: str, payload: dict[str, Any], headers: dict[str, str], timeout: float
    ) -> dict[str, Any]:
        del url, headers, timeout
        queries.append(payload)
        return {"groups": [], "total_count": 0}

    verifier = WeaveVerifier(project="e/p", api_key="secret", transport=transport)
    result = verifier.reconcile(
        conversation_id="hivemind:s",
        expected_trace_ids=[],
        turn_key="atif:synthetic:1",
        payload_sha256="a" * 64,
        timeout_seconds=0,
    )
    assert result == ReconcileResult(matches=0, trace_ids=[])
    assert len(queries) == 2
    assert "parent_span_id" in str(queries[0])
    assert "parent_span_id" not in str(queries[1])


def test_reconcile_does_not_reupload_after_absence_then_transport_failure() -> None:
    now = 0.0

    def monotonic() -> float:
        return now

    def sleep(seconds: float) -> None:
        nonlocal now
        now += seconds

    def transport(
        url: str, payload: dict[str, Any], headers: dict[str, str], timeout: float
    ) -> dict[str, Any]:
        del payload, headers, timeout
        if now >= 1:
            raise VerificationError("Weave verification transport failed")
        if url.endswith("/chat"):
            return {"turns": [], "has_more": False}
        if url.endswith("/conversations/spans"):
            return {"conversations": []}
        return {"groups": [], "total_count": 0}

    verifier = WeaveVerifier(
        project="e/p",
        api_key="secret",
        transport=transport,
        sleep=sleep,
        monotonic=monotonic,
    )
    with pytest.raises(VerificationError, match="transport failed"):
        verifier.reconcile(
            conversation_id="hivemind:s",
            expected_trace_ids=["trace-recorded"],
            turn_key="atif:step:1",
            payload_sha256="a" * 64,
            expected_span_count=3,
            timeout_seconds=1,
        )
