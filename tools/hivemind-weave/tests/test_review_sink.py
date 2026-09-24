from __future__ import annotations

import base64
import hashlib
import importlib
import json
import os
import subprocess
import sys
from collections.abc import Callable
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from typing import Any

import pytest

from hivemind_weave import review_sink as review_sink_module
from hivemind_weave.atif import map_atif
from hivemind_weave.models import Session
from hivemind_weave.pii import sanitize_mapped_conversation
from hivemind_weave.review_manifest import build_review_manifest
from hivemind_weave.review_sink import (
    HostedProjectGuard,
    HostedReviewError,
    HostedReviewManifest,
    HostedReviewSink,
    ObjectPublication,
    ProjectAccess,
    ReviewContent,
    ReviewObjectPublicationError,
    ReviewRootConflictError,
    ReviewRootUncertainError,
    RootMatchCertificate,
    preflight_review_bundle,
)
from hivemind_weave.review_state import review_logical_key

_TRACE_ID = "1" * 32
_ROOT_SPAN_ID = "2" * 16
_OTHER_TRACE_ID = "3" * 32
_OTHER_ROOT_SPAN_ID = "4" * 16
_SESSION_ID = "11111111-1111-4111-8111-111111111111"
_OTHER_SESSION_ID = "22222222-2222-4222-8222-222222222222"
_PARENT_SESSION_ID = "33333333-3333-4333-8333-333333333333"


class Box:
    def __init__(self, **values: Any) -> None:
        self.__dict__.update(values)


class FakeTurn(Box):
    def _build_attrs(self, **_values: Any) -> dict[str, Any]:
        return {"gen_ai.operation.name": "invoke_agent"}


class FakeDistribution:
    def __init__(self, direct_url: dict[str, Any] | None) -> None:
        self.direct_url = direct_url

    def read_text(self, filename: str) -> str | None:
        assert filename == "direct_url.json"
        return None if self.direct_url is None else json.dumps(self.direct_url)


class FakeRecordPath:
    def __init__(
        self,
        path: str,
        data: bytes,
        *,
        mode: str = "sha256",
        value: str | None = None,
        size: int | None = None,
        include_hash: bool = True,
    ) -> None:
        self.path = path
        digest = base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=").decode()
        self.hash = SimpleNamespace(mode=mode, value=value or digest) if include_hash else None
        self.size = len(data) if size is None else size

    def __str__(self) -> str:
        return self.path


class FakeRecordDistribution:
    def __init__(
        self,
        root: Any,
        records: list[FakeRecordPath],
        *,
        overrides: dict[str, Any] | None = None,
    ) -> None:
        self.root = root
        self.files = records
        self.overrides = overrides or {}

    def locate_file(self, path: Any) -> Any:
        name = str(path)
        return self.overrides.get(name, self.root / name)


class FakeConversationModule:
    Message = Box
    TextPart = Box
    UriPart = Box
    Turn = FakeTurn


class FakeGuard:
    def __init__(self, access: ProjectAccess, events: list[tuple[Any, ...]]) -> None:
        self.access = access
        self.events = events

    def check(self, *, entity: str, project: str) -> ProjectAccess:
        self.events.append(("guard", entity, project))
        return self.access


class FakeRef:
    def __init__(
        self,
        owner: FakeWeave,
        *,
        name: str,
        digest: str,
        uri: str,
        content: Box,
    ) -> None:
        self.owner = owner
        self.name = name
        self.digest = digest
        self.uri = uri
        self.content = content

    def get(self) -> Box:
        self.owner.events.append(("get", self.name, self.uri))
        data = self.content.data
        if self.owner.corrupt_name == self.name:
            data = data + b"corrupt"
        return Box(
            data=data,
            digest=self.content.digest,
            size=self.content.size,
            mimetype=self.content.mimetype,
        )


class FakeContent:
    @classmethod
    def from_bytes(
        cls,
        data: bytes,
        *,
        mimetype: str,
        extension: str,
    ) -> Box:
        return Box(
            data=data,
            digest=hashlib.sha256(data).hexdigest(),
            size=len(data),
            mimetype=mimetype,
            extension=extension,
        )


class FakeWeave:
    Content = FakeContent

    def __init__(self, events: list[tuple[Any, ...]]) -> None:
        self.events = events
        self.project = ""
        self.init_call: dict[str, Any] | None = None
        self.refs: dict[str, FakeRef] = {}
        self.logged: list[dict[str, Any]] = []
        self.fail_first_publish_after_store = False
        self.publish_attempts = 0
        self.corrupt_name = ""
        self.root_error = False
        self.trace_ids = [_TRACE_ID]
        self.root_span_ids = [_ROOT_SPAN_ID]

    def init(
        self,
        project: str,
        *,
        ensure_project_exists: bool,
        settings: dict[str, Any],
    ) -> None:
        self.project = project
        self.init_call = {
            "project": project,
            "ensure_project_exists": ensure_project_exists,
            "settings": settings,
        }
        self.events.append(("init", project, ensure_project_exists))

    def publish(self, content: Box, *, name: str) -> FakeRef:
        self.publish_attempts += 1
        self.events.append(("publish", name, content.digest))
        raw_digest = hashlib.sha256(f"{name}:{content.digest}".encode()).digest()
        object_digest = (
            base64.urlsafe_b64encode(raw_digest)
            .decode("ascii")
            .replace("-", "X")
            .replace("_", "Y")
            .rstrip("=")
        )
        uri = f"weave:///{self.project}/object/{name}:{object_digest}"
        ref = FakeRef(
            self,
            name=name,
            digest=object_digest,
            uri=uri,
            content=content,
        )
        self.refs[uri] = ref
        if self.fail_first_publish_after_store and self.publish_attempts == 1:
            raise RuntimeError("response lost after immutable object acceptance")
        return ref

    def ref(self, uri: str) -> FakeRef:
        self.events.append(("ref", uri))
        assert ":latest" not in uri
        return self.refs[uri]

    def log_turn(self, **payload: Any) -> SimpleNamespace:
        self.events.append(("log_turn", payload["attributes"]["hivemind.turn_key"]))
        self.logged.append(payload)
        if self.root_error:
            raise RuntimeError("response lost after root submission")
        return SimpleNamespace(
            trace_ids=self.trace_ids,
            root_span_ids=self.root_span_ids,
            span_count=1,
        )

    def finish(self) -> None:
        self.events.append(("finish",))


class FakeVerifier:
    def __init__(self, events: list[tuple[Any, ...]]) -> None:
        self.events = events
        self.response = SimpleNamespace(
            matches=1,
            trace_ids=[_TRACE_ID],
            root_span_ids=[_ROOT_SPAN_ID],
            span_count=1,
        )
        self.calls: list[dict[str, Any]] = []
        self.logical_response = SimpleNamespace(
            matches=0,
            trace_ids=[],
            root_span_ids=[],
            span_count=0,
        )
        self.logical_calls: list[dict[str, Any]] = []

    def reconcile(self, **query: Any) -> SimpleNamespace:
        self.events.append(("query", query["turn_key"], query["payload_sha256"]))
        self.calls.append(query)
        return self.response

    def logical_root_matches(self, **query: Any) -> SimpleNamespace:
        self.events.append(("logical_query", query["turn_key"]))
        self.logical_calls.append(query)
        return self.logical_response


def _private_access(**updates: Any) -> ProjectAccess:
    values = {
        "exists": True,
        "visibility_scope": "private",
        "can_read": True,
        "can_write": True,
        "canonical_entity": "wandb",
        "canonical_project": "hivemind-chats-review",
    }
    values.update(updates)
    return ProjectAccess(**values)


def _content(value: bytes, *, kind: str) -> ReviewContent:
    digest = hashlib.sha256(value).hexdigest()
    extension = "json" if kind == "index" else "txt"
    mimetype = "application/json; charset=utf-8" if kind == "index" else "text/plain; charset=utf-8"
    return ReviewContent.from_bytes(
        value,
        mimetype=mimetype,
        extension=extension,
        name=f"hm-review-{kind}-{digest}.{extension}",
    )


def _manifest() -> HostedReviewManifest:
    started = datetime(2026, 8, 1, 12, tzinfo=UTC)
    return HostedReviewManifest(
        conversation_id=f"hivemind:{_SESSION_ID}",
        conversation_name="Review session",
        agent_name="codex",
        model="gpt-5",
        agent_id="codex",
        agent_version="1.2.3",
        preview="User: inspect this repository\n\nAssistant: completed review",
        chunks=(
            _content(b'{"turn":"first"}', kind="chunk"),
            _content(b'{"turn":"second"}', kind="chunk"),
        ),
        index=_content(b'{"chunks":2}', kind="index"),
        started_at=started,
        ended_at=started + timedelta(minutes=2),
        session_id=_SESSION_ID,
        attributes={
            "hivemind.repository": "wandb/hivemind",
            "hivemind.branch": "codex/review-mirror",
            "hivemind.parent_session_id": _PARENT_SESSION_ID,
            "hivemind.is_subagent": True,
        },
        manifest_sha256="a" * 64,
        source_payload_sha256="b" * 64,
        preview_signature="c" * 64,
        source_turn_key="turn-1",
        user_preview="inspect this repository",
        final_assistant_preview="completed review",
    )


def _sink(
    *,
    access: ProjectAccess | None = None,
    object_publish_attempts: int = 2,
) -> tuple[HostedReviewSink, FakeWeave, FakeVerifier, list[tuple[Any, ...]]]:
    events: list[tuple[Any, ...]] = []
    fake = FakeWeave(events)
    verifier = FakeVerifier(events)
    sink = HostedReviewSink(
        project_guard=FakeGuard(access or _private_access(), events),
        root_verifier=verifier,
        weave_module=fake,
        conversation_module=FakeConversationModule,
        require_pii_dependencies=False,
        object_publish_attempts=object_publish_attempts,
    )
    return sink, fake, verifier, events


@pytest.mark.parametrize(
    "access",
    [
        _private_access(exists=False),
        _private_access(visibility_scope="public"),
        _private_access(can_read=False),
        _private_access(can_write=False),
        _private_access(canonical_entity="other"),
    ],
)
def test_start_requires_authoritative_existing_private_write_access(
    access: ProjectAccess,
) -> None:
    sink, fake, _verifier, events = _sink(access=access)

    with pytest.raises(HostedReviewError, match="already exist"):
        sink.start("wandb/hivemind-chats-review")

    assert fake.init_call is None
    assert events == [("guard", "wandb", "hivemind-chats-review")]


def test_start_initializes_only_through_no_create_interface() -> None:
    sink, fake, _verifier, events = _sink()

    sink.start("wandb/hivemind-chats-review")

    assert fake.init_call is not None
    assert fake.init_call["ensure_project_exists"] is False
    assert fake.init_call["settings"]["retry_max_attempts"] == 1
    assert fake.init_call["settings"]["enable_disk_fallback"] is False
    assert events[:2] == [
        ("guard", "wandb", "hivemind-chats-review"),
        ("init", "wandb/hivemind-chats-review", False),
    ]


def test_read_only_start_authorizes_queries_without_initializing_write_transport() -> None:
    sink, fake, verifier, events = _sink(access=_private_access(can_write=False))
    started = datetime(2026, 8, 1, 12, tzinfo=UTC)
    index_hash = "1" * 64
    index_ref = (
        "weave:///wandb/hivemind-chats-review/object/"
        f"hivemind-hosted-review-index-v1-{index_hash}.json:{'Z' * 43}"
    )

    sink.start_read_only("wandb/hivemind-chats-review")
    evidence = sink.find_roots(
        conversation_id=f"hivemind:{_SESSION_ID}",
        logical_key="3" * 64,
        manifest_ref=index_ref,
        preview_signature="4" * 64,
        started_at=started,
        ended_at=started + timedelta(minutes=1),
    )
    sink.finish()

    assert evidence.matches == 1
    assert fake.init_call is None
    assert fake.logged == []
    assert [event[0] for event in events] == ["guard", "query"]
    query = verifier.calls[0]
    assert query["expected_span_count"] == 1
    assert query["expected_started_at"] == started
    assert query["expected_ended_at"] == started + timedelta(minutes=1)
    assert query["expected_root_attributes"]["hivemind.review.index_uri"] == index_ref
    assert query["expected_root_attributes"]["hivemind.review.preview_signature"] == "4" * 64


@pytest.mark.parametrize("read_only", [False, True])
def test_transport_is_validated_before_even_an_injected_guard(
    monkeypatch: Any,
    read_only: bool,
) -> None:
    monkeypatch.setenv("WEAVE_INSECURE_DISABLE_SSL", "true")
    sink, fake, _verifier, events = _sink()

    with pytest.raises(HostedReviewError, match="transport is unsafe"):
        if read_only:
            sink.start_read_only("wandb/hivemind-chats-review")
        else:
            sink.start("wandb/hivemind-chats-review")

    assert events == []
    assert fake.init_call is None


def test_default_guard_fails_closed_without_api_key_and_rejects_other_project(
    monkeypatch: Any,
) -> None:
    monkeypatch.delenv("WANDB_API_KEY", raising=False)
    events: list[tuple[Any, ...]] = []
    fake = FakeWeave(events)
    verifier = FakeVerifier(events)
    missing_guard = HostedReviewSink(
        root_verifier=verifier,
        weave_module=fake,
        conversation_module=FakeConversationModule,
        require_pii_dependencies=False,
    )
    with pytest.raises(HostedReviewError, match="WANDB_API_KEY"):
        missing_guard.start("wandb/hivemind-chats-review")

    sink, fake, _verifier, events = _sink()
    with pytest.raises(HostedReviewError, match="restricted"):
        sink.start("wandb/hivemind-chats")
    assert fake.init_call is None
    assert events == []


@pytest.mark.parametrize(
    "overrides",
    [
        {"trace_server_url": "https://attacker.example"},
        {"wandb_base_url": "https://attacker.example"},
    ],
)
def test_custom_endpoints_fail_at_construction_before_credentials_or_guard(
    overrides: dict[str, str],
) -> None:
    events: list[tuple[Any, ...]] = []
    with pytest.raises(HostedReviewError, match="custom hosted-review endpoints"):
        HostedReviewSink(
            project_guard=FakeGuard(_private_access(), events),
            root_verifier=FakeVerifier(events),
            weave_module=FakeWeave(events),
            conversation_module=FakeConversationModule,
            require_pii_dependencies=False,
            **overrides,
        )
    assert events == []


def test_default_hosted_guard_uses_one_read_only_graphql_query(
    monkeypatch: Any,
) -> None:
    monkeypatch.setenv("WANDB_API_KEY", "a" * 40)
    requests: list[Any] = []

    def transport(request: Any, timeout: float) -> bytes:
        requests.append(request)
        assert timeout == 15.0
        return json.dumps(
            {
                "data": {
                    "project": {
                        "id": "project-id",
                        "name": "hivemind-chats-review",
                        "entityName": "wandb",
                        "access": "PRIVATE",
                        "readOnly": False,
                    }
                }
            }
        ).encode()

    access = HostedProjectGuard(transport=transport).check(
        entity="wandb",
        project="hivemind-chats-review",
    )

    assert access == _private_access()
    assert len(requests) == 1
    request = requests[0]
    assert request.full_url == "https://api.wandb.ai/graphql"
    assert request.method == "POST"
    assert request.get_header("Authorization") == (
        "Basic YXBpOmFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWE="
    )
    payload = json.loads(request.data)
    assert payload["operationName"] == "HivemindReviewProject"
    assert payload["variables"] == {
        "entity": "wandb",
        "project": "hivemind-chats-review",
    }
    assert "mutation" not in payload["query"].lower()
    assert all(
        field in payload["query"] for field in ("id", "name", "entityName", "access", "readOnly")
    )


def test_default_hosted_guard_accepts_restricted_private_scope(monkeypatch: Any) -> None:
    monkeypatch.setenv("WANDB_API_KEY", "a" * 40)
    response = {
        "data": {
            "project": {
                "id": "project-id",
                "name": "hivemind-chats-review",
                "entityName": "wandb",
                "access": "RESTRICTED",
                "readOnly": False,
            }
        }
    }

    access = HostedProjectGuard(
        transport=lambda _request, _timeout: json.dumps(response).encode()
    ).check(entity="wandb", project="hivemind-chats-review")

    assert access == _private_access()


@pytest.mark.parametrize(
    "response",
    [
        {"data": {"project": None}},
        {"errors": [{"message": "withheld"}], "data": {"project": None}},
        {
            "data": {
                "project": {
                    "id": "id",
                    "name": "hivemind-chats-review",
                    "entityName": "wandb",
                    "access": "PUBLIC",
                    "readOnly": False,
                }
            }
        },
        {
            "data": {
                "project": {
                    "id": "id",
                    "name": "hivemind-chats-review",
                    "entityName": "wandb",
                    "access": "USER_READ",
                    "readOnly": False,
                }
            }
        },
        {
            "data": {
                "project": {
                    "id": "id",
                    "name": "hivemind-chats-review",
                    "entityName": "wandb",
                    "access": "USER_WRITE",
                    "readOnly": False,
                }
            }
        },
        {
            "data": {
                "project": {
                    "id": "id",
                    "name": "hivemind-chats-review",
                    "entityName": "wandb",
                    "access": "PRIVATE",
                    "readOnly": None,
                }
            }
        },
    ],
)
def test_default_hosted_guard_fails_closed_on_incomplete_or_unsafe_evidence(
    monkeypatch: Any,
    response: dict[str, Any],
) -> None:
    monkeypatch.setenv("WANDB_API_KEY", "a" * 40)
    guard = HostedProjectGuard(transport=lambda _request, _timeout: json.dumps(response).encode())
    with pytest.raises(HostedReviewError, match="privacy and effective access"):
        guard.check(entity="wandb", project="hivemind-chats-review")


def test_default_guard_allows_private_read_only_reconcile_but_blocks_apply(
    monkeypatch: Any,
) -> None:
    monkeypatch.setenv("WANDB_API_KEY", "a" * 40)
    response = {
        "data": {
            "project": {
                "id": "id",
                "name": "hivemind-chats-review",
                "entityName": "wandb",
                "access": "PRIVATE",
                "readOnly": True,
            }
        }
    }
    guard = HostedProjectGuard(transport=lambda _request, _timeout: json.dumps(response).encode())
    events: list[tuple[Any, ...]] = []
    verifier = FakeVerifier(events)
    fake = FakeWeave(events)
    apply_sink = HostedReviewSink(
        project_guard=guard,
        root_verifier=verifier,
        weave_module=fake,
        conversation_module=FakeConversationModule,
        require_pii_dependencies=False,
    )
    with pytest.raises(HostedReviewError, match="read/write"):
        apply_sink.start("wandb/hivemind-chats-review")
    assert fake.init_call is None

    reconcile_sink = HostedReviewSink(
        project_guard=guard,
        root_verifier=verifier,
        weave_module=fake,
        conversation_module=FakeConversationModule,
        require_pii_dependencies=False,
    )
    reconcile_sink.start_read_only("wandb/hivemind-chats-review")
    assert fake.init_call is None


def test_default_verifier_is_bound_lazily_without_weave_init(
    monkeypatch: Any,
) -> None:
    monkeypatch.setenv("WANDB_API_KEY", "a" * 40)
    events: list[tuple[Any, ...]] = []
    fake_weave = FakeWeave(events)
    created: list[FakeVerifier] = []

    def verifier_factory(*, project: str, api_key: str, base_url: str) -> FakeVerifier:
        assert project == "wandb/hivemind-chats-review"
        assert api_key == "a" * 40
        assert base_url == "https://trace.wandb.ai"
        verifier = FakeVerifier(events)
        verifier.project = project
        verifier.base_url = base_url
        created.append(verifier)
        return verifier

    monkeypatch.setattr(review_sink_module, "WeaveVerifier", verifier_factory)
    sink = HostedReviewSink(
        project_guard=FakeGuard(_private_access(can_write=False), events),
        weave_module=fake_weave,
        conversation_module=FakeConversationModule,
        require_pii_dependencies=False,
    )

    sink.start_read_only("wandb/hivemind-chats-review")

    assert len(created) == 1
    assert sink.root_verifier is created[0]
    assert fake_weave.init_call is None
    assert [event[0] for event in events] == ["guard"]


def test_real_sdk_requires_pep610_proof_of_exact_companion_commit(
    monkeypatch: Any,
) -> None:
    direct_url = {
        "url": "https://github.com/wandb/weave.git",
        "vcs_info": {
            "vcs": "git",
            "commit_id": "0b58f67e1539bfaa2c705e35bed2d9896a319c6a",
            "requested_revision": "0b58f67e1539bfaa2c705e35bed2d9896a319c6a",
        },
    }
    monkeypatch.setattr(
        review_sink_module.importlib_metadata,
        "distributions",
        lambda **_kwargs: [FakeDistribution(direct_url)],
    )
    review_sink_module._assert_pinned_weave_distribution()

    mismatched = json.loads(json.dumps(direct_url))
    mismatched["vcs_info"]["commit_id"] = "0" * 40
    monkeypatch.setattr(
        review_sink_module.importlib_metadata,
        "distributions",
        lambda **_kwargs: [FakeDistribution(mismatched)],
    )
    with pytest.raises(HostedReviewError, match="exact reviewed companion"):
        review_sink_module._assert_pinned_weave_distribution()

    monkeypatch.setattr(
        review_sink_module.importlib_metadata,
        "distributions",
        lambda **_kwargs: [FakeDistribution(None)],
    )
    with pytest.raises(HostedReviewError, match="lacks PEP 610"):
        review_sink_module._assert_pinned_weave_distribution()

    monkeypatch.setattr(
        review_sink_module.importlib_metadata,
        "distributions",
        lambda **_kwargs: [FakeDistribution(direct_url), FakeDistribution(direct_url)],
    )
    with pytest.raises(HostedReviewError, match="lacks readable PEP 610"):
        review_sink_module._assert_pinned_weave_distribution()


def test_pinned_distribution_cannot_authorize_a_shadow_import(tmp_path: Any) -> None:
    shadow_file = tmp_path / "shadow_weave.py"
    shadow_file.write_text("# deliberately not the installed Weave package\n")
    shadow_conversation_file = tmp_path / "shadow_conversation.py"
    shadow_conversation_file.write_text("# deliberately not the installed conversation package\n")
    shadow_conversation = SimpleNamespace(
        __name__="weave.conversation",
        __file__=str(shadow_conversation_file),
        __spec__=SimpleNamespace(origin=str(shadow_conversation_file)),
    )
    shadow_weave = SimpleNamespace(
        __name__="weave",
        __file__=str(shadow_file),
        __spec__=SimpleNamespace(origin=str(shadow_file)),
        conversation=shadow_conversation,
    )

    with pytest.raises(HostedReviewError, match="do not match the pinned distribution"):
        review_sink_module._assert_pinned_weave_runtime(
            shadow_weave,
            shadow_conversation,
        )


def test_runtime_preflight_rejects_shadow_spec_before_import(
    tmp_path: Any,
    monkeypatch: Any,
) -> None:
    expected = tmp_path / "site-packages" / "weave" / "__init__.py"
    expected.parent.mkdir(parents=True)
    expected.write_text("# reviewed package\n")
    shadow = tmp_path / "shadow" / "weave" / "__init__.py"
    shadow.parent.mkdir(parents=True)
    shadow.write_text("raise AssertionError('shadow package executed')\n")
    monkeypatch.setattr(
        review_sink_module,
        "_assert_pinned_weave_distribution",
        lambda: object(),
    )
    monkeypatch.setattr(
        review_sink_module,
        "_verified_weave_record",
        lambda _distribution: {"weave/__init__.py": expected.resolve()},
    )
    monkeypatch.setattr(
        review_sink_module.importlib.util,
        "find_spec",
        lambda _name: SimpleNamespace(
            name="weave",
            origin=str(shadow),
            submodule_search_locations=[str(shadow.parent)],
        ),
    )
    imports: list[str] = []

    def import_module(name: str) -> Any:
        imports.append(name)
        raise AssertionError("shadow import must not execute")

    monkeypatch.setattr(review_sink_module.importlib, "import_module", import_module)

    with pytest.raises(HostedReviewError, match="import resolution"):
        review_sink_module.preflight_review_runtime()

    assert imports == []


def test_weave_record_verification_detects_changed_bytes(tmp_path: Any) -> None:
    root = tmp_path / "site-packages"
    package = root / "weave"
    package.mkdir(parents=True)
    original = b"reviewed"
    initializer = package / "__init__.py"
    initializer.write_bytes(original)
    record = FakeRecordPath("weave/__init__.py", original)
    initializer.write_bytes(b"tampered")

    with pytest.raises(HostedReviewError, match="installation record"):
        review_sink_module._verified_weave_record(FakeRecordDistribution(root, [record]))


@pytest.mark.parametrize(
    "record",
    [
        FakeRecordPath("weave/__init__.py", b"reviewed", include_hash=False),
        FakeRecordPath("weave/__init__.py", b"reviewed", mode="sha512"),
        FakeRecordPath("weave/__init__.py", b"reviewed", value="wrong-hash"),
        FakeRecordPath("weave/__init__.py", b"reviewed", size=-1),
    ],
)
def test_weave_record_verification_rejects_incomplete_or_wrong_metadata(
    tmp_path: Any,
    record: FakeRecordPath,
) -> None:
    initializer = tmp_path / "site-packages" / "weave" / "__init__.py"
    initializer.parent.mkdir(parents=True)
    initializer.write_bytes(b"reviewed")

    with pytest.raises(HostedReviewError, match="installation record"):
        review_sink_module._verified_weave_record(
            FakeRecordDistribution(tmp_path / "site-packages", [record])
        )


def test_weave_record_verification_rejects_missing_file(tmp_path: Any) -> None:
    root = tmp_path / "site-packages"
    root.mkdir()
    record = FakeRecordPath("weave/__init__.py", b"reviewed")

    with pytest.raises(HostedReviewError, match="installation record"):
        review_sink_module._verified_weave_record(FakeRecordDistribution(root, [record]))


def test_weave_record_verification_rejects_path_escape(tmp_path: Any) -> None:
    root = tmp_path / "site-packages"
    package = root / "weave"
    package.mkdir(parents=True)
    initializer_data = b"reviewed"
    (package / "__init__.py").write_bytes(initializer_data)
    outside = tmp_path / "outside.py"
    outside.write_bytes(b"outside")
    records = [
        FakeRecordPath("weave/__init__.py", initializer_data),
        FakeRecordPath("weave/escape.py", b"outside"),
    ]

    with pytest.raises(HostedReviewError, match="installation record"):
        review_sink_module._verified_weave_record(
            FakeRecordDistribution(
                root,
                records,
                overrides={"weave/escape.py": outside},
            )
        )


def test_weave_record_verification_rejects_traversal_entry(tmp_path: Any) -> None:
    root = tmp_path / "site-packages"
    root.mkdir()
    outside = root / "outside.py"
    outside.write_bytes(b"outside")
    record = FakeRecordPath("weave/../outside.py", b"outside")

    with pytest.raises(HostedReviewError, match="installation record"):
        review_sink_module._verified_weave_record(FakeRecordDistribution(root, [record]))


def test_runtime_preflight_disables_weave_error_telemetry_in_fresh_process() -> None:
    environment = os.environ.copy()
    environment.pop("WANDB_ERROR_REPORTING", None)
    script = """
from hivemind_weave.review_sink import preflight_review_runtime
preflight_review_runtime()
from weave.telemetry import trace_sentry
sentry = trace_sentry.global_trace_sentry
assert sentry._disabled is True
assert sentry.scope is None
print("disabled")
"""

    completed = subprocess.run(
        [sys.executable, "-c", script],
        check=False,
        capture_output=True,
        text=True,
        env=environment,
        timeout=30,
    )

    assert completed.returncode == 0, completed.stderr
    assert completed.stdout.strip() == "disabled"


def test_real_sdk_reinit_keeps_first_init_provider_guard_strict(
    monkeypatch: Any,
) -> None:
    sink, fake, _verifier, _events = _sink()
    fake.__name__ = "weave"
    first_init_checks: list[bool] = []
    ownership_checks: list[str] = []
    monkeypatch.setattr(
        review_sink_module,
        "_assert_pinned_weave_runtime",
        lambda _weave, _conversation: None,
    )
    monkeypatch.setattr(
        review_sink_module,
        "_assert_no_preexisting_tracer_provider",
        lambda: first_init_checks.append(True),
    )
    monkeypatch.setattr(
        review_sink_module,
        "_assert_owned_weave_transport",
        lambda endpoint: ownership_checks.append(endpoint),
    )
    monkeypatch.setattr(review_sink_module, "_assert_locked_weave_settings", lambda: None)
    monkeypatch.setattr(review_sink_module, "_disable_weave_version_check", lambda: None)
    monkeypatch.setattr(
        review_sink_module,
        "enforce_weave_error_reporting_disabled",
        lambda: None,
    )

    sink.start("wandb/hivemind-chats-review")
    sink.finish()
    sink.start("wandb/hivemind-chats-review")

    assert first_init_checks == [True]
    assert ownership_checks == ["https://trace.wandb.ai", "https://trace.wandb.ai"]
    assert len([event for event in fake.events if event[0] == "init"]) == 2


def test_previews_are_separate_and_bounded_before_any_object_upload() -> None:
    sink, fake, _verifier, _events = _sink()
    sink.start("wandb/hivemind-chats-review")
    valid = replace(
        _manifest(),
        user_preview="u" * 4_096,
        final_assistant_preview="a" * 4_096,
    )
    publication = sink.publish_objects(valid)
    submission = sink.submit_root(valid, publication)
    assert submission.acknowledged is True
    assert len(fake.logged[0]["messages"][0].parts[0].content) == 4_096
    assert len(fake.logged[0]["output_messages"][0].parts[0].content) == 4_096
    assert fake.logged[0]["messages"][0].parts[0].content.startswith("[REVIEW PREVIEW — USER;")
    assert (
        fake.logged[0]["output_messages"][0]
        .parts[0]
        .content.startswith("[REVIEW PREVIEW — FINAL ASSISTANT;")
    )
    assert "[PREVIEW SHORTENED FOR ROOT;" in (fake.logged[0]["messages"][0].parts[0].content)

    second_sink, second_fake, _verifier, _events = _sink()
    second_sink.start("wandb/hivemind-chats-review")
    with pytest.raises(ValueError, match="4096"):
        second_sink.publish_objects(replace(_manifest(), user_preview="x" * 4_097))
    assert second_fake.refs == {}


@pytest.mark.parametrize(
    "manifest",
    [
        replace(_manifest(), conversation_name="x" * (20 * 1_024 + 1)),
        replace(
            _manifest(),
            attributes={**_manifest().attributes, "hivemind.turn_key": "shadowed"},
        ),
    ],
)
def test_deterministic_root_preflight_fails_before_first_object_upload(
    manifest: HostedReviewManifest,
) -> None:
    sink, fake, _verifier, events = _sink()
    sink.start("wandb/hivemind-chats-review")

    with pytest.raises(HostedReviewError):
        sink.publish_objects(manifest)

    assert fake.refs == {}
    assert all(event[0] != "publish" for event in events)


def test_sink_enforces_64_chunks_and_8_mib_before_publication() -> None:
    sink, fake, _verifier, _events = _sink()
    sink.start("wandb/hivemind-chats-review")
    manifest = _manifest()
    with pytest.raises(ValueError, match="chunk count"):
        sink.publish_objects(replace(manifest, chunks=(manifest.chunks[0],) * 65))
    assert fake.refs == {}

    oversized = _content(b"x" * (8 * 1024 * 1024 + 1), kind="chunk")
    with pytest.raises(ValueError, match="8 MiB"):
        sink.publish_objects(replace(manifest, chunks=(oversized,)))
    assert fake.refs == {}


def test_publish_objects_uses_certified_names_and_verifies_chunks_before_index() -> None:
    sink, fake, _verifier, events = _sink()
    manifest = _manifest()
    sink.start("wandb/hivemind-chats-review")

    publication = sink.publish_objects(manifest)

    assert [item.name for item in publication.chunks] == [item.name for item in manifest.chunks]
    assert publication.index.name.startswith("hivemind-hosted-review-index-v1-")
    assert publication.planning_index_sha256 == manifest.index.sha256
    assert publication.manifest_sha256 == manifest.manifest_sha256
    assert [event[1] for event in events if event[0] == "publish"] == [
        *(item.name for item in manifest.chunks),
        publication.index.name,
    ]
    hosted_index = json.loads(fake.refs[publication.index.uri].content.data)
    assert hosted_index["schema"] == "hivemind-hosted-review-index-v1"
    assert hosted_index["importer_version"] == review_sink_module.__version__
    assert hosted_index["manifest"]["schema"] == "hivemind-review-turn-v1"
    assert hosted_index["planning_index"]["schema"] == ("hivemind-review-turn-index-v1")
    assert [item["uri"] for item in hosted_index["chunks"]] == list(publication.chunk_refs)
    assert [item["sha256"] for item in hosted_index["chunks"]] == list(publication.chunk_hashes)
    assert [item["byte_count"] for item in hosted_index["chunks"]] == list(publication.chunk_sizes)
    assert hosted_index["planning_index"]["sha256"] == manifest.index.sha256
    assert all(":latest" not in item.uri for item in (*publication.chunks, publication.index))
    assert fake.logged == []


def test_corrupt_chunk_readback_blocks_index_and_root() -> None:
    sink, fake, _verifier, events = _sink(object_publish_attempts=1)
    manifest = _manifest()
    fake.corrupt_name = manifest.chunks[0].name
    sink.start("wandb/hivemind-chats-review")

    with pytest.raises(ReviewObjectPublicationError, match="safe content-addressed retry"):
        sink.publish_objects(manifest)

    assert [event[1] for event in events if event[0] == "publish"] == [manifest.chunks[0].name]
    assert fake.logged == []


def test_object_publication_retries_same_content_addressed_name_safely() -> None:
    sink, fake, _verifier, events = _sink(object_publish_attempts=2)
    manifest = _manifest()
    fake.fail_first_publish_after_store = True
    sink.start("wandb/hivemind-chats-review")

    publication = sink.publish_objects(manifest)

    attempts = [event[1] for event in events if event[0] == "publish"]
    assert attempts[:2] == [manifest.chunks[0].name, manifest.chunks[0].name]
    assert publication.chunks[0].name == manifest.chunks[0].name
    assert ReviewObjectPublicationError.retry_safe is True


def test_submit_rereads_every_object_then_logs_one_compact_spanless_root() -> None:
    sink, fake, verifier, events = _sink()
    manifest = _manifest()
    sink.start("wandb/hivemind-chats-review")
    publication = sink.publish_objects(manifest)
    events.clear()

    submission = sink.submit_root(manifest, publication)

    assert submission.acknowledged is True
    assert events[-1][0] == "log_turn"
    assert all(event[0] in {"ref", "get"} for event in events[:-1])
    assert len([event for event in events if event[0] == "get"]) == 3
    assert len(fake.logged) == 1
    payload = fake.logged[0]
    assert payload["spans"] == []
    assert len(payload["output_messages"]) == 1
    assert payload["include_content"] is True
    assert len(payload["messages"]) == 1
    parts = payload["messages"][0].parts
    assert parts[0].content.startswith("[REVIEW PREVIEW — USER;")
    assert parts[0].content.endswith(manifest.user_preview)
    assert (
        payload["output_messages"][0]
        .parts[0]
        .content.startswith("[REVIEW PREVIEW — FINAL ASSISTANT;")
    )
    assert payload["output_messages"][0].parts[0].content.endswith(manifest.final_assistant_preview)
    assert len(parts[0].content) <= 4_096
    assert len(payload["output_messages"][0].parts[0].content) <= 4_096
    assert [part.uri for part in parts[1:]] == [
        publication.index.uri,
        *(item.uri for item in publication.chunks),
    ]
    assert all("charset=utf-8" in part.mime_type for part in parts[1:])
    attributes = payload["attributes"]
    assert attributes["hivemind.review.manifest_sha256"] == manifest.manifest_sha256
    assert attributes["hivemind.source_payload_sha256"] == manifest.source_payload_sha256
    assert attributes["hivemind.review.object_refs_verified"] is True
    assert attributes["hivemind.review.noncanonical"] is True
    assert attributes["hivemind.review.repository"] == "wandb/hivemind"
    assert attributes["hivemind.review.branch"] == "codex/review-mirror"
    assert attributes["hivemind.review.parent_session_id"] == _PARENT_SESSION_ID
    assert attributes["hivemind.review.is_subagent"] is True
    expected_logical_key = review_logical_key(
        "wandb/hivemind-chats-review",
        manifest.conversation_id,
        manifest.source_turn_key,
    )
    assert publication.logical_key == expected_logical_key
    assert attributes["hivemind.review.logical_key"] == expected_logical_key
    assert attributes["hivemind.turn_key"] == f"review:{expected_logical_key}"
    assert attributes["hivemind.review.match_sha256"] == (publication.root_match_certificate.sha256)
    assert attributes["hivemind.payload_sha256"] == (publication.root_match_certificate.sha256)

    sink.finish()
    outcome = sink.verify_root(publication, submission)

    assert outcome.trace_id == _TRACE_ID
    assert outcome.root_span_id == _ROOT_SPAN_ID
    assert events[-2][0] == "finish"
    assert events[-1][0] == "query"
    query = verifier.calls[0]
    assert query["expected_span_count"] == 1
    assert query["expected_trace_ids"] == [_TRACE_ID]
    assert query["turn_key"] == f"review:{expected_logical_key}"
    assert query["payload_sha256"] == publication.root_match_certificate.sha256
    assert query["expected_root_attributes"] == (
        publication.root_match_certificate.expected_root_attributes
    )
    assert query["expected_started_at"] == publication.started_at
    assert query["expected_ended_at"] == publication.ended_at


@pytest.mark.parametrize(
    ("trace_id", "root_span_id"),
    [
        ("0" * 32, _ROOT_SPAN_ID),
        ("A" * 32, _ROOT_SPAN_ID),
        ("1" * 31, _ROOT_SPAN_ID),
        (_TRACE_ID, "0" * 16),
        (_TRACE_ID, "A" * 16),
        (_TRACE_ID, "2" * 15),
    ],
)
def test_submit_never_acknowledges_invalid_w3c_root_ids(
    trace_id: str,
    root_span_id: str,
) -> None:
    sink, fake, _verifier, _events = _sink()
    sink.start("wandb/hivemind-chats-review")
    publication = sink.publish_objects(_manifest())
    fake.trace_ids = [trace_id]
    fake.root_span_ids = [root_span_id]

    submission = sink.submit_root(_manifest(), publication)

    assert submission.attempted is True
    assert submission.acknowledged is False
    assert submission.trace_ids == ()
    assert submission.root_span_ids == ()
    assert submission.error_code == "root_acknowledgement_invalid"


@pytest.mark.parametrize(
    ("trace_id", "root_span_id"),
    [
        ("0" * 32, _ROOT_SPAN_ID),
        ("A" * 32, _ROOT_SPAN_ID),
        (_TRACE_ID, "0" * 16),
        (_TRACE_ID, "A" * 16),
    ],
)
def test_query_rejects_invalid_w3c_root_ids(
    trace_id: str,
    root_span_id: str,
) -> None:
    sink, _fake, verifier, _events = _sink()
    sink.start("wandb/hivemind-chats-review")
    publication = sink.publish_objects(_manifest())
    sink.finish()
    verifier.response = SimpleNamespace(
        matches=1,
        trace_ids=[trace_id],
        root_span_ids=[root_span_id],
        span_count=1,
    )

    with pytest.raises(ReviewRootConflictError, match="W3C identity"):
        sink.query_root(publication)


def test_ambiguous_root_is_never_automatically_resubmitted() -> None:
    sink, fake, verifier, events = _sink()
    manifest = _manifest()
    sink.start("wandb/hivemind-chats-review")
    publication = sink.publish_objects(manifest)
    fake.root_error = True

    submission = sink.submit_root(manifest, publication)
    with pytest.raises(ReviewRootUncertainError, match="already attempted"):
        sink.submit_root(manifest, publication)

    assert submission.acknowledged is False
    assert len(fake.logged) == 1
    assert ReviewRootUncertainError.retry_safe is False
    sink.finish()
    verifier.response = SimpleNamespace(
        matches=0,
        trace_ids=[],
        root_span_ids=[],
        span_count=0,
    )
    with pytest.raises(ReviewRootUncertainError, match="not conclusively visible"):
        sink.verify_root(publication, submission)
    assert len([event for event in events if event[0] == "log_turn"]) == 1


def test_query_only_reconciliation_detects_multiple_roots_without_writing() -> None:
    sink, fake, verifier, events = _sink()
    sink.start("wandb/hivemind-chats-review")
    publication = sink.publish_objects(_manifest())
    sink.finish()
    events.clear()
    verifier.response = SimpleNamespace(
        matches=2,
        trace_ids=[_TRACE_ID, _OTHER_TRACE_ID],
        root_span_ids=[_ROOT_SPAN_ID, _OTHER_ROOT_SPAN_ID],
        span_count=2,
    )

    evidence = sink.query_root(publication)
    with pytest.raises(ReviewRootConflictError, match="multiple"):
        sink.verify_root(publication)

    assert evidence.matches == 2
    assert all(event[0] == "query" for event in events)
    assert fake.logged == []


def test_logical_root_probe_is_read_only_and_uses_no_content_certificate() -> None:
    sink, fake, verifier, events = _sink()
    logical_key = "a" * 64
    sink.start_read_only("wandb/hivemind-chats-review")
    events.clear()

    evidence = sink.find_logical_roots(
        conversation_id=f"hivemind:{_SESSION_ID}",
        logical_key=logical_key,
        timeout_seconds=11.0,
    )

    assert evidence.matches == 0
    assert evidence.trace_ids == ()
    assert evidence.root_span_ids == ()
    assert evidence.span_count == 0
    assert events == [("logical_query", f"review:{logical_key}")]
    assert verifier.logical_calls == [
        {
            "conversation_id": f"hivemind:{_SESSION_ID}",
            "turn_key": f"review:{logical_key}",
            "request_timeout": 11.0,
        }
    ]
    assert fake.init_call is None
    assert fake.logged == []
    assert fake.publish_attempts == 0


def test_logical_root_probe_returns_positive_evidence_without_uploading() -> None:
    sink, fake, verifier, events = _sink()
    verifier.logical_response = SimpleNamespace(
        matches=1,
        trace_ids=[_TRACE_ID],
        root_span_ids=[_ROOT_SPAN_ID],
        span_count=1,
    )
    sink.start_read_only("wandb/hivemind-chats-review")
    events.clear()

    evidence = sink.find_logical_roots(
        conversation_id=f"hivemind:{_SESSION_ID}",
        logical_key="a" * 64,
    )

    assert evidence.matches == 1
    assert evidence.trace_ids == (_TRACE_ID,)
    assert evidence.root_span_ids == (_ROOT_SPAN_ID,)
    assert evidence.span_count == 1
    assert [event[0] for event in events] == ["logical_query"]
    assert fake.init_call is None
    assert fake.logged == []
    assert fake.publish_attempts == 0


def test_logical_root_probe_fails_closed_on_query_or_response_error() -> None:
    sink, fake, verifier, events = _sink()
    sink.start_read_only("wandb/hivemind-chats-review")
    verifier.logical_response = SimpleNamespace(
        matches=0,
        trace_ids=[_TRACE_ID],
        root_span_ids=[],
        span_count=0,
    )

    with pytest.raises(ReviewRootConflictError, match="contradictory"):
        sink.find_logical_roots(
            conversation_id=f"hivemind:{_SESSION_ID}",
            logical_key="a" * 64,
        )

    def failed_query(**_query: Any) -> Any:
        raise RuntimeError("transport failed")

    verifier.logical_root_matches = failed_query  # type: ignore[method-assign]
    with pytest.raises(ReviewRootUncertainError, match="absence could not be established"):
        sink.find_logical_roots(
            conversation_id=f"hivemind:{_SESSION_ID}",
            logical_key="a" * 64,
        )

    assert fake.init_call is None
    assert fake.logged == []
    assert fake.publish_attempts == 0
    assert [event[0] for event in events].count("logical_query") == 1


@pytest.mark.parametrize(
    ("conversation_id", "logical_key"),
    [
        ("not-hivemind", "a" * 64),
        (f"hivemind:{_SESSION_ID}", "A" * 64),
        (f"hivemind:{_SESSION_ID}", "a" * 63),
    ],
)
def test_logical_root_probe_rejects_malformed_local_identity_before_query(
    conversation_id: str,
    logical_key: str,
) -> None:
    sink, fake, verifier, events = _sink()
    sink.start_read_only("wandb/hivemind-chats-review")
    events.clear()

    with pytest.raises(ReviewRootConflictError, match="expectation is malformed"):
        sink.find_logical_roots(
            conversation_id=conversation_id,
            logical_key=logical_key,
        )

    assert verifier.logical_calls == []
    assert events == []
    assert fake.init_call is None
    assert fake.logged == []


def test_root_match_certificate_covers_every_persisted_matching_field() -> None:
    sink, _fake, _verifier, _events = _sink()
    sink.start("wandb/hivemind-chats-review")
    publication = sink.publish_objects(_manifest())
    baseline = publication.root_match_certificate
    values = {
        "conversation_id": baseline.conversation_id,
        "logical_key": baseline.logical_key,
        "index_ref": baseline.index_ref,
        "preview_signature": baseline.preview_signature,
        "started_at": baseline.started_at,
        "ended_at": baseline.ended_at,
    }
    alternatives = {
        "conversation_id": f"hivemind:{_OTHER_SESSION_ID}",
        "logical_key": "d" * 64,
        "index_ref": baseline.index_ref.rsplit(":", 1)[0] + ":" + "e" * 64,
        "preview_signature": "f" * 64,
        "started_at": baseline.started_at - timedelta(seconds=1),
        "ended_at": baseline.ended_at + timedelta(seconds=1),
    }
    for field_name, replacement in alternatives.items():
        candidate = RootMatchCertificate.build(
            **{**values, field_name: replacement},
        )
        assert candidate.sha256 != baseline.sha256


def test_persisted_publication_can_only_reconcile_without_source_content() -> None:
    sink, fake, verifier, events = _sink()
    manifest = _manifest()
    sink.start("wandb/hivemind-chats-review")
    publication = sink.publish_objects(manifest)
    sink.finish()
    reconstructed = ObjectPublication.from_persisted_evidence(
        conversation_id=publication.conversation_id,
        manifest_sha256=publication.manifest_sha256,
        logical_key=publication.logical_key,
        preview_signature=publication.preview_signature,
        started_at=publication.started_at,
        ended_at=publication.ended_at,
        chunk_refs=publication.chunk_refs,
        chunk_hashes=publication.chunk_hashes,
        chunk_sizes=publication.chunk_sizes,
        index_ref=publication.index_ref,
        index_sha256=publication.index_sha256,
        index_size=publication.index.size,
    )
    assert reconstructed.query_only is True
    assert reconstructed.root_payload_sha256 == publication.root_payload_sha256
    assert reconstructed.root_match_certificate == publication.root_match_certificate
    events.clear()

    evidence = sink.query_root(reconstructed)

    assert evidence.matches == 1
    assert [event[0] for event in events] == ["query"]
    assert fake.logged == []
    assert verifier.calls[-1]["payload_sha256"] == publication.root_payload_sha256

    second_sink, _fake, _verifier, _events = _sink()
    second_sink.start("wandb/hivemind-chats-review")
    with pytest.raises(HostedReviewError, match="query-only"):
        second_sink.submit_root(manifest, reconstructed)


def test_exact_root_query_rejects_a_root_with_any_child_span() -> None:
    sink, _fake, verifier, _events = _sink()
    sink.start("wandb/hivemind-chats-review")
    publication = sink.publish_objects(_manifest())
    sink.finish()
    verifier.response = SimpleNamespace(
        matches=1,
        trace_ids=[_TRACE_ID],
        root_span_ids=[_ROOT_SPAN_ID],
        span_count=2,
    )

    with pytest.raises(ReviewRootConflictError, match="incomplete"):
        sink.query_root(publication)


def test_persisted_publication_rejects_mutable_or_cross_project_refs() -> None:
    sink, _fake, _verifier, _events = _sink()
    sink.start("wandb/hivemind-chats-review")
    publication = sink.publish_objects(_manifest())
    common = {
        "conversation_id": publication.conversation_id,
        "manifest_sha256": publication.manifest_sha256,
        "logical_key": publication.logical_key,
        "preview_signature": publication.preview_signature,
        "started_at": publication.started_at,
        "ended_at": publication.ended_at,
        "chunk_hashes": publication.chunk_hashes,
        "chunk_sizes": publication.chunk_sizes,
        "index_ref": publication.index_ref,
        "index_sha256": publication.index_sha256,
        "index_size": publication.index.size,
    }
    with pytest.raises(ReviewRootConflictError, match="mutable"):
        ObjectPublication.from_persisted_evidence(
            **common,
            chunk_refs=(
                publication.chunk_refs[0].rsplit(":", 1)[0] + ":latest",
                *publication.chunk_refs[1:],
            ),
        )
    with pytest.raises(ReviewRootConflictError, match="malformed"):
        ObjectPublication.from_persisted_evidence(
            **common,
            chunk_refs=tuple(
                value.replace("wandb/hivemind-chats-review", "wandb/other")
                for value in publication.chunk_refs
            ),
        )
    sentinel = "sk-proj-1234567890abcdef"
    with pytest.raises(ReviewRootConflictError, match="mutable") as exc_info:
        ObjectPublication.from_persisted_evidence(
            **common,
            chunk_refs=(
                publication.chunk_refs[0].rsplit(":", 1)[0] + f":{sentinel}",
                *publication.chunk_refs[1:],
            ),
        )
    assert sentinel not in str(exc_info.value)


@pytest.mark.parametrize(
    "manifest",
    [
        replace(
            _manifest(),
            conversation_id="hivemind:session-AliceJohnson",
            session_id="session-AliceJohnson",
        ),
        replace(_manifest(), session_id=_OTHER_SESSION_ID),
    ],
)
def test_sink_rejects_nonopaque_or_mismatched_source_coordinates(
    manifest: HostedReviewManifest,
) -> None:
    sink, _fake, _verifier, _events = _sink()
    sink.start("wandb/hivemind-chats-review")

    with pytest.raises((HostedReviewError, ValueError), match=r"(?:conversation|session) ID"):
        sink.publish_objects(manifest)


def test_root_match_rejects_name_like_conversation_coordinate() -> None:
    manifest = _manifest()
    index_hash = "1" * 64
    index_ref = (
        "weave:///wandb/hivemind-chats-review/object/"
        f"hivemind-hosted-review-index-v1-{index_hash}.json:{'Z' * 43}"
    )

    with pytest.raises(ReviewRootConflictError, match="malformed"):
        RootMatchCertificate.build(
            conversation_id="hivemind:session-AliceJohnson",
            logical_key="2" * 64,
            index_ref=index_ref,
            preview_signature="3" * 64,
            started_at=manifest.started_at,
            ended_at=manifest.ended_at,
        )


def test_root_rejects_name_like_parent_coordinate() -> None:
    manifest = replace(
        _manifest(),
        attributes={
            **_manifest().attributes,
            "hivemind.parent_session_id": "child-JohnSmith",
        },
    )
    sink, _fake, _verifier, _events = _sink()
    sink.start("wandb/hivemind-chats-review")

    with pytest.raises(HostedReviewError, match="linkage attributes"):
        sink.publish_objects(manifest)


def test_sink_accepts_and_preserves_canonical_review_manifest_bundle(
    session_payload: Callable[..., dict[str, Any]],
    atif_wrapper: Callable[..., dict[str, Any]],
) -> None:
    conversation = sanitize_mapped_conversation(
        map_atif(Session.from_api(session_payload()), atif_wrapper())
    )
    bundle = build_review_manifest(conversation, conversation.turns[0], max_chunk_bytes=500)
    sink, fake, _verifier, _events = _sink()
    sink.start("wandb/hivemind-chats-review")

    publication = sink.publish_objects(bundle)
    submission = sink.submit_root(
        conversation,
        conversation.turns[0],
        bundle,
        publication,
        logical_key=review_logical_key(
            "wandb/hivemind-chats-review",
            conversation.conversation_id,
            conversation.turns[0].key,
        ),
    )

    assert publication.manifest_sha256 == bundle.manifest_sha256
    assert [item.name for item in publication.chunks] == [item.name for item in bundle.chunks]
    assert publication.index.name.startswith("hivemind-hosted-review-index-v1-")
    assert publication.planning_index_sha256 == bundle.index_sha256
    assert all(item.mimetype == "text/plain; charset=utf-8" for item in publication.chunks)
    assert publication.index.mimetype == "application/json; charset=utf-8"
    assert submission.acknowledged is True
    root = fake.logged[0]
    assert len(root["messages"][0].parts[0].content) <= 4_096
    assert len(root["output_messages"][0].parts[0].content) <= 4_096
    assert root["attributes"]["hivemind.source_payload_sha256"] == (bundle.source_payload_sha256)
    assert root["attributes"]["hivemind.review.preview_signature"] == (bundle.preview_signature)
    published_bytes = {ref.name: ref.content.data for ref in fake.refs.values()}
    assert [published_bytes[item.name] for item in bundle.chunks] == [
        item.content for item in bundle.chunks
    ]
    hosted_index = json.loads(published_bytes[publication.index.name])
    assert hosted_index["planning_index"] == {
        "byte_count": bundle.index_byte_count,
        "name": bundle.index_name,
        "schema": "hivemind-review-turn-index-v1",
        "sha256": bundle.index_sha256,
    }
    assert [item["uri"] for item in hosted_index["chunks"]] == list(publication.chunk_refs)
    reconstructed_chunks: list[bytes] = []
    for item in hosted_index["chunks"]:
        readback = fake.ref(item["uri"]).get()
        assert readback.digest == item["sha256"]
        assert readback.size == item["byte_count"]
        assert readback.mimetype == item["media_type"]
        assert hashlib.sha256(readback.data).hexdigest() == item["sha256"]
        reconstructed_chunks.append(readback.data)
    reconstructed_manifest = b"".join(reconstructed_chunks)
    assert reconstructed_manifest == bundle.manifest_json.encode()
    assert hashlib.sha256(reconstructed_manifest).hexdigest() == bundle.manifest_sha256


def test_pure_bundle_preflight_needs_no_sink_credentials_or_initialization(
    monkeypatch: Any,
    session_payload: Callable[..., dict[str, Any]],
    atif_wrapper: Callable[..., dict[str, Any]],
) -> None:
    monkeypatch.delenv("WANDB_API_KEY", raising=False)
    conversation = map_atif(Session.from_api(session_payload()), atif_wrapper())
    bundle = build_review_manifest(conversation, conversation.turns[0])

    result = preflight_review_bundle(bundle, redactor=review_sink_module.redact_data)

    assert result.manifest.manifest_sha256 == bundle.manifest_sha256
    assert result.logical_key == review_logical_key(
        "wandb/hivemind-chats-review",
        conversation.conversation_id,
        conversation.turns[0].key,
    )
    assert result.root_user_preview.startswith("[REVIEW PREVIEW — USER;")
    assert result.root_final_assistant_preview.startswith("[REVIEW PREVIEW — FINAL ASSISTANT;")


def test_pinned_sdk_preflight_preserves_uri_discriminator_with_pii_enabled(
    monkeypatch: Any,
    session_payload: Callable[..., dict[str, Any]],
    atif_wrapper: Callable[..., dict[str, Any]],
) -> None:
    """Exercise the exact post-init redaction path that previously broke UriPart."""
    runtime = review_sink_module.preflight_review_runtime()
    pii_redaction = importlib.import_module("weave.utils.pii_redaction")
    weave_settings = importlib.import_module("weave.trace.settings")
    analyzed: list[str] = []

    class Analyzer:
        def analyze(self, *, text: str, **_kwargs: Any) -> list[Box]:
            analyzed.append(text)
            return [Box(start=0, end=len(text))] if text == "uri" else []

    class Anonymizer:
        def anonymize(self, *, text: str, analyzer_results: list[Box]) -> Box:
            redacted = "<PERSON>" if analyzer_results else text
            return Box(text=redacted)

    monkeypatch.setattr(
        pii_redaction,
        "_get_engines",
        lambda: (Analyzer(), Anonymizer()),
    )
    monkeypatch.setattr(
        pii_redaction,
        "_get_redaction_entities",
        lambda: ["PERSON"],
    )
    conversation = map_atif(Session.from_api(session_payload()), atif_wrapper())
    bundle = build_review_manifest(conversation, conversation.turns[0])

    with weave_settings.override_settings(
        redact_pii=True,
        capture_client_info=False,
        capture_system_info=False,
    ):
        result = preflight_review_bundle(
            bundle,
            redactor=review_sink_module.redact_data,
            _runtime=runtime,
        )

    assert result.manifest.manifest_sha256 == bundle.manifest_sha256
    assert "uri" not in analyzed


def test_bundle_preflight_exercises_exact_sdk_turn_and_attribute_encoder(
    monkeypatch: Any,
    session_payload: Callable[..., dict[str, Any]],
    atif_wrapper: Callable[..., dict[str, Any]],
) -> None:
    observed: dict[str, Any] = {}

    class ExactTurn(Box):
        def __init__(self, **values: Any) -> None:
            super().__init__(**values)
            observed["turn"] = self

        def _build_attrs(self, **values: Any) -> dict[str, Any]:
            observed["build_attrs"] = values
            return {"gen_ai.operation.name": "invoke_agent"}

    exact_types = SimpleNamespace(
        Message=Box,
        TextPart=Box,
        UriPart=Box,
        Turn=ExactTurn,
    )
    monkeypatch.setattr(
        review_sink_module,
        "preflight_review_runtime",
        lambda: review_sink_module.ReviewRuntime(
            weave=SimpleNamespace(Content=FakeContent, log_turn=lambda **_kwargs: None),
            conversation_types=exact_types,
        ),
    )
    conversation = map_atif(Session.from_api(session_payload()), atif_wrapper())
    bundle = build_review_manifest(conversation, conversation.turns[0])

    preflight_review_bundle(bundle, redactor=review_sink_module.redact_data)

    root = observed["turn"]
    assert root.spans == []
    assert root.continue_parent_trace is False
    assert root.started_at == conversation.turns[0].started_at
    assert root.ended_at == conversation.turns[0].ended_at
    assert len(root.messages) == 1
    assert len(root.messages[0].parts) == 2 + len(bundle.chunks)
    assert all(len(part.uri.rsplit(":", 1)[1]) == 64 for part in root.messages[0].parts[1:])
    assert observed["build_attrs"] == {
        "conversation_id": conversation.conversation_id,
        "conversation_name": conversation.conversation_name,
        "include_content": True,
    }


def test_bundle_preflight_hides_sdk_validation_content(
    monkeypatch: Any,
    session_payload: Callable[..., dict[str, Any]],
    atif_wrapper: Callable[..., dict[str, Any]],
) -> None:
    sentinel = "Authorization: Bearer abcdefghijklmnopqrstuvwxyz"

    class RejectingTurn:
        def __init__(self, **_values: Any) -> None:
            raise ValueError(sentinel)

    rejecting_types = SimpleNamespace(
        Message=Box,
        TextPart=Box,
        UriPart=Box,
        Turn=RejectingTurn,
    )
    monkeypatch.setattr(
        review_sink_module,
        "preflight_review_runtime",
        lambda: review_sink_module.ReviewRuntime(
            weave=SimpleNamespace(Content=FakeContent, log_turn=lambda **_kwargs: None),
            conversation_types=rejecting_types,
        ),
    )
    conversation = map_atif(Session.from_api(session_payload()), atif_wrapper())
    bundle = build_review_manifest(conversation, conversation.turns[0])

    with pytest.raises(HostedReviewError, match="pinned Weave rejected") as exc_info:
        preflight_review_bundle(bundle, redactor=review_sink_module.redact_data)

    assert sentinel not in str(exc_info.value)


def test_bundle_preflight_hides_attribute_encoder_content(
    monkeypatch: Any,
    session_payload: Callable[..., dict[str, Any]],
    atif_wrapper: Callable[..., dict[str, Any]],
) -> None:
    sentinel = "Authorization: Bearer abcdefghijklmnopqrstuvwxyz"

    class RejectingEncoderTurn(FakeTurn):
        def _build_attrs(self, **_values: Any) -> dict[str, Any]:
            raise HostedReviewError(sentinel)

    rejecting_types = SimpleNamespace(
        Message=Box,
        TextPart=Box,
        UriPart=Box,
        Turn=RejectingEncoderTurn,
    )
    monkeypatch.setattr(
        review_sink_module,
        "preflight_review_runtime",
        lambda: review_sink_module.ReviewRuntime(
            weave=SimpleNamespace(Content=FakeContent, log_turn=lambda **_kwargs: None),
            conversation_types=rejecting_types,
        ),
    )
    conversation = map_atif(Session.from_api(session_payload()), atif_wrapper())
    bundle = build_review_manifest(conversation, conversation.turns[0])

    with pytest.raises(HostedReviewError, match="could not serialize") as exc_info:
        preflight_review_bundle(bundle, redactor=review_sink_module.redact_data)

    assert sentinel not in str(exc_info.value)


def test_bundle_preflight_binds_every_root_submission_keyword(
    monkeypatch: Any,
    session_payload: Callable[..., dict[str, Any]],
    atif_wrapper: Callable[..., dict[str, Any]],
) -> None:
    class MissingDescriptionWeave:
        Content = FakeContent

        @staticmethod
        def log_turn(
            *,
            conversation_id: str,
            conversation_name: str,
            messages: list[Any],
            output_messages: list[Any],
            spans: list[Any],
        ) -> None:
            return None

    monkeypatch.setattr(
        review_sink_module,
        "preflight_review_runtime",
        lambda: review_sink_module.ReviewRuntime(
            weave=MissingDescriptionWeave,
            conversation_types=FakeConversationModule,
        ),
    )
    conversation = map_atif(Session.from_api(session_payload()), atif_wrapper())
    bundle = build_review_manifest(conversation, conversation.turns[0])

    with pytest.raises(HostedReviewError, match="could not serialize"):
        preflight_review_bundle(bundle, redactor=review_sink_module.redact_data)


def test_content_constructor_failure_blocks_all_publication(
    monkeypatch: Any,
    session_payload: Callable[..., dict[str, Any]],
    atif_wrapper: Callable[..., dict[str, Any]],
) -> None:
    attempts = 0

    class RejectingSecondContent:
        @classmethod
        def from_bytes(cls, *args: Any, **kwargs: Any) -> Any:
            nonlocal attempts
            attempts += 1
            if attempts == 2:
                raise ValueError("private content should never appear in the public error")
            return FakeContent.from_bytes(*args, **kwargs)

    conversation = map_atif(Session.from_api(session_payload()), atif_wrapper())
    bundle = build_review_manifest(conversation, conversation.turns[0], max_chunk_bytes=100)
    sink, fake, _verifier, events = _sink()
    sink.start("wandb/hivemind-chats-review")
    sink.weave = SimpleNamespace(
        Content=RejectingSecondContent,
        log_turn=fake.log_turn,
    )

    with pytest.raises(HostedReviewError, match="rejected prepared review content") as exc_info:
        sink.publish_objects(bundle)

    assert "private content" not in str(exc_info.value)
    assert attempts == 2
    assert fake.refs == {}
    assert all(event[0] != "publish" for event in events)


def test_canonical_bundle_must_be_a_redaction_fixed_point_before_any_upload(
    session_payload: Callable[..., dict[str, Any]],
    atif_wrapper: Callable[..., dict[str, Any]],
) -> None:
    conversation = map_atif(Session.from_api(session_payload()), atif_wrapper())
    turn = conversation.turns[0]
    turn.messages[0] = replace(
        turn.messages[0],
        content="Authorization: Bearer abcdefghijklmnopqrstuvwxyz",
    )
    turn.finalize_hash()
    bundle = build_review_manifest(conversation, turn)
    sink, fake, _verifier, _events = _sink()
    sink.start("wandb/hivemind-chats-review")

    with pytest.raises(HostedReviewError, match="not a fixed point"):
        sink.publish_objects(bundle)

    assert fake.refs == {}
    assert fake.logged == []


def test_canonical_sanitized_review_omits_secrets_and_pii_from_every_sent_payload(
    session_payload: Callable[..., dict[str, Any]],
    atif_wrapper: Callable[..., dict[str, Any]],
) -> None:
    api_key = "sk-abcdefghijklmnopqrstuvwxyz123456"
    bearer = "Bearer abcdefghijklmnopqrstuvwxyz"
    private_key_marker = "FAKEPRIVATEKEYSENTINEL"
    private_key = f"-----BEGIN PRIVATE KEY-----\n{private_key_marker}\n-----END PRIVATE KEY-----"
    email = "alice@example.com"
    phone = "212-555-1212"
    person = "Alice Johnson"
    ordinary_code = "class CustomerLedger:\n    pass\n\nledger = CustomerLedger()"
    steps = [
        {
            "step_id": 1,
            "timestamp": "2026-08-01T12:00:00Z",
            "source": "system",
            "message": "You are a coding agent.",
        },
        {
            "step_id": 2,
            "timestamp": "2026-08-01T12:00:01Z",
            "source": "user",
            "message": f"Contact {person} at {email} or {phone}. API key: {api_key}",
        },
        {
            "step_id": 3,
            "timestamp": "2026-08-01T12:00:02Z",
            "source": "agent",
            "model_name": "gpt-5.6-codex",
            "message": "I will inspect the safe implementation.",
            "reasoning_content": f"Use {bearer} only in the source transcript.",
            "tool_calls": [
                {
                    "tool_call_id": "call-privacy",
                    "function_name": "inspect_config",
                    "arguments": {
                        "private_key": private_key,
                        "contact": phone,
                    },
                }
            ],
            "observation": {
                "results": [
                    {
                        "source_call_id": "call-privacy",
                        "content": {"owner": person, "email": email},
                    }
                ]
            },
            "finish_reason": "tool_call",
        },
        {
            "step_id": 4,
            "timestamp": "2026-08-01T12:00:04Z",
            "source": "agent",
            "message": f"The ordinary implementation remains:\n{ordinary_code}",
        },
    ]
    lowercase_agent_id = "nonopaque-source-coordinate"
    mapped = map_atif(
        Session.from_api(session_payload(agent_session_id=lowercase_agent_id)),
        atif_wrapper(steps=steps),
    )
    conversation = sanitize_mapped_conversation(mapped)
    turn = conversation.turns[0]
    bundle = build_review_manifest(conversation, turn, max_chunk_bytes=500)
    events: list[tuple[Any, ...]] = []
    fake = FakeWeave(events)
    sink = HostedReviewSink(
        project_guard=FakeGuard(_private_access(), events),
        root_verifier=FakeVerifier(events),
        weave_module=fake,
        conversation_module=FakeConversationModule,
        require_pii_dependencies=True,
    )
    sink.start("wandb/hivemind-chats-review")

    publication = sink.publish_objects(bundle)
    submission = sink.submit_root(
        conversation,
        turn,
        bundle,
        publication,
        logical_key=review_logical_key(
            "wandb/hivemind-chats-review",
            conversation.conversation_id,
            turn.key,
        ),
    )

    assert submission.acknowledged is True
    assert len(publication.chunks) > 1
    chunk_wire = b"".join(fake.refs[item.uri].content.data for item in publication.chunks).decode()
    index_wire = fake.refs[publication.index.uri].content.data.decode()
    root_wire = json.dumps(
        fake.logged[0],
        default=lambda value: vars(value) if hasattr(value, "__dict__") else str(value),
        sort_keys=True,
    )
    all_sent_wire = "\n".join((chunk_wire, index_wire, root_wire))

    for private_value in (
        api_key,
        bearer,
        private_key,
        private_key_marker,
        email,
        phone,
        person,
        lowercase_agent_id,
    ):
        assert private_value not in all_sent_wire
    manifest_payload = json.loads(chunk_wire)

    def string_values(value: Any) -> list[str]:
        if isinstance(value, str):
            return [value]
        if isinstance(value, dict):
            return [item for child in value.values() for item in string_values(child)]
        if isinstance(value, list):
            return [item for child in value for item in string_values(child)]
        return []

    assert any(ordinary_code in value for value in string_values(manifest_payload))
    assert "class CustomerLedger:" in root_wire
