"""Internal models independent of the optional-at-import-time Weave SDK."""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass, field
from datetime import datetime
from typing import Any

from .errors import ATIFSchemaError
from .redaction import redact_string
from .utils import coerce_string, first_present, parse_datetime, sha256_json

_SOURCE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$")


@dataclass(frozen=True)
class Session:
    id: str
    agent_session_id: str
    title: str
    agent_type: str
    model: str
    started_at: datetime
    last_activity_at: datetime
    last_activity_known: bool = True
    repository: str = ""
    branch: str = ""
    parent_session_id: str = ""
    user: str = ""

    @classmethod
    def from_api(cls, data: dict[str, Any]) -> Session:
        session_id = coerce_string(data.get("id")).strip()
        if not session_id:
            raise ATIFSchemaError("session summary is missing id")
        if not _SOURCE_ID.fullmatch(session_id) or redact_string(session_id) != session_id:
            raise ATIFSchemaError("session summary has an unsafe or unsupported id")
        started_at = parse_datetime(data.get("started_at"))
        if started_at is None:
            raise ATIFSchemaError("session summary has an invalid started_at timestamp")
        parsed_activity = parse_datetime(data.get("last_activity_at"))
        last_activity_at = parsed_activity or started_at
        repository = first_present(data, "git_repo", "repository", "repo", "repo_name", default="")
        user = first_present(data, "username", "user", "user_email", default="")
        if isinstance(user, dict):
            user = first_present(user, "username", "email", "name", "id", default="")
        return cls(
            id=session_id,
            agent_session_id=coerce_string(data.get("agent_session_id")),
            title=coerce_string(data.get("title"), "Untitled HiveMind session"),
            agent_type=coerce_string(data.get("agent_type"), "unknown").lower(),
            model=coerce_string(first_present(data, "model", "model_name", default="")),
            started_at=started_at,
            last_activity_at=last_activity_at,
            last_activity_known=parsed_activity is not None,
            repository=coerce_string(repository),
            branch=coerce_string(first_present(data, "git_branch", "branch", default="")),
            parent_session_id=coerce_string(data.get("parent_session_id")),
            user=coerce_string(user),
        )


@dataclass(frozen=True)
class ChatMessage:
    role: str
    content: str


@dataclass(frozen=True)
class MappedTool:
    name: str
    arguments: Any
    result: Any
    tool_call_id: str
    tool_type: str
    description: str
    started_at: datetime
    ended_at: datetime


@dataclass(frozen=True)
class MappedLLM:
    model: str
    provider: str
    system_instructions: list[str]
    input_messages: list[ChatMessage]
    output_messages: list[ChatMessage]
    reasoning: str
    usage: dict[str, int]
    finish_reasons: list[str]
    started_at: datetime
    ended_at: datetime


@dataclass(frozen=True)
class MappedSubAgent:
    name: str
    model: str
    agent_id: str
    description: str
    version: str
    system_instructions: list[str]
    started_at: datetime
    ended_at: datetime
    timestamp_inferred: bool


@dataclass
class MappedTurn:
    key: str
    messages: list[ChatMessage]
    output_messages: list[ChatMessage]
    system_instructions: list[str]
    llms: list[MappedLLM]
    tools: list[MappedTool]
    subagents: list[MappedSubAgent]
    started_at: datetime
    ended_at: datetime
    hash_context: dict[str, Any] = field(default_factory=dict)
    attributes: dict[str, Any] = field(default_factory=dict)
    payload_sha256: str = ""
    verification_signature: str = ""

    def payload_for_hash(self) -> dict[str, Any]:
        payload = asdict(self)
        payload.pop("payload_sha256", None)
        payload.pop("verification_signature", None)
        # Search/provenance attributes can legitimately change independently of
        # a source turn (for example importer version or session branch).
        stable_attribute_roots = {
            "hivemind.session_id",
            "hivemind.agent_session_id",
            "hivemind.turn_key",
            "hivemind.repository",
            "hivemind.parent_session_id",
            "hivemind.is_subagent",
            "hivemind.atif_schema_version",
            "hivemind.timestamp_inferred",
            "hivemind.synthetic_turn",
            "hivemind.llm_spans_inferred",
            "hivemind.copied_context_steps",
            "hivemind.mapping_warnings",
            "hivemind.preserved_step_data",
            "hivemind.unreferenced_subagent_trajectories",
        }
        stable_attributes = {
            key: value
            for key, value in self.attributes.items()
            if any(key == root or key.startswith(f"{root}.") for root in stable_attribute_roots)
        }
        payload["attributes"] = stable_attributes
        return payload

    def finalize_hash(self) -> None:
        self.payload_sha256 = sha256_json(self.payload_for_hash())
        self.attributes["hivemind.payload_sha256"] = self.payload_sha256


@dataclass(frozen=True)
class MappedConversation:
    conversation_id: str
    conversation_name: str
    agent_name: str
    model: str
    agent_id: str
    agent_version: str
    schema_version: str
    source_last_activity_at: datetime
    turns: list[MappedTurn]


@dataclass
class RunReport:
    discovered: int = 0
    eligible: int = 0
    deferred: int = 0
    planned: int = 0
    imported: int = 0
    skipped: int = 0
    conflicted: int = 0
    failed: int = 0
    emitted_spans: int = 0
    errors: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return self.conflicted == 0 and self.failed == 0

    def render(self, *, dry_run: bool = False) -> str:
        prefix = "Dry run" if dry_run else "Import"
        lines = [
            f"{prefix} summary:",
            f"  discovered sessions: {self.discovered}",
            f"  eligible sessions:   {self.eligible}",
            f"  deferred sessions:   {self.deferred}",
            f"  planned turns:        {self.planned}",
            f"  imported turns:       {self.imported}",
            f"  skipped turns:        {self.skipped}",
            f"  conflicted turns:     {self.conflicted}",
            f"  failed items:         {self.failed}",
            f"  emitted spans:        {self.emitted_spans}",
        ]
        if self.errors:
            lines.append(f"  withheld error details: {len(self.errors)}")
        return "\n".join(lines)
