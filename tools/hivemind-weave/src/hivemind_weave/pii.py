"""Configure Weave Presidio redaction without runtime model downloads."""

from __future__ import annotations

import hashlib
import json
import re
import threading
from collections import OrderedDict
from dataclasses import replace
from functools import lru_cache
from typing import Any

from .models import (
    ChatMessage,
    MappedConversation,
    MappedTurn,
)
from .redaction import redact_data, redact_string
from .utils import canonical_json, sha256_json

_PII_ENGINE_REDACTOR: Any | None = None
_REDACTION_CACHE: OrderedDict[tuple[int, str], str] = OrderedDict()
_REDACTION_CACHE_CHARS = 0
_MAX_REDACTION_CACHE_ENTRY_CHARS = 256 * 1024
_MAX_REDACTION_CACHE_CHARS = 32 * 1024 * 1024
_CORRELATION_ATTRIBUTES = {
    "hivemind.session_id",
    "hivemind.turn_key",
    "hivemind.payload_sha256",
    "hivemind.source_payload_sha256",
    "hivemind.atif_schema_version",
    "hivemind.importer_version",
}

_HASH_CORRELATORS = {"conversation_id"}

_KNOWN_AGENT_TYPES = {
    "claude",
    "claude-code",
    "codex",
    "copilot",
    "cursor",
    "gemini",
    "gemini-cli",
    "github-copilot",
    "github-copilot-cli",
    "opencode",
    "pi",
    "unknown",
}
_KNOWN_PROVIDERS = {"anthropic", "google", "openai", "unknown"}
_KNOWN_MODEL = re.compile(
    r"^(?:gpt-|o[134](?:$|[-.])|claude(?:$|[-.])|gemini(?:$|[-.])|codex(?:$|[-.]))"
    r"[a-z0-9._:/-]*$",
    re.IGNORECASE,
)
_CODE_DECLARATION = re.compile(
    r"(?P<prefix>^[ \t]*(?:(?:export|default|public|private|protected|internal|static|"
    r"abstract|final|sealed|async|pub)\s+)*(?:class|def|function|const|let|var|struct|"
    r"enum|interface|"
    r"type|func|fn|module|namespace)\s+)(?P<identifier>[A-Za-z_$][A-Za-z0-9_$]*)",
    re.MULTILINE,
)
_NEW_EXPRESSION = re.compile(
    r"(?P<prefix>\bnew\s+)(?P<identifier>[A-Za-z_$][A-Za-z0-9_$]*)(?=\s*\()"
)
_SCOPED_CODE_IDENTIFIER = re.compile(
    r"\b[A-Za-z_$][A-Za-z0-9_$]*(?:::[A-Za-z_$][A-Za-z0-9_$]*)+"
    r"(?=(?:\s*\(|\b))"
)
_LIKELY_FULL_NAME_OR_LOCATION = re.compile(
    r"\b[A-Z][a-z]{1,}(?:[-'][A-Z]?[a-z]+)?\s+"
    r"[A-Z][a-z]{1,}(?:[-'][A-Z]?[a-z]+)?\b"
)
_UUID = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
    re.IGNORECASE,
)
_ATIF_VERSION = re.compile(r"^ATIF-v\d+\.\d+$", re.IGNORECASE)
_TECHNICAL_ID = re.compile(
    r"^(?:atif|step|call|trace|span|session|req|run|child|tool)[-_:][a-z0-9._:-]+$",
    re.IGNORECASE,
)


class _FullTextAnalyzer:
    """Raise spaCy's safety ceiling monotonically before full-text analysis.

    Presidio and its anonymizer continue to receive the original complete
    string, so entity context and offsets are never divided, truncated, or
    bypassed. The cached pipeline is process-local; the lock makes concurrent
    calls in one process safe, and the monotonic update can never reduce a
    limit needed by an analysis already starting on another thread.
    """

    def __init__(self, analyzer: Any, nlp_engine: Any) -> None:
        self._analyzer = analyzer
        self._nlp_engine = nlp_engine
        self._max_length_lock = threading.Lock()

    def analyze(self, text: str, language: str, **kwargs: Any) -> list[Any]:
        pipeline = self._nlp_engine.nlp.get(language)
        if pipeline is not None:
            with self._max_length_lock:
                pipeline.max_length = max(int(pipeline.max_length), len(text))
        return list(self._analyzer.analyze(text=text, language=language, **kwargs))

    def __getattr__(self, name: str) -> Any:
        return getattr(self._analyzer, name)


def _looks_like_technical_identifier(value: str) -> bool:
    stripped = value.strip()
    return bool(
        _UUID.fullmatch(stripped)
        or _ATIF_VERSION.fullmatch(stripped)
        or _TECHNICAL_ID.fullmatch(stripped)
        or _KNOWN_MODEL.fullmatch(stripped)
        or stripped.lower() in _KNOWN_AGENT_TYPES | _KNOWN_PROVIDERS
    )


def _code_positions(value: str) -> list[bool]:
    """Mark positions outside comments and string/regex literals."""
    positions = [True] * len(value)
    quote = ""
    line_comment = False
    block_comment = False
    escaped = False
    index = 0
    previous_significant = ""
    while index < len(value):
        if line_comment:
            positions[index] = False
            if value[index] == "\n":
                line_comment = False
                previous_significant = ""
            index += 1
            continue
        if block_comment:
            positions[index] = False
            if value.startswith("*/", index):
                if index + 1 < len(value):
                    positions[index + 1] = False
                block_comment = False
                index += 2
            else:
                index += 1
            continue
        if quote:
            positions[index] = False
            char = value[index]
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                quote = ""
            index += 1
            continue
        if value.startswith("```", index):
            positions[index : index + 3] = [False] * min(3, len(value) - index)
            index += 3
            continue
        if value.startswith("//", index) or value.startswith("--", index):
            line_comment = True
            continue
        if value.startswith("/*", index):
            block_comment = True
            continue
        char = value[index]
        if char == "#":
            line_comment = True
            continue
        if char in {"'", '"', "`"}:
            quote = char
            positions[index] = False
            index += 1
            continue
        if char == "/" and previous_significant in {
            "",
            "=",
            "(",
            ":",
            ",",
            "[",
            "!",
            "&",
            "|",
            "?",
            "{",
            ";",
        }:
            quote = "/"
            positions[index] = False
            index += 1
            continue
        if char == "\n":
            previous_significant = ""
        elif not char.isspace():
            previous_significant = char
        index += 1
    return positions


def _protect_declared_code_identifiers(value: str) -> tuple[str, dict[str, str]]:
    positions = _code_positions(value)
    spans: list[tuple[int, int]] = []
    declared_identifiers: set[str] = set()
    for pattern in (_CODE_DECLARATION, _NEW_EXPRESSION):
        for match in pattern.finditer(value):
            start, end = match.span("identifier")
            if start < len(positions) and positions[start]:
                spans.append((start, end))
                if pattern is _CODE_DECLARATION:
                    declared_identifiers.add(match.group("identifier"))

    # A declaration is only useful if later references survive too. Protect
    # exact identifier tokens outside comments and literals; those regions stay
    # unprotected so real names and locations there are still removed.
    for identifier in declared_identifiers:
        reference = re.compile(rf"(?<![A-Za-z0-9_$]){re.escape(identifier)}(?![A-Za-z0-9_$])")
        for match in reference.finditer(value):
            start, end = match.span()
            if start < len(positions) and all(positions[start:end]):
                spans.append((start, end))
    for match in _SCOPED_CODE_IDENTIFIER.finditer(value):
        start, end = match.span()
        if start < len(positions) and all(positions[start:end]):
            spans.append((start, end))

    # Prefer the widest candidate when syntaxes overlap, then apply replacements
    # right-to-left so source offsets remain valid.
    selected: list[tuple[int, int]] = []
    for span in sorted(set(spans), key=lambda item: (-(item[1] - item[0]), item[0])):
        if not any(span[0] < other[1] and other[0] < span[1] for other in selected):
            selected.append(span)
    replacements: dict[str, str] = {}
    protected = value
    placeholder_offset = 0
    while any(
        f"hm_code_identifier_{placeholder_offset + number:06d}_zx" in value
        for number in range(len(selected))
    ):
        placeholder_offset += max(1, len(selected))
    for number, (start, end) in enumerate(sorted(selected, reverse=True)):
        # Keep this lowercase and underscore-delimited: title-cased opaque
        # tokens are themselves classified as names by small English NER.
        token = f"hm_code_identifier_{placeholder_offset + number:06d}_zx"
        replacements[token] = value[start:end]
        protected = f"{protected[:start]}{token}{protected[end:]}"
    return (protected, replacements)


def _source_aware_redact(value: str, engine_redactor: Any) -> str:
    """Redact all content while shielding declared code identifiers.

    Identifiers in syntactically explicit declarations and their code-position
    references are masked during NER and restored afterward. Comments, literals,
    regexes, template strings, fenced blocks, and inline backticks all remain
    subject to PII redaction.
    """
    scrubbed = redact_string(value)
    if _looks_like_technical_identifier(scrubbed):
        return scrubbed
    protected, replacements = _protect_declared_code_identifiers(scrubbed)
    # Small NER models occasionally tag only the surname of a two-token name.
    # Remove an obvious title-cased pair up front; declared/scoped identifiers
    # are already shielded above, so this remains conservative around code.
    protected = _LIKELY_FULL_NAME_OR_LOCATION.sub("[REDACTED]", protected)
    redacted = engine_redactor(protected)
    for placeholder, identifier in replacements.items():
        redacted = redacted.replace(placeholder, identifier)
    return redacted


@lru_cache(maxsize=1)
def configure_weave_pii() -> None:
    """Install a cached, offline Presidio engine into Weave's redaction hook.

    Presidio's default provider downloads a large language model on first use.
    Import jobs must not gain a hidden network dependency, so the package locks
    and installs a compact English NER model ahead of time. The importer's own
    credential/PII scrubber runs before this second layer.
    """
    import tldextract
    from presidio_analyzer import AnalyzerEngine
    from presidio_analyzer.nlp_engine import SpacyNlpEngine
    from presidio_anonymizer import AnonymizerEngine
    from weave.utils import pii_redaction

    global _PII_ENGINE_REDACTOR, _REDACTION_CACHE_CHARS
    _REDACTION_CACHE.clear()
    _REDACTION_CACHE_CHARS = 0
    engine_redactor = getattr(
        pii_redaction,
        "_hivemind_engine_redactor",
        pii_redaction.redact_pii_string,
    )
    _PII_ENGINE_REDACTOR = engine_redactor
    pii_redaction._hivemind_engine_redactor = engine_redactor

    # Presidio's email recognizer uses tldextract, whose module-level default
    # fetches the public-suffix list on first use. The package ships a snapshot,
    # so force that deterministic offline path before creating the recognizers.
    tldextract.extract = tldextract.TLDExtract(cache_dir=None, suffix_list_urls=())

    @lru_cache(maxsize=1)
    def offline_engines() -> tuple[Any, AnonymizerEngine]:
        nlp_engine = SpacyNlpEngine(models=[{"lang_code": "en", "model_name": "en_core_web_sm"}])
        nlp_engine.load()
        analyzer = AnalyzerEngine(
            nlp_engine=nlp_engine,
            supported_languages=["en"],
        )
        return (
            _FullTextAnalyzer(analyzer, nlp_engine),
            AnonymizerEngine(),
        )

    pii_redaction._get_engines = offline_engines
    supported = set(offline_engines()[0].get_supported_entities("en"))
    requested = tuple(pii_redaction._get_redaction_entities())

    def supported_redaction_entities() -> list[str]:
        return [entity for entity in requested if entity in supported]

    # Weave's cross-country default contains a few recognizers Presidio does
    # not ship for English. Filtering those avoids a warning for every string;
    # all locally available Weave-requested entities remain enabled.
    pii_redaction._get_redaction_entities = supported_redaction_entities
    pii_redaction.redact_pii_string = lambda value: _source_aware_redact(
        value,
        engine_redactor,
    )
    probe = "Alice Johnson lives in New York and uses codex-pii-probe@example.com"
    redacted_probe = pii_redaction.redact_pii_string(probe)
    if any(value in redacted_probe for value in ("Alice Johnson", "New York", "probe@example")):
        raise RuntimeError("Presidio person/location/email redaction self-test failed")


def _redact_pii_string_uncached(value: str) -> str:
    try:
        decoded = json.loads(value)
    except (TypeError, json.JSONDecodeError):
        decoded = None
    if isinstance(decoded, (dict, list)):
        return canonical_json(_pii_walk(redact_data(decoded)))
    # Call the captured engine directly. Importing the mutable Weave hook here
    # made cached/reconfigured test and long-running processes intermittently
    # bypass the source-aware wrapper.
    if _PII_ENGINE_REDACTOR is None:
        configure_weave_pii()
    if _PII_ENGINE_REDACTOR is None:  # pragma: no cover - guarded above.
        raise RuntimeError("Presidio redaction engine was not configured")
    return _source_aware_redact(value, _PII_ENGINE_REDACTOR)


def _redact_pii_string(value: str) -> str:
    """Cache by digest only; raw pre-redaction text is never retained as a key."""
    if len(value) > _MAX_REDACTION_CACHE_ENTRY_CHARS:
        return _redact_pii_string_uncached(value)

    global _REDACTION_CACHE_CHARS
    cache_key = (len(value), hashlib.sha256(value.encode("utf-8")).hexdigest())
    cached = _REDACTION_CACHE.get(cache_key)
    if cached is not None:
        _REDACTION_CACHE.move_to_end(cache_key)
        return cached

    redacted = _redact_pii_string_uncached(value)
    if len(redacted) <= _MAX_REDACTION_CACHE_ENTRY_CHARS:
        _REDACTION_CACHE[cache_key] = redacted
        _REDACTION_CACHE_CHARS += len(redacted)
        while _REDACTION_CACHE_CHARS > _MAX_REDACTION_CACHE_CHARS:
            _, evicted = _REDACTION_CACHE.popitem(last=False)
            _REDACTION_CACHE_CHARS -= len(evicted)
    return redacted


def _pii_walk(value: Any) -> Any:
    if isinstance(value, str):
        return _redact_pii_string(value)
    if isinstance(value, dict):
        result: dict[str, Any] = {}
        redacted_key_index = 0
        for raw_key, raw_value in value.items():
            source_key = str(raw_key)
            scrubbed_key = _redact_pii_string(source_key)
            if scrubbed_key != source_key:
                redacted_key_index += 1
                scrubbed_key = f"[REDACTED_PII_KEY_{redacted_key_index:04d}]"
            if scrubbed_key in result:
                raise ValueError("mapping keys collide after PII redaction")
            result[scrubbed_key] = _pii_walk(raw_value)
        return result
    if isinstance(value, list):
        return [_pii_walk(item) for item in value]
    if isinstance(value, tuple):
        return tuple(_pii_walk(item) for item in value)
    return value


def redact_upload_data(value: Any) -> Any:
    """Apply credential patterns and offline Presidio before SDK construction.

    Weave 0.53 redacts its typed conversation fields, but custom attributes are
    merged afterward. Running the same engine locally closes that gap and also
    makes the guarantee testable against the exact payload handed to the SDK.
    """
    configure_weave_pii()
    return _pii_walk(redact_data(value))


def redact_agent_name(value: str) -> str:
    return value if value.strip().lower() in _KNOWN_AGENT_TYPES else str(redact_upload_data(value))


def redact_model_name(value: str) -> str:
    return value if _KNOWN_MODEL.fullmatch(value.strip()) else str(redact_upload_data(value))


def redact_provider_name(value: str) -> str:
    return value if value.strip().lower() in _KNOWN_PROVIDERS else str(redact_upload_data(value))


def _message(item: ChatMessage) -> ChatMessage:
    return replace(item, content=str(redact_upload_data(item.content)))


def _destination_message_content(message: ChatMessage) -> str:
    """Return the exact text persisted by Weave for one typed message.

    ``sanitize_mapped_conversation`` has already applied the first local PII
    pass.  The sink applies ``redact_upload_data`` once more immediately before
    constructing Weave's ``Message`` object.  While building span attributes,
    Weave dumps that typed message to a dict, recursively redacts the dict, and
    validates it back into a ``Message``.  Reproduce that exact typed-message
    path here: its dict-leaf redaction can legitimately differ from Weave's
    top-level ``redact_pii_string`` hook.
    """
    sink_text = str(redact_upload_data(message.content))
    from weave.conversation import Message
    from weave.utils import pii_redaction

    redacted = pii_redaction.redact_messages([Message(role=message.role, content=sink_text)])
    return str(redacted[0].content)


def _verification_signature(turn: MappedTurn) -> str:
    first_user = next((item for item in turn.messages if item.role == "user"), None)
    last_assistant = next(
        (item for item in reversed(turn.output_messages) if item.role == "assistant"),
        None,
    )
    # Hash the exact destination representation: local sanitization (already
    # present on ``turn``), the sink pass, and Weave's final typed-message pass.
    # The signature is deliberately excluded from the semantic payload hash.
    uploaded_first_user = _destination_message_content(first_user) if first_user is not None else ""
    uploaded_last_assistant = (
        _destination_message_content(last_assistant) if last_assistant is not None else ""
    )
    return sha256_json(
        {
            "started_at_ms": int(turn.started_at.timestamp() * 1000),
            "first_user": uploaded_first_user,
            "last_assistant": uploaded_last_assistant,
        }
    )


def _sanitize_turn(turn: MappedTurn) -> MappedTurn:
    # Presidio's statistical recognizers are intentionally conservative, but
    # their choices across a multi-megabyte transcript are not a stable content
    # identity. Hash the complete credential-scrubbed mapped source before ML
    # redaction. Re-sanitizing an already sanitized turn preserves that identity.
    existing_source_hash = turn.attributes.get("hivemind.source_payload_sha256")
    source_payload_sha256 = (
        existing_source_hash
        if isinstance(existing_source_hash, str)
        and re.fullmatch(r"[0-9a-f]{64}", existing_source_hash)
        else sha256_json(turn.payload_for_hash())
    )
    attributes = redact_upload_data(turn.attributes)
    hash_context = redact_upload_data(turn.hash_context)
    assert isinstance(attributes, dict)
    assert isinstance(hash_context, dict)
    for key in _CORRELATION_ATTRIBUTES:
        if key in turn.attributes:
            attributes[key] = turn.attributes[key]
    attributes["hivemind.source_payload_sha256"] = source_payload_sha256
    for key in _HASH_CORRELATORS:
        if key in turn.hash_context:
            hash_context[key] = turn.hash_context[key]
    if "agent_name" in turn.hash_context:
        hash_context["agent_name"] = redact_agent_name(str(turn.hash_context["agent_name"]))
    if "model" in turn.hash_context:
        hash_context["model"] = redact_model_name(str(turn.hash_context["model"]))

    llms = [
        replace(
            item,
            model=redact_model_name(item.model),
            provider=redact_provider_name(item.provider),
            system_instructions=[
                str(redact_upload_data(value)) for value in item.system_instructions
            ],
            input_messages=[_message(message) for message in item.input_messages],
            output_messages=[_message(message) for message in item.output_messages],
            reasoning=str(redact_upload_data(item.reasoning)),
            finish_reasons=[str(redact_upload_data(value)) for value in item.finish_reasons],
        )
        for item in turn.llms
    ]
    tools = [
        replace(
            item,
            name=str(redact_upload_data(item.name)),
            arguments=redact_upload_data(item.arguments),
            result=redact_upload_data(item.result),
            tool_call_id=str(redact_upload_data(item.tool_call_id)),
            tool_type=str(redact_upload_data(item.tool_type)),
            description=str(redact_upload_data(item.description)),
        )
        for item in turn.tools
    ]
    subagents = [
        replace(
            item,
            name=str(redact_upload_data(item.name)),
            model=redact_model_name(item.model),
            agent_id=str(redact_upload_data(item.agent_id)),
            description=str(redact_upload_data(item.description)),
            version=str(redact_upload_data(item.version)),
            system_instructions=[
                str(redact_upload_data(value)) for value in item.system_instructions
            ],
        )
        for item in turn.subagents
    ]
    sanitized = replace(
        turn,
        messages=[_message(message) for message in turn.messages],
        output_messages=[_message(message) for message in turn.output_messages],
        system_instructions=[str(redact_upload_data(value)) for value in turn.system_instructions],
        llms=llms,
        tools=tools,
        subagents=subagents,
        hash_context=hash_context,
        attributes=attributes,
        payload_sha256="",
        verification_signature="",
    )
    sanitized.verification_signature = _verification_signature(sanitized)
    # `payload_sha256` is the stable source identity and remote correlator. The
    # upload representation remains fully Presidio-redacted, but never feeds
    # back into idempotency because ML output may vary across processes.
    sanitized.payload_sha256 = source_payload_sha256
    sanitized.attributes["hivemind.payload_sha256"] = source_payload_sha256
    return sanitized


def sanitize_mapped_conversation(conversation: MappedConversation) -> MappedConversation:
    """Return a PII-scrubbed upload with deterministic pre-ML source identity."""
    return replace(
        conversation,
        conversation_name=str(redact_upload_data(conversation.conversation_name)),
        agent_name=redact_agent_name(conversation.agent_name),
        model=redact_model_name(conversation.model),
        agent_id=str(redact_upload_data(conversation.agent_id)),
        agent_version=str(redact_upload_data(conversation.agent_version)),
        turns=[_sanitize_turn(turn) for turn in conversation.turns],
    )
