"""Defense-in-depth local redaction before any Weave object is constructed."""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from typing import Any

REDACTED = "[REDACTED]"

_CAMEL_CASE_BOUNDARY = re.compile(r"(?<=[a-z0-9])(?=[A-Z])")
_KEY_PART = re.compile(r"[A-Za-z0-9]+")
_PRIVATE_KEY = re.compile(
    r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?-----END [A-Z0-9 ]*PRIVATE KEY-----",
    re.DOTALL,
)
_BEARER = re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]{8,}")
_BASIC_AUTH = re.compile(r"(?i)\bBasic\s+[A-Za-z0-9+/=]{8,}")
_SECRET_HEADER = re.compile(
    r"(?im)^(?P<prefix>\s*(?:Authorization|Proxy-Authorization|Cookie|Set-Cookie|"
    r"X-API-Key|Api-Key)\s*[:=]\s*)(?P<value>[^\r\n]+)$"
)
_KNOWN_TOKEN = re.compile(
    r"(?i)\b(?:sk|rk|sa|gh[opusr]|github_pat|xox[a-z]?|hf|glpat|npm)[-_][A-Za-z0-9_-]{8,}"
)
_AWS_KEY = re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b")
_GOOGLE_API_KEY = re.compile(r"\bAIza[0-9A-Za-z_-]{20,}\b")
_JWT = re.compile(r"\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b")
_WANDB_KEY_CONTEXT = re.compile(
    r"(?i)(?P<prefix>\b(?:wandb|weights[ -]?and[ -]?biases)(?:[ _-]?api)?[ _-]?key\s*[:=]?\s*)"
    r"(?P<value>[a-f0-9]{40})\b"
)
_SECRET_KEY_NAME = r"[A-Z0-9_]*(?:API_KEY|TOKEN|SECRET|PASSWORD|PASSWD)"
_SECRET_QUOTED_ASSIGNMENT = re.compile(
    # Start only at a key-token boundary. Without this guard the greedy key
    # prefix is retried at every character of a large ordinary string, which
    # makes redaction quadratic before attributes can be safely chunked.
    rf"(?i)(?P<prefix>(?<![A-Z0-9_])['\"]?{_SECRET_KEY_NAME}['\"]?\s*[:=]\s*)"
    # Consume escaped characters as units so a quote inside a JSON/string
    # literal does not terminate the credential value early.
    r"(?P<quote>['\"])(?P<value>(?:\\.|(?!(?P=quote)).)*)(?P=quote)"
)
_SECRET_BARE_ASSIGNMENT = re.compile(
    rf"(?i)(?P<prefix>(?<![A-Z0-9_])['\"]?{_SECRET_KEY_NAME}['\"]?\s*[:=]\s*)"
    # Quoted values are handled by _SECRET_QUOTED_ASSIGNMENT above. Excluding
    # quotes here prevents a second pass from consuming the opening quote of
    # an already-redacted value and corrupting JSON or source code.
    rf"(?P<value>{re.escape(REDACTED)}|[^\s\"';,}}\]]+)"
)
_EMAIL = re.compile(r"(?<![\w.+-])[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}(?![\w.-])", re.I)
_SSN = re.compile(r"(?<!\d)\d{3}-\d{2}-\d{4}(?!\d)")
_PHONE = re.compile(r"(?<!\w)(?:\+?1[ .-]?)?\(?\d{3}\)?[ .-]\d{3}[ .-]\d{4}(?!\w)")
_CARD_CANDIDATE = re.compile(r"(?<!\d)(?:\d[ -]?){13,19}(?!\d)")


def _luhn(candidate: str) -> bool:
    digits = [int(char) for char in candidate if char.isdigit()]
    if not 13 <= len(digits) <= 19:
        return False
    total = 0
    parity = len(digits) % 2
    for index, digit in enumerate(digits):
        if index % 2 == parity:
            digit *= 2
            if digit > 9:
                digit -= 9
        total += digit
    return total % 10 == 0


def _key_parts(key: str) -> list[str]:
    """Split snake, kebab, and camel-case field names into semantic parts."""
    expanded = _CAMEL_CASE_BOUNDARY.sub("_", key)
    return [part.lower() for part in _KEY_PART.findall(expanded)]


def _is_sensitive_key(key: str) -> bool:
    """Return whether a structured field is expected to carry a credential.

    Matching semantic key parts avoids both sides of substring matching: it
    catches common forms such as ``apiToken`` and ``id_token`` while leaving
    ordinary schema keys such as ``authorizer`` and ``cookiecutter_template``
    intact.
    """
    parts = _key_parts(key)
    if not parts:
        return False
    compact = "".join(parts)

    if compact in {
        "apikey",
        "accesstoken",
        "authtoken",
        "authorization",
        "bearertoken",
        "clientsecret",
        "clienttoken",
        "credential",
        "credentials",
        "idtoken",
        "password",
        "passwd",
        "privatekey",
        "refreshtoken",
        "secret",
        "secretkey",
        "sessiontoken",
        "token",
    }:
        return True

    # Environment and provider prefixes are common (OPENAI_API_KEY,
    # GITHUB_TOKEN, AWS_SECRET_ACCESS_KEY). A credential term at the end of a
    # compound key denotes the value itself, unlike token_count or
    # password_policy, which describe non-secret metadata.
    if len(parts) >= 2 and parts[-2:] in (
        ["api", "key"],
        ["private", "key"],
        ["secret", "key"],
    ):
        return True
    if parts[-1] in {"credential", "credentials", "password", "passwd", "secret", "token"}:
        return True
    if parts[-1] == "cookie" or parts == ["auth"]:
        return True
    # Secret-bearing access-key names conventionally include an explicit
    # secret marker; public access-key IDs remain available for debugging.
    return "secret" in parts and "key" in parts


def redact_string(value: str) -> str:
    redacted = _PRIVATE_KEY.sub(REDACTED, value)
    redacted = _BEARER.sub(f"Bearer {REDACTED}", redacted)
    redacted = _BASIC_AUTH.sub(f"Basic {REDACTED}", redacted)
    redacted = _SECRET_HEADER.sub(lambda match: f"{match.group('prefix')}{REDACTED}", redacted)
    redacted = _KNOWN_TOKEN.sub(REDACTED, redacted)
    redacted = _AWS_KEY.sub(REDACTED, redacted)
    redacted = _GOOGLE_API_KEY.sub(REDACTED, redacted)
    redacted = _JWT.sub(REDACTED, redacted)
    redacted = _WANDB_KEY_CONTEXT.sub(
        lambda match: f"{match.group('prefix')}{REDACTED}",
        redacted,
    )
    redacted = _SECRET_QUOTED_ASSIGNMENT.sub(
        lambda match: (
            f"{match.group('prefix')}{match.group('quote')}{REDACTED}{match.group('quote')}"
        ),
        redacted,
    )
    redacted = _SECRET_BARE_ASSIGNMENT.sub(
        lambda match: f"{match.group('prefix')}{REDACTED}", redacted
    )
    redacted = _EMAIL.sub(REDACTED, redacted)
    redacted = _SSN.sub(REDACTED, redacted)
    redacted = _PHONE.sub(REDACTED, redacted)
    redacted = _CARD_CANDIDATE.sub(
        lambda match: REDACTED if _luhn(match.group(0)) else match.group(0), redacted
    )
    return redacted


def redact_data(value: Any, *, key: str = "") -> Any:
    """Return a shape-preserving copy with credentials and common PII removed."""
    if key and _is_sensitive_key(key):
        return REDACTED
    if isinstance(value, str):
        return redact_string(value)
    if isinstance(value, Mapping):
        return {
            str(item_key): redact_data(item_value, key=str(item_key))
            for item_key, item_value in value.items()
        }
    if isinstance(value, Sequence) and not isinstance(value, (bytes, bytearray, str)):
        return [redact_data(item) for item in value]
    return value
