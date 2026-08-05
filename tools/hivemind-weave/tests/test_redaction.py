from __future__ import annotations

import json

from hivemind_weave.redaction import REDACTED, redact_data, redact_string


def test_recursive_secret_and_pii_redaction() -> None:
    payload = {
        "api_key": "sk-example-super-secret-value",
        "nested": {
            "content": (
                "Authorization: Bearer abcdefghijklmnopqrstuvwxyz "
                "email alice@example.com phone 212-555-1212 card 4111 1111 1111 1111"
            )
        },
        "ordinary": "def token_count(value): return len(value)",
    }

    redacted = redact_data(payload)

    assert redacted["api_key"] == REDACTED
    nested = redacted["nested"]["content"]
    assert "abcdefghijklmnopqrstuvwxyz" not in nested
    assert "alice@example.com" not in nested
    assert "212-555-1212" not in nested
    assert "4111 1111 1111 1111" not in nested
    assert redacted["ordinary"] == payload["ordinary"]


def test_private_key_and_environment_assignment_redaction() -> None:
    text = (
        "OPENAI_API_KEY=fake-value\n-----BEGIN PRIVATE KEY-----\nabc123\n-----END PRIVATE KEY-----"
    )
    result = redact_string(text)
    assert "fake-value" not in result
    assert "abc123" not in result
    assert result.count(REDACTED) == 2


def test_quoted_environment_and_json_secret_assignments_are_redacted() -> None:
    text = 'OPENAI_API_KEY="secret-value"\n{"access_token": "another-secret"}'
    result = redact_string(text)
    assert "secret-value" not in result
    assert "another-secret" not in result
    assert result.count(REDACTED) == 2
    env_line, json_line = result.splitlines()
    assert env_line == f'OPENAI_API_KEY="{REDACTED}"'
    assert json.loads(json_line) == {"access_token": REDACTED}
    assert redact_string(result) == result

    escaped = r'{"token":"prefix\"private-suffix","ordinary":"kept"}'
    escaped_result = redact_string(escaped)
    assert json.loads(escaped_result) == {"token": REDACTED, "ordinary": "kept"}
    assert redact_string(escaped_result) == escaped_result


def test_structured_credential_keys_redact_without_substring_false_positives() -> None:
    secret = "plainopaquecredentialvalue1234567890"
    payload = {
        "token": secret,
        "id_token": secret,
        "apiToken": secret,
        "client_token": secret,
        "credentials": secret,
        "authorizer": "RoleBasedAuthorizer",
        "authorization_strategy": "RBAC",
        "password_policy": "minimum length 12",
        "secretary": "build-bot",
        "cookiecutter_template": "python-package",
        "token_count": 12,
    }

    redacted = redact_data(payload)

    for key in ("token", "id_token", "apiToken", "client_token", "credentials"):
        assert redacted[key] == REDACTED
    for key in (
        "authorizer",
        "authorization_strategy",
        "password_policy",
        "secretary",
        "cookiecutter_template",
        "token_count",
    ):
        assert redacted[key] == payload[key]


def test_common_github_and_google_tokens_are_redacted() -> None:
    github = "gho_abcdefghijklmnopqrstuvwxyz123456"
    google = "AIzaSyabcdefghijklmnopqrstuvwxyz123456"
    result = redact_string(f"{github} {google}")
    assert github not in result
    assert google not in result


def test_huggingface_gitlab_npm_jwt_and_wandb_tokens_are_redacted() -> None:
    tokens = [
        "hf_abcdefghijklmnopqrstuvwxyz1234567890",
        "glpat-abcdefghijklmnopqrstuvwxyz123456",
        "npm_abcdefghijklmnopqrstuvwxyz123456",
        "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjMifQ.signature123456",
        "wandb api key: 0123456789abcdef0123456789abcdef01234567",
    ]
    for token in tokens:
        assert token not in redact_string(token)


def test_redaction_is_idempotent() -> None:
    source = "api token: abcdefghijklmnopqrstuvwxyz0123456789ABCD"
    once = redact_string(source)
    assert redact_string(once) == once


def test_basic_auth_cookie_and_api_key_headers_are_redacted() -> None:
    text = (
        "Authorization: Basic dXNlcjpwYXNzd29yZA==\n"
        "Cookie: sessionid=abc123secret\n"
        "X-API-Key: abc123secret"
    )
    result = redact_string(text)
    assert "dXNlcjpwYXNzd29yZA" not in result
    assert "sessionid=abc123secret" not in result
    assert "abc123secret" not in result


def test_non_luhn_long_number_is_preserved() -> None:
    assert redact_string("build 1234567890123 completed") == "build 1234567890123 completed"


def test_large_ordinary_string_redaction_is_stable() -> None:
    source = "x" * 300_000
    assert redact_string(source) == source
