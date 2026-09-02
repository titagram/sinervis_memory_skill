"""Append-only, non-secret audit event storage."""

import json
import os
import re
from pathlib import Path
from typing import Any, Mapping, Union


PathLike = Union[str, Path]
FORBIDDEN_KEY_FRAGMENTS = ("token", "password", "secret", "content")
PRIVATE_KEY_SEPARATORS = re.compile(r"[_\-.\s]+")
_CAMEL = re.compile(r"([a-z0-9])([A-Z])")
_DROP_OR_SECRET_KEYS = {
    "token", "apitoken", "apikey", "accesstoken", "refreshtoken", "bearertoken",
    "authorization", "password", "secret", "credential", "privatekey", "content",
    "clientsecret", "signingsecret", "webhooksecret", "originaltext", "payload",
    "taskpayload", "rawbody", "body", "data", "items",
}
_CREDENTIAL_VALUE = re.compile(
    r"(?:-----BEGIN (?P<pem_label>(?:[A-Z0-9]+ )*(?:PRIVATE KEY|CERTIFICATE))-----[\s\S]*?-----END (?P=pem_label)-----|\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\b|"
    r"\b(?:ghp_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|sk-[A-Za-z0-9]{20,}|xox(?:b|p|a|r|s)-[A-Za-z0-9-]{16,}|AKIA[0-9A-Z]{16})\b|"
    r"\bBearer\s+[A-Za-z0-9._~+/=-]{16,}|[\"']?\b(?:api[_. -]?(?:token|key)|access[_. -]?token|refresh[_. -]?token|(?:client|signing|webhook)[_. -]?secret|password|secret|credential)\b[\"']?\s*[:=]\s*(?:\"(?:\\.|[^\"\\\n])*\"|'(?:\\.|[^'\\\n])*'|[^\s,'\"]+))", re.I)
_PLACEHOLDER_VALUE = re.compile(
    r"(?:<(?:TOKEN|API_KEY|API_TOKEN|YOUR_[A-Z0-9_]+|[A-Z][A-Z0-9_]*(?:_TOKEN|_KEY|_SECRET))>|\$\{[A-Z][A-Z0-9_]*\}|YOUR_[A-Z0-9_]+|EXAMPLE_[A-Z0-9_]+|CHANGEME|REDACTED|\[REDACTED\])",
    re.I,
)


def _is_forbidden_key(key: Any) -> bool:
    """Reject semantic data/credential fields, not harmless policy/metric names."""
    split = _CAMEL.sub(r"\1_\2", str(key)).casefold()
    normalized = PRIVATE_KEY_SEPARATORS.sub("", split)
    return normalized in _DROP_OR_SECRET_KEYS or "privatekey" in normalized


def _has_concrete_credential(value: str) -> bool:
    """Keep literal documentation placeholders out of the secret-value gate."""
    for match in _CREDENTIAL_VALUE.finditer(value):
        text = match.group(0)
        if re.search(r"[\"']?\b(?:api[_. -]?(?:token|key)|access[_. -]?token|refresh[_. -]?token|(?:client|signing|webhook)[_. -]?secret|password|secret|credential)\b[\"']?\s*[:=]", text, re.I):
            assigned = re.split(r"[:=]", text, maxsplit=1)[1].strip(" '\"")
            if _PLACEHOLDER_VALUE.fullmatch(assigned.rstrip(".,;:!?")):
                continue
        return True
    return False


def _reject_secret_keys(value: Any) -> None:
    """Raise when a mapping recursively contains a forbidden key fragment."""
    if isinstance(value, Mapping):
        for key, child in value.items():
            if _is_forbidden_key(key):
                raise ValueError("secret field is not allowed in audit events")
            _reject_secret_keys(child)
    elif isinstance(value, (list, tuple)):
        for child in value:
            _reject_secret_keys(child)
    elif isinstance(value, str) and _has_concrete_credential(value):
        raise ValueError("credential-shaped value is not allowed in audit events")


def validate_semantic_safe(value: Any, *, tag: bool = False) -> None:
    """Reject only concrete credentials and exact semantic data/secret fields.

    This is deliberately reusable for retain metadata and tags.  It does not
    apply vocabulary or entropy allowlists, so harmless future project fields
    remain transportable.
    """
    if tag:
        if not isinstance(value, str):
            raise ValueError("tag must be a string")
        prefix = value.split(":", 1)[0]
        if _is_forbidden_key(prefix) or _has_concrete_credential(value):
            raise ValueError("credential or data tag is not allowed")
        return
    _reject_secret_keys(value)


def append_audit(path: PathLike, event: Mapping[str, Any]) -> None:
    """Validate and append one UTF-8 JSON object line to the private audit log."""
    if not isinstance(event, Mapping):
        raise ValueError("audit event must be a JSON object")
    _reject_secret_keys(event)
    encoded = json.dumps(event, ensure_ascii=False, separators=(",", ":")) + "\n"
    destination = Path(path).expanduser().resolve()
    parent = destination.parent
    parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(parent, 0o700)

    descriptor = os.open(str(destination), os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
    try:
        os.chmod(destination, 0o600)
        with os.fdopen(descriptor, "a", encoding="utf-8") as handle:
            handle.write(encoded)
            handle.flush()
            os.fsync(handle.fileno())
    except BaseException:
        try:
            os.close(descriptor)
        except OSError:
            pass
        raise
