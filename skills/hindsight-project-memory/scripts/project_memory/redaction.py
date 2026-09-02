"""Deterministic, local-only preflight for exportable project text."""

from __future__ import annotations

from dataclasses import dataclass
from math import log2
from pathlib import PurePosixPath
import re
from typing import Literal, Tuple, Union


Decision = Literal["safe", "redacted", "blocked"]
Disposition = Literal["exclude", "blocked_review"]
CREDENTIAL_POLICIES = frozenset({"exclude", "allow_project_staging"})


@dataclass(frozen=True)
class Finding:
    """A non-secret explanation of one preflight decision."""

    rule: str
    line: int
    disposition: Disposition = "blocked_review"


@dataclass(frozen=True)
class ScanResult:
    """An immutable preflight result; secret matches are deliberately omitted."""

    decision: Decision
    exported_text: Union[str, None]
    findings: Tuple[Finding, ...]


_PEM = re.compile(r"-----BEGIN(?: [A-Z0-9]+)* (?:PRIVATE KEY|CERTIFICATE)-----", re.IGNORECASE)
_ASSIGNMENT = re.compile(
    r"(?P<key_quote>[\"']?)(?P<key>\b[A-Za-z][A-Za-z0-9_.-]*)(?P=key_quote)(?P<separator>\s*[:=]\s*)(?P<value>\"(?:\\.|[^\"\\\n])*\"|'(?:\\.|[^'\\\n])*'|Bearer\s+(?:\[REDACTED\]|[A-Za-z0-9._~+/=-]+)|<[^>\s]+>|\$\{[^}\s]+\}|\[REDACTED\]|[^\s,`}\]#]+)",
    re.IGNORECASE,
)
_AUTHORIZATION_BEARER = re.compile(
    r"(?P<prefix>\bauthorization\s*:\s*bearer\s+)(?P<value>[A-Za-z0-9._~+/=-]+)", re.IGNORECASE
)
_BARE_BEARER = re.compile(r"(?P<prefix>\bbearer\s+)(?P<value>[A-Za-z0-9._~+/=-]{16,})", re.IGNORECASE)
_UNKNOWN_ASSIGNMENT = re.compile(r"^\s*(?P<key>[A-Za-z][A-Za-z0-9_.-]*)\s*[:=]\s*(?P<value>[^\s#]+)", re.MULTILINE)
_PLACEHOLDER = re.compile(
    r"^(?:<(?:TOKEN|API_KEY|API_TOKEN|YOUR_[A-Z0-9_]+|[A-Z][A-Z0-9_]*(?:_TOKEN|_KEY|_SECRET))>|"
    r"\$\{[A-Z][A-Z0-9_]*\}|YOUR_[A-Z0-9_]+|EXAMPLE_[A-Z0-9_]+|CHANGEME|REDACTED|\[REDACTED\])$"
)
_SAFE_PATH_WORDS = {"policy", "policies", "guideline", "guidelines", "template", "templates", "example", "examples", "sample", "samples"}
_SENSITIVE_PATH_WORDS = {"payroll", "medical", "health", "customer", "customers", "database", "dump", "dumps", "upload", "uploads", "generated"}
_SAFE_KEY_SUFFIXES = {"budget", "limit", "count", "policy", "policies", "handling", "rules", "template", "example"}
_SENSITIVE_KEY_WORDS = {"password", "passphrase", "secret", "credential", "authorization"}
_SENSITIVE_KEY_PAIRS = {("api", "key"), ("api", "token"), ("access", "token"), ("refresh", "token"), ("bearer", "token"), ("private", "key")}


def normalize_credential_policy(value: object = None) -> str:
    """Return the effective project policy, defaulting old profiles safely."""
    policy = "exclude" if value is None else value
    if not isinstance(policy, str) or policy not in CREDENTIAL_POLICIES:
        raise ValueError("credential_policy must be exclude or allow_project_staging")
    return policy


def _path_finding(path: str) -> Union[Finding, None]:
    """Return an exclusion before inspecting potentially dangerous content."""
    normalized = path.replace("\\", "/").lstrip("/")
    raw_parts = PurePosixPath(normalized).parts
    parts = tuple(part.casefold() for part in raw_parts)
    name = parts[-1] if parts else ""
    if name == ".env" or (name.startswith(".env.") and name not in {".env.example", ".env.sample", ".env.template"}):
        return Finding("path_environment_file", 0, "exclude")
    if any(part in {"vendor", "node_modules", "build", "dist", ".cache", "cache", "__pycache__"} for part in parts):
        return Finding("path_dependency_or_build_artifact", 0, "exclude")
    seen_domain = False
    seen_indicator = False
    for raw_part in raw_parts:
        camel = re.sub(r"([a-z0-9])([A-Z])", r"\1 \2", raw_part).casefold()
        words = set(filter(None, re.split(r"[^a-z0-9]+", camel)))
        compact = "".join(words)
        domain = bool(words & {"payroll", "medical", "health", "customer", "customers"}) or any(word in compact for word in ("payroll", "medical", "health", "customer"))
        strong_indicator = bool(words & {"record", "records", "dump", "dumps", "raw", "export", "exports"}) or any(word in compact for word in ("record", "dump", "raw", "export"))
        data_indicator = "data" in words or "data" in compact
        seen_domain = seen_domain or domain
        seen_indicator = seen_indicator or strong_indicator
        if domain and (strong_indicator or (data_indicator and not (words & _SAFE_PATH_WORDS))):
            return Finding("path_sensitive_or_generated_data", 0, "exclude")
        if not (words & _SAFE_PATH_WORDS) and (words & {"database", "dump", "dumps", "upload", "uploads", "generated"}):
            return Finding("path_sensitive_or_generated_data", 0, "exclude")
    if seen_domain and seen_indicator:
        return Finding("path_sensitive_or_generated_data", 0, "exclude")
    if any(part in {"uploads", "upload", "generated", "generated-documents", "payroll", "medical", "health", "customers", "customer-data", "database", "dumps", "dump"} for part in parts):
        return Finding("path_sensitive_or_generated_data", 0, "exclude")
    if name.endswith((".sql", ".dump", ".sqlite", ".sqlite3", ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".zip", ".gz", ".tar", ".png", ".jpg", ".jpeg", ".gif", ".ico", ".woff", ".woff2", ".ttf", ".mp3", ".mp4")):
        return Finding("path_binary_or_dump_candidate", 0, "exclude")
    return None


def _is_env_template(path: str) -> bool:
    name = PurePosixPath(path.replace("\\", "/")).name.casefold()
    return name in {".env.example", ".env.sample", ".env.template"}


def _line_for(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def _key_words(key: str) -> Tuple[str, ...]:
    split_camel = re.sub(r"([a-z0-9])([A-Z])", r"\1 \2", key)
    return tuple(part.casefold() for part in re.split(r"[^A-Za-z0-9]+", split_camel) if part)


def _is_sensitive_key(key: str) -> bool:
    words = _key_words(key)
    if not words or words[-1] in _SAFE_KEY_SUFFIXES:
        return False
    if any(word in _SENSITIVE_KEY_WORDS for word in words):
        return True
    return any(tuple(words[index:index + 2]) in _SENSITIVE_KEY_PAIRS for index in range(len(words) - 1))


def _assignment_value(value: str) -> str:
    if len(value) >= 2 and value[0] == value[-1] and value[0] in "'\"":
        return value[1:-1]
    return value


def _is_placeholder_assignment(value: str) -> bool:
    """Recognize conventional placeholders without treating real tokens as one."""
    return bool(_PLACEHOLDER.fullmatch(_assignment_value(value).rstrip(".,;:!?")))


def _replacement(match: re.Match[str]) -> str:
    value = match.group("value")
    raw_value = _assignment_value(value)
    if not _is_sensitive_key(match.group("key")) or _is_placeholder_assignment(value) or raw_value.casefold().startswith("bearer [redacted]") or ("authorization" in _key_words(match.group("key")) and raw_value.casefold().startswith("bearer ")):
        return match.group(0)
    quote = value[0] if len(value) >= 2 and value[0] == value[-1] and value[0] in "'\"" else ""
    key_quote = match.group("key_quote") or ""
    return key_quote + match.group("key") + key_quote + match.group("separator") + quote + "[REDACTED]" + quote


def _bearer_replacement(match: re.Match[str]) -> str:
    if _PLACEHOLDER.fullmatch(match.group("value")):
        return match.group(0)
    return match.group("prefix") + "[REDACTED]"


def _is_unknown_high_entropy(value: str) -> bool:
    """Flag only assignment values shaped like opaque credentials, never whole prose."""
    if len(value) < 32 or _PLACEHOLDER.fullmatch(value):
        return False
    if not re.fullmatch(r"[A-Za-z0-9_+/-]+", value):
        return False
    classes = sum((any(character.islower() for character in value), any(character.isupper() for character in value), any(character.isdigit() for character in value)))
    if classes < 3:
        return False
    entropy = -sum((value.count(character) / len(value)) * log2(value.count(character) / len(value)) for character in set(value))
    return entropy >= 4.0


def _is_hash_key(key: str) -> bool:
    words = tuple(part for part in re.split(r"[_.-]+", key.casefold()) if part)
    return bool(words and words[-1] in {"hash", "sha", "sha256", "digest", "checksum", "uuid", "id"})


def _is_known_sensitive_key(key: str) -> bool:
    return _is_sensitive_key(key)


def scan_text(path: Union[str, PurePosixPath], content: Union[str, bytes], *, credential_policy: object = None) -> ScanResult:
    """Classify *content* without retaining a matched sensitive value in findings."""
    policy = normalize_credential_policy(credential_policy)
    path_text = str(path)
    path_finding = _path_finding(path_text)
    if path_finding is not None and not (
        policy == "allow_project_staging" and path_finding.rule == "path_environment_file"
    ):
        return ScanResult("blocked", None, (path_finding,))
    if isinstance(content, bytes):
        if b"\0" in content:
            return ScanResult("blocked", None, (Finding("binary_content", 0),))
        try:
            text = content.decode("utf-8")
        except UnicodeDecodeError:
            return ScanResult("blocked", None, (Finding("undecodable_content", 0),))
    else:
        text = content
    pem = _PEM.search(text)
    if policy == "allow_project_staging":
        findings = []
        if pem is not None:
            findings.append(Finding("credential_material_allowed", _line_for(text, pem.start())))
        for assignment in _ASSIGNMENT.finditer(text):
            raw_value = _assignment_value(assignment.group("value"))
            if (_is_sensitive_key(assignment.group("key")) and
                    not _is_placeholder_assignment(assignment.group("value")) and
                    not raw_value.casefold().startswith("bearer [redacted]")):
                findings.append(Finding("credential_assignment_allowed", _line_for(text, assignment.start())))
        for expression in (_AUTHORIZATION_BEARER, _BARE_BEARER):
            for match in expression.finditer(text):
                if not _PLACEHOLDER.fullmatch(match.group("value")):
                    findings.append(Finding("credential_assignment_allowed", _line_for(text, match.start())))
        for assignment in _UNKNOWN_ASSIGNMENT.finditer(text):
            if (not _is_known_sensitive_key(assignment.group("key")) and
                    not _is_hash_key(assignment.group("key")) and
                    _is_unknown_high_entropy(assignment.group("value"))):
                findings.append(Finding("credential_assignment_allowed", _line_for(text, assignment.start())))
        findings.sort(key=lambda finding: (finding.line, finding.rule))
        return ScanResult("safe", text, tuple(findings))
    if pem is not None:
        return ScanResult("blocked", None, (Finding("private_key_material", _line_for(text, pem.start())),))

    for assignment in _UNKNOWN_ASSIGNMENT.finditer(text):
        if not _is_known_sensitive_key(assignment.group("key")) and not _is_hash_key(assignment.group("key")) and _is_unknown_high_entropy(assignment.group("value")):
            return ScanResult("blocked", None, (Finding("unknown_high_entropy_assignment", _line_for(text, assignment.start())),))

    findings = []
    exported = text
    for expression, rule in ((_ASSIGNMENT, "credential_assignment"), (_AUTHORIZATION_BEARER, "bearer_token"), (_BARE_BEARER, "bearer_token")):
        matches = tuple(expression.finditer(exported))
        for match in matches:
            if expression is _ASSIGNMENT:
                raw_value = _assignment_value(match.group("value"))
                if not _is_sensitive_key(match.group("key")) or _is_placeholder_assignment(match.group("value")) or raw_value.casefold().startswith("bearer [redacted]") or ("authorization" in _key_words(match.group("key")) and raw_value.casefold().startswith("bearer ")):
                    continue
            if not _PLACEHOLDER.fullmatch(match.group("value")):
                findings.append(Finding(rule, _line_for(exported, match.start())))
        if expression is _ASSIGNMENT:
            exported = expression.sub(_replacement, exported)
        else:
            exported = expression.sub(_bearer_replacement, exported)
    if findings:
        findings.sort(key=lambda finding: (finding.line, finding.rule))
        if _is_env_template(path_text):
            return ScanResult("blocked", None, tuple(findings))
        return ScanResult("redacted", exported, tuple(findings))
    return ScanResult("safe", text, ())
