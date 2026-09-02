"""Private, atomic storage for project-to-bank registrations."""

import copy
import json
import os
import re
import tempfile
from pathlib import Path, PurePosixPath
from typing import Any, Dict, Mapping, Optional, Tuple, Union

from .redaction import normalize_credential_policy


Registry = Dict[str, Any]
PathLike = Union[str, Path]

_SAFE_POLICY_SUFFIXES = {"budget", "limit", "count", "policy", "handling", "rules"}
_SENSITIVE_COMPOUNDS = {"apitoken", "apikey", "privatekey", "accesstoken", "refreshtoken", "bearertoken"}
_SENSITIVE_WORDS = {"password", "secret", "credential", "authorization", "token"}
_SENSITIVE_PAIRS = {("api", "token"), ("api", "key"), ("private", "key"), ("access", "token"), ("refresh", "token"), ("bearer", "token")}
_PEM_CREDENTIAL_BLOCK = re.compile(
    r"-----BEGIN (?P<label>(?:[A-Z0-9]+ )*(?:PRIVATE KEY|CERTIFICATE))-----[\s\S]*?"
    r"-----END (?P=label)-----",
    re.I,
)
_ASSIGNMENT = re.compile(
    r"[\"']?\b(?:api[_. -]?token|api[_. -]?key|private[_. -]?key|access[_. -]?token|refresh[_. -]?token|"
    r"bearer[_. -]?token|password|secret|credential|authorization)\b[\"']?\s*[:=]\s*['\"]?\S+",
    re.I,
)
_BEARER_VALUE = re.compile(r"\bbearer\s+[A-Za-z0-9._~+/=-]{16,}\b", re.I)
_COMMON_TOKEN_VALUE = re.compile(
    r"(?:\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\b|\bghp_[A-Za-z0-9]{20,}\b|"
    r"\bsk-[A-Za-z0-9]{20,}\b|\bxox(?:b|p|a|r|s)-[A-Za-z0-9-]{16,}\b|\bAKIA[0-9A-Z]{16}\b)"
)
_ABSOLUTE_PATH_KEY = re.compile(r"^(?:/|[A-Za-z]:[\\/])")


def _key_words(key: Any) -> Tuple[str, ...]:
    text = re.sub(r"([a-z0-9])([A-Z])", r"\1 \2", str(key))
    return tuple(part.lower() for part in re.split(r"[^A-Za-z0-9]+", text) if part)


def _is_sensitive_key(key: Any) -> bool:
    if key == "credential_sources":
        return False
    if isinstance(key, str) and _ABSOLUTE_PATH_KEY.match(key):
        return False
    words = _key_words(key)
    if not words:
        return False
    if words[-1] in _SAFE_POLICY_SUFFIXES:
        return False
    joined = "".join(words)
    if joined in _SENSITIVE_COMPOUNDS or any(pair == words[index:index + 2] for pair in _SENSITIVE_PAIRS for index in range(len(words) - 1)) or words[-1] == "token":
        return True
    return any(word in _SENSITIVE_WORDS - {"token"} for word in words)


def validate_registry_data(value: Any) -> None:
    """Reject actual credentials while permitting policy and measurement metadata."""
    if isinstance(value, Mapping):
        for key, child in value.items():
            if key == "credential_policy":
                normalize_credential_policy(child)
            if _is_sensitive_key(key):
                raise ValueError("sensitive registry data is not allowed")
            validate_registry_data(child)
    elif isinstance(value, (list, tuple)):
        for child in value:
            validate_registry_data(child)
    elif isinstance(value, str) and (_PEM_CREDENTIAL_BLOCK.search(value) or _ASSIGNMENT.search(value) or _BEARER_VALUE.search(value) or _COMMON_TOKEN_VALUE.search(value)):
        raise ValueError("sensitive registry data is not allowed")


def credential_source_paths(profile: Mapping[str, Any]) -> Tuple[str, ...]:
    """Validate exact source paths required by the staging-credential opt-in."""
    if normalize_credential_policy(profile.get("credential_policy")) == "exclude":
        return ()
    if profile.get("reviewed") is not True:
        raise ValueError("allow_project_staging requires a reviewed profile")
    source_policy = profile.get("source_policy")
    selectors = source_policy.get("credential_sources") if isinstance(source_policy, Mapping) else None
    if not isinstance(selectors, list) or not selectors:
        raise ValueError("allow_project_staging requires explicit credential_sources")
    result = []
    for selector in selectors:
        if not isinstance(selector, str) or not selector or "\\" in selector:
            raise ValueError("credential_sources must contain canonical relative POSIX paths")
        path = PurePosixPath(selector)
        if path.is_absolute() or ".." in path.parts or selector in {".", "./"} or path.as_posix() != selector:
            raise ValueError("credential_sources must contain canonical relative POSIX paths")
        result.append(selector)
    if len(result) != len(set(result)):
        raise ValueError("credential_sources must not contain duplicates")
    return tuple(result)


def _normalized_path(value: PathLike) -> Path:
    """Return a canonical absolute path without requiring it to exist."""
    return Path(value).expanduser().resolve()


def _is_relative_to(path: Path, root: Path) -> bool:
    """Support Python versions without ``Path.is_relative_to``."""
    try:
        return path.is_relative_to(root)
    except AttributeError:
        try:
            path.relative_to(root)
        except ValueError:
            return False
        return True


def read_registry(path: PathLike) -> Registry:
    """Read a UTF-8 JSON registry from *path*."""
    with _normalized_path(path).open("r", encoding="utf-8") as handle:
        return json.load(handle)


def resolve_project(registry: Mapping[str, Any], workspace: PathLike) -> Optional[Dict[str, Any]]:
    """Return the registration for the most-specific containing project root."""
    workspace_path = _normalized_path(workspace)
    registration = resolve_project_registration(registry, workspace_path)
    if registration is None:
        return None
    return registration[1]


def resolve_project_registration(
    registry: Mapping[str, Any], workspace: PathLike
) -> Optional[Tuple[Path, Dict[str, Any]]]:
    """Return the most-specific canonical root and its project profile."""
    workspace_path = _normalized_path(workspace)
    matches = []
    for root_text, profile in registry.get("projects", {}).items():
        root_path = _normalized_path(root_text)
        if _is_relative_to(workspace_path, root_path):
            matches.append((root_path, profile))
    if not matches:
        return None
    root, profile = max(matches, key=lambda item: len(item[0].parts))
    return root, copy.deepcopy(dict(profile))


def register_project(registry: Mapping[str, Any], profile: Mapping[str, Any], registered_at: str) -> Registry:
    """Return a registry copy with *profile* registered at its canonical root."""
    validate_registry_data(registry)
    validate_registry_data(profile)
    credential_source_paths(profile)
    root_value = profile.get("root")
    bank_id = profile.get("bank_id")
    if not isinstance(root_value, (str, Path)) or not root_value:
        raise ValueError("project profile requires a root")
    if not isinstance(bank_id, str) or not bank_id:
        raise ValueError("project profile requires a bank_id")

    result = copy.deepcopy(dict(registry))
    projects = result.setdefault("projects", {})
    root = str(_normalized_path(root_value))

    existing_at_root = None
    for existing_root, existing_profile in projects.items():
        if str(_normalized_path(existing_root)) == root:
            existing_at_root = existing_profile
            if existing_profile.get("bank_id") != bank_id:
                raise ValueError("changing a registered root bank requires an explicit remap workflow")
            for field in ("product_identity", "relationship", "owner_slug", "project_slug"):
                established = existing_profile.get(field)
                requested = profile.get(field)
                if established not in (None, "") and requested != established:
                    raise ValueError("changing established project identity requires an explicit remap workflow")

    matching_bank_profiles = []
    for existing_root, existing_profile in projects.items():
        if str(_normalized_path(existing_root)) == root:
            continue
        if existing_profile.get("bank_id") == bank_id:
            matching_bank_profiles.append(existing_profile)

    if matching_bank_profiles:
        product_identity = profile.get("product_identity")
        project_slug = profile.get("project_slug")
        is_explicit_reuse = (
            profile.get("relationship") == "existing_product_additional_root"
            and profile.get("reviewed") is True
        )
        if (
            not isinstance(product_identity, str)
            or not product_identity
            or not isinstance(project_slug, str)
            or not project_slug
            or not is_explicit_reuse
            or any(existing.get("product_identity") != product_identity for existing in matching_bank_profiles)
            or any(existing.get("project_slug") != project_slug for existing in matching_bank_profiles)
        ):
            raise ValueError("bank_id already assigned to another project root")

    stored_profile = copy.deepcopy(dict(existing_at_root or {}))
    stored_profile.update(copy.deepcopy(dict(profile)))
    stored_profile["credential_policy"] = normalize_credential_policy(profile.get("credential_policy"))
    stored_profile.pop("root", None)
    if existing_at_root:
        for field in ("product_identity", "relationship", "owner_slug", "project_slug"):
            if existing_at_root.get(field) not in (None, ""):
                stored_profile[field] = existing_at_root[field]
    operator = result.get("operator") or {}
    nickname = operator.get("nickname")
    if existing_at_root:
        if existing_at_root.get("registered_at"):
            stored_profile["registered_at"] = existing_at_root["registered_at"]
        else:
            stored_profile["registered_at"] = registered_at
        if existing_at_root.get("registered_by"):
            stored_profile["registered_by"] = existing_at_root["registered_by"]
        elif nickname:
            stored_profile["registered_by"] = nickname
        if nickname:
            stored_profile["updated_by"] = nickname
        stored_profile["updated_at"] = registered_at
    else:
        stored_profile["registered_at"] = registered_at
        if nickname:
            stored_profile["registered_by"] = nickname
    projects[root] = stored_profile
    return result


def write_registry(path: PathLike, registry: Mapping[str, Any]) -> None:
    """Atomically persist a registry using a private sibling temporary file."""
    validate_registry_data(registry)
    encoded = json.dumps(registry, ensure_ascii=False, indent=2, sort_keys=True).encode("utf-8") + b"\n"
    destination = _normalized_path(path)
    parent = destination.parent
    parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(parent, 0o700)

    descriptor, temporary_name = tempfile.mkstemp(prefix=".{0}.".format(destination.name), dir=str(parent))
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(encoded)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, 0o600)
        os.replace(str(temporary), str(destination))
        os.chmod(destination, 0o600)
        directory_descriptor = os.open(str(parent), os.O_RDONLY)
        try:
            os.fsync(directory_descriptor)
        finally:
            os.close(directory_descriptor)
    except BaseException:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass
        raise
