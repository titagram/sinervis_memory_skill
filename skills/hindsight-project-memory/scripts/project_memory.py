#!/usr/bin/env python3
"""Project-neutral local registry and connector commands.

All paths are explicit so this helper never selects or mutates a live home
directory by default.  Successful results and handled failures are JSON.
"""

import argparse
import copy
import hashlib
import json
import os
import re
import sys
import tempfile
import unicodedata
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional

from project_memory.audit import append_audit, validate_semantic_safe
from project_memory.graph_capsules import build_graph_capsules, graph_capsule_inventory
from project_memory.manifest import _assert_no_staging_symlinks, build_manifest, read_manifest, validate_manifest_files, write_manifest
from project_memory.redaction import normalize_credential_policy, scan_text
from project_memory.registry import (
    credential_source_paths,
    read_registry,
    register_project,
    resolve_project_registration,
    validate_registry_data,
    write_registry,
)
from project_memory.transport import HindsightTransport, TransportError, load_hindsight_config, sanitize


class CommandError(Exception):
    """A safe, machine-readable command failure."""

    def __init__(self, status: str, message: str, confirmation_required: bool = False):
        super().__init__(message)
        self.status = status
        self.message = message
        self.confirmation_required = confirmation_required


class PartialCommandError(CommandError):
    """A remote mutation may have partly succeeded; retain only safe identifiers."""

    def __init__(self, message: str, result: Mapping[str, Any]):
        super().__init__("partial", message)
        self.result = dict(result)


CORE_PROFILE_FIELDS = (
    "root", "display_name", "owner_slug", "project_slug", "bank_id",
    "product_identity", "relationship", "reviewed",
)
_CANONICAL_BANK_ID = re.compile(
    r"(?P<owner>[a-z0-9]+(?:-[a-z0-9]+)*)::(?P<project>[a-z0-9]+(?:-[a-z0-9]+)*)\Z"
)


def _timestamp(value: Optional[str] = None) -> str:
    return value or datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")


def _empty_registry() -> Dict[str, Any]:
    return {"schema_version": 1, "operator": None, "projects": {}}


def _read_registry_or_empty(path: str) -> Dict[str, Any]:
    candidate = Path(path).expanduser().resolve()
    if not candidate.exists():
        return _empty_registry()
    data = read_registry(candidate)
    if not isinstance(data, dict) or not isinstance(data.get("projects", {}), dict):
        raise CommandError("invalid_registry", "registry must be a JSON object with project mappings")
    try:
        validate_registry_data(data)
    except ValueError as error:
        raise CommandError("invalid_registry", "registry contains sensitive material") from error
    return data


def _slug(value: str, label: str) -> str:
    ascii_value = unicodedata.normalize("NFKD", value).encode("ascii", "ignore").decode("ascii")
    normalized = re.sub(r"[^a-z0-9]+", "-", ascii_value.lower()).strip("-")
    if not normalized:
        raise CommandError("invalid_input", "{0} must contain ASCII letters or digits".format(label))
    return normalized


def _json_object(raw: str, label: str) -> Dict[str, Any]:
    try:
        value = json.loads(raw)
    except (TypeError, ValueError) as error:
        raise CommandError("invalid_input", "{0} must be valid JSON".format(label)) from error
    if not isinstance(value, dict):
        raise CommandError("invalid_input", "{0} must be a JSON object".format(label))
    return value


def _load_profile(path: Optional[str]) -> Dict[str, Any]:
    try:
        raw = Path(path).read_text(encoding="utf-8") if path else sys.stdin.read()
    except OSError as error:
        raise CommandError("invalid_input", "profile could not be read") from error
    profile = _json_object(raw, "profile")
    contained = profile.get("profile")
    if isinstance(contained, dict):
        return contained
    return profile


def _validate_profile(profile: Mapping[str, Any]) -> Dict[str, Any]:
    """Validate core identity while preserving safe future JSON metadata."""
    if not isinstance(profile, Mapping):
        raise CommandError("invalid_profile", "profile must be a JSON object")
    try:
        validate_registry_data(profile)
    except ValueError as error:
        raise CommandError("invalid_profile", "profile contains sensitive material") from error
    result = copy.deepcopy(dict(profile))
    try:
        result["credential_policy"] = normalize_credential_policy(result.get("credential_policy"))
        credential_source_paths(result)
    except ValueError as error:
        raise CommandError("invalid_profile", str(error)) from error
    missing = [field for field in CORE_PROFILE_FIELDS if field not in result]
    if missing:
        raise CommandError("invalid_profile", "profile is missing required identity fields")
    if not all(isinstance(result[field], str) and result[field] for field in CORE_PROFILE_FIELDS[:-1]):
        raise CommandError("invalid_profile", "profile identity fields must be non-empty strings")
    if result["reviewed"] is not True:
        raise CommandError("review_required", "profile must be reviewed")
    if result["relationship"] not in ("new_product", "existing_product_additional_root"):
        raise CommandError("relationship_uncertain", "project relationship requires review", True)
    root = str(Path(result["root"]).expanduser().resolve())
    if result["root"] != root:
        raise CommandError("invalid_profile", "profile root must be canonical")
    bank_match = _CANONICAL_BANK_ID.fullmatch(result["bank_id"])
    if bank_match is None or bank_match.group("owner") != result["owner_slug"]:
        raise CommandError("invalid_profile", "profile bank identity is inconsistent")
    try:
        json.dumps(result, ensure_ascii=False)
    except (TypeError, ValueError) as error:
        raise CommandError("invalid_profile", "profile must contain JSON-compatible metadata") from error
    return result


def _safe_profile_summary(root: str, profile: Mapping[str, Any]) -> Dict[str, Any]:
    summary = {"root": root, "bank_id": profile["bank_id"]}
    for field in ("product_identity", "relationship"):
        if isinstance(profile.get(field), str):
            summary[field] = profile[field]
    return summary


def _append_audit_phase(path: str, event: Mapping[str, Any], phase: str) -> None:
    record = dict(event)
    record.update({"phase": phase, "result": phase})
    try:
        append_audit(path, record)
    except (OSError, ValueError, TypeError) as error:
        raise CommandError("audit_unavailable", "audit record could not be written") from error


def _complete_audit(path: str, event: Mapping[str, Any]) -> None:
    try:
        _append_audit_phase(path, event, "completed")
    except CommandError as error:
        raise CommandError("audit_completion_uncertain", "operation completed but completion audit is uncertain") from error


def _only_resolved_mapping_changed(before: Mapping[str, Any], after: Mapping[str, Any], root: str) -> bool:
    """Allow one exact mapPathToBank entry change and no other configuration drift."""
    if not isinstance(before.get("mapPathToBank"), Mapping) or not isinstance(after.get("mapPathToBank"), Mapping):
        return False
    before_other = copy.deepcopy(dict(before))
    after_other = copy.deepcopy(dict(after))
    before_map = dict(before_other.pop("mapPathToBank"))
    after_map = dict(after_other.pop("mapPathToBank"))
    before_map.pop(root, None)
    after_map.pop(root, None)
    return before_other == after_other and before_map == after_map


def _profile_for_existing_product(
    registry: Mapping[str, Any], product_identity: str
) -> Optional[Dict[str, Any]]:
    candidates = []
    for profile in registry.get("projects", {}).values():
        if isinstance(profile, Mapping) and profile.get("product_identity") == product_identity:
            bank_id = profile.get("bank_id")
            if isinstance(bank_id, str) and bank_id:
                candidates.append(dict(profile))
    banks = {candidate["bank_id"] for candidate in candidates}
    if not candidates:
        raise CommandError(
            "relationship_uncertain", "existing product is not registered", confirmation_required=True
        )
    if len(banks) != 1:
        raise CommandError(
            "relationship_uncertain", "existing product resolves to multiple banks", confirmation_required=True
        )
    return candidates[0]


def _propose(arguments: argparse.Namespace) -> Dict[str, Any]:
    registry = _read_registry_or_empty(arguments.registry)
    root = str(Path(arguments.root).expanduser().resolve())
    owner_slug = _slug(arguments.owner, "owner")
    project_slug = _slug(arguments.name, "project name")
    profile: Dict[str, Any] = {
        "root": root,
        "display_name": arguments.name,
        "owner_slug": owner_slug,
        "project_slug": project_slug,
        "bank_id": "{0}::{1}".format(owner_slug, project_slug),
        "product_identity": "{0}-{1}".format(owner_slug, project_slug),
        "relationship": "new_product",
        "reviewed": False,
        "credential_policy": "exclude",
    }
    if arguments.existing_product:
        existing = _profile_for_existing_product(registry, arguments.existing_product)
        existing_owner, existing_project = existing["bank_id"].split("::", 1)
        profile.update({
            "bank_id": existing["bank_id"],
            "owner_slug": existing.get("owner_slug") or existing_owner,
            "project_slug": existing.get("project_slug") or existing_project,
            "product_identity": arguments.existing_product,
            "relationship": "existing_product_additional_root",
        })
    return {"status": "proposal", "confirmation_required": True, "profile": profile}


def _require_operator(registry: Mapping[str, Any]) -> str:
    operator = registry.get("operator")
    nickname = operator.get("nickname") if isinstance(operator, Mapping) else None
    if not isinstance(nickname, str) or not nickname:
        raise CommandError("operator_required", "set an active operator before registration")
    return nickname


def _register(arguments: argparse.Namespace) -> Dict[str, Any]:
    supplied_profile = _load_profile(arguments.profile)
    registry = _read_registry_or_empty(arguments.registry)
    operator = _require_operator(registry)
    profile = _validate_profile(supplied_profile)
    if not arguments.confirm:
        raise CommandError("confirmation_required", "registration requires explicit confirmation", True)
    try:
        registered = register_project(registry, profile, _timestamp(arguments.at))
    except ValueError as error:
        raise CommandError("invalid_registration", str(error)) from error
    root = str(Path(profile["root"]).expanduser().resolve())
    stored = registered["projects"][root]
    event = {
        "timestamp": _timestamp(arguments.at), "operator": operator, "action": "project_registered",
        "project_root": root, "bank_id": stored["bank_id"], "run_id": str(uuid.uuid4()),
    }
    _append_audit_phase(arguments.audit, event, "intended")
    write_registry(arguments.registry, registered)
    _complete_audit(arguments.audit, event)
    return {"status": "registered", "project": _safe_profile_summary(root, stored)}


def _resolve(arguments: argparse.Namespace) -> Dict[str, Any]:
    registration = resolve_project_registration(_read_registry_or_empty(arguments.registry), arguments.root)
    if registration is None:
        raise CommandError("project_not_registered", "no registered project contains this path")
    root, profile = registration
    summary_profile = dict(profile)
    summary_profile["root"] = str(root)
    return {"status": "resolved", "project": _safe_profile_summary(str(root), summary_profile)}


def _atomic_write_bytes(destination: Path, content: bytes) -> None:
    descriptor, temporary_name = tempfile.mkstemp(prefix=".{0}.".format(destination.name), dir=str(destination.parent))
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, 0o600)
        os.replace(str(temporary), str(destination))
        os.chmod(destination, 0o600)
        parent_descriptor = os.open(str(destination.parent), os.O_RDONLY)
        try:
            os.fsync(parent_descriptor)
        finally:
            os.close(parent_descriptor)
    except BaseException:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass
        raise


def _backup_name(connector: Path) -> Path:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    return connector.with_name("{0}.project-memory-backup-{1}".format(connector.name, stamp))


def _private_backup(destination: Path, content: bytes) -> None:
    descriptor = os.open(str(destination), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(destination, 0o600)
    except BaseException:
        try:
            destination.unlink()
        except FileNotFoundError:
            pass
        raise


def _connector_sync(arguments: argparse.Namespace) -> Dict[str, Any]:
    connector = Path(arguments.connector).expanduser().resolve()
    try:
        original = connector.read_bytes()
        configuration = json.loads(original.decode("utf-8"))
    except (OSError, UnicodeDecodeError, ValueError) as error:
        raise CommandError("invalid_connector", "connector configuration must be valid UTF-8 JSON") from error
    if not isinstance(configuration, dict):
        raise CommandError("invalid_connector", "connector configuration must be a JSON object")
    mappings = configuration.get("mapPathToBank")
    if not isinstance(mappings, dict):
        raise CommandError("invalid_connector", "mapPathToBank must be a JSON object")
    registry = _read_registry_or_empty(arguments.registry)
    operator = _require_operator(registry)
    if not arguments.confirm:
        raise CommandError("confirmation_required", "connector sync requires explicit confirmation", True)
    registration = resolve_project_registration(registry, arguments.root)
    if registration is None:
        raise CommandError("project_not_registered", "connector sync requires a resolved registration")
    resolved_root, resolved_profile = registration
    resolved = dict(resolved_profile)
    resolved["root"] = str(resolved_root)
    resolved = _validate_profile(resolved)
    supplied_profile = _validate_profile(_load_profile(arguments.profile))
    identity_fields = (
        "root", "bank_id", "owner_slug", "project_slug", "product_identity", "relationship",
    )
    if any(supplied_profile[field] != resolved[field] for field in identity_fields):
        raise CommandError("profile_mismatch", "connector sync requires the reviewed resolved profile")
    updated = copy.deepcopy(configuration)
    updated["mapPathToBank"][str(resolved_root)] = resolved["bank_id"]
    encoded = json.dumps(updated, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    try:
        round_trip = json.loads(encoded.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as error:
        raise CommandError("invalid_connector", "connector serialization could not be validated") from error
    if not _only_resolved_mapping_changed(configuration, round_trip, str(resolved_root)):
        raise CommandError("invalid_connector", "connector update would change unrelated settings")
    backup = _backup_name(connector)
    event = {
        "timestamp": _timestamp(arguments.at), "operator": operator, "action": "connector_synced",
        "project_root": str(resolved_root), "bank_id": resolved["bank_id"], "run_id": str(uuid.uuid4()),
    }
    _append_audit_phase(arguments.audit, event, "intended")
    try:
        _private_backup(backup, original)
        _atomic_write_bytes(connector, encoded)
    except OSError as error:
        raise CommandError("connector_write_failed", "connector configuration was not updated") from error
    _complete_audit(arguments.audit, event)
    return {"status": "synced", "root": str(resolved_root), "bank_id": resolved["bank_id"], "backup": str(backup)}


def _operator_set(arguments: argparse.Namespace) -> Dict[str, Any]:
    registry = _read_registry_or_empty(arguments.registry)
    nickname = _slug(arguments.nickname, "operator nickname")
    registry["operator"] = {"nickname": nickname, "set_at": _timestamp(arguments.at)}
    event = {
        "timestamp": _timestamp(arguments.at), "operator": nickname, "action": "operator_set",
        "run_id": str(uuid.uuid4()),
    }
    _append_audit_phase(arguments.audit, event, "intended")
    write_registry(arguments.registry, registry)
    _complete_audit(arguments.audit, event)
    return {"status": "operator_set", "operator": registry["operator"]}


def _profile_show(arguments: argparse.Namespace) -> Dict[str, Any]:
    registry = _read_registry_or_empty(arguments.registry)
    return {"status": "profile", "operator": registry.get("operator"), "project_count": len(registry["projects"])}


def _read_json_list(path: str, label: str) -> list:
    try:
        with Path(path).open("r", encoding="utf-8") as handle:
            value = json.load(handle)
    except (OSError, ValueError) as error:
        raise CommandError("invalid_" + label, label + " could not be read") from error
    if not isinstance(value, list) or not all(isinstance(item, str) and item for item in value):
        raise CommandError("invalid_" + label, label + " must be a JSON list of non-empty strings")
    if len(value) != len(set(value)):
        raise CommandError("invalid_" + label, label + " must not contain duplicates")
    return value


def _manifest_build(arguments: argparse.Namespace) -> Dict[str, Any]:
    operator, root, profile = _require_registered_project(arguments.registry, arguments.root)
    candidates = _read_json_list(arguments.candidates, "candidates")
    previous = read_manifest(arguments.previous_manifest) if arguments.previous_manifest else None
    manifest = build_manifest(
        root,
        candidates,
        profile,
        previous_manifest=previous,
        staging_root=arguments.staging_root,
        operator=operator,
    )
    write_manifest(arguments.output, manifest)
    classifications: Dict[str, int] = {}
    deltas: Dict[str, int] = {}
    for entry in manifest.entries:
        classifications[entry.classification] = classifications.get(entry.classification, 0) + 1
        deltas[entry.delta] = deltas.get(entry.delta, 0) + 1
    return {
        "status": "manifest_built",
        "operator": operator,
        "project_slug": profile.get("project_slug"),
        "bank_id": profile.get("bank_id"),
        "manifest_path": str(Path(arguments.output).expanduser().resolve()),
        "manifest_sha256": manifest.manifest_sha256,
        "entry_count": len(manifest.entries),
        "deleted_count": len(manifest.deleted),
        "classifications": classifications,
        "deltas": deltas,
    }


def _write_private_json(path: str, value: Any) -> None:
    destination = Path(path).expanduser().absolute()
    destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(destination.parent, 0o700)
    raw = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    _atomic_write_bytes(destination, raw)


def _graph_capsules_build(arguments: argparse.Namespace) -> Dict[str, Any]:
    operator, _, profile = _require_registered_project(arguments.registry, arguments.root)
    effective_profile = copy.deepcopy(dict(profile))
    effective_profile["operator"] = operator
    capsules = build_graph_capsules(
        arguments.sidecar,
        effective_profile,
        audit_status=arguments.audit_status,
        sidecar_sha256=arguments.sidecar_sha256,
        max_edges=arguments.max_edges,
    )
    previous_ids = ()
    if arguments.previous_inventory:
        previous = _read_json_file(arguments.previous_inventory, "graph_inventory")
        previous_ids = previous.get("expected_document_ids", ())
    inventory = graph_capsule_inventory(capsules, previous_document_ids=previous_ids)
    _write_private_json(arguments.output, capsules)
    _write_private_json(arguments.inventory_output, inventory)
    return {
        "status": "graph_capsules_built",
        "operator": operator,
        "project_slug": profile.get("project_slug"),
        "bank_id": profile.get("bank_id"),
        "capsule_count": len(capsules),
        "expected_document_ids": inventory["expected_document_ids"],
        "stale_document_ids": inventory["stale_document_ids"],
        "stale_id_policy": inventory["stale_id_policy"],
    }


def _read_json_file(path: str, label: str) -> Dict[str, Any]:
    try:
        with Path(path).open("r", encoding="utf-8") as handle:
            value = json.load(handle)
    except (OSError, ValueError) as error:
        raise CommandError("invalid_" + label, label + " could not be read") from error
    if not isinstance(value, dict):
        raise CommandError("invalid_" + label, label + " must be a JSON object")
    return value


def _require_registered_project(registry_path: str, root_text: str) -> tuple:
    """Return only a confirmed operator plus the exact registered root/profile."""
    registry = _read_registry_or_empty(registry_path)
    operator = registry.get("operator")
    if not isinstance(operator, Mapping) or not isinstance(operator.get("nickname"), str) or not operator["nickname"]:
        raise CommandError("operator_required", "an active operator is required")
    target = Path(root_text).expanduser().resolve()
    resolved = resolve_project_registration(registry, target)
    if resolved is None or resolved[0] != target:
        raise CommandError("project_required", "an exact registered project root is required")
    root, profile = resolved
    if not isinstance(profile.get("bank_id"), str) or not profile["bank_id"]:
        raise CommandError("invalid_project", "registered project has no bank")
    return operator["nickname"], root, profile


def _parse_approved_at(value: Any) -> str:
    if not isinstance(value, str) or not value:
        raise CommandError("approval_required", "run record requires an explicit approved_at")
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError as error:
        raise CommandError("approval_required", "approved_at must be ISO-8601") from error
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise CommandError("approval_required", "approved_at must include a timezone")
    return value


def _canonical_explicit_path(value: Any, label: str) -> str:
    """Resolve an explicit run path without accepting a local symlink alias.

    macOS exposes /var and /tmp through system aliases, which the manifest
    layer already treats as safe platform roots.  Any other symlink in an
    explicit approval path would make a durable approval ambiguous.
    """
    if not isinstance(value, str) or not value:
        raise CommandError("approval_required", "run record requires " + label)
    raw = Path(value).expanduser()
    if not raw.is_absolute() or ".." in raw.parts:
        raise CommandError("approval_required", label + " must be an absolute canonical path")
    current = Path(raw.anchor)
    for part in raw.parts[1:]:
        current = current / part
        if current.exists() and current.is_symlink() and str(current) not in {"/var", "/tmp"}:
            raise CommandError("approval_mismatch", label + " must not use a symlink alias")
    return str(raw.resolve())


def _approved_run(arguments: argparse.Namespace, action: Optional[str], *, needs_manifest: bool = True) -> tuple:
    """Validate local approval before config/source/staging bytes are touched."""
    # Check caller-supplied paths before the registry resolves them.  A
    # symlink can otherwise resolve to the right project after an approval was
    # made for a different filesystem identity.
    requested_root = _canonical_explicit_path(arguments.root, "project_root")
    operator, root, profile = _require_registered_project(arguments.registry, arguments.root)
    if requested_root != str(root):
        raise CommandError("approval_mismatch", "root must be the exact registered project root")
    requested_manifest = _canonical_explicit_path(arguments.manifest, "manifest_path") if needs_manifest else None
    requested_source = _canonical_explicit_path(arguments.source_root, "source_root") if action == "hindsight_submit" else None
    requested_stage = _canonical_explicit_path(arguments.staging_root, "staging_root") if action == "hindsight_submit" else None
    run = _read_json_file(arguments.run, "run")
    run_operator = run.get("operator")
    run_root = run.get("project_root")
    if run_operator != operator or run.get("project_slug") != profile.get("project_slug") or run.get("bank_id") != profile.get("bank_id"):
        raise CommandError("approval_mismatch", "run record does not bind the current operator and project")
    if _canonical_explicit_path(run_root, "project_root") != str(root):
        raise CommandError("approval_mismatch", "run record does not bind the exact project root")
    approved_at = _parse_approved_at(run.get("approved_at"))
    if not isinstance(run.get("run_id"), str) or not run["run_id"]:
        raise CommandError("approval_required", "run record requires a stable run_id")
    if action is not None:
        actions = run.get("approved_actions")
        if not isinstance(actions, list) or action not in actions or not all(isinstance(item, str) for item in actions):
            raise CommandError("approval_required", "run record does not approve this action")
    if needs_manifest and _canonical_explicit_path(run.get("manifest_path"), "manifest_path") != requested_manifest:
        raise CommandError("approval_mismatch", "run record does not bind manifest_path")
    if action == "hindsight_submit":
        if requested_source != str(root):
            raise CommandError("approval_mismatch", "source_root must be the exact registered project root")
        bound_paths = {
            "project_root": str(root),
            "source_root": str(root),
            "manifest_path": requested_manifest,
            "staging_root": requested_stage,
        }
        for key, expected in bound_paths.items():
            if _canonical_explicit_path(run.get(key), key) != expected:
                raise CommandError("approval_mismatch", "run record does not bind " + key)
        approved_operation_id = run.get("operation_id")
        if not isinstance(approved_operation_id, str) or not approved_operation_id:
            raise CommandError("approval_required", "run record requires an approved operation_id")
        if getattr(arguments, "operation_id", None) and arguments.operation_id != approved_operation_id:
            raise CommandError("approval_mismatch", "operation_id differs from the approved durable ID")
    manifest = None
    if needs_manifest:
        manifest = read_manifest(arguments.manifest)
        if run.get("manifest_sha256") != manifest.manifest_sha256:
            raise CommandError("approval_mismatch", "run record does not bind this validated manifest")
    return operator, root, profile, run, approved_at, manifest


def _client(config_path: str) -> HindsightTransport:
    # This deliberately has no implicit ~/.hindsight default: callers select it.
    try:
        config = load_hindsight_config(config_path)
        return HindsightTransport(config["api_url"], config["api_token"])
    except TransportError:
        raise
    except ValueError as error:
        raise TransportError("Hindsight configuration is invalid") from error


def _audit_transport(path: str, operator: str, profile: Mapping[str, Any], action: str,
                     run: Optional[Mapping[str, Any]], phase: str, **extra: Any) -> None:
    event: Dict[str, Any] = {"at": _timestamp(), "operator": operator, "project_root": (run or {}).get("project_root"), "project_slug": profile.get("project_slug"),
                             "bank": profile.get("bank_id"), "bank_id": profile.get("bank_id"), "action": action,
                             "phase": phase, "result": phase}
    if run is not None:
        event["run_id"] = run.get("run_id")
        event["manifest_sha256"] = run.get("manifest_sha256")
        event["approved_at"] = run.get("approved_at")
    event.update({key: value for key, value in extra.items() if value is not None})
    try:
        append_audit(path, event)
    except (OSError, ValueError, TypeError) as error:
        raise CommandError("audit_unavailable", "local audit record could not be written") from error


def _bound_read(path: Path, root: Path, expected_sha256: Any, label: str) -> bytes:
    """Read one approved locator only after repeating its path and byte gate."""
    if not isinstance(expected_sha256, str) or not re.fullmatch(r"[0-9a-f]{64}", expected_sha256):
        raise CommandError("preflight_failed", label + " has no approved hash")
    lexical_root, lexical_path = Path(root).absolute(), Path(path).absolute()
    try:
        relative = lexical_path.relative_to(lexical_root)
    except ValueError as error:
        raise CommandError("preflight_failed", label + " escapes its approved root") from error
    current = lexical_root
    if current.is_symlink():
        raise CommandError("preflight_failed", label + " root uses a symlink")
    for part in relative.parts:
        current = current / part
        if current.is_symlink():
            raise CommandError("preflight_failed", label + " uses a symlink")
    try:
        raw = lexical_path.read_bytes()
    except OSError as error:
        raise CommandError("preflight_failed", "approved export source is unavailable") from error
    if hashlib.sha256(raw).hexdigest() != expected_sha256:
        raise CommandError("preflight_failed", label + " bytes differ from the approved hash")
    return raw


def _entry_text(entry: Any, source_root: Path, staging_root: Path, credential_policy: object = None) -> str:
    if entry.export_path:
        try:
            _assert_no_staging_symlinks(staging_root)
        except ValueError as error:
            raise CommandError("preflight_failed", "staging path uses a symlink") from error
        raw = _bound_read(staging_root / entry.export_path, staging_root, entry.exported_sha256 or entry.source_sha256, "staged export")
    else:
        raw = _bound_read(source_root / entry.relative_path, source_root, entry.source_sha256, "source")
    # A forged manifest cannot turn live secret-bearing bytes into an include.
    scan = scan_text(entry.relative_path, raw, credential_policy=credential_policy)
    if entry.export_path:
        if scan.decision != "safe":
            raise CommandError("preflight_failed", "staged export failed the secret preflight")
        return scan.exported_text or ""
    if scan.decision != "safe":
        raise CommandError("preflight_failed", "source changed since the approved preflight")
    return scan.exported_text or ""


def _manifest_items(manifest: Any, source_root: Path, staging_root: Path, operator: str, run: Mapping[str, Any],
                    profile: Optional[Mapping[str, Any]] = None) -> tuple:
    validate_manifest_files(manifest, source_root, staging_root)
    configured_policy = normalize_credential_policy((profile or {}).get("credential_policy"))
    credential_sources = set(credential_source_paths(profile or {}))
    exported_at = _timestamp()
    items = []
    skipped = 0
    for entry in manifest.entries:
        if entry.classification not in {"include", "include_redacted"} or entry.delta == "unchanged":
            skipped += 1
            continue
        if entry.delta not in {"new", "changed", "renamed"}:
            skipped += 1
            continue
        policy = "allow_project_staging" if configured_policy == "allow_project_staging" and entry.relative_path in credential_sources else "exclude"
        metadata_policy = dict(entry.metadata).get("credential_policy", "exclude")
        if metadata_policy != policy:
            raise CommandError("preflight_failed", "manifest credential policy differs from the reviewed profile")
        metadata = dict(entry.metadata)
        user_tags = [tag for tag in entry.tags if tag.startswith("user:")]
        if user_tags != ["user:" + operator] or metadata.get("operator") != operator:
            raise CommandError("preflight_failed", "manifest attribution does not match the active operator")
        text = _entry_text(entry, source_root, staging_root, policy)
        metadata.update({"operator": operator, "exported_at": exported_at, "export_run_id": str(run["run_id"])})
        item = {"content": text, "context": "project knowledge: " + entry.knowledge_layer,
                "timestamp": entry.event_timestamp or "unset", "document_id": entry.document_id,
                "tags": list(entry.tags), "metadata": metadata, "observation_scopes": "shared"}
        items.append(item)
    return items, skipped, len(manifest.deleted)


def _strict_sha256(value: Any, label: str) -> str:
    if not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{64}", value):
        raise CommandError("approval_required", label + " must be a SHA-256")
    return value


def _required_tags(item: Mapping[str, Any], operator: str, project_slug: str, kind: str) -> None:
    tags = item.get("tags")
    if not isinstance(tags, (list, tuple)) or not all(isinstance(tag, str) for tag in tags):
        raise CommandError("derived_invalid", "derived item tags must be strings")
    try:
        for tag in tags:
            validate_semantic_safe(tag, tag=True)
    except ValueError as error:
        raise CommandError("derived_invalid", "derived item has unsafe tag") from error
    if any(tag.startswith(("source:", "harness:")) for tag in tags):
        raise CommandError("derived_invalid", "derived item uses a reserved tag namespace")
    grouped: Dict[str, List[str]] = {}
    for tag in tags:
        if ":" not in tag:
            continue
        prefix, value = tag.split(":", 1)
        grouped.setdefault(prefix, []).append(value)
    expected = {"user": operator, "project": project_slug, "kind": kind}
    for key, value in expected.items():
        if grouped.get(key) != [value]:
            raise CommandError("derived_invalid", "derived item has inconsistent " + key + " tag")
    for key in ("scope", "trust", "knowledge"):
        if len(grouped.get(key, ())) != 1 or not grouped[key][0]:
            raise CommandError("derived_invalid", "derived item lacks a controlled " + key + " tag")
    # The source-approved values must agree with metadata below, but projects
    # remain free to introduce new trust/knowledge categories.


def _safe_project_source(root: Path, source_path: Any, source_hash: Any) -> None:
    if not isinstance(source_path, str) or not source_path or not isinstance(source_hash, str) or not re.fullmatch(r"[0-9a-f]{64}", source_hash):
        raise CommandError("derived_invalid", "derived item provenance is incomplete")
    root = Path(root).resolve()
    if "\\" in source_path:
        raise CommandError("derived_invalid", "derived provenance source must use a canonical POSIX path")
    raw = Path(source_path).expanduser()
    if ".." in raw.parts or source_path in {".", "./"}:
        raise CommandError("derived_invalid", "derived provenance source is not canonical")
    if raw.is_absolute():
        lexical = raw
        if str(lexical) != str(lexical.resolve()):
            raise CommandError("derived_invalid", "derived provenance source is not canonical")
    else:
        normalized = "/".join(raw.parts)
        if source_path != normalized or not normalized:
            raise CommandError("derived_invalid", "derived provenance source is not canonical")
        lexical = root.joinpath(*raw.parts)
    try:
        relative = lexical.relative_to(root)
    except ValueError as error:
        raise CommandError("derived_invalid", "derived provenance source is outside project root") from error
    current = root
    for part in relative.parts:
        current = current / part
        if current.is_symlink():
            raise CommandError("derived_invalid", "derived provenance source uses a symlink")
    resolved = lexical.resolve()
    try:
        resolved.relative_to(root)
    except ValueError as error:
        raise CommandError("derived_invalid", "derived provenance source escapes project root") from error
    try:
        actual = hashlib.sha256(resolved.read_bytes()).hexdigest()
    except OSError as error:
        raise CommandError("derived_invalid", "derived provenance source could not be read") from error
    if actual != source_hash:
        raise CommandError("derived_invalid", "derived provenance hash differs from source bytes")


def _canonical_evidence_hash(evidence: list) -> str:
    return hashlib.sha256(json.dumps(evidence, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()


def _verify_multi_source_dossier(root: Path, metadata: Mapping[str, str], kind: str) -> None:
    """Bind an aggregate dossier to an ordered, hash-checked evidence list."""
    if kind != "dossier" or "source_path" in metadata:
        raise CommandError("derived_invalid", "multi-source provenance is only valid for dossiers")
    try:
        source_paths = json.loads(metadata.get("source_paths", ""))
        evidence = json.loads(metadata.get("evidence", ""))
    except (TypeError, ValueError) as error:
        raise CommandError("derived_invalid", "dossier sources and evidence must be JSON text") from error
    if (not isinstance(source_paths, list) or len(source_paths) < 2 or
            not all(isinstance(path, str) and path for path in source_paths) or
            len(set(source_paths)) != len(source_paths) or not isinstance(evidence, list) or len(evidence) != len(source_paths)):
        raise CommandError("derived_invalid", "dossier evidence must be an ordered unique source list")
    canonical_evidence = []
    for expected_path, item in zip(source_paths, evidence):
        if not isinstance(item, Mapping) or set(item) != {"source_path", "source_sha256"} or item.get("source_path") != expected_path:
            raise CommandError("derived_invalid", "dossier evidence does not match source_paths")
        source_hash = item.get("source_sha256")
        _safe_project_source(root, expected_path, source_hash)
        canonical_evidence.append({"source_path": expected_path, "source_sha256": source_hash})
    if metadata.get("source_sha256") != _canonical_evidence_hash(canonical_evidence):
        raise CommandError("derived_invalid", "dossier aggregate provenance hash differs from evidence")


def _derived_timestamp(value: Any) -> str:
    if value is None or value == "unset":
        return "unset"
    if not isinstance(value, str):
        raise CommandError("derived_invalid", "derived event_timestamp must be unset or timezone-aware")
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError as error:
        raise CommandError("derived_invalid", "derived event_timestamp must be ISO-8601") from error
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise CommandError("derived_invalid", "derived event_timestamp must include a timezone")
    return value


def _nonnegative_int(value: Any, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise CommandError("approval_required", label + " must be a nonnegative integer")
    return value


def _exact_ids(value: Any, label: str) -> List[str]:
    if not isinstance(value, list) or not all(isinstance(item, str) and item for item in value):
        raise CommandError("approval_required", label + " must be a list of nonempty IDs")
    if len({item.casefold() for item in value}) != len(value):
        raise CommandError("approval_required", label + " contains duplicate IDs")
    return value


def _derived_items(arguments: argparse.Namespace, run: Mapping[str, Any], profile: Mapping[str, Any], operator: str,
                   root: Path, manifest_document_ids: set) -> List[Dict[str, Any]]:
    derived_path = getattr(arguments, "derived_batch", None)
    if not derived_path:
        return []
    canonical = _canonical_explicit_path(derived_path, "derived_batch_path")
    if _canonical_explicit_path(run.get("derived_batch_path"), "derived_batch_path") != canonical:
        raise CommandError("approval_mismatch", "run record does not bind derived_batch_path")
    try:
        raw = Path(canonical).read_bytes()
    except OSError as error:
        raise CommandError("derived_invalid", "derived batch could not be read") from error
    if hashlib.sha256(raw).hexdigest() != _strict_sha256(run.get("derived_batch_sha256"), "derived_batch_sha256"):
        raise CommandError("approval_mismatch", "derived batch hash differs from approval")
    try:
        records = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as error:
        raise CommandError("derived_invalid", "derived batch must be a JSON list") from error
    if not isinstance(records, list):
        raise CommandError("derived_invalid", "derived batch must be a JSON list")
    project = profile.get("project_slug")
    if not isinstance(project, str) or not project:
        raise CommandError("invalid_project", "project has no project_slug")
    derived_ids, converted = [], []
    for record in records:
        if not isinstance(record, Mapping):
            raise CommandError("derived_invalid", "derived batch item must be an object")
        document_id, content = record.get("document_id"), record.get("content")
        match = re.fullmatch(r"kb:" + re.escape(project) + r":(graph|dossier):.+", document_id or "")
        if not match or not isinstance(content, str) or not content:
            raise CommandError("derived_invalid", "derived item has invalid document_id or content")
        kind = "graph_projection" if match.group(1) == "graph" else "dossier"
        _required_tags(record, operator, project, kind)
        metadata = record.get("metadata")
        if not isinstance(metadata, Mapping) or not all(isinstance(key, str) and isinstance(value, str) for key, value in metadata.items()):
            raise CommandError("derived_invalid", "derived item metadata must be string-valued")
        try:
            validate_semantic_safe(metadata)
        except ValueError as error:
            raise CommandError("derived_invalid", "derived item has unsafe metadata") from error
        if (metadata.get("operator") != operator or metadata.get("project_slug") != project or
                not isinstance(metadata.get("generator"), str) or not metadata["generator"] or
                not isinstance(metadata.get("generator_version"), str) or not metadata["generator_version"]):
            raise CommandError("derived_invalid", "derived item provenance is incomplete")
        tags = {tag.split(":", 1)[0]: tag.split(":", 1)[1] for tag in record["tags"] if ":" in tag}
        if metadata.get("knowledge_layer") != tags["knowledge"] or metadata.get("verification_status") != tags["trust"]:
            raise CommandError("derived_invalid", "derived item metadata conflicts with controlled tags")
        if "source_paths" in metadata or "evidence" in metadata:
            _verify_multi_source_dossier(root, metadata, kind)
        else:
            _safe_project_source(root, metadata.get("source_path"), metadata.get("source_sha256"))
        # Derived IDs are semantic identities, not filesystem paths.  Words such
        # as "generated-document" must not activate source-path exclusions;
        # provenance paths were already hash-checked above.
        scan = scan_text("derived/knowledge-record.md", content)
        if scan.decision != "safe":
            raise CommandError("derived_invalid", "derived item failed sensitive-data preflight")
        if document_id.casefold() in {item.casefold() for item in manifest_document_ids | set(derived_ids)}:
            raise CommandError("derived_invalid", "derived document ID collides with approved items")
        derived_ids.append(document_id)
        converted.append({"content": content, "context": "project knowledge: " + str(metadata.get("knowledge_layer", kind)),
                          "timestamp": _derived_timestamp(record.get("event_timestamp")), "document_id": document_id,
                          "tags": list(record["tags"]), "metadata": dict(metadata), "observation_scopes": "shared"})
    expected_ids = _exact_ids(run.get("derived_document_ids"), "derived_document_ids")
    if expected_ids != derived_ids:
        raise CommandError("approval_mismatch", "derived document IDs differ from approval")
    if _nonnegative_int(run.get("derived_item_count"), "derived_item_count") != len(converted) or _nonnegative_int(run.get("derived_total_bytes"), "derived_total_bytes") != sum(len(item["content"].encode("utf-8")) for item in converted):
        raise CommandError("approval_mismatch", "derived batch count or bytes differ from approval")
    return converted


def _verify_combined_approval(run: Mapping[str, Any], items: List[Dict[str, Any]]) -> None:
    ids = [item["document_id"] for item in items]
    if (_exact_ids(run.get("approved_document_ids"), "approved_document_ids") != ids or
            len({item.casefold() for item in ids}) != len(ids) or
            _nonnegative_int(run.get("approved_item_count"), "approved_item_count") != len(items) or
            _nonnegative_int(run.get("approved_total_bytes"), "approved_total_bytes") != sum(len(item["content"].encode("utf-8")) for item in items)):
        raise CommandError("approval_mismatch", "approved item IDs, count, or byte total differ")


def _verify_manifest_identity_approval(run: Mapping[str, Any], manifest: Any) -> None:
    """Reject a forged/mismatched item set before reading any source or staging text."""
    manifest_ids = [entry.document_id for entry in manifest.entries
                    if entry.classification in {"include", "include_redacted"} and entry.delta in {"new", "changed", "renamed"}]
    approved = run.get("approved_document_ids")
    if (_exact_ids(approved, "approved_document_ids")[:len(manifest_ids)] != manifest_ids or
            len({item.casefold() for item in manifest_ids}) != len(manifest_ids)):
        raise CommandError("approval_mismatch", "approved manifest document IDs differ")


def _mutation_phase(result: Mapping[str, Any]) -> str:
    status = result.get("status")
    if status in {"acknowledged", "completed", "failed", "cancelled"}:
        return status
    return "uncertain"


def _hindsight_submit(arguments: argparse.Namespace) -> Dict[str, Any]:
    # Order is intentional: invalid approval must not read manifest bytes, staging,
    # source content, config, or create a network client.
    operator, root, profile, run, approved_at, manifest = _approved_run(arguments, "hindsight_submit")
    source_root, staging_root = Path(arguments.source_root).resolve(), Path(arguments.staging_root).absolute()
    _verify_manifest_identity_approval(run, manifest)
    items, skipped, deleted = _manifest_items(manifest, source_root, staging_root, operator, run, profile)
    items.extend(_derived_items(arguments, run, profile, operator, root, {item["document_id"] for item in items}))
    _verify_combined_approval(run, items)
    if not items:
        return {"status": "no_op", "bank_id": profile["bank_id"], "submitted": 0,
                "unchanged_or_ineligible": skipped, "deleted_reported": deleted}
    operation_id = run["operation_id"]
    _audit_transport(arguments.audit, operator, profile, "hindsight_submit", run, "intended", operation_id=operation_id,
                     item_count=len(items), total_bytes=sum(len(item["content"].encode("utf-8")) for item in items),
                     document_ids=[item["document_id"] for item in items], source_sha256s=[item["metadata"].get("source_sha256") for item in items])
    try:
        result = _client(arguments.config).submit_retain(profile["bank_id"], items, operation_id)
    except TransportError as error:
        try:
            _audit_transport(arguments.audit, operator, profile, "hindsight_submit", run,
                             "uncertain" if error.uncertain else "failed", operation_id=operation_id,
                             http_status=error.status_code)
        except CommandError:
            return {"status": "audit_completion_uncertain", "operation_id": operation_id, "bank_id": profile["bank_id"]}
        return dict(error.safe_result(), bank_id=profile["bank_id"], retry_operation_id=operation_id)
    phase = _mutation_phase(result)
    try:
        _audit_transport(arguments.audit, operator, profile, "hindsight_submit", run, phase, operation_id=operation_id,
                         item_count=len(items), total_bytes=sum(len(item["content"].encode("utf-8")) for item in items),
                         document_ids=[item["document_id"] for item in items], source_sha256s=[item["metadata"].get("source_sha256") for item in items])
    except CommandError:
        return {"status": "audit_completion_uncertain", "operation_id": operation_id, "bank_id": profile["bank_id"]}
    return {"status": phase, "bank_id": profile["bank_id"],
            "operation_id": operation_id, "submitted": len(items), "unchanged_or_ineligible": skipped,
            "deleted_reported": deleted}


def _hindsight_wait(arguments: argparse.Namespace) -> Dict[str, Any]:
    operator, _, profile, run, _, _ = _approved_run(arguments, None, needs_manifest=True)
    if not isinstance(arguments.operation_id, str) or not arguments.operation_id:
        raise CommandError("invalid_input", "operation_id is required")
    if run.get("operation_id") != arguments.operation_id:
        raise CommandError("approval_mismatch", "wait operation_id is not bound by the run")
    try:
        result = _client(arguments.config).wait_operation(profile["bank_id"], arguments.operation_id,
                                                          deadline_seconds=arguments.deadline)
    except TransportError as error:
        phase = "uncertain" if error.uncertain else "failed"
        try:
            _audit_transport(arguments.audit, operator, profile, "hindsight_wait", run, phase, operation_id=arguments.operation_id, http_status=error.status_code)
        except CommandError:
            return {"status": "audit_completion_uncertain", "operation_id": arguments.operation_id, "bank_id": profile["bank_id"]}
        return dict(error.safe_result(), bank_id=profile["bank_id"])
    phase = result.get("status")
    try:
        _audit_transport(arguments.audit, operator, profile, "hindsight_wait", run, phase if phase in {"completed", "failed", "cancelled", "timed_out"} else "uncertain", operation_id=arguments.operation_id)
    except CommandError:
        return {"status": "audit_completion_uncertain", "operation_id": arguments.operation_id, "bank_id": profile["bank_id"]}
    return dict(result, bank_id=profile["bank_id"], operator=operator)


def _approved_action(arguments: argparse.Namespace, action: str) -> tuple:
    operator, root, profile, run, approved_at, manifest = _approved_run(arguments, action, needs_manifest=True)
    _ = root, approved_at
    return operator, profile, run, manifest


def _canonical_json_sha256(value: Any) -> str:
    try:
        raw = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    except (TypeError, ValueError) as error:
        raise CommandError("approval_mismatch", "approved target is not canonical JSON") from error
    return hashlib.sha256(raw).hexdigest()


def _require_approved_target(run: Mapping[str, Any], profile: Mapping[str, Any], manifest: Any,
                             action: str, **specific: Any) -> str:
    expected = {
        "action": action,
        "bank_id": profile.get("bank_id"),
        "project_slug": profile.get("project_slug"),
        "profile_sha256": _canonical_json_sha256(profile),
        "manifest_sha256": manifest.manifest_sha256,
    }
    expected.update(specific)
    targets = run.get("approved_targets")
    if not isinstance(targets, Mapping) or targets.get(action) != expected:
        raise CommandError("approval_mismatch", "run record does not bind the exact operation target")
    return _canonical_json_sha256(expected)


def _terminal_result(client: HindsightTransport, bank_id: str, initial: Mapping[str, Any], deadline: float) -> Dict[str, Any]:
    operation_id = initial.get("operation_id")
    if not isinstance(operation_id, str) or not operation_id:
        raise TransportError("Hindsight returned a mutation without an operation ID", uncertain=True)
    if initial.get("status") in {"completed", "failed", "cancelled"}:
        return dict(initial)
    return client.wait_operation(bank_id, operation_id, deadline_seconds=deadline)


def _hindsight_consolidate(arguments: argparse.Namespace) -> Dict[str, Any]:
    operator, profile, run, manifest = _approved_action(arguments, "hindsight_consolidate")
    target_sha256 = _require_approved_target(run, profile, manifest, "hindsight_consolidate")
    _audit_transport(arguments.audit, operator, profile, "hindsight_consolidate", run, "intended", target_sha256=target_sha256)
    try:
        client = _client(arguments.config)
        acknowledgement = client.consolidate(profile["bank_id"])
    except TransportError as error:
        try:
            _audit_transport(arguments.audit, operator, profile, "hindsight_consolidate", run, "uncertain" if error.uncertain else "failed", target_sha256=target_sha256, http_status=error.status_code)
        except CommandError:
            return {"status": "audit_completion_uncertain", "bank_id": profile["bank_id"]}
        return error.safe_result()
    operation_id = acknowledgement.get("operation_id")
    try:
        _audit_transport(arguments.audit, operator, profile, "hindsight_consolidate", run, "acknowledged", target_sha256=target_sha256, operation_id=operation_id)
    except CommandError:
        return {"status": "audit_completion_uncertain", "operation_id": operation_id, "bank_id": profile["bank_id"]}
    try:
        terminal = _terminal_result(client, profile["bank_id"], acknowledgement, arguments.deadline)
    except TransportError as error:
        phase = "uncertain" if error.uncertain else "failed"
        try:
            _audit_transport(arguments.audit, operator, profile, "hindsight_consolidate", run, phase, target_sha256=target_sha256, operation_id=operation_id, http_status=error.status_code)
        except CommandError:
            return {"status": "audit_completion_uncertain", "operation_id": operation_id, "bank_id": profile["bank_id"]}
        return dict(error.safe_result(), operation_id=operation_id, bank_id=profile["bank_id"])
    phase = terminal.get("status")
    if phase not in {"completed", "failed", "cancelled", "timed_out"}:
        phase = "uncertain"
    try:
        _audit_transport(arguments.audit, operator, profile, "hindsight_consolidate", run, phase, target_sha256=target_sha256, operation_id=operation_id)
    except CommandError:
        return {"status": "audit_completion_uncertain", "operation_id": operation_id, "bank_id": profile["bank_id"]}
    return dict(terminal, status=phase, operation_id=operation_id, bank_id=profile["bank_id"])


def _knowledge_tree_index(tree: Any) -> tuple:
    """Validate the official tree shape before using it to suppress creates."""
    if not isinstance(tree, Mapping) or not isinstance(tree.get("roots"), list):
        raise CommandError("invalid_response", "knowledge tree requires an official roots list")
    pages: List[Dict[str, Any]] = []
    folders = set()
    seen = set()

    def visit(node: Any, expected_parent: Optional[str]) -> None:
        if not isinstance(node, Mapping):
            raise CommandError("invalid_response", "knowledge tree node must be an object")
        kind_raw = node.get("kind")
        kind = kind_raw.casefold() if isinstance(kind_raw, str) else ""
        identifier = node.get("id")
        if not isinstance(identifier, str) or not identifier or kind not in {"folder", "page"}:
            raise CommandError("invalid_response", "knowledge tree node has invalid kind or ID")
        if not isinstance(node.get("name"), str) or not node["name"]:
            raise CommandError("invalid_response", "knowledge tree node has no name")
        if node.get("parent_id") != expected_parent:
            raise CommandError("invalid_response", "knowledge tree parent ownership is invalid")
        identity = identifier.casefold()
        if identity in seen:
            raise CommandError("invalid_response", "knowledge tree contains duplicate IDs")
        seen.add(identity)
        children = node.get("children", [])
        if not isinstance(children, list):
            raise CommandError("invalid_response", "knowledge tree children must be a list")
        if kind == "page":
            if children:
                raise CommandError("invalid_response", "knowledge pages cannot own children")
            if not isinstance(node.get("mental_model_id"), str) or not node["mental_model_id"]:
                raise CommandError("invalid_response", "knowledge page has no mental model ID")
            pages.append({"id": identifier, "name": node["name"], "parent_id": expected_parent,
                          "mental_model_id": node.get("mental_model_id")})
            return
        if node.get("mental_model_id") is not None:
            raise CommandError("invalid_response", "knowledge folder cannot have a mental model ID")
        folders.add(identifier)
        for child in children:
            visit(child, identifier)

    for root in tree["roots"]:
        visit(root, None)
    return pages, folders


def _tree_pages(tree: Any, parent_id: Optional[str] = None) -> list:
    _ = parent_id
    return _knowledge_tree_index(tree)[0]


def _tree_folder_ids(tree: Any) -> set:
    return _knowledge_tree_index(tree)[1]


def _knowledge_specs(profile: Mapping[str, Any]) -> list:
    pages = profile.get("knowledge_pages")
    if isinstance(pages, Mapping):
        pages = pages.get("pages")
    if not isinstance(pages, list) or not pages:
        raise CommandError("invalid_project", "knowledge_pages must be a non-empty list")
    result = []
    seen = set()
    for page in pages:
        page_name = page.get("name", page.get("label")) if isinstance(page, Mapping) else None
        if not isinstance(page, Mapping) or not isinstance(page_name, str) or not page_name or not isinstance(page.get("source_query"), str) or not page["source_query"]:
            raise CommandError("invalid_project", "knowledge page taxonomy is invalid")
        allowed = {key: page[key] for key in ("source_query", "parent_id", "tags", "max_tokens", "trigger") if key in page}
        allowed["name"] = page_name
        if "parent_id" in allowed and allowed["parent_id"] is not None and not isinstance(allowed["parent_id"], str):
            raise CommandError("invalid_project", "knowledge page parent_id must be a string or null")
        if "tags" in allowed and (not isinstance(allowed["tags"], list) or not all(isinstance(tag, str) for tag in allowed["tags"])):
            raise CommandError("invalid_project", "knowledge page tags must be strings")
        if "max_tokens" in allowed and (isinstance(allowed["max_tokens"], bool) or not isinstance(allowed["max_tokens"], int) or allowed["max_tokens"] <= 0):
            raise CommandError("invalid_project", "knowledge page max_tokens must be a positive integer")
        if "trigger" in allowed and not isinstance(allowed["trigger"], Mapping):
            raise CommandError("invalid_project", "knowledge page trigger must be an object")
        identity = (allowed.get("parent_id"), page_name.casefold())
        if identity in seen:
            raise CommandError("invalid_project", "knowledge page names must be unique within a parent")
        seen.add(identity)
        result.append(allowed)
    return result


def _knowledge_page_result(spec: Mapping[str, Any], acknowledgement: Mapping[str, Any],
                           terminal: Mapping[str, Any]) -> Dict[str, Any]:
    identifiers = {}
    for key in ("page_id", "mental_model_id", "operation_id"):
        value = acknowledgement.get(key)
        if isinstance(value, str) and value:
            identifiers[key] = value
    return dict(identifiers, name=spec["name"], status=terminal.get("status"))


def _inspect_page(client: HindsightTransport, bank_id: str, page_id: Any) -> Dict[str, Any]:
    if not isinstance(page_id, str) or not page_id:
        raise TransportError("Hindsight returned a knowledge-page mutation without a page ID", uncertain=True)
    page = client.get_knowledge_page(bank_id, page_id)
    if not isinstance(page, Mapping) or page.get("id") != page_id:
        raise TransportError("Hindsight returned a mismatched knowledge page ID")
    inspectable = page.get("body")
    if not isinstance(inspectable, str):
        inspectable = page.get("markdown")
    if not isinstance(inspectable, str) or not inspectable.strip():
        raise TransportError("Hindsight returned a knowledge page without inspectable body")
    return dict(page)


def _contains_config(actual: Any, expected: Any) -> bool:
    """Compare an API effective config with the reviewed patch fields only."""
    if isinstance(expected, Mapping):
        return isinstance(actual, Mapping) and all(
            key in actual and _contains_config(actual[key], value)
            for key, value in expected.items()
        )
    return actual == expected


def _existing_page_matches(spec: Mapping[str, Any], page: Mapping[str, Any],
                           model: Mapping[str, Any]) -> bool:
    if model.get("id") != page.get("mental_model_id"):
        return False
    if not isinstance(model.get("name"), str) or model["name"].casefold() != spec["name"].casefold():
        return False
    if model.get("source_query") != spec["source_query"]:
        return False
    if "tags" in spec:
        actual_tags = model.get("tags")
        if not isinstance(actual_tags, list) or sorted(actual_tags) != sorted(spec["tags"]):
            return False
    if "max_tokens" in spec and model.get("max_tokens") != spec["max_tokens"]:
        return False
    if "trigger" in spec and not _contains_config(model.get("trigger"), spec["trigger"]):
        return False
    return True


def _knowledge_ensure(arguments: argparse.Namespace) -> Dict[str, Any]:
    operator, profile, run, manifest = _approved_action(arguments, "knowledge_pages_ensure")
    specs = _knowledge_specs(profile)
    target_sha256 = _require_approved_target(
        run, profile, manifest, "knowledge_pages_ensure", page_specs=specs,
    )
    try:
        client = _client(arguments.config)
        tree = client.get_knowledge_tree(profile["bank_id"])
    except TransportError as error:
        return dict(error.safe_result(), bank_id=profile["bank_id"])
    current, folders = _knowledge_tree_index(tree)
    for spec in specs:
        parent = spec.get("parent_id")
        if parent is not None and parent not in folders:
            raise CommandError("invalid_project", "knowledge page parent_id must reference an existing folder")
    created, existing = [], []
    for spec in specs:
        intended_parent = spec.get("parent_id")
        existing_page = next((item for item in current if item.get("parent_id") == intended_parent and isinstance(item.get("name"), str) and item["name"].casefold() == spec["name"].casefold()), None)
        if existing_page is not None:
            try:
                model = client.get_mental_model(profile["bank_id"], existing_page["mental_model_id"])
            except TransportError as error:
                raise PartialCommandError("existing knowledge page configuration could not be inspected", {
                    "status": "inspection_failed", "bank_id": profile["bank_id"],
                    "created": created, "existing": existing, "page_name": spec["name"],
                }) from error
            if not _existing_page_matches(spec, existing_page, model):
                raise PartialCommandError("existing knowledge page differs from the reviewed specification", {
                    "status": "configuration_mismatch", "bank_id": profile["bank_id"],
                    "created": created, "existing": existing, "page_name": spec["name"],
                    "page_id": existing_page["id"], "mental_model_id": existing_page["mental_model_id"],
                })
            try:
                inspected = _inspect_page(client, profile["bank_id"], existing_page["id"])
            except TransportError as error:
                raise PartialCommandError("existing knowledge page body could not be inspected", {
                    "status": "inspection_failed", "bank_id": profile["bank_id"],
                    "created": created, "existing": existing, "page_name": spec["name"],
                    "page_id": existing_page["id"], "mental_model_id": existing_page["mental_model_id"],
                }) from error
            existing.append({"name": spec["name"], "page_id": existing_page["id"],
                             "mental_model_id": existing_page["mental_model_id"],
                             "status": "verified", "page": inspected})
            continue
        spec_sha256 = _canonical_json_sha256(spec)
        try:
            _audit_transport(
                arguments.audit, operator, profile, "knowledge_pages_ensure", run, "intended",
                target_sha256=target_sha256, page_spec_sha256=spec_sha256,
                page_name=spec["name"], parent_id=intended_parent,
            )
        except CommandError as error:
            if created:
                raise PartialCommandError("knowledge page intended audit is uncertain", {"status": "audit_completion_uncertain", "bank_id": profile["bank_id"], "created": created, "failed_page": spec["name"]}) from error
            raise
        try:
            created_page = client.create_knowledge_page(profile["bank_id"], spec)
        except TransportError as error:
            try:
                _audit_transport(
                    arguments.audit, operator, profile, "knowledge_pages_ensure", run,
                    "uncertain" if error.uncertain else "failed", target_sha256=target_sha256,
                    page_spec_sha256=spec_sha256, page_name=spec["name"],
                    operation_id=error.operation_id, http_status=error.status_code,
                )
            except CommandError:
                raise PartialCommandError("knowledge page mutation audit is uncertain", {"status": "audit_completion_uncertain", "bank_id": profile["bank_id"], "created": created, "failed_page": spec["name"]}) from error
            raise PartialCommandError("knowledge page request failed", {"status": "partial", "bank_id": profile["bank_id"], "created": created, "failed_page": spec["name"]}) from error
        operation_id = created_page.get("operation_id")
        page_id = created_page.get("page_id")
        mental_model_id = created_page.get("mental_model_id")
        try:
            _audit_transport(
                arguments.audit, operator, profile, "knowledge_pages_ensure", run, "acknowledged",
                target_sha256=target_sha256, page_spec_sha256=spec_sha256,
                page_name=spec["name"], operation_id=operation_id,
                page_id=page_id, mental_model_id=mental_model_id,
            )
        except CommandError as error:
            failed = _knowledge_page_result(spec, created_page, {"status": "audit_completion_uncertain"})
            raise PartialCommandError("knowledge page acknowledgement audit is uncertain", {"status": "audit_completion_uncertain", "bank_id": profile["bank_id"], "created": created, "failed": failed, "failed_page": spec["name"]}) from error
        try:
            terminal = _terminal_result(client, profile["bank_id"], created_page, arguments.deadline)
        except TransportError as error:
            phase = "uncertain" if error.uncertain else "failed"
            try:
                _audit_transport(
                    arguments.audit, operator, profile, "knowledge_pages_ensure", run, phase,
                    target_sha256=target_sha256, page_spec_sha256=spec_sha256,
                    page_name=spec["name"], operation_id=operation_id,
                    page_id=page_id, mental_model_id=mental_model_id,
                    http_status=error.status_code,
                )
            except CommandError:
                phase = "audit_completion_uncertain"
            failed = _knowledge_page_result(spec, created_page, {"status": phase})
            raise PartialCommandError("knowledge page terminal state is uncertain", {"status": "partial", "bank_id": profile["bank_id"], "created": created, "failed": failed, "failed_page": spec["name"]}) from error
        phase = terminal.get("status")
        if phase not in {"completed", "failed", "cancelled", "timed_out"}:
            phase = "uncertain"
        page_result = _knowledge_page_result(spec, created_page, {"status": phase})
        page = None
        inspection_error = None
        if phase == "completed":
            try:
                page = _inspect_page(client, profile["bank_id"], page_id)
            except TransportError as error:
                inspection_error = error
        try:
            _audit_transport(
                arguments.audit, operator, profile, "knowledge_pages_ensure", run, phase,
                target_sha256=target_sha256, page_spec_sha256=spec_sha256,
                page_name=spec["name"], operation_id=operation_id,
                page_id=page_id, mental_model_id=mental_model_id,
                body_retrieved=page is not None,
            )
        except CommandError as error:
            raise PartialCommandError("knowledge page completion audit is uncertain", {"status": "audit_completion_uncertain", "bank_id": profile["bank_id"], "created": created, "failed": page_result, "failed_page": spec["name"]}) from error
        if phase != "completed":
            raise PartialCommandError("knowledge page did not complete successfully", {"status": "partial", "bank_id": profile["bank_id"], "created": created, "failed": page_result, "failed_page": spec["name"]})
        if inspection_error is not None:
            page_result["status"] = "inspection_failed"
            raise PartialCommandError("knowledge page body could not be inspected", {"status": "partial", "bank_id": profile["bank_id"], "created": created, "failed": page_result, "failed_page": spec["name"]}) from inspection_error
        page_result["page"] = page
        created.append(page_result)
        current.append({"id": page_id, "name": spec["name"], "parent_id": intended_parent,
                        "mental_model_id": mental_model_id})
    return {"status": "knowledge_pages_ensured", "bank_id": profile["bank_id"], "created": created, "existing": existing}


def _knowledge_refresh(arguments: argparse.Namespace) -> Dict[str, Any]:
    operator, profile, run, manifest = _approved_action(arguments, "knowledge_pages_refresh")
    target_sha256 = _require_approved_target(
        run, profile, manifest, "knowledge_pages_refresh",
        page_id=arguments.page_id, mental_model_id=arguments.mental_model_id,
    )
    _audit_transport(
        arguments.audit, operator, profile, "knowledge_pages_refresh", run, "intended",
        target_sha256=target_sha256, page_id=arguments.page_id,
        mental_model_id=arguments.mental_model_id,
    )
    try:
        client = _client(arguments.config)
        acknowledgement = client.refresh_mental_model(profile["bank_id"], arguments.mental_model_id)
    except TransportError as error:
        try:
            _audit_transport(
                arguments.audit, operator, profile, "knowledge_pages_refresh", run,
                "uncertain" if error.uncertain else "failed", target_sha256=target_sha256,
                page_id=arguments.page_id, mental_model_id=arguments.mental_model_id,
                operation_id=error.operation_id, http_status=error.status_code,
            )
        except CommandError:
            return {"status": "audit_completion_uncertain", "bank_id": profile["bank_id"], "mental_model_id": arguments.mental_model_id}
        return dict(error.safe_result(), bank_id=profile["bank_id"], page_id=arguments.page_id,
                    mental_model_id=arguments.mental_model_id)
    operation_id = acknowledgement.get("operation_id")
    try:
        _audit_transport(
            arguments.audit, operator, profile, "knowledge_pages_refresh", run, "acknowledged",
            target_sha256=target_sha256, page_id=arguments.page_id,
            mental_model_id=arguments.mental_model_id, operation_id=operation_id,
        )
    except CommandError:
        return {"status": "audit_completion_uncertain", "bank_id": profile["bank_id"],
                "page_id": arguments.page_id, "mental_model_id": arguments.mental_model_id,
                "operation_id": operation_id}
    try:
        terminal = _terminal_result(client, profile["bank_id"], acknowledgement, arguments.deadline)
    except TransportError as error:
        phase = "uncertain" if error.uncertain else "failed"
        try:
            _audit_transport(
                arguments.audit, operator, profile, "knowledge_pages_refresh", run, phase,
                target_sha256=target_sha256, page_id=arguments.page_id,
                mental_model_id=arguments.mental_model_id, operation_id=operation_id,
                http_status=error.status_code,
            )
        except CommandError:
            return {"status": "audit_completion_uncertain", "bank_id": profile["bank_id"],
                    "page_id": arguments.page_id, "mental_model_id": arguments.mental_model_id,
                    "operation_id": operation_id}
        return dict(error.safe_result(), bank_id=profile["bank_id"], page_id=arguments.page_id,
                    mental_model_id=arguments.mental_model_id, operation_id=operation_id)
    phase = terminal.get("status")
    if phase not in {"completed", "failed", "cancelled", "timed_out"}:
        phase = "uncertain"
    page = None
    inspection_error = None
    if phase == "completed":
        try:
            page = _inspect_page(client, profile["bank_id"], arguments.page_id)
        except TransportError as error:
            inspection_error = error
    try:
        _audit_transport(
            arguments.audit, operator, profile, "knowledge_pages_refresh", run, phase,
            target_sha256=target_sha256, page_id=arguments.page_id,
            mental_model_id=arguments.mental_model_id, operation_id=operation_id,
            body_retrieved=page is not None,
        )
    except CommandError:
        return {"status": "audit_completion_uncertain", "bank_id": profile["bank_id"],
                "page_id": arguments.page_id, "mental_model_id": arguments.mental_model_id,
                "operation_id": operation_id}
    result = {"status": phase, "bank_id": profile["bank_id"], "page_id": arguments.page_id,
              "mental_model_id": arguments.mental_model_id, "operation_id": operation_id}
    if inspection_error is not None:
        result["status"] = "inspection_failed"
        return result
    if page is not None:
        result["page"] = page
    return result


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Project-neutral local memory registry")
    commands = parser.add_subparsers(dest="group", required=True)

    profile = commands.add_parser("profile").add_subparsers(dest="action", required=True)
    show = profile.add_parser("show")
    show.add_argument("--registry", required=True)
    show.set_defaults(handler=_profile_show)

    operator = commands.add_parser("operator").add_subparsers(dest="action", required=True)
    set_operator = operator.add_parser("set")
    set_operator.add_argument("nickname")
    set_operator.add_argument("--registry", required=True)
    set_operator.add_argument("--audit", required=True)
    set_operator.add_argument("--at")
    set_operator.set_defaults(handler=_operator_set)

    project = commands.add_parser("project").add_subparsers(dest="action", required=True)
    propose = project.add_parser("propose")
    propose.add_argument("--root", required=True)
    propose.add_argument("--name", required=True)
    propose.add_argument("--owner", required=True)
    propose.add_argument("--existing-product")
    propose.add_argument("--registry", required=True)
    propose.set_defaults(handler=_propose)
    register = project.add_parser("register")
    register.add_argument("--profile")
    register.add_argument("--confirm", action="store_true")
    register.add_argument("--registry", required=True)
    register.add_argument("--audit", required=True)
    register.add_argument("--at")
    register.set_defaults(handler=_register)
    resolve = project.add_parser("resolve")
    resolve.add_argument("--root", required=True)
    resolve.add_argument("--registry", required=True)
    resolve.set_defaults(handler=_resolve)

    connector = commands.add_parser("connector").add_subparsers(dest="action", required=True)
    sync = connector.add_parser("sync")
    sync.add_argument("--connector", required=True)
    sync.add_argument("--root", required=True)
    sync.add_argument("--registry", required=True)
    sync.add_argument("--profile", required=True)
    sync.add_argument("--audit", required=True)
    sync.add_argument("--confirm", action="store_true")
    sync.add_argument("--at")
    sync.set_defaults(handler=_connector_sync)

    manifest = commands.add_parser("manifest").add_subparsers(dest="action", required=True)
    build = manifest.add_parser("build")
    for option in ("registry", "root", "candidates", "staging_root", "output"):
        build.add_argument("--" + option.replace("_", "-"), dest=option, required=True)
    build.add_argument("--previous-manifest")
    build.set_defaults(handler=_manifest_build)

    graph = commands.add_parser("graph-capsules").add_subparsers(dest="action", required=True)
    graph_build = graph.add_parser("build")
    for option in ("registry", "root", "sidecar", "audit_status", "sidecar_sha256", "output", "inventory_output"):
        graph_build.add_argument("--" + option.replace("_", "-"), dest=option, required=True)
    graph_build.add_argument("--max-edges", type=int)
    graph_build.add_argument("--previous-inventory")
    graph_build.set_defaults(handler=_graph_capsules_build)

    hindsight = commands.add_parser("hindsight").add_subparsers(dest="action", required=True)
    submit = hindsight.add_parser("submit")
    for option in ("registry", "root", "run", "manifest", "source_root", "staging_root", "config", "audit"):
        submit.add_argument("--" + option.replace("_", "-"), dest=option, required=True)
    submit.add_argument("--operation-id")
    submit.add_argument("--derived-batch")
    submit.set_defaults(handler=_hindsight_submit)
    wait = hindsight.add_parser("wait")
    for option in ("registry", "root", "run", "manifest", "config", "audit", "operation_id"):
        wait.add_argument("--" + option.replace("_", "-"), dest=option, required=True)
    wait.add_argument("--deadline", type=float, default=300.0)
    wait.set_defaults(handler=_hindsight_wait)
    consolidate = hindsight.add_parser("consolidate")
    for option in ("registry", "root", "run", "manifest", "config", "audit"):
        consolidate.add_argument("--" + option.replace("_", "-"), dest=option, required=True)
    consolidate.add_argument("--deadline", type=float, default=300.0)
    consolidate.set_defaults(handler=_hindsight_consolidate)

    knowledge = commands.add_parser("knowledge-pages").add_subparsers(dest="action", required=True)
    ensure = knowledge.add_parser("ensure")
    for option in ("registry", "root", "run", "manifest", "config", "audit"):
        ensure.add_argument("--" + option.replace("_", "-"), dest=option, required=True)
    ensure.add_argument("--deadline", type=float, default=300.0)
    ensure.set_defaults(handler=_knowledge_ensure)
    refresh = knowledge.add_parser("refresh")
    for option in ("registry", "root", "run", "manifest", "config", "audit", "page_id", "mental_model_id"):
        refresh.add_argument("--" + option.replace("_", "-"), dest=option, required=True)
    refresh.add_argument("--deadline", type=float, default=300.0)
    refresh.set_defaults(handler=_knowledge_refresh)
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    try:
        arguments = _parser().parse_args(argv)
        result = arguments.handler(arguments)
    except PartialCommandError as error:
        print(json.dumps(error.result, ensure_ascii=False, sort_keys=True))
        print(error.message, file=sys.stderr)
        return 2
    except CommandError as error:
        result = {"status": error.status, "confirmation_required": error.confirmation_required}
        print(json.dumps(result, ensure_ascii=False, sort_keys=True))
        print(error.message, file=sys.stderr)
        return 2
    except (KeyError, TypeError, ValueError, OSError) as error:
        print(json.dumps({"status": "invalid_input", "confirmation_required": False}, sort_keys=True))
        print("command could not be completed", file=sys.stderr)
        return 2
    print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    return 2 if result.get("status") in {"failed", "uncertain", "timed_out", "cancelled", "partial", "inspection_failed", "audit_completion_uncertain"} else 0


if __name__ == "__main__":
    raise SystemExit(main())
