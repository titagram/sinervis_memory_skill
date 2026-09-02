"""Deterministic, local manifest construction for project-memory dry runs."""

from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import tempfile
from typing import Any, Iterable, Mapping, Optional, Sequence, Tuple, Union
from zoneinfo import ZoneInfo

from .redaction import ScanResult, normalize_credential_policy, scan_text
from .audit import validate_semantic_safe
from .registry import credential_source_paths


PathLike = Union[str, Path]
_ROME = ZoneInfo("Europe/Rome")
_EVENT_HEADING = re.compile(r"^### (\d{4}-\d{2}-\d{2} \d{2}:\d{2}) CEST - (.+?)\s*$", re.MULTILINE)


@dataclass(frozen=True)
class ManifestEntry:
    relative_path: str
    classification: str
    reason: str
    size: int
    source_modified_at: Optional[str]
    source_sha256: Optional[str]
    exported_sha256: Optional[str]
    knowledge_layer: str
    sensitivity_summary: Tuple[str, ...]
    document_id: Optional[str]
    tags: Tuple[str, ...]
    metadata: Tuple[Tuple[str, str], ...]
    delta: str
    event_timestamp: Optional[str] = None
    export_path: Optional[str] = None
    renamed_from: Optional[str] = None


@dataclass(frozen=True)
class Manifest:
    entries: Tuple[ManifestEntry, ...]
    deleted: Tuple[ManifestEntry, ...]
    manifest_sha256: str

    def as_dict(self) -> Mapping[str, Any]:
        """Return only string-valued metadata ready for a JSON transport layer."""
        def entry_dict(entry: ManifestEntry) -> Mapping[str, Any]:
            return {
                "relative_path": entry.relative_path,
                "classification": entry.classification,
                "reason": entry.reason,
                "size": entry.size,
                "source_modified_at": entry.source_modified_at,
                "source_sha256": entry.source_sha256,
                "exported_sha256": entry.exported_sha256,
                "knowledge_layer": entry.knowledge_layer,
                "sensitivity_summary": list(entry.sensitivity_summary),
                "document_id": entry.document_id,
                "tags": list(entry.tags),
                "metadata": dict(entry.metadata),
                "delta": entry.delta,
                "event_timestamp": entry.event_timestamp,
                "export_path": entry.export_path,
                "renamed_from": entry.renamed_from,
            }
        payload = {"entries": [entry_dict(entry) for entry in self.entries], "deleted": [entry_dict(entry) for entry in self.deleted]}
        payload["manifest_sha256"] = _canonical_hash(payload)
        return payload

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "Manifest":
        if not isinstance(value, Mapping) or set(value) != {"entries", "deleted", "manifest_sha256"}:
            raise ValueError("malformed manifest")
        expected = value.get("manifest_sha256")
        body = {"entries": value.get("entries"), "deleted": value.get("deleted")}
        if not isinstance(body["entries"], list) or not isinstance(body["deleted"], list) or not isinstance(expected, str) or _canonical_hash(body) != expected:
            raise ValueError("manifest hash mismatch")
        entries = tuple(_entry_from_dict(item) for item in body["entries"])
        deleted = tuple(_entry_from_dict(item) for item in body["deleted"])
        eligible_ids = [entry.document_id for entry in entries + deleted if entry.document_id is not None]
        if len(eligible_ids) != len(set(eligible_ids)):
            raise ValueError("duplicate eligible document ID")
        return cls(entries, deleted, expected)


def _is_relative_to(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
    except ValueError:
        return False
    return True


def _has_symlink_ancestor(path: Path, root: Path) -> bool:
    current = path.absolute()
    while True:
        if current.is_symlink():
            return True
        if current.resolve() == root.resolve() or current.parent == current:
            return False
        current = current.parent


def _relative_candidate(root: Path, candidate: PathLike) -> Tuple[Path, str]:
    raw = Path(candidate)
    path = raw if raw.is_absolute() else root / raw
    lexical = Path(os.path.abspath(str(path)))
    if not _is_relative_to(lexical, root):
        raise ValueError("candidate is outside the configured root")
    relative = lexical.relative_to(root).as_posix()
    return lexical, relative


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _canonical_hash(value: Mapping[str, Any]) -> str:
    return _sha256(json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8"))


def _entry_from_dict(value: Any) -> ManifestEntry:
    fields = {"relative_path", "classification", "reason", "size", "source_modified_at", "source_sha256", "exported_sha256", "knowledge_layer", "sensitivity_summary", "document_id", "tags", "metadata", "delta", "event_timestamp", "export_path", "renamed_from"}
    if not isinstance(value, Mapping) or set(value) != fields:
        raise ValueError("malformed manifest entry")
    if not isinstance(value["relative_path"], str) or not isinstance(value["classification"], str) or not isinstance(value["reason"], str) or not isinstance(value["size"], int) or not isinstance(value["knowledge_layer"], str) or not isinstance(value["delta"], str):
        raise ValueError("malformed manifest entry types")
    for key in ("source_modified_at", "source_sha256", "exported_sha256", "document_id", "event_timestamp", "export_path", "renamed_from"):
        if value[key] is not None and not isinstance(value[key], str):
            raise ValueError("malformed nullable manifest value")
    if not isinstance(value["sensitivity_summary"], list) or not all(isinstance(item, str) for item in value["sensitivity_summary"]):
        raise ValueError("malformed sensitivity summary")
    if not isinstance(value["tags"], list) or not all(isinstance(item, str) for item in value["tags"]):
        raise ValueError("malformed tags")
    if not isinstance(value["metadata"], dict) or not all(isinstance(key, str) and isinstance(item, str) for key, item in value["metadata"].items()):
        raise ValueError("malformed metadata")
    entry = ManifestEntry(value["relative_path"], value["classification"], value["reason"], value["size"], value["source_modified_at"], value["source_sha256"], value["exported_sha256"], value["knowledge_layer"], tuple(value["sensitivity_summary"]), value["document_id"], tuple(value["tags"]), tuple(sorted(value["metadata"].items())), value["delta"], value["event_timestamp"], value["export_path"], value["renamed_from"])
    _validate_entry(entry)
    return entry


def _safe_relative(value: str) -> bool:
    path = Path(value)
    return bool(value) and not path.is_absolute() and ".." not in path.parts and value.replace("\\", "/") == value


def _validate_entry(entry: ManifestEntry) -> None:
    if entry.classification not in {"include", "include_redacted", "exclude", "blocked_review", "derived_after_audit"} or entry.delta not in {"new", "unchanged", "changed", "deleted", "renamed"} or not _safe_relative(entry.relative_path):
        raise ValueError("invalid manifest entry semantics")
    for digest in (entry.source_sha256, entry.exported_sha256):
        if digest is not None and not re.fullmatch(r"[0-9a-f]{64}", digest):
            raise ValueError("invalid manifest hash field")
    eligible = entry.classification in {"include", "include_redacted"}
    if eligible:
        if not entry.document_id or not re.fullmatch(r"kb:[a-z0-9-]+:(?:source|event):[a-z0-9-]+:.+", entry.document_id):
            raise ValueError("invalid eligible document ID")
        tag_map = {}
        seen_tags = set()
        for tag in entry.tags:
            try:
                validate_semantic_safe(tag, tag=True)
            except ValueError as error:
                raise ValueError("unsafe manifest tag") from error
            if ":" not in tag:
                raise ValueError("invalid tag")
            prefix, component = tag.split(":", 1)
            if tag in seen_tags or (prefix in tag_map and prefix in {"user", "project", "kind", "scope", "trust", "knowledge"}) or not re.fullmatch(r"[a-z0-9]+(?:-[a-z0-9]+)*", component) and not (prefix == "kind" and component == "graph_projection"):
                raise ValueError("invalid controlled tag")
            seen_tags.add(tag)
            if prefix in {"user", "project", "kind", "scope", "trust", "knowledge"}:
                tag_map[prefix] = component
        if any(tag.startswith(("source:", "harness:")) for tag in entry.tags) or set(("user", "project", "kind", "scope", "trust", "knowledge")) - set(tag_map):
            raise ValueError("invalid required tags")
        if tag_map["kind"] not in {"source", "event"}:
            raise ValueError("invalid controlled tag value")
        metadata = dict(entry.metadata)
        try:
            validate_semantic_safe(metadata)
        except ValueError as error:
            raise ValueError("unsafe manifest metadata") from error
        required_metadata = {"operator": tag_map["user"], "project_slug": tag_map["project"], "source_path": entry.relative_path, "source_sha256": entry.source_sha256 or "", "knowledge_layer": tag_map["knowledge"], "verification_status": tag_map["trust"]}
        if entry.knowledge_layer != tag_map["knowledge"] or any(metadata.get(key) != expected for key, expected in required_metadata.items()) or metadata.get("source_modified_at") != (entry.source_modified_at or ""):
            raise ValueError("inconsistent core metadata")
        if entry.exported_sha256 is not None and metadata.get("exported_sha256") != entry.exported_sha256:
            raise ValueError("inconsistent exported hash metadata")
        if entry.document_id.startswith("kb:{0}:source:{1}:".format(tag_map["project"], tag_map["scope"])):
            if tag_map["kind"] != "source":
                raise ValueError("source ID kind mismatch")
            if entry.document_id != "kb:{0}:source:{1}:{2}".format(tag_map["project"], tag_map["scope"], entry.relative_path):
                raise ValueError("noncanonical source ID")
        elif entry.document_id.startswith("kb:{0}:event:{1}:".format(tag_map["project"], tag_map["scope"])):
            if tag_map["kind"] != "event":
                raise ValueError("event ID kind mismatch")
            if entry.event_timestamp is None:
                raise ValueError("event timestamp required")
            try:
                timestamp = datetime.fromisoformat(entry.event_timestamp)
            except ValueError:
                raise ValueError("invalid event timestamp")
            rome_timestamp = timestamp.astimezone(_ROME)
            if timestamp.tzinfo is None or timestamp.utcoffset() != rome_timestamp.utcoffset() or timestamp.replace(tzinfo=None) != rome_timestamp.replace(tzinfo=None) or not entry.document_id.startswith("kb:{0}:event:{1}:{2}:".format(tag_map["project"], tag_map["scope"], entry.event_timestamp[:16].replace(":", "-"))):
                raise ValueError("noncanonical event ID")
        else:
            raise ValueError("document ID does not bind tags")
        if tag_map["kind"] == "source" and entry.event_timestamp is not None:
            raise ValueError("timeless source cannot have event timestamp")
    elif entry.document_id is not None or entry.export_path is not None:
        raise ValueError("ineligible entry cannot carry ID or export locator")
    if entry.export_path is not None and not _safe_relative(entry.export_path):
        raise ValueError("invalid export locator")
    if entry.classification == "include_redacted" and entry.export_path is None:
        raise ValueError("redacted entry requires staging locator")


def _iso_mtime(info: os.stat_result) -> str:
    return datetime.fromtimestamp(info.st_mtime, tz=ZoneInfo("UTC")).isoformat()


def _slug(value: str) -> str:
    normalized = re.sub(r"[^a-z0-9]+", "-", value.casefold()).strip("-")
    if not normalized:
        raise ValueError("event heading must contain a stable slug")
    return normalized


def _metadata(profile: Mapping[str, Any], path: str, source_hash: Optional[str], exported_hash: Optional[str], mtime: Optional[str], knowledge_layer: str) -> Tuple[Tuple[str, str], ...]:
    operator = profile.get("operator")
    if not isinstance(operator, str) or not operator or operator.casefold() == "unknown":
        raise ValueError("active operator is required")
    values = {
        "operator": _tag_component(operator),
        "project_slug": str(profile["project_slug"]),
        "source_path": path,
        "source_sha256": source_hash or "",
        "source_modified_at": mtime or "",
        "knowledge_layer": knowledge_layer,
        "verification_status": _tag_component(profile.get("trust", "verified")),
        "credential_policy": normalize_credential_policy(profile.get("credential_policy")),
    }
    if exported_hash is not None:
        values["exported_sha256"] = exported_hash
    return tuple(sorted(values.items()))


def _tag_component(value: Any) -> str:
    component = str(value).casefold()
    if not re.fullmatch(r"[a-z0-9]+(?:-[a-z0-9]+)*", component):
        raise ValueError("invalid tag component")
    return component


def _source_tags(profile: Mapping[str, Any], scope: str, layer: str, kind: str = "source") -> Tuple[str, ...]:
    operator = profile.get("operator")
    if not isinstance(operator, str) or not operator or operator.casefold() == "unknown":
        raise ValueError("active operator is required")
    tags = ["kind:" + _tag_component(kind), "scope:" + _tag_component(scope), "trust:" + _tag_component(profile.get("trust", "verified")), "knowledge:" + _tag_component(layer), "user:" + _tag_component(operator), "project:" + _tag_component(profile["project_slug"])]
    for topic in profile.get("topics", ()):
        if not isinstance(topic, str) or not topic.startswith("topic:"):
            raise ValueError("topics must use the topic namespace")
        tags.append("topic:" + _tag_component(topic.split(":", 1)[1]))
    return tuple(sorted(set(tags)))


def _stage_redacted(staging_root: Path, relative_path: str, content: str) -> None:
    """Write only redacted exports below an owned private staging tree."""
    stage = staging_root.absolute()
    _assert_no_staging_symlinks(stage)
    nearest_existing = stage.parent
    while not nearest_existing.exists():
        nearest_existing = nearest_existing.parent
    if nearest_existing.is_symlink():
        raise ValueError("staging path contains a symlink")
    stage.mkdir(mode=0o700, parents=True, exist_ok=True)
    _assert_no_staging_symlinks(stage)
    if stage.is_symlink():
        raise ValueError("staging root must not be a symlink")
    os.chmod(stage, 0o700)
    current = stage
    for part in Path(relative_path).parts[:-1]:
        current = current / part
        current.mkdir(mode=0o700, exist_ok=True)
        if current.is_symlink():
            raise ValueError("staging path contains a symlink")
        os.chmod(current, 0o700)
    destination = stage.joinpath(*Path(relative_path).parts)
    if not _is_relative_to(destination, stage) or destination.is_symlink():
        raise ValueError("staging destination escapes its root")
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(str(destination), flags, 0o600)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
    finally:
        os.chmod(destination, 0o600)


def _assert_no_staging_symlinks(path: Path) -> None:
    current = Path(path.anchor)
    for part in path.parts[1:]:
        current = current / part
        if current.exists() and current.is_symlink() and str(current) not in {"/var", "/tmp"}:
            raise ValueError("staging path contains a symlink")


def _entry_from_scan(root: Path, path: Path, relative: str, profile: Mapping[str, Any],
                     staging_root: Optional[Path], plans: list,
                     credential_sources: Tuple[str, ...]) -> ManifestEntry:
    scope = str(profile.get("scope", "workspace"))
    layer = str(profile.get("knowledge_layer", "concept"))
    try:
        info = path.lstat()
    except FileNotFoundError:
        return ManifestEntry(relative, "blocked_review", "candidate disappeared before preflight", 0, None, None, None, layer, ("candidate_missing",), None, (), (), "new")
    resolved = path.resolve()
    if _has_symlink_ancestor(path, root) or not _is_relative_to(resolved, root):
        return ManifestEntry(relative, "blocked_review", "symlink target escapes configured root", 0, None, None, None, layer, ("symlink_escapes_root",), None, (), (), "new")
    if not stat.S_ISREG(info.st_mode):
        return ManifestEntry(relative, "exclude", "candidate is not a regular text file", info.st_size, _iso_mtime(info), None, None, layer, ("not_regular_file",), None, (), (), "new")
    raw = path.read_bytes()
    source_hash = _sha256(raw)
    mtime = _iso_mtime(info)
    configured_policy = normalize_credential_policy(profile.get("credential_policy"))
    policy = "allow_project_staging" if configured_policy == "allow_project_staging" and relative in credential_sources else "exclude"
    effective_profile = dict(profile)
    effective_profile["credential_policy"] = policy
    scan = scan_text(relative, raw, credential_policy=policy)
    sensitivity = tuple(finding.rule for finding in scan.findings)
    if scan.decision == "blocked":
        classification = "exclude" if scan.findings and scan.findings[0].disposition == "exclude" else "blocked_review"
        reason = "deterministic path exclusion" if classification == "exclude" else "suspicious or unexportable content requires review"
        return ManifestEntry(relative, classification, reason, info.st_size, mtime, source_hash, None, layer, sensitivity, None, (), _metadata(effective_profile, relative, source_hash, None, mtime, layer), "new")
    derived_paths = {str(item).replace("\\", "/") for item in profile.get("derived_after_audit_paths", ())}
    if relative in derived_paths:
        return ManifestEntry(relative, "derived_after_audit", "derived candidate awaits external audit eligibility", info.st_size, mtime, source_hash, None, layer, sensitivity, None, (), _metadata(effective_profile, relative, source_hash, None, mtime, layer), "new")
    document_id = "kb:{0}:source:{1}:{2}".format(profile["project_slug"], scope, relative)
    if scan.decision == "redacted":
        assert scan.exported_text is not None
        exported = scan.exported_text.encode("utf-8")
        exported_hash = _sha256(exported)
        if staging_root is None:
            return ManifestEntry(relative, "blocked_review", "redacted export requires an explicit staging root", info.st_size, mtime, source_hash, None, layer, sensitivity, None, (), _metadata(effective_profile, relative, source_hash, None, mtime, layer), "new")
        plans.append((relative, scan.exported_text))
        return ManifestEntry(relative, "include_redacted", "recognized credential value redacted in staging export", info.st_size, mtime, source_hash, exported_hash, layer, sensitivity, document_id, _source_tags(profile, scope, layer), _metadata(effective_profile, relative, source_hash, exported_hash, mtime, layer), "new", export_path=relative)
    reason = "credential-bearing source allowed by reviewed project policy" if scan.findings else "safe text candidate"
    return ManifestEntry(relative, "include", reason, info.st_size, mtime, source_hash, None, layer, sensitivity, document_id, _source_tags(profile, scope, layer), _metadata(effective_profile, relative, source_hash, None, mtime, layer), "new")


def _event_entries(source_entry: ManifestEntry, text: str, profile: Mapping[str, Any], previous_entries: Tuple[ManifestEntry, ...], scope: str, plans: list) -> Tuple[ManifestEntry, ...]:
    headings = tuple(_EVENT_HEADING.finditer(text))
    result = []
    identities = set()
    for index, heading in enumerate(headings):
        end = headings[index + 1].start() if index + 1 < len(headings) else len(text)
        event_text = text[heading.start():end]
        local = datetime.strptime(heading.group(1), "%Y-%m-%d %H:%M").replace(tzinfo=_ROME)
        timestamp_key = local.strftime("%Y-%m-%dT%H-%M")
        identity = "kb:{0}:event:{1}:{2}:{3}".format(profile["project_slug"], scope, timestamp_key, _slug(heading.group(2)))
        if identity in identities:
            raise ValueError("duplicate logbook event identity")
        identities.add(identity)
        event_hash = _sha256(event_text.encode("utf-8"))
        layer = source_entry.knowledge_layer
        same_time = [entry for entry in previous_entries if entry.document_id and entry.document_id.startswith("kb:{0}:event:".format(profile["project_slug"])) and entry.relative_path == source_entry.relative_path and entry.event_timestamp == local.isoformat()]
        if len(same_time) > 1:
            raise ValueError("ambiguous previous event identity")
        if same_time:
            identity = same_time[0].document_id
        source_identity = _sha256(source_entry.relative_path.encode("utf-8"))[:16]
        export_path = "events/{0}/{1}.md".format(source_identity, _sha256(identity.encode("utf-8")))
        plans.append((export_path, event_text))
        metadata = dict(_metadata(profile, source_entry.relative_path, event_hash, None, source_entry.source_modified_at, layer))
        metadata["credential_policy"] = dict(source_entry.metadata).get("credential_policy", "exclude")
        metadata["container_sha256"] = source_entry.source_sha256 or ""
        result.append(ManifestEntry(source_entry.relative_path, "include", "bounded logbook event", len(event_text.encode("utf-8")), source_entry.source_modified_at, event_hash, None, layer, (), identity, _source_tags(profile, scope, layer, "event"), tuple(sorted(metadata.items())), "new", local.isoformat(), export_path))
    return tuple(result)


def _previous_entries(previous: Optional[Union[Manifest, Mapping[str, Any]]]) -> Tuple[ManifestEntry, ...]:
    if previous is None:
        return ()
    if isinstance(previous, Manifest):
        return previous.entries
    if isinstance(previous, Mapping):
        return Manifest.from_dict(previous).entries
    raise TypeError("previous_manifest must be a Manifest or validated mapping")


def _finalize(entries: Iterable[ManifestEntry], previous: Optional[Union[Manifest, Mapping[str, Any]]]) -> Manifest:
    previous_entries = _previous_entries(previous)
    earlier = {entry.document_id: entry for entry in previous_entries if entry.document_id is not None}
    completed = []
    seen = set()
    for entry in entries:
        if entry.document_id is None:
            completed.append(entry)
            continue
        if entry.document_id in seen:
            raise ValueError("duplicate document ID in manifest")
        seen.add(entry.document_id)
        older = earlier.get(entry.document_id)
        delta = "new" if older is None else ("unchanged" if (older.source_sha256, older.exported_sha256) == (entry.source_sha256, entry.exported_sha256) else "changed")
        if older is None and entry.document_id.startswith("kb:") and ":source:" in entry.document_id:
            matches = [candidate for candidate in previous_entries if candidate.document_id and ":source:" in candidate.document_id and candidate.source_sha256 == entry.source_sha256 and candidate.exported_sha256 == entry.exported_sha256 and candidate.relative_path != entry.relative_path]
            if len(matches) == 1:
                delta = "renamed"
                entry = replace(entry, renamed_from=matches[0].relative_path)
        completed.append(replace(entry, delta=delta))
    deleted = tuple(replace(entry, delta="deleted") for key, entry in sorted(earlier.items()) if key not in seen)
    completed.sort(key=lambda entry: ((entry.document_id or "~"), entry.relative_path, entry.event_timestamp or ""))
    body = Manifest(tuple(completed), deleted, "").as_dict()
    return Manifest(tuple(completed), deleted, body["manifest_sha256"])


def build_manifest(
    root: PathLike,
    candidates: Sequence[PathLike],
    profile: Mapping[str, Any],
    previous_manifest: Optional[Union[Manifest, Mapping[str, Any]]] = None,
    staging_root: Optional[PathLike] = None,
    *,
    operator: Optional[str] = None,
) -> Manifest:
    """Build a sorted dry-run manifest from explicit candidates under *root* only."""
    if not profile.get("project_slug"):
        raise ValueError("profile requires project_slug")
    if not isinstance(operator, str) or not operator or operator.casefold() == "unknown":
        raise ValueError("active operator is required")
    effective_profile = dict(profile)
    effective_profile["operator"] = _tag_component(operator)
    credential_sources = credential_source_paths(effective_profile)
    root_path = Path(os.path.abspath(str(root)))
    root_real = root_path.resolve()
    if not root_real.is_dir():
        raise ValueError("root must be an existing directory")
    stage = Path(staging_root) if staging_root is not None else None
    previous_entries = _previous_entries(previous_manifest)
    normalized = sorted((_relative_candidate(root_path, candidate) for candidate in candidates), key=lambda item: item[1])
    event_paths = {str(item).replace("\\", "/") for item in effective_profile.get("event_paths", ())}
    event_scopes = effective_profile.get("event_scopes", {})
    if len(event_paths) > 1 and (not isinstance(event_scopes, Mapping) or not event_paths.issubset(set(event_scopes))):
        raise ValueError("multiple event paths require event_scopes")
    entries = []
    plans = []
    for path, relative in normalized:
        source_entry = _entry_from_scan(root_real, path, relative, effective_profile, stage, plans, credential_sources)
        if relative in event_paths and source_entry.classification in {"include", "include_redacted"}:
            if source_entry.classification == "include_redacted":
                raise ValueError("logbook events must be safe before event parsing")
            if stage is None:
                raise ValueError("event paths require an explicit staging root")
            scope = str(event_scopes.get(relative, effective_profile.get("scope", "project-logbook"))) if isinstance(event_scopes, Mapping) else str(effective_profile.get("scope", "project-logbook"))
            entries.extend(_event_entries(source_entry, path.read_text(encoding="utf-8"), effective_profile, previous_entries, scope, plans))
        else:
            entries.append(source_entry)
    manifest = _finalize(entries, previous_manifest)
    paths = [path for path, _ in plans]
    if len(paths) != len(set(paths)):
        raise ValueError("staging export path collision")
    Manifest.from_dict(manifest.as_dict())
    if stage is not None:
        for export_path, content in sorted(plans):
            _stage_redacted(stage, export_path, content)
    return manifest


def write_manifest(path: PathLike, manifest: Manifest) -> None:
    """Atomically persist a source-content-free, private manifest JSON document."""
    payload = manifest.as_dict()
    if Manifest.from_dict(payload) != manifest:
        raise ValueError("manifest is not self-consistent")
    destination = Path(path).absolute()
    destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(destination.parent, 0o700)
    descriptor, temporary_name = tempfile.mkstemp(prefix=".{0}.".format(destination.name), dir=str(destination.parent))
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, 0o600)
        os.replace(str(temporary), str(destination))
        os.chmod(destination, 0o600)
    except BaseException:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass
        raise


def read_manifest(path: PathLike) -> Manifest:
    """Load and hash-validate a manifest without accepting arbitrary JSON shapes."""
    with Path(path).open("r", encoding="utf-8") as handle:
        return Manifest.from_dict(json.load(handle))


def validate_manifest_files(manifest: Manifest, source_root: PathLike, staging_root: PathLike) -> None:
    """Verify local source/staging bytes before a later retain operation consumes them."""
    Manifest.from_dict(manifest.as_dict())
    source = Path(source_root).resolve()
    stage = Path(staging_root).absolute()
    _assert_no_staging_symlinks(stage)
    if stage.exists() and stage.is_symlink():
        raise ValueError("staging root must not be a symlink")
    if stage.exists():
        for directory, names, files in os.walk(stage, followlinks=False):
            for name in names + files:
                if (Path(directory) / name).is_symlink():
                    raise ValueError("staging tree contains a symlink")
    for entry in manifest.entries:
        _validate_entry(entry)
        if entry.classification not in {"include", "include_redacted"}:
            if entry.document_id is not None or entry.export_path is not None:
                raise ValueError("ineligible manifest entry")
            continue
        candidate = source.joinpath(*Path(entry.relative_path).parts)
        if _has_symlink_ancestor(candidate, source) or not _is_relative_to(candidate.resolve(), source):
            raise ValueError("source path escapes root")
        if not candidate.is_file():
            raise ValueError("source file missing")
        if entry.document_id and ":event:" not in entry.document_id:
            if _sha256(candidate.read_bytes()) != entry.source_sha256:
                raise ValueError("source hash mismatch")
        elif entry.document_id and ":event:" in entry.document_id:
            container_hash = dict(entry.metadata).get("container_sha256")
            if not re.fullmatch(r"[0-9a-f]{64}", container_hash or "") or _sha256(candidate.read_bytes()) != container_hash:
                raise ValueError("event container hash mismatch")
        if entry.export_path is not None:
            staged = stage.joinpath(*Path(entry.export_path).parts)
            if staged.is_symlink() or not _is_relative_to(staged.absolute(), stage) or not staged.is_file():
                raise ValueError("staged locator invalid")
            expected = entry.exported_sha256 or entry.source_sha256
            if _sha256(staged.read_bytes()) != expected:
                raise ValueError("staged hash mismatch")
