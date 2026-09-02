"""Create bounded, provenance-preserving capsules from an audited Graphify sidecar.

The sidecar is a local derived artifact.  This module deliberately accepts only that
small JSON projection: it never reads Graphify AST caches, Cypher or HTML output.
"""

from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime
from pathlib import Path
from pathlib import PurePosixPath
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple, Union


PathLike = Union[str, Path]
_GENERATOR = "graphify-sidecar-capsules"
_VERSION = "1"
_DEFAULT_MAX_EDGES = 12
_TAG = re.compile(r"[a-z0-9]+(?:-[a-z0-9]+)*$")


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _tag(value: Any, name: str) -> str:
    if not isinstance(value, str):
        raise ValueError("invalid " + name)
    normalized = value.casefold()
    if not _TAG.fullmatch(normalized):
        raise ValueError("invalid " + name)
    return normalized


def _read_sidecar(path: PathLike, expected_sha256: Optional[str]) -> Tuple[Mapping[str, Any], str]:
    raw = Path(path).read_bytes()
    actual = _sha256(raw)
    if expected_sha256 is not None:
        if not isinstance(expected_sha256, str) or not re.fullmatch(r"[0-9a-f]{64}", expected_sha256):
            raise ValueError("sidecar_sha256 must be a lowercase SHA-256")
        if expected_sha256 != actual:
            raise ValueError("sidecar_sha256 does not match sidecar bytes")
    try:
        decoded = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("malformed sidecar JSON") from exc
    if not isinstance(decoded, dict):
        raise ValueError("malformed sidecar root")
    return decoded, actual


def _safe_prefix(value: Any, name: str) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError(name + " must contain non-empty relative prefixes")
    normalized = value.replace("\\", "/")
    path = PurePosixPath(normalized)
    if path.is_absolute() or ".." in path.parts or normalized.startswith("/") or re.match(r"^[A-Za-z]:", normalized):
        raise ValueError(name + " contains unsafe prefix")
    text = path.as_posix().rstrip("/")
    if not text or text == ".":
        raise ValueError(name + " contains unsafe prefix")
    return text + "/"


def _policy(profile: Mapping[str, Any], explicit_hash: Optional[str]) -> Tuple[Mapping[str, Any], str, str, str, Tuple[str, ...], Tuple[str, ...], Tuple[str, ...], str]:
    policy = profile.get("graph_policy")
    if not isinstance(policy, Mapping) or policy.get("enabled") is not True:
        raise ValueError("profile graph_policy.enabled must be true")
    scope = _tag(policy.get("scope"), "graph_policy.scope")
    coverage = policy.get("coverage_note")
    if not isinstance(coverage, str) or not coverage.strip():
        raise ValueError("graph_policy.coverage_note is required")
    included_raw = policy.get("included_path_prefixes")
    excluded_raw = policy.get("excluded_path_prefixes", ())
    url_types_raw = policy.get("url_node_types", ())
    if not isinstance(included_raw, (list, tuple)) or not included_raw:
        raise ValueError("graph_policy.included_path_prefixes must be a non-empty list")
    if not isinstance(excluded_raw, (list, tuple)):
        raise ValueError("graph_policy.excluded_path_prefixes must be a list")
    if not isinstance(url_types_raw, (list, tuple)):
        raise ValueError("graph_policy.url_node_types must be a list")
    included = tuple(sorted(set(_safe_prefix(item, "included_path_prefixes") for item in included_raw)))
    excluded = tuple(sorted(set(_safe_prefix(item, "excluded_path_prefixes") for item in excluded_raw)))
    url_types = tuple(_tag(item, "graph_policy.url_node_types") for item in url_types_raw)
    if len(url_types) != len(set(url_types)):
        raise ValueError("graph_policy.url_node_types must be distinct")
    projection_slug = _tag(policy.get("projection_slug", scope), "graph_policy.projection_slug")
    declared = policy.get("sidecar_sha256")
    hashes = [value for value in (declared, explicit_hash) if value is not None]
    if not hashes:
        raise ValueError("sidecar_sha256 is required to bind the audit to exact bytes")
    for value in hashes:
        if not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{64}", value):
            raise ValueError("sidecar_sha256 must be a lowercase SHA-256")
    if len(hashes) == 2 and hashes[0] != hashes[1]:
        raise ValueError("conflicting sidecar_sha256 declarations")
    return policy, hashes[0], scope, coverage, included, excluded, url_types, projection_slug


def _validate_node_path(node: Mapping[str, Any], index: int, included: Sequence[str], excluded: Sequence[str], url_types: Sequence[str]) -> None:
    if "path" not in node or node["path"] is None:
        return
    value = node["path"]
    if not isinstance(value, str) or not value:
        raise ValueError("node[%d] has invalid path" % index)
    normalized_type = node["type"].casefold()
    if normalized_type in url_types and value.startswith("/"):
        if value.startswith("//") or "\\" in value or any(ord(character) < 32 or ord(character) == 127 for character in value):
            raise ValueError("node[%d] has an ambiguous URL locator" % index)
        return  # Profile-declared URL locator, not a filesystem path.
    normalized = value.replace("\\", "/")
    path = PurePosixPath(normalized)
    if path.is_absolute() or ".." in path.parts or normalized.startswith("/") or re.match(r"^[A-Za-z]:", normalized):
        raise ValueError("node[%d] path is not a safe relative repository path" % index)
    text = path.as_posix()
    if any(text.startswith(prefix) for prefix in excluded):
        raise ValueError("node[%d] path is excluded by graph policy" % index)
    if not any(text.startswith(prefix) for prefix in included):
        raise ValueError("node[%d] path is outside graph policy" % index)


def _validate_sidecar(data: Mapping[str, Any], included: Sequence[str], excluded: Sequence[str], url_types: Sequence[str]) -> Dict[str, Mapping[str, Any]]:
    metadata = data.get("metadata")
    nodes = data.get("nodes")
    edges = data.get("edges")
    if not isinstance(metadata, Mapping) or not isinstance(metadata.get("generated_at"), str) or not metadata["generated_at"]:
        raise ValueError("sidecar metadata.generated_at is required")
    try:
        generated = datetime.fromisoformat(metadata["generated_at"])
    except ValueError as exc:
        raise ValueError("sidecar metadata.generated_at must be ISO-8601") from exc
    if generated.tzinfo is None or generated.utcoffset() is None:
        raise ValueError("sidecar metadata.generated_at must carry an offset")
    if not isinstance(nodes, list) or not isinstance(edges, list):
        raise ValueError("sidecar nodes and edges must be lists")
    if not nodes or not edges:
        raise ValueError("sidecar nodes and edges must be non-empty")
    node_index: Dict[str, Mapping[str, Any]] = {}
    for index, node in enumerate(nodes):
        if not isinstance(node, Mapping):
            raise ValueError("node[%d] must be an object" % index)
        for field in ("id", "type", "label"):
            if not isinstance(node.get(field), str) or not node[field]:
                raise ValueError("node[%d] missing valid %s" % (index, field))
        if node["id"] in node_index:
            raise ValueError("duplicate node ID: " + node["id"])
        _validate_node_path(node, index, included, excluded, url_types)
        node_index[node["id"]] = node
    seen_edges = set()
    for index, edge in enumerate(edges):
        if not isinstance(edge, Mapping):
            raise ValueError("edge[%d] must be an object" % index)
        for field in ("source", "target", "type", "evidence", "confidence"):
            if not isinstance(edge.get(field), str) or not edge[field]:
                raise ValueError("edge[%d] missing valid %s" % (index, field))
        for endpoint in ("source", "target"):
            if edge[endpoint] not in node_index:
                raise ValueError("edge[%d] references unknown node: %s" % (index, edge[endpoint]))
        identity = tuple(edge[field] for field in ("source", "target", "type", "evidence", "confidence"))
        if identity in seen_edges:
            raise ValueError("duplicate edge required tuple")
        seen_edges.add(identity)
    return node_index


def _subject(edge: Mapping[str, Any], nodes: Mapping[str, Mapping[str, Any]]) -> str:
    """Prefer useful centres, but retain future schema-valid relations generically."""
    endpoints = (edge["source"], edge["target"])
    for preferred in ("route", "entity", "wiki"):
        for endpoint in endpoints:
            node = nodes[endpoint]
            if node["type"] == preferred or endpoint.startswith(preferred + ":"):
                return endpoint
    return edge["source"]


def _subject_slug(subject: str) -> str:
    base = re.sub(r"[^a-z0-9]+", "-", subject.casefold()).strip("-") or "relation"
    digest = hashlib.sha256(subject.encode("utf-8")).hexdigest()[:10]
    return base[:72].rstrip("-") + "-" + digest


def _edge_sort_key(edge: Mapping[str, Any]) -> Tuple[str, str, str, str, str]:
    return (edge["type"], edge["source"], edge["target"], edge["evidence"], edge["confidence"])


def _edge_line(edge: Mapping[str, Any]) -> str:
    # Only explicit schema fields are serialized; benign future metadata is ignored.
    return "\n".join((
        "- type: " + edge["type"],
        "  source: " + edge["source"],
        "  target: " + edge["target"],
        "  evidence: " + edge["evidence"],
        "  confidence: " + edge["confidence"],
    ))


def _content(subject: str, edges: Sequence[Mapping[str, Any]], part: Optional[int], parts: int, coverage_note: str) -> str:
    heading = "# Audited Graphify projection: " + subject
    if parts > 1:
        heading += " (part %d of %d)" % (part, parts)
    return "\n".join((
        heading,
        "",
        "This is a bounded, derived projection of audited Graphify sidecar relationships.",
        "Coverage: " + coverage_note,
        "The graph is derived and subordinate to maintained wiki, live code, router and runtime verification.",
        "",
        "## Relationships",
        *(_edge_line(edge) for edge in edges),
        "",
    ))


def build_graph_capsules(
    sidecar_path: PathLike,
    profile: Mapping[str, Any],
    *,
    audit_status: str,
    sidecar_sha256: Optional[str] = None,
    max_edges: Optional[int] = None,
) -> List[Dict[str, Any]]:
    """Return retain-ready graph records after the caller's exact passed audit gate."""
    if audit_status != "passed":
        raise ValueError("audit_status must be exactly 'passed'")
    if not isinstance(profile, Mapping):
        raise ValueError("profile must be a mapping")
    policy, expected, scope, coverage_note, included, excluded, url_types, projection_slug = _policy(profile, sidecar_sha256)
    project = _tag(profile.get("project_slug"), "project_slug")
    operator = _tag(profile.get("operator"), "operator")
    data, source_hash = _read_sidecar(sidecar_path, expected)
    nodes = _validate_sidecar(data, included, excluded, url_types)
    selected_limit = max_edges if max_edges is not None else policy.get("max_edges", _DEFAULT_MAX_EDGES)
    if isinstance(selected_limit, bool) or not isinstance(selected_limit, int) or selected_limit <= 0:
        raise ValueError("max_edges must be a positive integer")
    topics = []
    raw_topics = profile.get("topics", ())
    if not isinstance(raw_topics, (list, tuple)):
        raise ValueError("topics must be a list or tuple")
    for topic in raw_topics:  # flexible, but never silently fabricate a tag.
        if not isinstance(topic, str) or not topic.startswith("topic:"):
            raise ValueError("topics must use the topic namespace")
        topics.append("topic:" + _tag(topic.split(":", 1)[1], "topic"))

    grouped: Dict[str, List[Mapping[str, Any]]] = {}
    for edge in data["edges"]:
        grouped.setdefault(_subject(edge, nodes), []).append(edge)
    capsules: List[Dict[str, Any]] = []
    generated_at = data["metadata"]["generated_at"]
    for subject in sorted(grouped):
        edges = sorted(grouped[subject], key=_edge_sort_key)
        parts = [edges[index:index + selected_limit] for index in range(0, len(edges), selected_limit)]
        identifier = "kb:%s:graph:%s:%s" % (project, projection_slug, _subject_slug(subject))
        for index, chunk in enumerate(parts, 1):
            document_id = identifier if index == 1 else identifier + ":part-%d" % index
            tags = tuple(sorted({
                "user:" + operator, "project:" + project, "kind:graph_projection",
                "scope:" + scope, "trust:derived", "knowledge:component", *topics,
            }))
            metadata = {
                "operator": operator,
                "project_slug": project,
                "source_path": str(Path(sidecar_path)),
                "source_sha256": source_hash,
                "sidecar_sha256": source_hash,
                "sidecar_generated_at": generated_at,
                "knowledge_layer": "component",
                "verification_status": "derived",
                "generator": _GENERATOR,
                "generator_version": _VERSION,
                "coverage": coverage_note,
                "projection_slug": projection_slug,
                "subject_node_id": subject,
            }
            capsules.append({
                "document_id": document_id,
                "tags": tags,
                "metadata": metadata,
                "content": _content(subject, chunk, index if len(parts) > 1 else None, len(parts), coverage_note),
                "event_timestamp": None,
            })
    return capsules


def graph_capsule_inventory(
    capsules: Sequence[Mapping[str, Any]],
    *,
    previous_document_ids: Sequence[str] = (),
) -> Dict[str, Any]:
    """Expose deterministic expected IDs and stale proposals without deleting."""
    if not isinstance(capsules, (list, tuple)) or not all(isinstance(item, Mapping) for item in capsules):
        raise ValueError("capsules must be a list of mappings")
    expected = [item.get("document_id") for item in capsules]
    if not expected or not all(isinstance(item, str) and item for item in expected):
        raise ValueError("capsules require document IDs")
    if len(expected) != len(set(expected)):
        raise ValueError("capsule document IDs must be unique")
    if not isinstance(previous_document_ids, (list, tuple)) or not all(isinstance(item, str) and item for item in previous_document_ids):
        raise ValueError("previous document IDs must be strings")
    if len(previous_document_ids) != len(set(previous_document_ids)):
        raise ValueError("previous document IDs must be unique")
    expected_ids = sorted(expected)
    stale_ids = sorted(set(previous_document_ids) - set(expected_ids))
    return {
        "expected_document_ids": expected_ids,
        "stale_document_ids": stale_ids,
        "stale_id_policy": "explicit_deletion_approval_required",
    }
