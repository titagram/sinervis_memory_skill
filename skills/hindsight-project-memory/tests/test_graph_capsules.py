"""Behavioral tests for bounded, audited Graphify capsules."""

from __future__ import annotations

import copy
import hashlib
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


SKILL_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SKILL_ROOT / "scripts"))

from project_memory import graph_capsules  # noqa: E402
from project_memory.graph_capsules import build_graph_capsules  # noqa: E402


class GraphCapsulesTests(unittest.TestCase):
    def setUp(self):
        self.fixture = Path(__file__).parent / "fixtures" / "sidecar.json"
        self.profile = {
            "operator": "alice",
            "project_slug": "acme-portal",
            "topics": ["topic:architecture"],
            "graph_policy": {
                "enabled": True, "max_edges": 2,
                "sidecar_sha256": hashlib.sha256(self.fixture.read_bytes()).hexdigest(),
                "scope": "webapp",
                "coverage_note": "The Acme Portal webapp graph excludes the mobile client.",
                "included_path_prefixes": ["portal/", "wiki/"],
                "excluded_path_prefixes": ["portal-mobile/"],
                "url_node_types": ["route"],
            },
        }

    def test_groups_audited_relations_with_exact_provenance_and_webapp_coverage(self):
        capsules = build_graph_capsules(self.fixture, self.profile, audit_status="passed")

        self.assertGreaterEqual(len(capsules), 4)
        flattened = "\n".join(capsule["content"] for capsule in capsules)
        for edge_type in ("references", "handled_by", "configured_by", "entity_listener", "synchronizes"):
            self.assertIn("type: " + edge_type, flattened)
        self.assertIn("source: route:employee_list", flattened)
        self.assertIn("target: file:portal/src/Controller/EmployeeController.php", flattened)
        self.assertIn("evidence: EmployeeController::list", flattened)
        self.assertIn("The Acme Portal webapp graph excludes the mobile client.", flattened)
        for capsule in capsules:
            self.assertIn("kind:graph_projection", capsule["tags"])
            self.assertIn("scope:webapp", capsule["tags"])
            self.assertIn("trust:derived", capsule["tags"])
            self.assertIn("knowledge:component", capsule["tags"])
            self.assertIn("user:alice", capsule["tags"])
            self.assertIn("project:acme-portal", capsule["tags"])
            self.assertEqual("graphify-sidecar-capsules", capsule["metadata"]["generator"])
            self.assertEqual("derived", capsule["metadata"]["verification_status"])
            self.assertEqual("acme-portal", capsule["metadata"]["project_slug"])
            self.assertEqual("2026-09-01T10:00:00+02:00", capsule["metadata"]["sidecar_generated_at"])
            self.assertEqual(64, len(capsule["metadata"]["source_sha256"]))
            self.assertEqual("webapp", capsule["metadata"]["projection_slug"])
            self.assertIn(":graph:webapp:", capsule["document_id"])

    def test_is_deterministic_and_splits_only_when_a_subject_exceeds_max_edges(self):
        first = build_graph_capsules(self.fixture, self.profile, audit_status="passed")
        second = build_graph_capsules(self.fixture, self.profile, audit_status="passed")
        first_hash = hashlib.sha256(json.dumps(first, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        second_hash = hashlib.sha256(json.dumps(second, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        self.assertEqual(first_hash, second_hash)
        self.assertTrue(any(":part-" in capsule["document_id"] for capsule in first))
        self.assertFalse(any(capsule["document_id"].endswith(":part-1") for capsule in first))

    def test_first_capsule_id_survives_one_to_many_and_many_to_one_transitions(self):
        one_part = build_graph_capsules(self.fixture, self.profile, audit_status="passed", max_edges=100)
        many_parts = build_graph_capsules(self.fixture, self.profile, audit_status="passed", max_edges=1)
        one_ids = {capsule["document_id"] for capsule in one_part}
        many_ids = {capsule["document_id"] for capsule in many_parts}

        self.assertTrue(one_ids.issubset(many_ids))
        self.assertFalse(any(identifier.endswith(":part-1") for identifier in many_ids))
        self.assertTrue(any(identifier.endswith(":part-2") for identifier in many_ids))

        collapsed = build_graph_capsules(self.fixture, self.profile, audit_status="passed", max_edges=100)
        self.assertEqual(one_ids, {capsule["document_id"] for capsule in collapsed})

    def test_inventory_exposes_expected_and_stale_ids_without_deleting(self):
        self.assertTrue(hasattr(graph_capsules, "graph_capsule_inventory"))
        capsules = build_graph_capsules(self.fixture, self.profile, audit_status="passed", max_edges=100)
        expected = sorted(capsule["document_id"] for capsule in capsules)
        stale = "kb:acme-portal:graph:webapp:old-subject:part-2"

        inventory = graph_capsules.graph_capsule_inventory(capsules, previous_document_ids=expected + [stale])

        self.assertEqual(expected, inventory["expected_document_ids"])
        self.assertEqual([stale], inventory["stale_document_ids"])
        self.assertEqual("explicit_deletion_approval_required", inventory["stale_id_policy"])

    def test_graph_capsules_cli_injects_registry_operator_and_writes_inventory(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "project"
            root.mkdir()
            profile = copy.deepcopy(self.profile)
            profile.pop("operator")
            profile["bank_id"] = "acme::portal"
            registry = Path(directory) / "registry.json"
            registry.write_text(json.dumps({
                "schema_version": 1,
                "operator": {"nickname": "alice"},
                "projects": {str(root): profile},
            }), encoding="utf-8")
            output = Path(directory) / "capsules.json"
            inventory = Path(directory) / "inventory.json"
            prior = Path(directory) / "prior.json"
            stale = "kb:acme-portal:graph:webapp:old:part-2"
            prior.write_text(json.dumps({"expected_document_ids": [stale]}), encoding="utf-8")

            completed = subprocess.run([
                sys.executable, str(SKILL_ROOT / "scripts" / "project_memory.py"),
                "graph-capsules", "build",
                "--registry", str(registry), "--root", str(root),
                "--sidecar", str(self.fixture), "--audit-status", "passed",
                "--sidecar-sha256", hashlib.sha256(self.fixture.read_bytes()).hexdigest(),
                "--output", str(output), "--inventory-output", str(inventory),
                "--previous-inventory", str(prior),
            ], capture_output=True, text=True, check=False)

            self.assertEqual(0, completed.returncode, completed.stderr)
            capsules = json.loads(output.read_text(encoding="utf-8"))
            generated_inventory = json.loads(inventory.read_text(encoding="utf-8"))
            self.assertTrue(all("user:alice" in item["tags"] for item in capsules))
            self.assertFalse(any(item["document_id"].endswith(":part-1") for item in capsules))
            self.assertEqual([stale], generated_inventory["stale_document_ids"])

    def test_refuses_unaudited_or_tampered_or_malformed_sidecars_before_output(self):
        with self.assertRaisesRegex(ValueError, "audit_status"):
            build_graph_capsules(self.fixture, self.profile, audit_status="warning")
        with tempfile.TemporaryDirectory() as directory:
            sidecar = Path(directory) / "sidecar.json"
            sidecar.write_bytes(self.fixture.read_bytes() + b"\n")
            with self.assertRaisesRegex(ValueError, "sha256"):
                build_graph_capsules(sidecar, self.profile, audit_status="passed", sidecar_sha256="0" * 64)
            malformed = json.loads(self.fixture.read_text(encoding="utf-8"))
            malformed["edges"][0].pop("evidence")
            sidecar.write_text(json.dumps(malformed), encoding="utf-8")
            malformed_profile = copy.deepcopy(self.profile)
            malformed_profile["graph_policy"]["sidecar_sha256"] = hashlib.sha256(sidecar.read_bytes()).hexdigest()
            with self.assertRaisesRegex(ValueError, "evidence"):
                build_graph_capsules(sidecar, malformed_profile, audit_status="passed")

    def test_uses_profile_max_edges_and_rejects_unsafe_policy_values(self):
        compact = build_graph_capsules(self.fixture, self.profile, audit_status="passed", max_edges=1)
        self.assertGreater(len(compact), 4)
        invalid = copy.deepcopy(self.profile)
        invalid["graph_policy"]["max_edges"] = 0
        with self.assertRaisesRegex(ValueError, "max_edges"):
            build_graph_capsules(self.fixture, invalid, audit_status="passed")

    def test_requires_audit_bound_hash_and_rejects_conflicting_declarations(self):
        no_hash = copy.deepcopy(self.profile)
        no_hash["graph_policy"].pop("sidecar_sha256")
        with self.assertRaisesRegex(ValueError, "sidecar_sha256"):
            build_graph_capsules(self.fixture, no_hash, audit_status="passed")
        actual = hashlib.sha256(self.fixture.read_bytes()).hexdigest()
        self.assertTrue(build_graph_capsules(self.fixture, self.profile, audit_status="passed", sidecar_sha256=actual))
        with self.assertRaisesRegex(ValueError, "conflict"):
            build_graph_capsules(self.fixture, self.profile, audit_status="passed", sidecar_sha256="0" * 64)

    def test_rejects_out_of_policy_paths_duplicate_edges_and_empty_graphs_before_output(self):
        base = json.loads(self.fixture.read_text(encoding="utf-8"))
        with tempfile.TemporaryDirectory() as directory:
            sidecar = Path(directory) / "sidecar.json"
            mobile = copy.deepcopy(base)
            mobile["nodes"][0]["path"] = "portal-mobile/src/screens/Home.tsx"
            sidecar.write_text(json.dumps(mobile), encoding="utf-8")
            profile = copy.deepcopy(self.profile)
            profile["graph_policy"]["sidecar_sha256"] = hashlib.sha256(sidecar.read_bytes()).hexdigest()
            with self.assertRaisesRegex(ValueError, "excluded"):
                build_graph_capsules(sidecar, profile, audit_status="passed")
            duplicate = copy.deepcopy(base)
            duplicate["edges"].append(copy.deepcopy(duplicate["edges"][0]))
            sidecar.write_text(json.dumps(duplicate), encoding="utf-8")
            profile["graph_policy"]["sidecar_sha256"] = hashlib.sha256(sidecar.read_bytes()).hexdigest()
            with self.assertRaisesRegex(ValueError, "duplicate edge"):
                build_graph_capsules(sidecar, profile, audit_status="passed")
            empty = copy.deepcopy(base)
            empty["nodes"] = []
            empty["edges"] = []
            sidecar.write_text(json.dumps(empty), encoding="utf-8")
            profile["graph_policy"]["sidecar_sha256"] = hashlib.sha256(sidecar.read_bytes()).hexdigest()
            with self.assertRaisesRegex(ValueError, "non-empty"):
                build_graph_capsules(sidecar, profile, audit_status="passed")

    def test_uses_project_neutral_scope_coverage_and_accepts_future_in_policy_types(self):
        generic = copy.deepcopy(self.profile)
        generic["project_slug"] = "other-product"
        generic["graph_policy"].update({
            "scope": "backend", "coverage_note": "Only the backend sources were indexed.",
            "included_path_prefixes": ["backend/", "docs/"], "excluded_path_prefixes": ["mobile/"],
        })
        source = json.loads(self.fixture.read_text(encoding="utf-8"))
        for node in source["nodes"]:
            if node.get("path") and not (node["type"] == "route" and node["path"].startswith("/")):
                node["path"] = node["path"].replace("portal/", "backend/").replace("wiki/", "docs/")
        generic["graph_policy"]["sidecar_sha256"] = hashlib.sha256(json.dumps(source).encode()).hexdigest()
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "future.json"
            path.write_text(json.dumps(source), encoding="utf-8")
            generic["graph_policy"]["sidecar_sha256"] = hashlib.sha256(path.read_bytes()).hexdigest()
            capsules = build_graph_capsules(path, generic, audit_status="passed")
        self.assertTrue(capsules)
        self.assertTrue(all("scope:backend" in capsule["tags"] for capsule in capsules))
        self.assertIn("Only the backend sources were indexed.", capsules[0]["content"])

    def test_allows_url_locators_only_for_profile_declared_node_types(self):
        source = json.loads(self.fixture.read_text(encoding="utf-8"))
        source["nodes"][1]["type"] = "endpoint"
        source["nodes"][1]["path"] = "/api/items"
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "endpoint.json"
            path.write_text(json.dumps(source), encoding="utf-8")
            profile = copy.deepcopy(self.profile)
            profile["graph_policy"]["sidecar_sha256"] = hashlib.sha256(path.read_bytes()).hexdigest()
            with self.assertRaisesRegex(ValueError, "safe relative"):
                build_graph_capsules(path, profile, audit_status="passed")
            profile["graph_policy"]["url_node_types"].append("endpoint")
            self.assertTrue(build_graph_capsules(path, profile, audit_status="passed"))

    def test_projection_slug_prevents_stable_id_collisions_between_projections(self):
        backend = copy.deepcopy(self.profile)
        backend["graph_policy"].update({"scope": "backend", "projection_slug": "backend"})
        admin = copy.deepcopy(self.profile)
        admin["graph_policy"].update({"scope": "admin", "projection_slug": "admin"})
        alternate = copy.deepcopy(self.profile)
        alternate["graph_policy"].update({"scope": "backend", "projection_slug": "backend-alt"})
        backend_ids = {capsule["document_id"] for capsule in build_graph_capsules(self.fixture, backend, audit_status="passed")}
        admin_ids = {capsule["document_id"] for capsule in build_graph_capsules(self.fixture, admin, audit_status="passed")}
        alternate_ids = {capsule["document_id"] for capsule in build_graph_capsules(self.fixture, alternate, audit_status="passed")}
        self.assertFalse(backend_ids & admin_ids)
        self.assertFalse(backend_ids & alternate_ids)


if __name__ == "__main__":
    unittest.main()
