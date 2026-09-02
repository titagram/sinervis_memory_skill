"""Tests for the project-memory registry boundary."""

import json
import importlib.util
import os
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
from pathlib import Path


SCRIPTS_ROOT = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPTS_ROOT))

from project_memory.registry import (  # noqa: E402
    read_registry,
    register_project,
    resolve_project,
    write_registry,
)


CLI = SCRIPTS_ROOT / "project_memory.py"

AWS_ACCESS_KEY_CANARY = "AKIA" + "IOSFODNN7EXAMPLE"
GITHUB_TOKEN_CANARY = "ghp_" + "abcdefghijklmnopqrstuvwxyz0123456789"
JWT_CANARY = "eyJ" + "hbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signaturevalue"
OPENAI_TOKEN_CANARY = "sk-" + "abcdefghijklmnopqrstuvwxyz0123456789"


class ProjectMemoryCliTests(unittest.TestCase):
    """Black-box contracts for the project-neutral command-line interface."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.registry_path = self.root / "state" / "registry.json"
        self.audit_path = self.root / "state" / "audit.jsonl"

    def tearDown(self):
        self.temp.cleanup()

    def registry(self, operator=None, projects=None):
        write_registry(self.registry_path, {
            "schema_version": 1,
            "operator": operator,
            "projects": projects or {},
        })

    def invoke(self, *arguments, input_text=None):
        return subprocess.run(
            [sys.executable, str(CLI), *arguments],
            cwd=str(self.root),
            input=input_text,
            text=True,
            capture_output=True,
            check=False,
        )

    def result(self, completed):
        self.assertTrue(completed.stdout, completed.stderr)
        return json.loads(completed.stdout)

    def write_profile(self, profile, name="profile.json"):
        path = self.root / name
        path.write_text(json.dumps(profile), encoding="utf-8")
        return path

    def approved_profile(self, root, bank_id="owner::product", product_identity="owner-product",
                         relationship="new_product"):
        owner_slug, project_slug = bank_id.split("::", 1)
        return {
            "root": str(Path(root).resolve()), "display_name": "Product", "owner_slug": owner_slug,
            "project_slug": project_slug, "bank_id": bank_id,
            "product_identity": product_identity, "relationship": relationship, "reviewed": True,
            "source_policy": {"authoritative_sources": ["README.md"], "exclusions": [".env"]},
            "knowledge_layers": ["source", "event", "dossier"],
            "graph_policy": {"enabled": False, "scope": "repository"},
        }

    def approved_portal_profile(self, root, relationship="new_product"):
        return {
            "root": str(Path(root).resolve()), "display_name": "Acme Portal", "owner_slug": "acme",
            "project_slug": "acme-portal", "bank_id": "acme::portal",
            "product_identity": "acme-portal", "relationship": relationship, "reviewed": True,
            "credential_policy": "allow_project_staging",
            "source_policy": {"credential_sources": [
                "portal/.env", "portal/config/jwt/private.pem", "portal/config/jwt/public.pem",
            ]},
        }

    def test_profile_accepts_exact_credential_policies_and_rejects_unknown_without_closing_metadata(self):
        for policy in ("exclude", "allow_project_staging"):
            with self.subTest(policy=policy):
                self.registry({"nickname": "ada"})
                root = self.root / policy
                profile = self.approved_profile(root, "owner::{0}".format(policy.replace("_", "-")),
                                                "owner-" + policy.replace("_", "-"))
                profile["credential_policy"] = policy
                if policy == "allow_project_staging":
                    profile["source_policy"]["credential_sources"] = ["README.md"]
                profile["future_metadata"] = {"retrieval_hint": "prefer-complete-memory", "enabled": True}
                completed = self.invoke(
                    "project", "register", "--confirm", "--profile", str(self.write_profile(profile, policy + ".json")),
                    "--registry", str(self.registry_path), "--audit", str(self.audit_path),
                )
                self.assertEqual(0, completed.returncode, completed.stderr)
                stored = read_registry(self.registry_path)["projects"][str(root.resolve())]
                self.assertEqual(policy, stored["credential_policy"])
                self.assertEqual(profile["future_metadata"], stored["future_metadata"])

        self.registry({"nickname": "ada"})
        profile = self.approved_profile(self.root / "unknown")
        profile["credential_policy"] = "allow_anywhere"
        before = read_registry(self.registry_path)
        completed = self.invoke(
            "project", "register", "--confirm", "--profile", str(self.write_profile(profile, "unknown.json")),
            "--registry", str(self.registry_path), "--audit", str(self.audit_path),
        )
        self.assertEqual(2, completed.returncode)
        self.assertEqual("invalid_profile", self.result(completed)["status"])
        self.assertEqual(before, read_registry(self.registry_path))

    def test_profile_show_uses_explicit_registry_path(self):
        self.registry({"nickname": "ada", "set_at": "2026-09-01T00:00:00+02:00"})
        completed = self.invoke("profile", "show", "--registry", str(self.registry_path))
        self.assertEqual(0, completed.returncode, completed.stderr)
        self.assertEqual("ada", self.result(completed)["operator"]["nickname"])

    def test_operator_set_updates_current_operator_and_appends_audit_without_rewriting_history(self):
        project_root = self.root / "product"
        self.registry({"nickname": "old", "set_at": "2026-08-31T00:00:00+02:00"}, {
            str(project_root): {"bank_id": "owner::product", "registered_by": "old"}
        })
        completed = self.invoke(
            "operator", "set", "new-operator", "--registry", str(self.registry_path),
            "--audit", str(self.audit_path), "--at", "2026-09-01T00:00:00+02:00",
        )
        self.assertEqual(0, completed.returncode, completed.stderr)
        stored = read_registry(self.registry_path)
        self.assertEqual("new-operator", stored["operator"]["nickname"])
        self.assertEqual("old", stored["projects"][str(project_root)]["registered_by"])
        event = json.loads(self.audit_path.read_text(encoding="utf-8").splitlines()[0])
        self.assertEqual("operator_set", event["action"])
        self.assertEqual("new-operator", event["operator"])

    def test_project_propose_normalizes_ascii_slugs_and_never_inherits_portal(self):
        self.registry({"nickname": "ada"}, {
            str(self.root / "portal"): {
                "bank_id": "acme::portal", "product_identity": "acme-portal"
            }
        })
        before = read_registry(self.registry_path)
        completed = self.invoke(
            "project", "propose", "--root", str(self.root / "acme"), "--name", "Acme Wídgets!",
            "--owner", "Äcme", "--registry", str(self.registry_path),
        )
        self.assertEqual(0, completed.returncode, completed.stderr)
        payload = self.result(completed)
        self.assertTrue(payload["confirmation_required"])
        self.assertEqual("acme::acme-widgets", payload["profile"]["bank_id"])
        self.assertEqual("acme-acme-widgets", payload["profile"]["product_identity"])
        self.assertNotEqual("acme::portal", payload["profile"]["bank_id"])
        self.assertEqual(before, read_registry(self.registry_path))

    def test_approved_portal_profile_registers_and_resolves_with_distinct_document_project_slug(self):
        root = self.root / "acme"
        self.registry({"nickname": "ada"})
        profile = self.approved_portal_profile(root)
        registered = self.invoke(
            "project", "register", "--confirm", "--profile", str(self.write_profile(profile)),
            "--registry", str(self.registry_path), "--audit", str(self.audit_path),
        )
        self.assertEqual(0, registered.returncode, registered.stderr)
        stored = read_registry(self.registry_path)["projects"][str(root.resolve())]
        self.assertEqual("acme-portal", stored["project_slug"])
        self.assertEqual("acme::portal", stored["bank_id"])

        resolved = self.invoke(
            "project", "resolve", "--root", str(root / "wiki"), "--registry", str(self.registry_path),
        )
        self.assertEqual(0, resolved.returncode, resolved.stderr)
        payload = self.result(resolved)
        self.assertEqual(str(root.resolve()), payload["project"]["root"])
        self.assertEqual("acme::portal", payload["project"]["bank_id"])

    def test_profile_rejects_malformed_bank_ids_without_audit_or_mutation(self):
        malformed = (
            "acme:portal",
            "acme::portal::archive",
            "Acme::portal",
            "acme::Portal",
            "acme::_portal",
            "acme::portal-",
            "acme::portal_app",
        )
        for index, bank_id in enumerate(malformed):
            with self.subTest(bank_id=bank_id):
                self.registry({"nickname": "ada"})
                if self.audit_path.exists():
                    self.audit_path.unlink()
                profile = self.approved_portal_profile(self.root / ("malformed-" + str(index)))
                profile["bank_id"] = bank_id
                before = read_registry(self.registry_path)
                completed = self.invoke(
                    "project", "register", "--confirm",
                    "--profile", str(self.write_profile(profile, "malformed.json")),
                    "--registry", str(self.registry_path), "--audit", str(self.audit_path),
                )
                self.assertEqual(2, completed.returncode)
                self.assertEqual("invalid_profile", self.result(completed)["status"])
                self.assertEqual(before, read_registry(self.registry_path))
                self.assertFalse(self.audit_path.exists())

    def test_profile_rejects_bank_owner_mismatch_without_audit_or_mutation(self):
        self.registry({"nickname": "ada"})
        profile = self.approved_portal_profile(self.root / "owner-mismatch")
        profile["bank_id"] = "other::portal"
        before = read_registry(self.registry_path)
        completed = self.invoke(
            "project", "register", "--confirm", "--profile", str(self.write_profile(profile)),
            "--registry", str(self.registry_path), "--audit", str(self.audit_path),
        )
        self.assertEqual(2, completed.returncode)
        self.assertEqual("invalid_profile", self.result(completed)["status"])
        self.assertEqual(before, read_registry(self.registry_path))
        self.assertFalse(self.audit_path.exists())

    def test_project_propose_rejects_an_empty_ascii_slug(self):
        self.registry()
        before = read_registry(self.registry_path)
        completed = self.invoke(
            "project", "propose", "--root", str(self.root / "empty"), "--name", "!!!",
            "--owner", "owner", "--registry", str(self.registry_path),
        )
        self.assertEqual(2, completed.returncode)
        self.assertEqual("invalid_input", self.result(completed)["status"])

    def test_existing_product_additional_root_reuses_identity_but_requires_confirmation(self):
        existing_root = self.root / "web"
        self.registry({"nickname": "ada"}, {
            str(existing_root): {
                "bank_id": "acme::portal", "project_slug": "portal",
                "product_identity": "acme-portal"
            }
        })
        completed = self.invoke(
            "project", "propose", "--root", str(self.root / "mobile"), "--name", "Acme Portal Mobile",
            "--owner", "acme", "--existing-product", "acme-portal",
            "--registry", str(self.registry_path),
        )
        self.assertEqual(0, completed.returncode, completed.stderr)
        payload = self.result(completed)
        self.assertTrue(payload["confirmation_required"])
        self.assertEqual("acme::portal", payload["profile"]["bank_id"])
        self.assertEqual("existing_product_additional_root", payload["profile"]["relationship"])

    def test_ambiguous_or_uncertain_relationship_fails_closed_with_confirmation_json(self):
        self.registry({"nickname": "ada"}, {
            str(self.root / "one"): {"bank_id": "one::product", "product_identity": "shared"},
            str(self.root / "two"): {"bank_id": "two::product", "product_identity": "shared"},
        })
        before = read_registry(self.registry_path)
        completed = self.invoke(
            "project", "propose", "--root", str(self.root / "candidate"), "--name", "Candidate",
            "--owner", "new", "--existing-product", "shared", "--registry", str(self.registry_path),
        )
        self.assertEqual(2, completed.returncode)
        payload = self.result(completed)
        self.assertEqual("relationship_uncertain", payload["status"])
        self.assertTrue(payload["confirmation_required"])
        self.assertEqual(before, read_registry(self.registry_path))

    def test_proposal_alone_does_not_persist_and_register_requires_reviewed_confirmed_profile_and_operator(self):
        root = self.root / "acme"
        self.registry()
        proposed = self.invoke(
            "project", "propose", "--root", str(root), "--name", "Acme", "--owner", "acme",
            "--registry", str(self.registry_path),
        )
        self.assertEqual(0, proposed.returncode, proposed.stderr)
        profile = self.result(proposed)["profile"]
        self.assertEqual({}, read_registry(self.registry_path)["projects"])
        profile_path = self.write_profile(profile)
        missing_operator = self.invoke(
            "project", "register", "--profile", str(profile_path), "--confirm",
            "--registry", str(self.registry_path), "--audit", str(self.audit_path),
        )
        self.assertEqual(2, missing_operator.returncode)
        self.assertEqual("operator_required", self.result(missing_operator)["status"])
        self.registry({"nickname": "ada"})
        unreviewed = self.invoke(
            "project", "register", "--profile", str(profile_path), "--confirm",
            "--registry", str(self.registry_path), "--audit", str(self.audit_path),
        )
        self.assertEqual(2, unreviewed.returncode)
        self.assertEqual("review_required", self.result(unreviewed)["status"])
        profile["reviewed"] = True
        profile_path = self.write_profile(profile)
        unconfirmed = self.invoke(
            "project", "register", "--profile", str(profile_path), "--registry", str(self.registry_path),
            "--audit", str(self.audit_path),
        )
        self.assertEqual(2, unconfirmed.returncode)
        self.assertTrue(self.result(unconfirmed)["confirmation_required"])
        registered = self.invoke(
            "project", "register", "--profile", str(profile_path), "--confirm", "--registry",
            str(self.registry_path), "--audit", str(self.audit_path), "--at", "2026-09-01T00:00:00+02:00",
        )
        self.assertEqual(0, registered.returncode, registered.stderr)
        self.assertEqual("acme::acme", read_registry(self.registry_path)["projects"][str(root.resolve())]["bank_id"])

    def test_project_resolve_returns_the_longest_registered_root(self):
        parent = self.root / "product"
        child = parent / "mobile"
        self.registry({"nickname": "ada"}, {
            str(parent): {"bank_id": "owner::parent"},
            str(child): {"bank_id": "owner::mobile"},
        })
        completed = self.invoke("project", "resolve", "--root", str(child / "src"), "--registry", str(self.registry_path))
        self.assertEqual(0, completed.returncode, completed.stderr)
        payload = self.result(completed)
        self.assertEqual(str(child.resolve()), payload["project"]["root"])
        self.assertEqual("owner::mobile", payload["project"]["bank_id"])

    def test_reviewed_existing_product_profile_can_register_a_confirmed_additional_root_from_stdin(self):
        web = self.root / "web"
        mobile = self.root / "mobile"
        existing = self.approved_portal_profile(web)
        self.registry({"nickname": "ada"}, {
            str(web): {key: value for key, value in existing.items() if key != "root"}
        })
        profile = self.approved_portal_profile(mobile, "existing_product_additional_root")
        completed = self.invoke(
            "project", "register", "--confirm", "--registry", str(self.registry_path),
            "--audit", str(self.audit_path), input_text=json.dumps(profile),
        )
        self.assertEqual(0, completed.returncode, completed.stderr)
        stored = read_registry(self.registry_path)["projects"][str(mobile.resolve())]
        self.assertEqual("acme-portal", stored["project_slug"])
        self.assertEqual("acme::portal", stored["bank_id"])

    def test_connector_sync_rejects_malformed_or_invalid_mapping_without_mutation_or_backup(self):
        root = self.root / "product"
        profile = self.approved_profile(root)
        self.registry({"nickname": "ada"}, {str(root): {key: value for key, value in profile.items() if key != "root"}})
        profile_path = self.write_profile(profile)
        connector = self.root / "coding-agent.json"
        for content in (b"{", b'{"mapPathToBank": []}'):
            connector.write_bytes(content)
            completed = self.invoke(
                "connector", "sync", "--connector", str(connector), "--root", str(root / "src"),
                "--registry", str(self.registry_path), "--profile", str(profile_path), "--audit", str(self.audit_path), "--confirm",
            )
            self.assertEqual(2, completed.returncode)
            self.assertEqual(content, connector.read_bytes())
            self.assertEqual([], list(self.root.glob("coding-agent.json.project-memory-backup-*")))

    def test_connector_sync_backs_up_privately_and_preserves_secret_and_unrelated_values(self):
        root = self.root / "product"
        other_root = self.root / "other"
        profile = self.approved_profile(root)
        self.registry({"nickname": "ada"}, {str(root): {key: value for key, value in profile.items() if key != "root"}})
        profile_path = self.write_profile(profile)
        connector = self.root / "coding-agent.json"
        original = {
            "token": "do-not-print-this-token",
            "unrelated": {"keep": ["every", "value"]},
            "mapPathToBank": {str(root.resolve()): "old::bank", str(other_root.resolve()): "other::bank"},
        }
        connector.write_text(json.dumps(original, separators=(",", ":")), encoding="utf-8")
        completed = self.invoke(
            "connector", "sync", "--connector", str(connector), "--root", str(root / "src"),
            "--registry", str(self.registry_path), "--profile", str(profile_path), "--audit", str(self.audit_path), "--confirm",
        )
        self.assertEqual(0, completed.returncode, completed.stderr)
        self.assertNotIn("do-not-print-this-token", completed.stdout + completed.stderr)
        updated = json.loads(connector.read_text(encoding="utf-8"))
        self.assertEqual("do-not-print-this-token", updated["token"])
        self.assertEqual(original["unrelated"], updated["unrelated"])
        self.assertEqual("owner::product", updated["mapPathToBank"][str(root.resolve())])
        self.assertEqual("other::bank", updated["mapPathToBank"][str(other_root.resolve())])
        self.assertEqual(0o600, stat.S_IMODE(connector.stat().st_mode))
        backups = list(self.root.glob("coding-agent.json.project-memory-backup-*[0-9]Z"))
        self.assertEqual(1, len(backups))
        self.assertEqual(original, json.loads(backups[0].read_text(encoding="utf-8")))
        self.assertEqual(0o600, stat.S_IMODE(backups[0].stat().st_mode))

    def test_connector_gates_fail_before_audit_backup_or_write(self):
        root = self.root / "product"
        profile = self.approved_profile(root)
        connector = self.root / "coding-agent.json"
        original = b'{"mapPathToBank":{}}'
        connector.write_bytes(original)
        profile_path = self.write_profile(profile)
        for operator, extra, expected in ((None, ("--confirm",), "operator_required"), ({"nickname": "ada"}, (), "confirmation_required")):
            with self.subTest(expected=expected):
                self.registry(operator, {str(root): {key: value for key, value in profile.items() if key != "root"}})
                if self.audit_path.exists():
                    self.audit_path.unlink()
                completed = self.invoke(
                    "connector", "sync", "--connector", str(connector), "--root", str(root), "--registry",
                    str(self.registry_path), "--profile", str(profile_path), "--audit", str(self.audit_path), *extra,
                )
                self.assertEqual(2, completed.returncode)
                self.assertEqual(expected, self.result(completed)["status"])
                self.assertEqual(original, connector.read_bytes())
                self.assertFalse(self.audit_path.exists())
                self.assertEqual([], list(self.root.glob("coding-agent.json.project-memory-backup-*")))

    def test_secret_profile_is_rejected_without_echo_or_mutation(self):
        root = self.root / "product"
        self.registry({"nickname": "ada"})
        canary = "CANARY_SECRET_7b64de"
        profile = self.approved_profile(root)
        profile["source_policy"]["api_token"] = canary
        profile_path = self.write_profile(profile)
        before = read_registry(self.registry_path)
        completed = self.invoke(
            "project", "register", "--confirm", "--profile", str(profile_path), "--registry", str(self.registry_path),
            "--audit", str(self.audit_path),
        )
        self.assertEqual(2, completed.returncode)
        self.assertEqual("invalid_profile", self.result(completed)["status"])
        self.assertNotIn(canary, completed.stdout + completed.stderr)
        self.assertEqual(before, read_registry(self.registry_path))
        self.assertFalse(self.audit_path.exists())

    def test_connector_rejects_secret_profile_without_echo_audit_or_backup(self):
        root = self.root / "product"
        profile = self.approved_profile(root)
        canary = "CANARY_CONNECTOR_SECRET_349e"
        profile["graph_policy"]["private_key"] = canary
        self.registry({"nickname": "ada"}, {str(root): {
            key: value for key, value in self.approved_profile(root).items() if key != "root"
        }})
        connector = self.root / "coding-agent.json"
        original = b'{"mapPathToBank":{}}'
        connector.write_bytes(original)
        completed = self.invoke(
            "connector", "sync", "--confirm", "--connector", str(connector), "--root", str(root), "--registry",
            str(self.registry_path), "--profile", str(self.write_profile(profile)), "--audit", str(self.audit_path),
        )
        self.assertEqual(2, completed.returncode)
        self.assertEqual("invalid_profile", self.result(completed)["status"])
        self.assertNotIn(canary, completed.stdout + completed.stderr)
        self.assertEqual(original, connector.read_bytes())
        self.assertFalse(self.audit_path.exists())
        self.assertEqual([], list(self.root.glob("coding-agent.json.project-memory-backup-*")))

    def test_benign_future_profile_metadata_is_preserved_without_being_echoed(self):
        root = self.root / "product"
        self.registry({"nickname": "ada"})
        profile = self.approved_profile(root)
        profile["future_metadata"] = {"team": "alpha", "feature": True}
        completed = self.invoke(
            "project", "register", "--confirm", "--profile", str(self.write_profile(profile)),
            "--registry", str(self.registry_path), "--audit", str(self.audit_path),
        )
        self.assertEqual(0, completed.returncode, completed.stderr)
        stored = read_registry(self.registry_path)["projects"][str(root.resolve())]
        self.assertEqual(profile["future_metadata"], stored["future_metadata"])
        self.assertNotIn("future_metadata", completed.stdout)

    def test_register_rejects_existing_root_bank_change_without_audit_or_mutation(self):
        root = self.root / "product"
        existing = self.approved_profile(root)
        self.registry({"nickname": "ada"}, {str(root): {key: value for key, value in existing.items() if key != "root"}})
        replacement = self.approved_profile(root, "owner::other", "owner-other")
        before = read_registry(self.registry_path)
        completed = self.invoke(
            "project", "register", "--confirm", "--profile", str(self.write_profile(replacement)),
            "--registry", str(self.registry_path), "--audit", str(self.audit_path),
        )
        self.assertEqual(2, completed.returncode)
        self.assertEqual("invalid_registration", self.result(completed)["status"])
        self.assertEqual(before, read_registry(self.registry_path))
        self.assertFalse(self.audit_path.exists())

    def test_cli_refresh_preserves_registration_attribution_and_rejects_identity_conflict(self):
        root = self.root / "product"
        existing = self.approved_profile(root)
        existing.update({"registered_by": "old", "registered_at": "2026-08-01T00:00:00+02:00"})
        self.registry({"nickname": "new"}, {str(root): {key: value for key, value in existing.items() if key != "root"}})
        conflicting = self.approved_profile(root, product_identity="other-product")
        before = read_registry(self.registry_path)
        rejected = self.invoke("project", "register", "--confirm", "--profile", str(self.write_profile(conflicting)),
                               "--registry", str(self.registry_path), "--audit", str(self.audit_path))
        self.assertEqual(2, rejected.returncode)
        self.assertEqual("invalid_registration", self.result(rejected)["status"])
        self.assertEqual(before, read_registry(self.registry_path))
        refreshed = self.approved_profile(root)
        refreshed["future_metadata"] = {"revision": 2}
        accepted = self.invoke("project", "register", "--confirm", "--profile", str(self.write_profile(refreshed)),
                               "--registry", str(self.registry_path), "--audit", str(self.audit_path),
                               "--at", "2026-09-01T18:30:00+02:00")
        self.assertEqual(0, accepted.returncode, accepted.stderr)
        stored = read_registry(self.registry_path)["projects"][str(root.resolve())]
        self.assertEqual("old", stored["registered_by"])
        self.assertEqual("2026-08-01T00:00:00+02:00", stored["registered_at"])
        self.assertEqual("new", stored["updated_by"])
        self.assertEqual("2026-09-01T18:30:00+02:00", stored["updated_at"])

    def test_cli_empty_established_identity_field_cannot_overwrite_registered_profile(self):
        root = self.root / "product"
        profile = self.approved_profile(root)
        self.registry({"nickname": "ada"}, {str(root): {key: value for key, value in profile.items() if key != "root"}})
        replacement = self.approved_profile(root)
        replacement["product_identity"] = ""
        before = read_registry(self.registry_path)
        completed = self.invoke("project", "register", "--confirm", "--profile", str(self.write_profile(replacement)),
                                "--registry", str(self.registry_path), "--audit", str(self.audit_path))
        self.assertEqual(2, completed.returncode)
        self.assertEqual("invalid_profile", self.result(completed)["status"])
        self.assertEqual(before, read_registry(self.registry_path))

    def test_connector_requires_exact_root_product_and_relationship_profile_binding(self):
        root = self.root / "product"
        foreign = self.root / "foreign"
        profile = self.approved_profile(root, relationship="existing_product_additional_root")
        self.registry({"nickname": "ada"}, {str(root): {key: value for key, value in profile.items() if key != "root"}})
        supplied = self.approved_profile(foreign, relationship="existing_product_additional_root")
        connector = self.root / "coding-agent.json"
        original = b'{"mapPathToBank":{}}'
        connector.write_bytes(original)
        completed = self.invoke(
            "connector", "sync", "--confirm", "--connector", str(connector), "--root", str(root), "--registry",
            str(self.registry_path), "--profile", str(self.write_profile(supplied)), "--audit", str(self.audit_path),
        )
        self.assertEqual(2, completed.returncode)
        self.assertEqual("profile_mismatch", self.result(completed)["status"])
        self.assertEqual(original, connector.read_bytes())
        self.assertFalse(self.audit_path.exists())
        self.assertEqual([], list(self.root.glob("coding-agent.json.project-memory-backup-*")))

    def test_connector_rejects_project_slug_mismatch_before_audit_backup_or_write(self):
        root = self.root / "acme"
        profile = self.approved_portal_profile(root)
        self.registry({"nickname": "ada"}, {
            str(root): {key: value for key, value in profile.items() if key != "root"}
        })
        supplied = dict(profile, project_slug="mobile-only")
        connector = self.root / "coding-agent.json"
        original = b'{"mapPathToBank":{},"unrelated":{"keep":true}}'
        connector.write_bytes(original)
        completed = self.invoke(
            "connector", "sync", "--confirm", "--connector", str(connector), "--root", str(root),
            "--registry", str(self.registry_path), "--profile", str(self.write_profile(supplied)),
            "--audit", str(self.audit_path),
        )
        self.assertEqual(2, completed.returncode)
        self.assertEqual("profile_mismatch", self.result(completed)["status"])
        self.assertEqual(original, connector.read_bytes())
        self.assertFalse(self.audit_path.exists())
        self.assertEqual([], list(self.root.glob("coding-agent.json.project-memory-backup-*")))

    def test_invalid_audit_parent_blocks_every_mutation_before_target_write(self):
        invalid_parent = self.root / "not-a-directory"
        invalid_parent.write_text("file", encoding="utf-8")
        invalid_audit = invalid_parent / "audit.jsonl"
        self.registry()
        before_operator = read_registry(self.registry_path)
        operator = self.invoke("operator", "set", "ada", "--registry", str(self.registry_path), "--audit", str(invalid_audit))
        self.assertEqual(2, operator.returncode)
        self.assertEqual(before_operator, read_registry(self.registry_path))
        root = self.root / "product"
        profile = self.approved_profile(root)
        self.registry({"nickname": "ada"})
        before_register = read_registry(self.registry_path)
        registered = self.invoke("project", "register", "--confirm", "--profile", str(self.write_profile(profile)),
                                 "--registry", str(self.registry_path), "--audit", str(invalid_audit))
        self.assertEqual(2, registered.returncode)
        self.assertEqual(before_register, read_registry(self.registry_path))
        self.registry({"nickname": "ada"}, {str(root): {key: value for key, value in profile.items() if key != "root"}})
        connector = self.root / "coding-agent.json"
        original = b'{"mapPathToBank":{}}'
        connector.write_bytes(original)
        synced = self.invoke("connector", "sync", "--confirm", "--connector", str(connector), "--root", str(root),
                             "--registry", str(self.registry_path), "--profile", str(self.write_profile(profile)),
                             "--audit", str(invalid_audit))
        self.assertEqual(2, synced.returncode)
        self.assertEqual(original, connector.read_bytes())
        self.assertEqual([], list(self.root.glob("coding-agent.json.project-memory-backup-*")))

    def test_connector_round_trip_invariant_allows_only_resolved_mapping_entry(self):
        specification = importlib.util.spec_from_file_location("project_memory_cli_invariant", CLI)
        module = importlib.util.module_from_spec(specification)
        specification.loader.exec_module(module)
        root = str((self.root / "product").resolve())
        before = {"nested": {"values": [1, {"keep": True}]}, "mapPathToBank": {root: "old", "/other": "other"}}
        after = json.loads(json.dumps(before))
        after["mapPathToBank"][root] = "new"
        self.assertTrue(module._only_resolved_mapping_changed(before, after, root))
        after["nested"]["values"][1]["keep"] = False
        self.assertFalse(module._only_resolved_mapping_changed(before, after, root))

    def test_atomic_connector_replace_failure_leaves_original_and_no_temporary_file(self):
        specification = importlib.util.spec_from_file_location("project_memory_cli", CLI)
        module = importlib.util.module_from_spec(specification)
        specification.loader.exec_module(module)
        connector = self.root / "coding-agent.json"
        connector.write_bytes(b'{"mapPathToBank":{}}')
        with patch.object(module.os, "replace", side_effect=OSError("replace failed")):
            with self.assertRaises(OSError):
                module._atomic_write_bytes(connector, b'{"mapPathToBank":{"/new":"owner::bank"}}')
        self.assertEqual(b'{"mapPathToBank":{}}', connector.read_bytes())
        self.assertEqual([], list(self.root.glob(".coding-agent.json.*")))


class RegistryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)

    def tearDown(self):
        self.temp.cleanup()

    def test_unregistered_workspace_requires_project(self):
        registry = {"schema_version": 1, "operator": None, "projects": {}}
        self.assertIsNone(resolve_project(registry, self.root / "new-project"))

    def test_longest_registered_root_wins(self):
        registry = {"schema_version": 1, "operator": {"nickname": "alice"}, "projects": {
            str(self.root): {"bank_id": "owner::parent"},
            str(self.root / "product"): {"bank_id": "owner::product"},
        }}
        resolved = resolve_project(registry, self.root / "product" / "repo")
        self.assertEqual("owner::product", resolved["bank_id"])

    def test_path_boundary_does_not_match_similarly_named_root(self):
        registry = {"schema_version": 1, "operator": None, "projects": {
            str(self.root / "product"): {"bank_id": "owner::product"},
        }}
        self.assertIsNone(resolve_project(registry, self.root / "product-copy"))

    def test_unrelated_project_cannot_reuse_existing_bank(self):
        registry = {"schema_version": 1, "operator": {"nickname": "alice"}, "projects": {
            str(self.root / "portal"): {"bank_id": "acme::portal"}
        }}
        profile = {"root": str(self.root / "unrelated"), "bank_id": "acme::portal"}
        with self.assertRaisesRegex(ValueError, "already assigned"):
            register_project(registry, profile, "2026-09-01T00:00:00+02:00")

    def test_re_registering_same_root_keeps_its_bank(self):
        project_root = self.root / "portal"
        registry = {"schema_version": 1, "operator": {"nickname": "alice"}, "projects": {
            str(project_root): {"bank_id": "acme::portal"}
        }}
        updated = register_project(
            registry,
            {"root": str(project_root), "bank_id": "acme::portal", "display_name": "Acme Portal"},
            "2026-09-01T00:00:00+02:00",
        )
        self.assertEqual("acme::portal", updated["projects"][str(project_root.resolve())]["bank_id"])

    def test_existing_root_cannot_change_bank_without_explicit_remap_workflow(self):
        project_root = self.root / "portal"
        registry = {"schema_version": 1, "operator": {"nickname": "alice"}, "projects": {
            str(project_root): {"bank_id": "acme::portal"}
        }}
        with self.assertRaisesRegex(ValueError, "explicit remap"):
            register_project(
                registry,
                {"root": str(project_root), "bank_id": "acme::other"},
                "2026-09-01T00:00:00+02:00",
            )

    def test_unreviewed_existing_product_reuse_cannot_bypass_registry_uniqueness(self):
        registry = {"schema_version": 1, "operator": {"nickname": "alice"}, "projects": {
            str(self.root / "web"): {
                "bank_id": "acme::portal", "product_identity": "acme-portal"
            }
        }}
        with self.assertRaisesRegex(ValueError, "already assigned"):
            register_project(registry, {
                "root": str(self.root / "mobile"), "bank_id": "acme::portal",
                "product_identity": "acme-portal",
                "relationship": "existing_product_additional_root",
            }, "2026-09-01T00:00:00+02:00")

    def test_additional_root_cannot_fragment_project_slug_within_existing_bank(self):
        registry = {"schema_version": 1, "operator": {"nickname": "alice"}, "projects": {
            str(self.root / "web"): {
                "bank_id": "acme::portal", "owner_slug": "acme",
                "project_slug": "acme-portal", "product_identity": "acme-portal",
                "relationship": "new_product", "reviewed": True,
            }
        }}
        before = json.loads(json.dumps(registry))
        profile = {
            "root": str(self.root / "mobile"), "bank_id": "acme::portal",
            "owner_slug": "acme", "project_slug": "mobile-only",
            "product_identity": "acme-portal",
            "relationship": "existing_product_additional_root", "reviewed": True,
        }
        with self.assertRaisesRegex(ValueError, "already assigned"):
            register_project(registry, profile, "2026-09-01T00:00:00+02:00")
        self.assertEqual(before, registry)

    def test_write_registry_is_atomic_and_applies_private_modes(self):
        path = self.root / "state" / "registry.json"
        registry = {"schema_version": 1, "operator": None, "projects": {}}
        write_registry(path, registry)
        self.assertEqual(registry, json.loads(path.read_text(encoding="utf-8")))
        self.assertEqual(0o700, stat.S_IMODE(path.parent.stat().st_mode))
        self.assertEqual(0o600, stat.S_IMODE(path.stat().st_mode))
        self.assertEqual([], list(path.parent.glob(".registry.json.*")))

    def test_write_registry_leaves_previous_file_when_json_encoding_fails(self):
        path = self.root / "registry.json"
        original = {"schema_version": 1, "operator": None, "projects": {}}
        write_registry(path, original)
        with self.assertRaises(TypeError):
            write_registry(path, {"unsupported": {"values"}})
        self.assertEqual(original, read_registry(path))
        self.assertEqual(0o600, stat.S_IMODE(os.stat(path).st_mode))

    def test_registry_boundary_rejects_semantic_secret_key_and_value_variants_before_mutation(self):
        base = {"schema_version": 1, "operator": {"nickname": "ada"}, "projects": {}}
        root = self.root / "product"
        variants = (
            {"apiToken": "value"},
            {"private.key": "value"},
            {"refresh_token": "value"},
            {"aws_private_key_value": "value"},
            {"deploymentApiTokenValue": "value"},
            {"refresh.token.value": "value"},
            {"note": "-----BEGIN PRIVATE KEY-----\nabc\n-----END PRIVATE KEY-----"},
            {"note": "Bearer abcdefghijklmnopqrstuvwxyz"},
            {"note": "password = correct-horse-battery-staple"},
            {"password_policy": GITHUB_TOKEN_CANARY},
            {"secret_handling": JWT_CANARY},
            {"credential_rules": OPENAI_TOKEN_CANARY},
            {"token_budget": AWS_ACCESS_KEY_CANARY},
        )
        for metadata in variants:
            with self.subTest(metadata=next(iter(metadata))):
                profile = {"root": str(root), "bank_id": "owner::product", **metadata}
                with self.assertRaisesRegex(ValueError, "sensitive"):
                    register_project(base, profile, "2026-09-01T00:00:00+02:00")
        path = self.root / "new-state" / "registry.json"
        with self.assertRaisesRegex(ValueError, "sensitive"):
            write_registry(path, {**base, "projects": {str(root): {"bank_id": "owner::product", "accessToken": "x"}}})
        self.assertFalse(path.exists())
        self.assertFalse(path.parent.exists())

    def test_registry_rejects_complete_private_key_and_certificate_blocks(self):
        base = {"schema_version": 1, "operator": {"nickname": "ada"}, "projects": {}}
        fixtures = (
            "-----BEGIN PRIVATE KEY-----\nPRIVATE-BODY-REGISTRY-CANARY\n-----END PRIVATE KEY-----",
            "-----BEGIN CERTIFICATE-----\nCERTIFICATE-BODY-REGISTRY-CANARY\n-----END CERTIFICATE-----",
        )
        for index, fixture in enumerate(fixtures):
            profile = {
                "root": str(self.root / ("pem-" + str(index))),
                "bank_id": "owner::product-" + str(index),
                "note": fixture,
            }
            with self.subTest(index=index), self.assertRaisesRegex(ValueError, "sensitive registry data"):
                register_project(base, profile, "2026-09-01T00:00:00+02:00")

    def test_registry_boundary_allows_benign_policy_measurement_and_prose_metadata(self):
        root = self.root / "product"
        profile = {
            "root": str(root), "bank_id": "owner::product", "token_budget": 100,
            "token_limit": 200, "token_count": 3, "password_policy": "Assignments should be blocked.",
            "secret_handling": "Secrets and password assignments should be blocked.",
            "credential_rules": ["Do not retain bearer credentials."],
        }
        registry = {"schema_version": 1, "operator": {"nickname": "ada"}, "projects": {}}
        updated = register_project(registry, profile, "2026-09-01T00:00:00+02:00")
        self.assertEqual(100, updated["projects"][str(root.resolve())]["token_budget"])
        path = self.root / "state" / "registry.json"
        write_registry(path, updated)
        self.assertEqual(updated, read_registry(path))

    def test_absolute_project_mapping_keys_and_benign_display_prose_remain_valid(self):
        roots = ("/work/secret-manager", "/work/token-service", "C:\\work\\secret-manager")
        registry = {"schema_version": 1, "operator": {"nickname": "ada"}, "projects": {
            root: {"bank_id": "owner::product", "display_name": "Secret Manager",
                   "token_budget": 20, "password_policy": "Password assignments should be blocked."}
            for root in roots
        }}
        path = self.root / "state" / "registry.json"
        write_registry(path, registry)
        self.assertEqual(registry, read_registry(path))
        profile = {"root": str(self.root / "token-service"), "bank_id": "owner::product",
                   "display_name": "Secret Manager", "token_budget": 10,
                   "password_policy": "Do not store password assignments."}
        updated = register_project({"schema_version": 1, "operator": {"nickname": "ada"}, "projects": {}}, profile,
                                   "2026-09-01T00:00:00+02:00")
        self.assertEqual("Secret Manager", updated["projects"][str((self.root / "token-service").resolve())]["display_name"])
        registry["projects"]["/work/secret-manager"]["apiToken"] = "bad"
        with self.assertRaisesRegex(ValueError, "sensitive"):
            write_registry(path, registry)

    def test_direct_same_root_refresh_preserves_identity_and_historical_attribution(self):
        root = self.root / "product"
        registry = {"schema_version": 1, "operator": {"nickname": "new"}, "projects": {
            str(root): {
                "bank_id": "owner::product", "owner_slug": "owner", "project_slug": "product",
                "product_identity": "owner-product", "relationship": "new_product",
                "registered_by": "old", "registered_at": "2026-08-01T00:00:00+02:00",
            }
        }}
        conflicting = {"root": str(root), "bank_id": "owner::product", "owner_slug": "owner",
                       "project_slug": "product", "product_identity": "other-product", "relationship": "new_product"}
        with self.assertRaisesRegex(ValueError, "explicit remap"):
            register_project(registry, conflicting, "2026-09-01T00:00:00+02:00")
        refreshed = dict(conflicting, product_identity="owner-product", future_metadata={"team": "alpha"})
        updated = register_project(registry, refreshed, "2026-09-01T00:00:00+02:00")
        stored = updated["projects"][str(root.resolve())]
        self.assertEqual("old", stored["registered_by"])
        self.assertEqual("2026-08-01T00:00:00+02:00", stored["registered_at"])
        self.assertEqual("new", stored["updated_by"])
        self.assertEqual("2026-09-01T00:00:00+02:00", stored["updated_at"])
        for field in ("product_identity", "relationship", "owner_slug", "project_slug"):
            missing = dict(refreshed)
            missing.pop(field)
            with self.assertRaisesRegex(ValueError, "explicit remap"):
                register_project(registry, missing, "2026-09-01T00:00:00+02:00")
            empty = dict(refreshed, **{field: ""})
            with self.assertRaisesRegex(ValueError, "explicit remap"):
                register_project(registry, empty, "2026-09-01T00:00:00+02:00")


if __name__ == "__main__":
    unittest.main()
