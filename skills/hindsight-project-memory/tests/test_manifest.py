"""Tests for deterministic, non-destructive project-memory manifests."""

from __future__ import annotations

import hashlib
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


SKILL_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SKILL_ROOT / "scripts"))

from project_memory.manifest import Manifest, build_manifest as _build_manifest, read_manifest, validate_manifest_files, write_manifest  # noqa: E402

GITHUB_TOKEN_CANARY = "ghp_" + "abcdefghijklmnopqrstuvwxyz1234567890"


def build_manifest(root, candidates, profile, *args, **kwargs):
    if "operator" not in kwargs and isinstance(profile.get("operator"), str):
        kwargs["operator"] = profile["operator"]
    return _build_manifest(root, candidates, profile, *args, **kwargs)


class ManifestTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name) / "project"
        self.root.mkdir()
        self.staging = Path(self.temporary.name) / "staging"
        self.profile = {"operator": "alice", "project_slug": "demo", "scope": "wiki", "knowledge_layer": "concept", "topics": ["topic:architecture"]}

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def write(self, relative: str, text: str) -> Path:
        destination = self.root / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(text, encoding="utf-8")
        return destination

    def test_stable_source_id_and_hashes_are_posix_and_deterministic(self) -> None:
        source = self.write("wiki/guide.md", "password: exposed-value\n")

        manifest = build_manifest(self.root, [source], self.profile, staging_root=self.staging)
        entry = manifest.entries[0]

        self.assertEqual("wiki/guide.md", entry.relative_path)
        self.assertEqual("kb:demo:source:wiki:wiki/guide.md", entry.document_id)
        self.assertEqual("include_redacted", entry.classification)
        self.assertEqual(hashlib.sha256(source.read_bytes()).hexdigest(), entry.source_sha256)
        self.assertEqual(hashlib.sha256(b"password: [REDACTED]\n").hexdigest(), entry.exported_sha256)
        self.assertEqual("password: [REDACTED]\n", (self.staging / "wiki/guide.md").read_text(encoding="utf-8"))
        self.assertEqual("password: exposed-value\n", source.read_text(encoding="utf-8"))
        self.assertIn("user:alice", entry.tags)
        self.assertIn("project:demo", entry.tags)
        self.assertIn("topic:architecture", entry.tags)

    def test_manifest_requires_explicit_active_operator_for_deployed_style_profile(self) -> None:
        source = self.write("wiki/guide.md", "Architecture facts.\n")
        deployed_profile = {key: value for key, value in self.profile.items() if key != "operator"}

        with self.assertRaisesRegex(ValueError, "operator"):
            build_manifest(self.root, [source], deployed_profile, staging_root=self.staging)

        manifest = build_manifest(
            self.root,
            [source],
            deployed_profile,
            staging_root=self.staging,
            operator="alice",
        )
        entry = manifest.entries[0]
        self.assertEqual(1, sum(tag == "user:alice" for tag in entry.tags))
        self.assertEqual("alice", dict(entry.metadata)["operator"])
        self.assertNotIn("user:unknown", entry.tags)

    def test_manifest_build_cli_injects_registry_operator_and_writes_local_manifest(self) -> None:
        source = self.write("wiki/guide.md", "Architecture facts.\n")
        registry = Path(self.temporary.name) / "registry.json"
        registry.write_text(json.dumps({
            "schema_version": 1,
            "operator": {"nickname": "alice"},
            "projects": {str(self.root): {
                "bank_id": "owner::demo",
                "project_slug": "demo",
                "scope": "wiki",
                "knowledge_layer": "concept",
            }},
        }), encoding="utf-8")
        candidates = Path(self.temporary.name) / "candidates.json"
        candidates.write_text(json.dumps(["wiki/guide.md"]), encoding="utf-8")
        output = Path(self.temporary.name) / "manifest.json"
        cli = SKILL_ROOT / "scripts" / "project_memory.py"

        completed = subprocess.run([
            sys.executable, str(cli), "manifest", "build",
            "--registry", str(registry),
            "--root", str(self.root),
            "--candidates", str(candidates),
            "--staging-root", str(self.staging),
            "--output", str(output),
        ], capture_output=True, text=True, check=False)

        self.assertEqual(0, completed.returncode, completed.stderr)
        manifest = read_manifest(output)
        self.assertIn("user:alice", manifest.entries[0].tags)
        self.assertEqual("alice", dict(manifest.entries[0].metadata)["operator"])

    def test_allow_project_staging_retains_selected_credentials_verbatim_with_provenance(self) -> None:
        credential_text = (
            "staging_password: correct horse battery staple\n"
            f"api_key: {GITHUB_TOKEN_CANARY}\n"
            "-----BEGIN PRIVATE KEY-----\nprivate-staging-material\n-----END PRIVATE KEY-----\n"
        )
        source = self.write("ops/staging-access.md", credential_text)
        profile = dict(
            self.profile,
            credential_policy="allow_project_staging",
            reviewed=True,
            source_policy={"credential_sources": ["ops/staging-access.md"]},
        )

        manifest = build_manifest(self.root, [source], profile, staging_root=self.staging)
        entry = manifest.entries[0]

        self.assertEqual("include", entry.classification)
        self.assertEqual("kb:demo:source:wiki:ops/staging-access.md", entry.document_id)
        self.assertEqual(hashlib.sha256(credential_text.encode("utf-8")).hexdigest(), entry.source_sha256)
        self.assertIsNone(entry.exported_sha256)
        self.assertIsNone(entry.export_path)
        self.assertEqual("allow_project_staging", dict(entry.metadata)["credential_policy"])
        self.assertEqual("ops/staging-access.md", dict(entry.metadata)["source_path"])
        self.assertFalse(self.staging.exists())
        self.assertEqual(credential_text, source.read_text(encoding="utf-8"))

    def test_missing_or_exclude_credential_policy_preserves_redaction(self) -> None:
        source = self.write("wiki/credentials.md", "password: staging-value\n")
        for policy in (None, "exclude"):
            with self.subTest(policy=policy):
                profile = dict(self.profile)
                if policy is not None:
                    profile["credential_policy"] = policy
                staging = self.staging / (policy or "default")
                entry = build_manifest(self.root, [source], profile, staging_root=staging).entries[0]
                self.assertEqual("include_redacted", entry.classification)
                self.assertEqual("password: [REDACTED]\n", (staging / "wiki/credentials.md").read_text(encoding="utf-8"))
                self.assertEqual("exclude", dict(entry.metadata)["credential_policy"])

    def test_allow_project_staging_can_retain_an_explicitly_selected_environment_source(self) -> None:
        source = self.write(".env.staging", "API_TOKEN=rotated-staging-token\n")
        entry = build_manifest(
            self.root, [source], dict(
                self.profile,
                credential_policy="allow_project_staging",
                reviewed=True,
                source_policy={"credential_sources": [".env.staging"]},
            )
        ).entries[0]
        self.assertEqual("include", entry.classification)
        self.assertEqual(hashlib.sha256(source.read_bytes()).hexdigest(), entry.source_sha256)
        self.assertIsNone(entry.exported_sha256)

    def test_allow_project_staging_requires_reviewed_profile_and_explicit_source_selection(self) -> None:
        source = self.write("ops/unselected.md", "password: staging-value\n")
        unreviewed = dict(
            self.profile,
            credential_policy="allow_project_staging",
            reviewed=False,
            source_policy={"credential_sources": ["ops/unselected.md"]},
        )
        with self.assertRaisesRegex(ValueError, "reviewed"):
            build_manifest(self.root, [source], unreviewed, staging_root=self.staging)

        reviewed_but_unselected = dict(
            self.profile,
            credential_policy="allow_project_staging",
            reviewed=True,
            source_policy={"credential_sources": ["ops/selected.md"]},
        )
        entry = build_manifest(
            self.root, [source], reviewed_but_unselected, staging_root=self.staging
        ).entries[0]
        self.assertEqual("include_redacted", entry.classification)
        self.assertEqual(
            "password: [REDACTED]\n",
            (self.staging / "ops/unselected.md").read_text(encoding="utf-8"),
        )

    def test_uses_hashes_for_unchanged_changed_and_deleted_without_duplicate_ids(self) -> None:
        guide = self.write("wiki/guide.md", "original\n")
        first = build_manifest(self.root, [guide], self.profile)
        unchanged = build_manifest(self.root, [guide], self.profile, previous_manifest=first)
        self.assertEqual("unchanged", unchanged.entries[0].delta)

        guide.write_text("changed\n", encoding="utf-8")
        changed = build_manifest(self.root, [guide], self.profile, previous_manifest=first)
        self.assertEqual("changed", changed.entries[0].delta)
        self.assertEqual(first.entries[0].document_id, changed.entries[0].document_id)

        deleted = build_manifest(self.root, [], self.profile, previous_manifest=first)
        self.assertEqual(["deleted"], [entry.delta for entry in deleted.deleted])
        self.assertEqual(first.entries[0].document_id, deleted.deleted[0].document_id)

    def test_unsafe_and_derived_candidates_are_recorded_but_never_staged(self) -> None:
        unsafe = self.write(".env", "PASSWORD=do-not-export\n")
        derived = self.write("graph/capsule.md", "derived only after audit\n")
        profile = dict(self.profile, derived_after_audit_paths=["graph/capsule.md"])

        manifest = build_manifest(self.root, [derived, unsafe], profile, staging_root=self.staging)
        entries = {entry.relative_path: entry for entry in manifest.entries}

        self.assertEqual("exclude", entries[".env"].classification)
        self.assertEqual("derived_after_audit", entries["graph/capsule.md"].classification)
        self.assertIsNone(entries[".env"].document_id)
        self.assertFalse(self.staging.exists())

    def test_logbook_events_have_stable_ids_and_rome_timestamps(self) -> None:
        logbook = self.write(
            "LOGBOOK.md",
            "### 2026-09-01 15:50 CEST - Export calendario\nDetails.\n\n"
            "### 2026-09-02 09:10 CEST - Fix routing\nDetails.\n",
        )
        profile = dict(self.profile, scope="project-logbook", event_paths=["LOGBOOK.md"])

        manifest = build_manifest(self.root, [logbook], profile, staging_root=self.staging)

        self.assertEqual(2, len(manifest.entries))
        self.assertEqual("kb:demo:event:project-logbook:2026-09-01T15-50:export-calendario", manifest.entries[0].document_id)
        self.assertEqual("2026-09-01T15:50:00+02:00", manifest.entries[0].event_timestamp)
        self.assertEqual("kind:event", manifest.entries[0].tags[0])

    def test_manifest_round_trips_reviewed_future_trust_and_knowledge_values(self) -> None:
        source = self.write("wiki/future.md", "safe\n")
        profile = dict(self.profile, trust="reviewed", knowledge_layer="architecture", topics=["topic:future-area"])
        manifest = build_manifest(self.root, [source], profile)
        entry = Manifest.from_dict(manifest.as_dict()).entries[0]
        self.assertIn("trust:reviewed", entry.tags); self.assertIn("knowledge:architecture", entry.tags)
        self.assertEqual("reviewed", dict(entry.metadata)["verification_status"])
        self.assertEqual("architecture", dict(entry.metadata)["knowledge_layer"])

    def test_duplicate_logbook_event_identity_is_rejected_and_escaping_symlink_is_not_read(self) -> None:
        logbook = self.write(
            "LOGBOOK.md",
            "### 2026-09-01 15:50 CEST - Same\na\n### 2026-09-01 15:50 CEST - Same\nb\n",
        )
        profile = dict(self.profile, event_paths=["LOGBOOK.md"])
        with self.assertRaises(ValueError):
            build_manifest(self.root, [logbook], profile, staging_root=self.staging)

        outside = Path(self.temporary.name) / "outside.txt"
        outside.write_text("password=outside-secret", encoding="utf-8")
        link = self.root / "wiki/link.md"
        link.parent.mkdir(exist_ok=True)
        link.symlink_to(outside)
        manifest = build_manifest(self.root, [link], self.profile)
        self.assertEqual("blocked_review", manifest.entries[0].classification)
        self.assertIsNone(manifest.entries[0].source_sha256)

    def test_persistent_manifest_round_trip_and_tamper_rejection(self) -> None:
        guide = self.write("wiki/guide.md", "safe\n")
        original = build_manifest(self.root, [guide], self.profile)
        destination = Path(self.temporary.name) / "manifest.json"
        write_manifest(destination, original)
        loaded = read_manifest(destination)
        self.assertEqual(original.as_dict(), loaded.as_dict())
        unchanged = build_manifest(self.root, [guide], self.profile, previous_manifest=json.loads(destination.read_text(encoding="utf-8")))
        self.assertEqual("unchanged", unchanged.entries[0].delta)
        payload = json.loads(destination.read_text(encoding="utf-8"))
        payload["entries"][0]["reason"] = "tampered"
        destination.write_text(json.dumps(payload), encoding="utf-8")
        with self.assertRaises(ValueError):
            read_manifest(destination)

    def test_event_staging_writes_only_exact_bounded_chunks(self) -> None:
        logbook = self.write("LOGBOOK.md", "### 2026-09-01 15:50 CEST - First\nfirst body\n\n### 2026-09-02 09:10 CEST - Second\nsecond body\n")
        profile = dict(self.profile, scope="project-logbook", event_paths=["LOGBOOK.md"])
        manifest = build_manifest(self.root, [logbook], profile, staging_root=self.staging)
        paths = [entry.export_path for entry in manifest.entries]
        self.assertEqual(2, len(set(paths)))
        self.assertTrue(all(path and path.startswith("events/") for path in paths))
        self.assertEqual("### 2026-09-01 15:50 CEST - First\nfirst body\n\n", (self.staging / paths[0]).read_text(encoding="utf-8"))
        self.assertFalse((self.staging / "LOGBOOK.md").exists())
        self.assertEqual(manifest.entries[0].source_sha256, hashlib.sha256((self.staging / paths[0]).read_bytes()).hexdigest())

    def test_event_heading_correction_reuses_unique_prior_timestamp_identity(self) -> None:
        logbook = self.write("LOGBOOK.md", "### 2026-09-01 15:50 CEST - Original title\nbody\n")
        profile = dict(self.profile, event_paths=["LOGBOOK.md"])
        first = build_manifest(self.root, [logbook], profile, staging_root=self.staging)
        original_id = first.entries[0].document_id
        logbook.write_text("### 2026-09-01 15:50 CEST - Corrected title\nbody revised\n", encoding="utf-8")
        changed = build_manifest(self.root, [logbook], profile, previous_manifest=first, staging_root=self.staging)
        self.assertEqual(original_id, changed.entries[0].document_id)
        self.assertEqual("changed", changed.entries[0].delta)

    def test_unique_same_hash_rename_is_reported_without_guessing_ambiguous_matches(self) -> None:
        original = self.write("wiki/old.md", "same\n")
        first = build_manifest(self.root, [original], self.profile)
        renamed = self.write("wiki/new.md", "same\n")
        second = build_manifest(self.root, [renamed], self.profile, previous_manifest=first)
        self.assertEqual("renamed", second.entries[0].delta)
        self.assertEqual("wiki/old.md", second.entries[0].renamed_from)
        self.assertEqual("deleted", second.deleted[0].delta)

    def test_rejects_symlinked_staging_root_without_touching_target(self) -> None:
        source = self.write("wiki/secret.md", "password=hidden\n")
        external = Path(self.temporary.name) / "external"
        external.mkdir()
        self.staging.symlink_to(external, target_is_directory=True)
        with self.assertRaises(ValueError):
            build_manifest(self.root, [source], self.profile, staging_root=self.staging)
        self.assertEqual([], list(external.iterdir()))

    def test_grandparent_staging_symlink_is_rejected_without_changing_external_mode(self) -> None:
        source = self.write("wiki/secret.md", "password=hidden\n")
        external = Path(self.temporary.name) / "external"
        external.mkdir(mode=0o755)
        link_parent = Path(self.temporary.name) / "linked-parent"
        link_parent.symlink_to(external, target_is_directory=True)
        requested = link_parent / "nested" / "stage"
        before_mode = external.stat().st_mode & 0o777
        with self.assertRaises(ValueError):
            build_manifest(self.root, [source], self.profile, staging_root=requested)
        self.assertEqual(before_mode, external.stat().st_mode & 0o777)
        self.assertEqual([], list(external.iterdir()))

    def test_redacted_candidate_without_staging_is_blocked_review(self) -> None:
        source = self.write("wiki/secret.md", "password=hidden\n")
        manifest = build_manifest(self.root, [source], self.profile)
        entry = manifest.entries[0]
        self.assertEqual("blocked_review", entry.classification)
        self.assertIsNone(entry.document_id)
        self.assertIsNone(entry.export_path)

    def test_validation_detects_tampered_staged_content_and_escape_locator(self) -> None:
        source = self.write("wiki/secret.md", "password=hidden\n")
        manifest = build_manifest(self.root, [source], self.profile, staging_root=self.staging)
        validate_manifest_files(manifest, self.root, self.staging)
        (self.staging / manifest.entries[0].export_path).write_text("tampered", encoding="utf-8")
        with self.assertRaises(ValueError):
            validate_manifest_files(manifest, self.root, self.staging)
        payload = manifest.as_dict()
        payload["entries"][0]["export_path"] = "../../outside"
        payload["manifest_sha256"] = hashlib.sha256(json.dumps({"entries": payload["entries"], "deleted": payload["deleted"]}, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        with self.assertRaises(ValueError):
            Manifest.from_dict(payload)

    def test_persisted_manifest_rejects_invalid_controlled_tags_and_cross_section_duplicate_id(self) -> None:
        source = self.write("wiki/guide.md", "safe\n")
        manifest = build_manifest(self.root, [source], self.profile)
        payload = manifest.as_dict()
        payload["entries"][0]["tags"] = ["user:", "project:demo", "kind:banana", "scope:wiki", "trust:invented", "knowledge:whatever"]
        payload["manifest_sha256"] = hashlib.sha256(json.dumps({"entries": payload["entries"], "deleted": payload["deleted"]}, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        with self.assertRaises(ValueError):
            Manifest.from_dict(payload)
        payload = manifest.as_dict()
        payload["deleted"] = [dict(payload["entries"][0], delta="deleted")]
        payload["manifest_sha256"] = hashlib.sha256(json.dumps({"entries": payload["entries"], "deleted": payload["deleted"]}, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        with self.assertRaises(ValueError):
            Manifest.from_dict(payload)

    def test_event_validation_detects_changed_logbook_container(self) -> None:
        logbook = self.write("LOGBOOK.md", "### 2026-09-01 15:50 CEST - First\nbody\n")
        profile = dict(self.profile, event_paths=["LOGBOOK.md"])
        manifest = build_manifest(self.root, [logbook], profile, staging_root=self.staging)
        logbook.write_text("### 2026-09-01 15:50 CEST - First\nchanged\n", encoding="utf-8")
        with self.assertRaises(ValueError):
            validate_manifest_files(manifest, self.root, self.staging)

    def test_nested_existing_staging_symlink_is_rejected_without_external_mutation(self) -> None:
        source = self.write("wiki/secret.md", "password=hidden\n")
        external = Path(self.temporary.name) / "external"
        (external / "nested" / "stage").mkdir(parents=True, mode=0o755)
        link = Path(self.temporary.name) / "link"
        link.symlink_to(external, target_is_directory=True)
        before = (external / "nested" / "stage").stat().st_mode & 0o777
        with self.assertRaises(ValueError):
            build_manifest(self.root, [source], self.profile, staging_root=link / "nested" / "stage")
        self.assertEqual(before, (external / "nested" / "stage").stat().st_mode & 0o777)
        self.assertEqual([], list((external / "nested" / "stage").iterdir()))

    def test_persisted_manifest_allows_multiple_topics_but_rejects_kind_and_metadata_mismatch(self) -> None:
        source = self.write("wiki/guide.md", "safe\n")
        profile = dict(self.profile, topics=["topic:architecture", "topic:security"])
        manifest = build_manifest(self.root, [source], profile)
        self.assertIn("topic:architecture", manifest.entries[0].tags)
        self.assertIn("topic:security", manifest.entries[0].tags)
        payload = manifest.as_dict()
        payload["entries"][0]["tags"] = [tag if tag != "kind:source" else "kind:event" for tag in payload["entries"][0]["tags"]]
        payload["manifest_sha256"] = hashlib.sha256(json.dumps({"entries": payload["entries"], "deleted": payload["deleted"]}, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        with self.assertRaises(ValueError):
            Manifest.from_dict(payload)

    def test_persisted_manifest_requires_exact_mtime_and_knowledge_and_handles_repeatable_tags(self) -> None:
        source = self.write("wiki/guide.md", "safe\n")
        manifest = build_manifest(self.root, [source], self.profile)
        payload = manifest.as_dict()
        payload["entries"][0]["tags"].extend(["team:platform", "team:backend"])
        payload["manifest_sha256"] = hashlib.sha256(json.dumps({"entries": payload["entries"], "deleted": payload["deleted"]}, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        Manifest.from_dict(payload)
        payload["entries"][0]["metadata"]["source_modified_at"] = "wrong"
        payload["manifest_sha256"] = hashlib.sha256(json.dumps({"entries": payload["entries"], "deleted": payload["deleted"]}, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        with self.assertRaises(ValueError): Manifest.from_dict(payload)
        payload = manifest.as_dict()
        payload["entries"][0]["tags"].extend(["team:platform", "team:platform"])
        payload["manifest_sha256"] = hashlib.sha256(json.dumps({"entries": payload["entries"], "deleted": payload["deleted"]}, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        with self.assertRaises(ValueError): Manifest.from_dict(payload)

    def test_validate_rejects_deep_and_internal_staging_symlinks_before_read(self) -> None:
        source = self.write("wiki/secret.md", "password=hidden\n")
        manifest = build_manifest(self.root, [source], self.profile, staging_root=self.staging)
        external = Path(self.temporary.name) / "external"
        external.mkdir()
        deep = self.staging / "deep"
        deep.symlink_to(external, target_is_directory=True)
        with self.assertRaises(ValueError): validate_manifest_files(manifest, self.root, self.staging)

    def test_validate_rejects_intermediate_in_root_source_symlink(self) -> None:
        nested = self.root / "nested"; nested.mkdir()
        source = nested / "safe.md"; source.write_text("safe\n", encoding="utf-8")
        manifest = build_manifest(self.root, [source], self.profile, staging_root=self.staging)
        target = self.root / "real"; nested.rename(target)
        nested.symlink_to(target, target_is_directory=True)
        with self.assertRaises(ValueError): validate_manifest_files(manifest, self.root, self.staging)

    def test_persisted_manifest_rejects_secret_metadata_but_keeps_future_safe_metadata(self) -> None:
        source = self.write("wiki/guide.md", "safe\n")
        manifest = build_manifest(self.root, [source], self.profile)
        payload = manifest.as_dict()
        payload["entries"][0]["metadata"].update({"token_budget": "800", "secret_handling_policy": "reviewed", "future_trust": "reviewed"})
        payload["manifest_sha256"] = hashlib.sha256(json.dumps({"entries": payload["entries"], "deleted": payload["deleted"]}, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        Manifest.from_dict(payload)
        payload["entries"][0]["metadata"]["clientSecret"] = GITHUB_TOKEN_CANARY
        payload["manifest_sha256"] = hashlib.sha256(json.dumps({"entries": payload["entries"], "deleted": payload["deleted"]}, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        with self.assertRaises(ValueError):
            Manifest.from_dict(payload)


if __name__ == "__main__":
    unittest.main()
