"""Tests for append-only project-memory audit events."""

import json
import stat
import sys
import tempfile
import unittest
from pathlib import Path


SCRIPTS_ROOT = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPTS_ROOT))

from project_memory.audit import append_audit  # noqa: E402

GITHUB_TOKEN_CANARY = "ghp_" + "abcdefghijklmnopqrstuvwxyz1234567890"
JWT_CANARY = "eyJ" + "abcde.abcdef.abcdef"


class AuditTests(unittest.TestCase):
    def test_append_audit_writes_one_json_object_per_line(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "audit.jsonl"
            event = {"operator": "alice", "action": "register", "result": "ok"}
            append_audit(path, event)
            rows = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]
            self.assertEqual([event], rows)

    def test_append_audit_rejects_secret_fields(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "audit.jsonl"
            with self.assertRaisesRegex(ValueError, "secret field"):
                append_audit(path, {"apiToken": "not-allowed"})

    def test_audit_rejects_concrete_credential_values_but_preserves_safe_policy_metrics_and_prose(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "audit.jsonl"
            for value in (f"Bearer {GITHUB_TOKEN_CANARY}", JWT_CANARY, f"password={GITHUB_TOKEN_CANARY}"):
                with self.assertRaisesRegex(ValueError, "credential-shaped"):
                    append_audit(path, {"message": value})
            append_audit(path, {"token_budget": 100, "total_tokens": 3, "content_hash": "a" * 64, "note": "Secret policy and API token budget are documented."})
            self.assertIn("token_budget", path.read_text(encoding="utf-8"))

    def test_audit_allows_documentation_placeholders_but_not_concrete_assignments(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "audit.jsonl"
            append_audit(path, {"note": "Set api_token=<YOUR_TOKEN> or api_key=${API_KEY} in local docs."})
            self.assertTrue(path.exists())

    def test_audit_rejects_concrete_bracketed_and_semantic_secret_keys_without_blocking_policy_keys(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "audit.jsonl"
            with self.assertRaisesRegex(ValueError, "credential-shaped"):
                append_audit(path, {"note": f"api_key=<{GITHUB_TOKEN_CANARY}>"})
            for key in ("clientSecret", "signing-secret", "webhook_secret"):
                with self.assertRaisesRegex(ValueError, "secret field"):
                    append_audit(path, {key: "not-logged"})
            append_audit(path, {"client_secret_rotation_policy": "weekly", "secret_handling_policy": "documented"})

    def test_append_audit_requires_a_json_object(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "audit.jsonl"
            with self.assertRaisesRegex(ValueError, "JSON object"):
                append_audit(path, ["not", "an", "event"])
            self.assertFalse(path.exists())

    def test_append_audit_rejects_nested_forbidden_key_case_insensitively(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "audit.jsonl"
            with self.assertRaisesRegex(ValueError, "secret field"):
                append_audit(path, {"details": [{"PRIVATE_KEY_hint": "not-allowed"}]})
            self.assertFalse(path.exists())

    def test_append_audit_rejects_private_key_separator_and_camel_case_variants(self):
        forbidden_keys = ("privateKey", "private-key", "PRIVATE.KEY", "private key")
        with tempfile.TemporaryDirectory() as directory:
            for forbidden_key in forbidden_keys:
                with self.subTest(forbidden_key=forbidden_key):
                    path = Path(directory) / (forbidden_key.replace(" ", "-") + ".jsonl")
                    with self.assertRaisesRegex(ValueError, "secret field"):
                        append_audit(path, {"nested": {forbidden_key: "not-allowed"}})
                    self.assertFalse(path.exists())

    def test_append_audit_rejects_embedded_private_key_variants(self):
        forbidden_keys = (
            "private_keyvalue",
            "prefix_private-key_suffix",
            "myPrivateKeyHint",
        )
        with tempfile.TemporaryDirectory() as directory:
            for forbidden_key in forbidden_keys:
                with self.subTest(forbidden_key=forbidden_key):
                    path = Path(directory) / (forbidden_key + ".jsonl")
                    with self.assertRaisesRegex(ValueError, "secret field"):
                        append_audit(path, {"nested": {forbidden_key: "not-allowed"}})
                    self.assertFalse(path.exists())

    def test_append_audit_does_not_mutate_existing_log_on_invalid_event(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "audit.jsonl"
            path.write_text('{"result":"ok"}\n', encoding="utf-8")
            before = path.read_bytes()
            with self.assertRaisesRegex(ValueError, "secret field"):
                append_audit(path, {"content": "not-allowed"})
            self.assertEqual(before, path.read_bytes())

    def test_append_audit_does_not_create_parent_for_unserializable_event(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "state" / "audit.jsonl"
            with self.assertRaises(TypeError):
                append_audit(path, {"metadata": {"unsupported": {"value"}}})
            self.assertFalse(path.parent.exists())
            self.assertFalse(path.exists())

    def test_append_audit_applies_private_parent_and_file_modes(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "state" / "audit.jsonl"
            append_audit(path, {"action": "register"})
            self.assertEqual(0o700, stat.S_IMODE(path.parent.stat().st_mode))
            self.assertEqual(0o600, stat.S_IMODE(path.stat().st_mode))

    def test_append_audit_rejects_full_quoted_credential_without_accepting_suffix(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "audit.jsonl"
            with self.assertRaisesRegex(ValueError, "credential-shaped"):
                append_audit(path, {"note": 'password="correct horse battery staple"'})
            self.assertFalse(path.exists())

    def test_append_audit_keeps_conventional_placeholder_with_punctuation(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "audit.jsonl"
            append_audit(path, {"note": 'api_token=<YOUR_TOKEN>. api_key=${API_KEY}; Password: "[REDACTED]."'})
            self.assertTrue(path.exists())

    def test_credential_opt_in_audit_is_content_free_and_rejects_retained_values(self):
        canary = "STAGING-CREDENTIAL-CANARY-82491"
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "audit.jsonl"
            append_audit(path, {
                "action": "retain",
                "credential_policy": "allow_project_staging",
                "credential_bearing_records_included": True,
                "document_count": 1,
            })
            with self.assertRaisesRegex(ValueError, "credential-shaped"):
                append_audit(path, {"summary": "password=" + canary})
            encoded = path.read_text(encoding="utf-8")
            self.assertIn("credential_bearing_records_included", encoded)
            self.assertNotIn(canary, encoded)

    def test_audit_rejects_credential_inside_json_serialized_diagnostic_text(self):
        canary = "STAGING-CREDENTIAL-CANARY-JSON-1957"
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "audit.jsonl"
            message = "upstream echoed " + json.dumps({"password": canary})
            with self.assertRaisesRegex(ValueError, "credential-shaped"):
                append_audit(path, {"message": message})
            self.assertFalse(path.exists())

    def test_audit_rejects_complete_private_key_and_certificate_blocks(self):
        fixtures = (
            "-----BEGIN PRIVATE KEY-----\nPRIVATE-BODY-AUDIT-CANARY\n-----END PRIVATE KEY-----",
            "-----BEGIN CERTIFICATE-----\nCERTIFICATE-BODY-AUDIT-CANARY\n-----END CERTIFICATE-----",
        )
        with tempfile.TemporaryDirectory() as directory:
            for index, fixture in enumerate(fixtures):
                path = Path(directory) / (str(index) + ".jsonl")
                with self.subTest(index=index), self.assertRaisesRegex(ValueError, "credential-shaped"):
                    append_audit(path, {"message": fixture})
                self.assertFalse(path.exists())


if __name__ == "__main__":
    unittest.main()
