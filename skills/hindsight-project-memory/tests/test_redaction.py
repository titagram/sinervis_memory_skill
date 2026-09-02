"""Behavioral tests for the deterministic local sensitive-data preflight."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path


SKILL_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SKILL_ROOT / "scripts"))

from project_memory.redaction import ScanResult, scan_text  # noqa: E402

GITHUB_TOKEN_CANARY = "ghp_" + "abcdefghijklmnopqrstuvwxyz1234567890"


class RedactionTests(unittest.TestCase):
    def test_blocks_private_key_without_recording_value(self) -> None:
        result = scan_text("wiki/keys.md", "-----BEGIN PRIVATE KEY-----\nvery-secret\n")

        self.assertEqual("blocked", result.decision)
        self.assertIsNone(result.exported_text)
        self.assertEqual("private_key_material", result.findings[0].rule)
        self.assertNotIn("very-secret", repr(result))

    def test_redacts_multiple_semantic_assignment_variants_without_value_leakage(self) -> None:
        source = "api_token: abcdefghijklmnopqrstuvwxyz\npassword = 'cleartext'\n"
        result = scan_text("wiki/runbook.md", source)

        self.assertEqual("redacted", result.decision)
        self.assertEqual(
            "api_token: [REDACTED]\npassword = '[REDACTED]'\n", result.exported_text
        )
        self.assertEqual([(1, "credential_assignment"), (2, "credential_assignment")], [
            (finding.line, finding.rule) for finding in result.findings
        ])
        self.assertNotIn("abcdefghijklmnopqrstuvwxyz", repr(result))
        self.assertNotIn("cleartext", repr(result))

    def test_blocks_environment_and_sensitive_paths_before_content(self) -> None:
        for candidate in (".env", "config/.env.local", "database/prod.sql", "uploads/42.pdf", "payroll/may.csv", "medical/record.txt", "vendor/a.php", "public/build/app.js"):
            with self.subTest(candidate=candidate):
                result = scan_text(candidate, "harmless prose")
                self.assertEqual("blocked", result.decision)
                self.assertIsNone(result.exported_text)
                self.assertTrue(result.findings[0].rule.startswith("path_"))

    def test_preserves_harmless_secret_handling_prose_and_placeholders(self) -> None:
        source = (
            "The token budget is 800. Secret handling is mandatory.\n"
            "Set API_TOKEN=<TOKEN>, API_TOKEN=${ENV_VAR}, or API_TOKEN=[REDACTED].\n"
            "Example UUID 550e8400-e29b-41d4-a716-446655440000 and sha256 deadbeef are normal.\n"
        )
        result = scan_text("README.md", source)

        self.assertEqual("safe", result.decision)
        self.assertEqual(source, result.exported_text)
        self.assertEqual((), result.findings)

    def test_only_conventional_placeholders_survive_sensitive_assignments(self) -> None:
        safe = scan_text("docs/security.md", "api_key=<YOUR_TOKEN>\npassword=${PASSWORD}\nsecret=CHANGEME\n")
        self.assertEqual("safe", safe.decision)
        unsafe = scan_text("docs/security.md", f"api_key=<{GITHUB_TOKEN_CANARY}>\npassword=<hunter2>\n")
        self.assertEqual("redacted", unsafe.decision)
        self.assertNotIn("ghp_", unsafe.exported_text or "")
        self.assertNotIn("hunter2", unsafe.exported_text or "")

    def test_preserves_placeholder_forms_with_sentence_punctuation_and_quotes(self) -> None:
        source = 'api_token=<YOUR_TOKEN>.\napi_key=${API_KEY};\nPassword: "[REDACTED]."\n'
        result = scan_text("docs/security.md", source)
        self.assertEqual("safe", result.decision)
        self.assertEqual(source, result.exported_text)
        unsafe = scan_text("docs/security.md", f"api_token=<{GITHUB_TOKEN_CANARY}>.\n")
        self.assertEqual("redacted", unsafe.decision)
        self.assertNotIn("ghp_", unsafe.exported_text or "")

    def test_redacts_bearer_in_inline_and_fenced_markdown(self) -> None:
        source = "Use `Authorization: Bearer abcdefghijklmnop` here.\n```yaml\naccess-token: zxcasdqwepoiuytr\n```\n"
        result = scan_text("wiki/api.md", source)

        self.assertEqual("redacted", result.decision)
        self.assertEqual("Use `Authorization: Bearer [REDACTED]` here.\n```yaml\naccess-token: [REDACTED]\n```\n", result.exported_text)
        self.assertEqual([1, 3], [finding.line for finding in result.findings])

    def test_redacts_recognized_opaque_api_key_instead_of_blocking_it_as_unknown(self) -> None:
        result = scan_text("wiki/api.md", "api-key=6Ba8LXlT7M8bEo9kw5VfKZr2NcQqP0dYsHj1WuIx\n")

        self.assertEqual("redacted", result.decision)
        self.assertEqual("api-key=[REDACTED]\n", result.exported_text)

    def test_redacts_prefixed_camel_case_password_and_full_bearer_assignment_value(self) -> None:
        source = "DEPLOY_PASSWORD=fake-demo-value-123 # keep comment\napi-token: Bearer abcdefghijklmnop\n"
        result = scan_text("docs/example.md", source)

        self.assertEqual("redacted", result.decision)
        self.assertEqual("DEPLOY_PASSWORD=[REDACTED] # keep comment\napi-token: [REDACTED]\n", result.exported_text)
        self.assertEqual([1, 2], [finding.line for finding in result.findings])
        self.assertNotIn("fake-demo-value-123", repr(result))
        self.assertNotIn("abcdefghijklmnop", repr(result))

    def test_allows_env_templates_and_policy_paths_but_blocks_sensitive_segment_variants(self) -> None:
        for candidate in (".env.example", "config/.env.sample", "templates/.env.template", "docs/payroll-guideline.md", "docs/customer-data-policy.md"):
            with self.subTest(candidate=candidate):
                self.assertEqual("safe", scan_text(candidate, "token budget policy\n").decision)
        for candidate in ("payroll-data/june.txt", "medical-records/a.txt", "health-records/a.txt", "customer-dumps/a.txt", "customer-data/rows.csv"):
            with self.subTest(candidate=candidate):
                self.assertEqual("blocked", scan_text(candidate, "safe prose\n").decision)

    def test_env_template_blocks_concrete_credentials_instead_of_exporting_redaction(self) -> None:
        result = scan_text(".env.example", "DEPLOY_PASSWORD=fake-demo-value-123\n")

        self.assertEqual("blocked", result.decision)
        self.assertIsNone(result.exported_text)

    def test_blocks_concatenated_record_domains_and_raw_policy_compounds_only_when_raw_indicator_exists(self) -> None:
        for candidate in ("data/customerRecords.csv", "medicalRecords/a.txt", "payrollrecords/a.txt", "customer-dump-policy/raw.csv"):
            with self.subTest(candidate=candidate):
                self.assertEqual("blocked", scan_text(candidate, "safe\n").decision)
        for candidate in ("docs/customer-data-policy.md", "docs/payroll-policy.md", "docs/medical-guidelines.md"):
            with self.subTest(candidate=candidate):
                self.assertEqual("safe", scan_text(candidate, "safe\n").decision)

    def test_customer_journey_document_is_not_treated_as_customer_data(self) -> None:
        self.assertEqual("safe", scan_text("docs/customer-journey.md", "Product onboarding\n").decision)

    def test_blocks_binary_and_unknown_high_entropy_assignment(self) -> None:
        binary = scan_text("notes.txt", b"plain\x00data")
        unknown = scan_text("notes.txt", "integration_blob=6Ba8LXlT7M8bEo9kw5VfKZr2NcQqP0dYsHj1WuIx\n")

        self.assertEqual("blocked", binary.decision)
        self.assertEqual("binary_content", binary.findings[0].rule)
        self.assertEqual("blocked", unknown.decision)
        self.assertEqual("unknown_high_entropy_assignment", unknown.findings[0].rule)

    def test_scan_result_and_finding_are_immutable_typed_records(self) -> None:
        result = scan_text("notes.txt", "safe")

        self.assertIsInstance(result, ScanResult)
        with self.assertRaises((AttributeError, TypeError)):
            result.decision = "blocked"  # type: ignore[misc]


if __name__ == "__main__":
    unittest.main()
