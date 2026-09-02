import io
import importlib.util
import json
import dataclasses
import hashlib
import sys
import tempfile
import unittest
from pathlib import Path
from urllib.error import HTTPError, URLError

SCRIPTS_ROOT = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPTS_ROOT))

from project_memory.transport import HindsightTransport, TransportError, load_hindsight_config
from project_memory.manifest import Manifest, build_manifest as _build_manifest, write_manifest

GITHUB_TOKEN_CANARY = "ghp_" + "abcdefghijklmnopqrstuvwxyz1234567890"


def build_manifest(root, candidates, profile, *args, **kwargs):
    if "operator" not in kwargs and isinstance(profile.get("operator"), str):
        kwargs["operator"] = profile["operator"]
    return _build_manifest(root, candidates, profile, *args, **kwargs)

_CLI_SPEC = importlib.util.spec_from_file_location("project_memory_cli_task7", SCRIPTS_ROOT / "project_memory.py")
CLI_MODULE = importlib.util.module_from_spec(_CLI_SPEC); _CLI_SPEC.loader.exec_module(CLI_MODULE)


class Response:
    def __init__(self, value): self.value = value
    def read(self): return json.dumps(self.value).encode()
    def close(self): pass


class RawResponse:
    def __init__(self, raw): self.raw = raw
    def read(self): return self.raw
    def close(self): pass


class RecordingOpener:
    def __init__(self, replies):
        self.replies = list(replies if isinstance(replies, list) else [replies]); self.requests = []; self.timeouts = []
    def __call__(self, request, timeout=None):
        self.requests.append(request); self.timeouts.append(timeout)
        value = self.replies.pop(0)
        if isinstance(value, BaseException): raise value
        if hasattr(value, "read"): return value
        return Response(value)


class TransportTests(unittest.TestCase):
    def test_async_retain_uses_idempotent_operation_id_and_encoded_bank(self):
        opener = RecordingOpener({"operation_id": "op-1", "status": "pending"})
        client = HindsightTransport("https://memory.example", "secret-value", opener=opener)
        result = client.submit_retain("owner::project", [{"content": "safe"}], "op-1")
        request = opener.requests[0]
        self.assertTrue(request.full_url.endswith("/v1/default/banks/owner%3A%3Aproject/memories"))
        self.assertEqual("Bearer secret-value", request.headers["Authorization"])
        self.assertEqual({"items": [{"content": "safe"}], "async": True, "operation_id": "op-1"}, json.loads(request.data))
        self.assertNotIn("secret-value", json.dumps(result))

    def test_pending_post_is_acknowledged_not_completed(self):
        client = HindsightTransport("https://memory.example", "token", opener=RecordingOpener({"operation_id": "op", "status": "pending"}))
        result = client.submit_retain("bank", [{"content": "safe"}], "op")
        self.assertEqual("acknowledged", result["status"])
        self.assertEqual("pending", result["remote_status"])

    def test_pending_non_retain_mutation_without_operation_id_is_uncertain(self):
        client = HindsightTransport("https://memory.example", "token", opener=RecordingOpener({"status": "pending"}))
        with self.assertRaises(TransportError) as caught:
            client.consolidate("bank")
        self.assertTrue(caught.exception.uncertain)

    def test_queued_refresh_is_acknowledged_but_get_lifecycle_stays_strict(self):
        client = HindsightTransport("https://memory.example", "token", opener=RecordingOpener({"operation_id": "op", "status": "queued"}))
        result = client.refresh_mental_model("bank", "model")
        self.assertEqual("acknowledged", result["status"])
        self.assertEqual("queued", result["remote_status"])
        lifecycle = HindsightTransport("https://memory.example", "token", opener=RecordingOpener({"operation_id": "op", "status": "queued"}))
        with self.assertRaises(TransportError):
            lifecycle.wait_operation("bank", "op", deadline_seconds=1)

    def test_queued_knowledge_page_requires_identifiers_and_accepts_complete_ack(self):
        page = {"name": "Page", "source_query": "Q"}
        client = HindsightTransport("https://memory.example", "token", opener=RecordingOpener({"operation_id": "op", "page_id": "page", "mental_model_id": "model", "status": "queued"}))
        self.assertEqual("acknowledged", client.create_knowledge_page("bank", page)["status"])
        malformed = HindsightTransport("https://memory.example", "token", opener=RecordingOpener({"operation_id": "op", "page_id": "page", "status": "queued"}))
        with self.assertRaises(TransportError):
            malformed.create_knowledge_page("bank", page)

    def test_transport_removes_full_quoted_credential_value(self):
        from project_memory.transport import sanitize
        result = sanitize({"note": 'password="correct horse battery staple"'})
        self.assertNotIn("correct horse battery staple", result["note"])
        self.assertNotIn("horse", result["note"])

    def test_transport_keeps_punctuated_conventional_placeholders(self):
        from project_memory.transport import sanitize
        result = sanitize({"note": 'api_token=<YOUR_TOKEN>. api_key=${API_KEY}; Password: "[REDACTED]."'})
        self.assertIn("<YOUR_TOKEN>", result["note"])
        self.assertIn("${API_KEY}", result["note"])
        self.assertIn("[REDACTED]", result["note"])

    def test_transport_sanitizes_serialized_and_escaped_credentials_without_changing_retain_payload(self):
        from project_memory.transport import sanitize
        canary = 'stage-value-with-"quoted"-part'
        diagnostics = {
            "json_echo": "upstream echoed " + json.dumps({"password": canary}),
            "quoted_echo": 'password="stage-value-with-\\"quoted\\"-part"',
        }
        safe = sanitize(diagnostics)
        safe_values = " ".join(safe.values())
        self.assertNotIn("stage-value", safe_values)
        self.assertNotIn("quoted", safe_values)

        item = {
            "content": 'password: stage-value-with-"quoted"-part\n',
            "document_id": "kb:demo:source:wiki:ops/staging.md",
            "metadata": {"credential_policy": "allow_project_staging"},
        }
        opener = RecordingOpener({"operation_id": "op-stage", "status": "pending", "message": diagnostics["json_echo"]})
        client = HindsightTransport("https://memory.example", "configured-token", opener=opener)
        result = client.submit_retain("owner::demo", [item], "op-stage")
        self.assertEqual(item, json.loads(opener.requests[0].data)["items"][0])
        self.assertNotIn("stage-value", json.dumps(result))

    def test_transport_sanitizes_complete_private_key_and_certificate_blocks(self):
        from project_memory.transport import sanitize
        private_key = "-----BEGIN PRIVATE KEY-----\nPRIVATE-BODY-CANARY\n-----END PRIVATE KEY-----"
        certificate = "-----BEGIN CERTIFICATE-----\nCERTIFICATE-BODY-CANARY\n-----END CERTIFICATE-----"
        encoded = json.dumps(sanitize({"private": private_key, "certificate": certificate}))
        self.assertNotIn("PRIVATE-BODY-CANARY", encoded)
        self.assertNotIn("CERTIFICATE-BODY-CANARY", encoded)
        self.assertNotIn("END PRIVATE KEY", encoded)
        self.assertNotIn("END CERTIFICATE", encoded)

    def test_knowledge_page_acknowledgement_requires_all_official_identifiers(self):
        client = HindsightTransport("https://memory.example", "token", opener=RecordingOpener({"operation_id": "op", "status": "pending", "page_id": "page"}))
        with self.assertRaises(TransportError) as caught:
            client.create_knowledge_page("bank", {"name": "Page", "source_query": "Q"})
        self.assertTrue(caught.exception.uncertain)

    def test_safe_config_and_config_loader_never_return_token(self):
        client = HindsightTransport("https://memory.example", "secret-value", opener=RecordingOpener({}))
        self.assertEqual({"api_url": "https://memory.example", "authenticated": True}, client.safe_config())
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "h.json"; path.write_text(json.dumps({"apiUrl": "https://memory.example", "apiToken": "secret-value"}))
            config = load_hindsight_config(str(path))
            self.assertEqual("https://memory.example", config["api_url"])
            self.assertNotIn("secret-value", json.dumps(client.safe_config()))

    def test_config_loader_accepts_codex_integration_field_names(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "codex.json"
            path.write_text(json.dumps({
                "hindsightApiUrl": "https://memory.example",
                "hindsightApiToken": "secret-value",
                "bankId": "owner::project",
            }))

            config = load_hindsight_config(str(path))

            self.assertEqual("https://memory.example", config["api_url"])
            self.assertEqual("secret-value", config["api_token"])

    def test_operations_paths_are_encoded_and_get_excludes_payload(self):
        opener = RecordingOpener([{"items": [], "total": 0, "limit": 100, "offset": 0}, {"id": "operation / one", "status": "pending", "task_payload": {"content": "no"}}, {"operation_id": "con-op"}, {}, {"operation_id": "refresh-op"}])
        client = HindsightTransport("https://memory.example", "secret-value", opener=opener)
        client.list_documents("owner/a b")
        operation = client.get_operation("owner/a b", "operation / one")
        client.consolidate("owner/a b"); client.get_knowledge_tree("owner/a b")
        client.refresh_mental_model("owner/a b", "model / one")
        self.assertIn("owner%2Fa%20b/documents", opener.requests[0].full_url)
        self.assertTrue(opener.requests[1].full_url.endswith("operations/operation%20%2F%20one?include_payload=false"))
        self.assertNotIn("task_payload", operation)
        self.assertEqual("POST", opener.requests[2].method)
        self.assertTrue(opener.requests[3].full_url.endswith("knowledge-base/tree"))
        self.assertTrue(opener.requests[4].full_url.endswith("mental-models/model%20%2F%20one/refresh"))

    def test_explicit_knowledge_page_read_preserves_inspection_body_only(self):
        opener = RecordingOpener({
            "id": "page / one", "name": "Architecture", "type": "knowledge-page",
            "description": "How is it built?", "tags": ["knowledge:component"],
            "body": "# Architecture\nGrounded result.\n",
            "markdown": "---\nname: Architecture\n---\n# Architecture\nGrounded result.\n",
            "message": "password=server-diagnostic configured-token",
        })
        client = HindsightTransport("https://memory.example", "configured-token", opener=opener)

        page = client.get_knowledge_page("owner::demo", "page / one")

        self.assertTrue(opener.requests[0].full_url.endswith("knowledge-base/pages/page%20%2F%20one"))
        self.assertEqual("# Architecture\nGrounded result.\n", page["body"])
        self.assertNotIn("message", page)
        self.assertNotIn("configured-token", json.dumps(page))

    def test_token_is_not_in_errors_for_http_network_invalid_json_or_server_echo(self):
        token = "secret-value"
        http = HTTPError("https://x", 400, "bad", {}, io.BytesIO(b'{"message":"secret-value", "content":"leak"}'))
        for opener in (RecordingOpener(http), RecordingOpener(URLError(token)), RecordingOpener(RawResponse(b"bad"))):
            client = HindsightTransport("https://memory.example", token, opener=opener)
            with self.assertRaises(TransportError) as caught: client.list_documents("bank")
            self.assertNotIn(token, str(caught.exception)); self.assertNotIn(token, json.dumps(caught.exception.safe_result()))

    def test_list_documents_preserves_items_metadata_and_pagination_without_content_or_diagnostics(self):
        token = "configured-token"
        opener = RecordingOpener({
            "items": [
                {"id": "doc-1", "content_hash": "a" * 64, "document_metadata": {"source_path": "wiki/a.md", "items": ["component-a"], "apiToken": "should-not-leak"}, "original_text": "private body"},
                {"id": "doc-2", "content_hash": "b" * 64, "document_metadata": {"source_path": "wiki/b.md"}},
            ],
            "total": 12,
            "limit": 2,
            "offset": 4,
            "message": "password=server-diagnostic " + token,
        })
        client = HindsightTransport("https://memory.example", token, opener=opener)

        result = client.list_documents("owner::project")

        self.assertEqual(["doc-1", "doc-2"], [item["id"] for item in result["items"]])
        self.assertEqual("wiki/a.md", result["items"][0]["document_metadata"]["source_path"])
        self.assertEqual(["component-a"], result["items"][0]["document_metadata"]["items"])
        self.assertEqual("<redacted>", result["items"][0]["document_metadata"]["apiToken"])
        self.assertEqual({"total": 12, "limit": 2, "offset": 4}, {key: result[key] for key in ("total", "limit", "offset")})
        self.assertNotIn("original_text", result["items"][0])
        self.assertNotIn("message", result)
        self.assertNotIn(token, json.dumps(result))
        self.assertNotIn("should-not-leak", json.dumps(result))

    def test_list_documents_requests_the_selected_page(self):
        opener = RecordingOpener({"items": [], "total": 220, "limit": 20, "offset": 40})
        client = HindsightTransport("https://memory.example", "token", opener=opener)

        result = client.list_documents("owner::project", limit=20, offset=40)

        self.assertEqual({"items": [], "total": 220, "limit": 20, "offset": 40}, result)
        self.assertTrue(opener.requests[0].full_url.endswith("/documents?limit=20&offset=40"))

    def test_get_mental_model_preserves_configuration_needed_for_page_verification(self):
        opener = RecordingOpener({
            "id": "model-1", "name": "Architecture", "source_query": "How is it built?",
            "content": "Grounded body.", "tags": ["knowledge:component"], "max_tokens": 4096,
            "trigger": {"mode": "delta", "fact_types": ["observation"], "refresh_after_consolidation": True},
        })
        client = HindsightTransport("https://memory.example", "token", opener=opener)

        model = client.get_mental_model("owner::project", "model-1")

        self.assertEqual(["knowledge:component"], model["tags"])
        self.assertEqual(4096, model["max_tokens"])
        self.assertEqual("delta", model["trigger"]["mode"])

    def test_sanitizer_preserves_safe_metrics_and_hashes_but_scrubs_independent_credentials(self):
        opener = RecordingOpener({"status": "failed", "error_message": f"Bearer {GITHUB_TOKEN_CANARY}", "total_tokens": 42, "input_tokens": 20, "output_tokens": 22, "content_hash": "a" * 64, "content": "private", "task_payload": {"items": ["private"]}})
        client = HindsightTransport("https://memory.example", "configured-token", opener=opener)
        result = client.get_operation("bank", "op")
        encoded = json.dumps(result)
        self.assertEqual(42, result["total_tokens"])
        self.assertEqual("a" * 64, result["content_hash"])
        self.assertNotIn("ghp_", encoded)
        self.assertNotIn("private", encoded)

    def test_sanitizer_normalizes_camel_and_separator_secret_payload_keys(self):
        from project_memory.transport import sanitize
        result = sanitize({"apiKey": "x", "accessToken": "x", "originalText": "private", "task-payload": {"content": "private"}, "token_budget": 10, "content_hash": "a" * 64, "note": "secret policy prose"})
        self.assertEqual("<redacted>", result["apiKey"])
        self.assertEqual("<redacted>", result["accessToken"])
        self.assertNotIn("originalText", result); self.assertNotIn("task-payload", result)
        self.assertEqual(10, result["token_budget"]); self.assertEqual("secret policy prose", result["note"])

    def test_sanitizer_rejects_bracketed_concrete_secret_but_keeps_conventional_placeholder(self):
        from project_memory.transport import sanitize
        result = sanitize({"note": f"api_key=<{GITHUB_TOKEN_CANARY}> api_token=<YOUR_TOKEN>",
                           "clientSecret": "nope", "client_secret_rotation_policy": "weekly"})
        self.assertNotIn("ghp_", result["note"])
        self.assertIn("<YOUR_TOKEN>", result["note"])
        self.assertEqual("<redacted>", result["clientSecret"])
        self.assertEqual("weekly", result["client_secret_rotation_policy"])

    def test_http_error_json_array_is_safe_transport_error(self):
        error = HTTPError("https://x", 500, "bad", {}, io.BytesIO(json.dumps([{"token": GITHUB_TOKEN_CANARY}]).encode()))
        client = HindsightTransport("https://memory.example", "configured-token", opener=RecordingOpener(error))
        with self.assertRaises(TransportError) as caught:
            client.list_documents("bank")
        self.assertEqual(500, caught.exception.status_code)
        self.assertNotIn("ghp_", str(caught.exception))

    def test_terminal_error_message_is_bounded_and_sanitized(self):
        client = HindsightTransport("https://memory.example", "configured-token", opener=RecordingOpener({"id": "op", "status": "failed", "error_message": f"password={GITHUB_TOKEN_CANARY}"}))
        result = client.get_operation("bank", "op")
        self.assertEqual("failed", result["status"])
        self.assertIn("error_message", result)
        self.assertNotIn("ghp_", result["error_message"])

    def test_uncertain_retain_preserves_caller_operation_id_and_never_resubmits(self):
        opener = RecordingOpener(URLError("offline")); client = HindsightTransport("https://memory.example", "secret-value", opener=opener)
        with self.assertRaises(TransportError) as caught: client.submit_retain("bank", [{"content": "safe"}], "caller-op")
        self.assertTrue(caught.exception.uncertain); self.assertEqual("caller-op", caught.exception.operation_id); self.assertEqual(1, len(opener.requests))

    def test_rejects_mismatched_operation_response(self):
        client = HindsightTransport("https://memory.example", "secret-value", opener=RecordingOpener({"operation_id": "other"}))
        with self.assertRaises(TransportError): client.submit_retain("bank", [{"content": "safe"}], "wanted")

    def test_polling_terminal_backoff_deadline_and_no_resubmit(self):
        clock_values = iter([0.0, 0.0, 1.0, 1.0, 3.0, 3.0])
        sleeps = []
        client = HindsightTransport("https://memory.example", "secret-value", opener=RecordingOpener([
            {"id": "op", "status": "pending", "task_payload": {"content": "bad"}},
            {"id": "op", "status": "processing", "progress": {"stage": "x", "processed": 1, "total": 2, "detail": {"content": "bad"}}},
            {"id": "op", "status": "completed"},
        ]), clock=lambda: next(clock_values), sleeper=sleeps.append)
        result = client.wait_operation("bank", "op", deadline_seconds=10, initial_backoff=1, max_backoff=99)
        self.assertEqual("completed", result["status"]); self.assertEqual([1, 2], sleeps); self.assertLessEqual(max(sleeps), 60)

    def test_poll_request_timeout_is_bounded_by_remaining_deadline(self):
        opener = RecordingOpener({"id": "op", "status": "pending"})
        client = HindsightTransport("https://memory.example", "token", opener=opener, timeout=30, clock=iter([0.0, 0.0, 0.5]).__next__, sleeper=lambda _: None)
        result = client.wait_operation("bank", "op", deadline_seconds=.5)
        self.assertEqual("timed_out", result["status"])
        self.assertEqual(.5, opener.timeouts[0])

    def test_url_and_inputs_are_validated(self):
        for url in ("ftp://memory.example", "https://x?token=no", "https://u:p@memory.example"):
            with self.assertRaises(ValueError): HindsightTransport(url, "token")
        client = HindsightTransport("https://memory.example", "token", opener=RecordingOpener({}))
        with self.assertRaises(ValueError): client.submit_retain("bank", [], "op")
        with self.assertRaises(ValueError): client.create_knowledge_page("bank", {"name": "Only name"})


class CliBatchTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.root = Path(self.temp.name) / "project"; self.root.mkdir()
        self.stage = Path(self.temp.name) / "stage"; self.state = Path(self.temp.name) / "state"; self.state.mkdir()
        self.source = self.root / "wiki.md"; self.source.write_text("safe source\n", encoding="utf-8")
        self.profile = {"project_slug": "demo", "operator": "ada", "scope": "workspace", "knowledge_layer": "concept"}
        self.manifest = build_manifest(self.root, [self.source], self.profile, staging_root=self.stage)
        self.manifest_path = self.state / "manifest.json"; write_manifest(self.manifest_path, self.manifest)
        self.registry_path = self.state / "registry.json"
        registered_profile = {"bank_id": "owner::demo", "project_slug": "demo", "knowledge_pages": [{"label": "Architecture", "source_query": "How is it built?"}]}
        self.registry_path.write_text(json.dumps({"schema_version": 1, "operator": {"nickname": "ada"}, "projects": {str(self.root): registered_profile}}), encoding="utf-8")
        profile_sha256 = hashlib.sha256(json.dumps(registered_profile, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()
        target_base = {"bank_id": "owner::demo", "project_slug": "demo", "profile_sha256": profile_sha256, "manifest_sha256": self.manifest.manifest_sha256}
        approved_targets = {
            "hindsight_consolidate": dict(target_base, action="hindsight_consolidate"),
            "knowledge_pages_ensure": dict(target_base, action="knowledge_pages_ensure", page_specs=[{"name": "Architecture", "source_query": "How is it built?"}]),
            "knowledge_pages_refresh": dict(target_base, action="knowledge_pages_refresh", page_id="page-1", mental_model_id="model-1"),
        }
        self.run_path = self.state / "run.json"; self.run_path.write_text(json.dumps({"operator": "ada", "project_root": str(self.root), "source_root": str(self.root), "project_slug": "demo", "bank_id": "owner::demo", "manifest_path": str(self.manifest_path), "staging_root": str(self.stage.absolute()), "manifest_sha256": self.manifest.manifest_sha256, "approved_at": "2026-09-01T10:00:00+02:00", "run_id": "run-1", "approved_actions": ["hindsight_submit", "hindsight_consolidate", "knowledge_pages_ensure", "knowledge_pages_refresh"], "approved_targets": approved_targets, "operation_id": "caller-op", "approved_document_ids": [self.manifest.entries[0].document_id], "approved_item_count": 1, "approved_total_bytes": len(b"safe source\n")}), encoding="utf-8")
        self.audit = self.state / "audit.jsonl"; self.config = self.state / "config.json"

    def tearDown(self): self.temp.cleanup()

    def args(self, **overrides):
        values = {"registry": str(self.registry_path), "root": str(self.root), "run": str(self.run_path), "manifest": str(self.manifest_path), "source_root": str(self.root), "staging_root": str(self.stage), "config": str(self.config), "audit": str(self.audit), "operation_id": "caller-op", "derived_batch": None, "deadline": 5.0, "page_id": "page-1", "mental_model_id": "model-1"}
        values.update(overrides)
        return type("Args", (), values)()

    def sync_knowledge_target(self):
        registry = json.loads(self.registry_path.read_text(encoding="utf-8"))
        profile = registry["projects"][str(self.root)]
        profile_sha256 = hashlib.sha256(json.dumps(profile, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()
        run = json.loads(self.run_path.read_text(encoding="utf-8"))
        run["approved_targets"]["knowledge_pages_ensure"] = {
            "action": "knowledge_pages_ensure", "bank_id": profile["bank_id"],
            "project_slug": profile["project_slug"], "profile_sha256": profile_sha256,
            "manifest_sha256": self.manifest.manifest_sha256,
            "page_specs": CLI_MODULE._knowledge_specs(profile),
        }
        self.run_path.write_text(json.dumps(run), encoding="utf-8")

    def test_bad_run_stops_before_manifest_sources_config_or_transport(self):
        self.run_path.write_text(json.dumps({"operator": "mallory"}), encoding="utf-8")
        original_manifest, original_client = CLI_MODULE.read_manifest, CLI_MODULE._client
        CLI_MODULE.read_manifest = lambda path: self.fail("must not read manifest")
        CLI_MODULE._client = lambda path: self.fail("must not read config/client")
        try:
            with self.assertRaises(CLI_MODULE.CommandError): CLI_MODULE._hindsight_submit(self.args())
        finally:
            CLI_MODULE.read_manifest, CLI_MODULE._client = original_manifest, original_client

    def test_wrong_source_root_is_blocked_before_manifest_or_config(self):
        wrong = Path(self.temp.name) / "wrong"; wrong.mkdir()
        original_manifest, original_client = CLI_MODULE.read_manifest, CLI_MODULE._client
        CLI_MODULE.read_manifest = lambda path: self.fail("must not read manifest")
        CLI_MODULE._client = lambda path: self.fail("must not read config/client")
        try:
            with self.assertRaises(CLI_MODULE.CommandError):
                CLI_MODULE._hindsight_submit(self.args(source_root=str(wrong)))
        finally:
            CLI_MODULE.read_manifest, CLI_MODULE._client = original_manifest, original_client

    def test_symlink_alias_for_registered_root_is_rejected_before_manifest_read(self):
        alias = Path(self.temp.name) / "project-alias"
        alias.symlink_to(self.root, target_is_directory=True)
        original_manifest = CLI_MODULE.read_manifest
        CLI_MODULE.read_manifest = lambda path: self.fail("alias must be rejected before reading manifest")
        try:
            with self.assertRaises(CLI_MODULE.CommandError):
                CLI_MODULE._hindsight_submit(self.args(root=str(alias), source_root=str(alias)))
        finally:
            CLI_MODULE.read_manifest = original_manifest

    def test_submit_requires_action_approval_and_durable_operation_id(self):
        run = json.loads(self.run_path.read_text()); run["approved_actions"] = ["hindsight_consolidate"]
        self.run_path.write_text(json.dumps(run), encoding="utf-8")
        with self.assertRaises(CLI_MODULE.CommandError): CLI_MODULE._hindsight_submit(self.args())
        run["approved_actions"] = ["hindsight_submit"]; self.run_path.write_text(json.dumps(run), encoding="utf-8")
        with self.assertRaises(CLI_MODULE.CommandError): CLI_MODULE._hindsight_submit(self.args(operation_id="different"))

    def test_consolidate_requires_and_uses_exact_hindsight_consolidate_action(self):
        class Client:
            def consolidate(self, bank): return {"operation_id": "op-con", "status": "acknowledged"}
            def wait_operation(self, bank, operation_id, deadline_seconds): return {"operation_id": operation_id, "status": "completed"}
        client = Client(); original = CLI_MODULE._client; CLI_MODULE._client = lambda _: client
        try:
            result = CLI_MODULE._hindsight_consolidate(self.args())
        finally: CLI_MODULE._client = original
        self.assertEqual("completed", result["status"])
        events = [json.loads(line) for line in self.audit.read_text(encoding="utf-8").splitlines()]
        self.assertEqual(["intended", "acknowledged", "completed"], [event["phase"] for event in events])
        run = json.loads(self.run_path.read_text()); run["approved_actions"].remove("hindsight_consolidate"); self.run_path.write_text(json.dumps(run), encoding="utf-8")
        with self.assertRaises(CLI_MODULE.CommandError): CLI_MODULE._hindsight_consolidate(self.args())

    def test_invalid_config_is_safe_failed_lifecycle_after_intended_audit(self):
        self.config.write_text(json.dumps({"apiUrl": "ftp://invalid", "apiToken": "configured-token"}), encoding="utf-8")
        result = CLI_MODULE._hindsight_consolidate(self.args())
        self.assertEqual("failed", result["status"])
        events = [json.loads(line) for line in self.audit.read_text(encoding="utf-8").splitlines()]
        self.assertEqual(["intended", "failed"], [event["phase"] for event in events])
        self.assertNotIn("configured-token", self.audit.read_text(encoding="utf-8"))

    def test_wait_records_terminal_audit_bound_to_approved_run(self):
        class Client:
            def wait_operation(self, bank, operation_id, deadline_seconds):
                return {"operation_id": operation_id, "status": "failed", "error_message": "safe reason"}
        original = CLI_MODULE._client; CLI_MODULE._client = lambda _: Client()
        try:
            result = CLI_MODULE._hindsight_wait(self.args(deadline=1))
        finally:
            CLI_MODULE._client = original
        self.assertEqual("failed", result["status"])
        event = json.loads(self.audit.read_text(encoding="utf-8").splitlines()[-1])
        self.assertEqual("hindsight_wait", event["action"]); self.assertEqual("failed", event["phase"])
        self.assertEqual("run-1", event["run_id"]); self.assertEqual("caller-op", event["operation_id"])

    def test_manifest_items_bind_provenance_and_skip_unchanged(self):
        items, skipped, deleted = CLI_MODULE._manifest_items(self.manifest, self.root, self.stage, "ada", {"run_id": "run-1"})
        self.assertEqual(1, len(items)); self.assertEqual("unset", items[0]["timestamp"])
        self.assertEqual("run-1", items[0]["metadata"]["export_run_id"]); self.assertEqual("ada", items[0]["metadata"]["operator"])
        self.assertEqual("shared", items[0]["observation_scopes"])
        unchanged = dataclasses.replace(self.manifest.entries[0], delta="unchanged")
        manifest = Manifest.from_dict(Manifest((unchanged,), (), "").as_dict())
        items, skipped, deleted = CLI_MODULE._manifest_items(manifest, self.root, self.stage, "ada", {"run_id": "run-1"})
        self.assertEqual([], items); self.assertEqual(1, skipped); self.assertEqual(0, deleted)

    def test_submit_uses_bounded_logbook_event_chunk_and_rejects_staged_tamper(self):
        logbook = self.root / "LOGBOOK.md"
        event_text = "### 2026-09-01 15:50 CEST - Export\nBounded event body.\n"
        logbook.write_text(event_text, encoding="utf-8")
        profile = {"operator": "ada", "project_slug": "demo", "scope": "project-logbook", "knowledge_layer": "concept", "event_paths": ["LOGBOOK.md"]}
        event_manifest = build_manifest(self.root, [logbook], profile, staging_root=self.stage)
        write_manifest(self.manifest_path, event_manifest)
        event = event_manifest.entries[0]
        run = json.loads(self.run_path.read_text())
        run.update({"manifest_sha256": event_manifest.manifest_sha256, "approved_document_ids": [event.document_id], "approved_item_count": 1, "approved_total_bytes": len(event_text.encode())})
        self.run_path.write_text(json.dumps(run), encoding="utf-8")
        class Client:
            def submit_retain(self, bank, items, operation_id): self.items = items; return {"operation_id": operation_id, "status": "acknowledged"}
        client = Client(); original = CLI_MODULE._client; CLI_MODULE._client = lambda _: client
        try:
            result = CLI_MODULE._hindsight_submit(self.args())
        finally: CLI_MODULE._client = original
        self.assertEqual("acknowledged", result["status"])
        self.assertEqual(event_text, client.items[0]["content"]); self.assertEqual(event.event_timestamp, client.items[0]["timestamp"])
        self.assertEqual("shared", client.items[0]["observation_scopes"])
        Path(self.stage / event.export_path).write_text("tampered event\n", encoding="utf-8")
        with self.assertRaises(ValueError):
            CLI_MODULE._manifest_items(event_manifest, self.root, self.stage, "ada", {"run_id": "run-1"})

    def test_submit_preflight_redacts_bracketed_concrete_credential_before_transport(self):
        source = self.root / "security.md"
        source.write_text(f"api_key=<{GITHUB_TOKEN_CANARY}>\n", encoding="utf-8")
        manifest = build_manifest(self.root, [source], self.profile, staging_root=self.stage)
        write_manifest(self.manifest_path, manifest)
        run = json.loads(self.run_path.read_text())
        run.update({"manifest_sha256": manifest.manifest_sha256,
                    "approved_document_ids": [manifest.entries[0].document_id],
                    "approved_item_count": 1,
                    "approved_total_bytes": len((manifest.entries[0].exported_sha256 or "").encode())})
        # The approved byte count is the actual exported content length, never the secret source.
        exported = (self.stage / manifest.entries[0].export_path).read_bytes()
        run["approved_total_bytes"] = len(exported)
        self.run_path.write_text(json.dumps(run), encoding="utf-8")

        class Client:
            def submit_retain(self, bank, items, operation_id):
                self.items = items
                return {"operation_id": operation_id, "status": "acknowledged"}

        client = Client(); original = CLI_MODULE._client; CLI_MODULE._client = lambda _: client
        try:
            result = CLI_MODULE._hindsight_submit(self.args())
        finally:
            CLI_MODULE._client = original
        self.assertEqual("acknowledged", result["status"])
        self.assertNotIn("ghp_", client.items[0]["content"])
        self.assertIn("[REDACTED]", client.items[0]["content"])

    def test_opt_in_source_flows_verbatim_through_manifest_and_fake_submit_without_diagnostic_echo(self):
        credential = "rotated-stage-value"
        key_body = "PRIVATE-BODY-E2E-CANARY"
        source = self.root / "ops" / "staging-access.md"
        source.parent.mkdir()
        content = (
            "password: " + credential + "\n"
            "-----BEGIN PRIVATE KEY-----\n" + key_body + "\n-----END PRIVATE KEY-----\n"
        )
        source.write_text(content, encoding="utf-8")
        profile = {
            "bank_id": "owner::demo", "project_slug": "demo", "operator": "ada",
            "scope": "workspace", "knowledge_layer": "concept", "reviewed": True,
            "credential_policy": "allow_project_staging",
            "source_policy": {"credential_sources": ["ops/staging-access.md"]},
        }
        manifest = build_manifest(self.root, [source], profile, staging_root=self.stage)
        write_manifest(self.manifest_path, manifest)
        registry = json.loads(self.registry_path.read_text(encoding="utf-8"))
        registry["projects"][str(self.root)].update(profile)
        self.registry_path.write_text(json.dumps(registry), encoding="utf-8")
        run = json.loads(self.run_path.read_text(encoding="utf-8"))
        run.update({
            "manifest_sha256": manifest.manifest_sha256,
            "approved_document_ids": [manifest.entries[0].document_id],
            "approved_item_count": 1,
            "approved_total_bytes": len(content.encode("utf-8")),
        })
        self.run_path.write_text(json.dumps(run), encoding="utf-8")
        opener = RecordingOpener({
            "operation_id": "caller-op", "status": "pending", "message": "server echoed " + content,
        })
        client = HindsightTransport("https://memory.example", "configured-token", opener=opener)
        original = CLI_MODULE._client
        CLI_MODULE._client = lambda _: client
        try:
            result = CLI_MODULE._hindsight_submit(self.args())
        finally:
            CLI_MODULE._client = original
        sent = json.loads(opener.requests[0].data)["items"][0]
        self.assertEqual(content, sent["content"])
        self.assertEqual(manifest.entries[0].source_sha256, sent["metadata"]["source_sha256"])
        self.assertEqual("allow_project_staging", sent["metadata"]["credential_policy"])
        self.assertNotIn(credential, json.dumps(result))
        self.assertNotIn(key_body, json.dumps(result))
        self.assertNotIn(credential, self.audit.read_text(encoding="utf-8"))
        self.assertNotIn(key_body, self.audit.read_text(encoding="utf-8"))

    def test_entry_text_rechecks_exact_bytes_after_manifest_validation(self):
        entry = self.manifest.entries[0]
        self.source.write_text("evil source\n", encoding="utf-8")
        with self.assertRaises(CLI_MODULE.CommandError):
            CLI_MODULE._entry_text(entry, self.root, self.stage)

    def test_empty_submit_is_noop_without_reading_config_or_network(self):
        unchanged = dataclasses.replace(self.manifest.entries[0], delta="unchanged")
        empty = Manifest.from_dict(Manifest((unchanged,), (), "").as_dict())
        run = json.loads(self.run_path.read_text()); run["manifest_sha256"] = empty.manifest_sha256; run["approved_document_ids"] = []; run["approved_item_count"] = 0; run["approved_total_bytes"] = 0
        self.run_path.write_text(json.dumps(run), encoding="utf-8")
        original_manifest, original_client = CLI_MODULE.read_manifest, CLI_MODULE._client
        CLI_MODULE.read_manifest = lambda path: empty
        CLI_MODULE._client = lambda path: self.fail("no-op must not make a client")
        try:
            result = CLI_MODULE._hindsight_submit(self.args())
        finally:
            CLI_MODULE.read_manifest, CLI_MODULE._client = original_manifest, original_client
        self.assertEqual("no_op", result["status"])

    def test_knowledge_specs_accept_label_and_tree_is_casefolded_by_parent(self):
        specs = CLI_MODULE._knowledge_specs({"knowledge_pages": [{"label": "Architecture", "source_query": "Q", "tags": []}]})
        self.assertEqual("Architecture", specs[0]["name"])
        pages = CLI_MODULE._tree_pages({"roots": [{"kind": "folder", "id": "root", "name": "Root", "children": [{"kind": "page", "id": "p", "name": "architecture", "parent_id": "root", "mental_model_id": "mm-p"}]}]})
        self.assertEqual("root", pages[0]["parent_id"])

    def test_knowledge_tree_roots_plural_and_duplicate_taxonomy_fail_before_client(self):
        pages = CLI_MODULE._tree_pages({"roots": [{"kind": "folder", "id": "one", "name": "One", "children": [{"kind": "page", "id": "p", "name": "One", "parent_id": "one", "mental_model_id": "mm-p"}]}]})
        self.assertEqual("one", pages[0]["parent_id"])
        profile = {"knowledge_pages": [{"name": "One", "source_query": "q"}, {"label": "one", "source_query": "q"}]}
        with self.assertRaises(CLI_MODULE.CommandError): CLI_MODULE._knowledge_specs(profile)

    def test_duplicate_knowledge_taxonomy_makes_zero_network_posts(self):
        registry = json.loads(self.registry_path.read_text())
        registry["projects"][str(self.root)]["knowledge_pages"] = [{"name": "One", "source_query": "q"}, {"label": "one", "source_query": "q"}]
        self.registry_path.write_text(json.dumps(registry), encoding="utf-8")
        original = CLI_MODULE._client
        CLI_MODULE._client = lambda _: self.fail("taxonomy failure must precede client/network")
        try:
            with self.assertRaises(CLI_MODULE.CommandError): CLI_MODULE._knowledge_ensure(self.args())
        finally: CLI_MODULE._client = original

    def test_missing_or_page_parent_is_rejected_before_any_create(self):
        registry = json.loads(self.registry_path.read_text())
        registry["projects"][str(self.root)]["knowledge_pages"] = [{"name": "First", "source_query": "q"}, {"name": "Later", "source_query": "q", "parent_id": "page-1"}]
        self.registry_path.write_text(json.dumps(registry), encoding="utf-8")
        self.sync_knowledge_target()
        class Client:
            def get_knowledge_tree(self, bank): return {"roots": [{"kind": "page", "id": "page-1", "name": "Not folder", "mental_model_id": "mm-1"}]}
            def create_knowledge_page(self, bank, page): self.fail("must not post")
        original = CLI_MODULE._client; CLI_MODULE._client = lambda _: Client()
        try:
            with self.assertRaises(CLI_MODULE.CommandError): CLI_MODULE._knowledge_ensure(self.args())
        finally: CLI_MODULE._client = original

    def test_knowledge_partial_reports_prior_created_ids(self):
        registry = json.loads(self.registry_path.read_text())
        registry["projects"][str(self.root)]["knowledge_pages"] = [{"name": "One", "source_query": "q"}, {"name": "Two", "source_query": "q"}]
        self.registry_path.write_text(json.dumps(registry), encoding="utf-8")
        self.sync_knowledge_target()
        class Client:
            def __init__(self): self.calls = 0
            def get_knowledge_tree(self, bank): return {"roots": []}
            def create_knowledge_page(self, bank, page):
                self.calls += 1
                if self.calls == 1: return {"page_id": "p1", "mental_model_id": "mm1", "operation_id": "op1", "status": "acknowledged"}
                raise TransportError("failed", status_code=500)
            def wait_operation(self, bank, operation_id, deadline_seconds): return {"operation_id": operation_id, "status": "completed"}
            def get_knowledge_page(self, bank, page_id): return {"id": page_id, "body": "# One\n"}
        client = Client(); original = CLI_MODULE._client; CLI_MODULE._client = lambda _: client
        try:
            with self.assertRaises(CLI_MODULE.PartialCommandError) as caught: CLI_MODULE._knowledge_ensure(self.args())
        finally: CLI_MODULE._client = original
        self.assertEqual("partial", caught.exception.result["status"])
        self.assertEqual("p1", caught.exception.result["created"][0]["page_id"])
        self.assertEqual("Two", caught.exception.result["failed_page"])

    def test_knowledge_terminal_page_failure_is_non_success_and_keeps_identifiers(self):
        registry = json.loads(self.registry_path.read_text())
        registry["projects"][str(self.root)]["knowledge_pages"] = [{"name": "One", "source_query": "q"}]
        self.registry_path.write_text(json.dumps(registry), encoding="utf-8")
        self.sync_knowledge_target()
        class Client:
            def get_knowledge_tree(self, bank): return {"roots": []}
            def create_knowledge_page(self, bank, page): return {"page_id": "p1", "operation_id": "op1", "status": "failed"}
        original = CLI_MODULE._client; CLI_MODULE._client = lambda _: Client()
        try:
            with self.assertRaises(CLI_MODULE.PartialCommandError) as caught: CLI_MODULE._knowledge_ensure(self.args())
        finally: CLI_MODULE._client = original
        self.assertEqual("partial", caught.exception.result["status"])
        self.assertEqual("p1", caught.exception.result["failed"]["page_id"])
        self.assertEqual("op1", caught.exception.result["failed"]["operation_id"])

    def test_knowledge_terminal_cancellation_keeps_prior_acknowledged_page(self):
        registry = json.loads(self.registry_path.read_text())
        registry["projects"][str(self.root)]["knowledge_pages"] = [{"name": "One", "source_query": "q"}, {"name": "Two", "source_query": "q"}]
        self.registry_path.write_text(json.dumps(registry), encoding="utf-8")
        self.sync_knowledge_target()
        class Client:
            def __init__(self): self.calls = 0
            def get_knowledge_tree(self, bank): return {"roots": []}
            def create_knowledge_page(self, bank, page):
                self.calls += 1
                return {"page_id": "p" + str(self.calls), "mental_model_id": "mm" + str(self.calls), "operation_id": "op" + str(self.calls), "status": "acknowledged" if self.calls == 1 else "cancelled"}
            def wait_operation(self, bank, operation_id, deadline_seconds): return {"operation_id": operation_id, "status": "completed"}
            def get_knowledge_page(self, bank, page_id): return {"id": page_id, "body": "# One\n"}
        original = CLI_MODULE._client; CLI_MODULE._client = lambda _: Client()
        try:
            with self.assertRaises(CLI_MODULE.PartialCommandError) as caught: CLI_MODULE._knowledge_ensure(self.args())
        finally: CLI_MODULE._client = original
        self.assertEqual("p1", caught.exception.result["created"][0]["page_id"])
        self.assertEqual("cancelled", caught.exception.result["failed"]["status"])
        self.assertEqual("cancelled", json.loads(self.audit.read_text(encoding="utf-8").splitlines()[-1])["phase"])

    def test_malformed_knowledge_tree_is_rejected_before_create(self):
        class Client:
            def get_knowledge_tree(self, bank): return {}
            def create_knowledge_page(self, bank, page): raise AssertionError("invalid tree must not create")
        original = CLI_MODULE._client; CLI_MODULE._client = lambda _: Client()
        try:
            with self.assertRaises(CLI_MODULE.CommandError): CLI_MODULE._knowledge_ensure(self.args())
        finally: CLI_MODULE._client = original

    def test_knowledge_tree_rejects_legacy_node_aliases_before_create(self):
        class Client:
            def get_knowledge_tree(self, bank):
                return {"roots": [{"type": "folder", "id": "root", "name": "Root", "children": []}]}
            def create_knowledge_page(self, bank, page):
                raise AssertionError("legacy tree aliases must not create")

        original = CLI_MODULE._client; CLI_MODULE._client = lambda _: Client()
        try:
            with self.assertRaises(CLI_MODULE.CommandError):
                CLI_MODULE._knowledge_ensure(self.args())
        finally:
            CLI_MODULE._client = original

    def test_approved_graph_projection_batch_is_combined_without_leaking_content_to_audit(self):
        body = "# derived graph\n"
        source = self.root / "sidecar.json"; source.write_text("sidecar", encoding="utf-8")
        derived = [{"document_id": "kb:demo:graph:webapp:subject", "content": body,
                    "tags": ["user:ada", "project:demo", "kind:graph_projection", "scope:webapp", "trust:derived", "knowledge:component", "topic:architecture"],
                    "metadata": {"operator": "ada", "project_slug": "demo", "source_path": "sidecar.json", "source_sha256": __import__("hashlib").sha256(source.read_bytes()).hexdigest(), "knowledge_layer": "component", "verification_status": "derived", "generator": "test", "generator_version": "1"}}]
        path = self.state / "derived.json"; path.write_text(json.dumps(derived), encoding="utf-8")
        raw = path.read_bytes(); run = json.loads(self.run_path.read_text())
        run.update({"derived_batch_path": str(path), "derived_batch_sha256": __import__("hashlib").sha256(raw).hexdigest(), "derived_document_ids": [derived[0]["document_id"]], "derived_item_count": 1, "derived_total_bytes": len(body.encode()), "approved_document_ids": [self.manifest.entries[0].document_id, derived[0]["document_id"]], "approved_item_count": 2, "approved_total_bytes": len(b"safe source\n") + len(body.encode())})
        self.run_path.write_text(json.dumps(run), encoding="utf-8")
        class Client:
            def submit_retain(self, bank, items, operation_id): self.items = items; return {"operation_id": operation_id, "status": "acknowledged"}
        client = Client(); original = CLI_MODULE._client; CLI_MODULE._client = lambda _: client
        try: result = CLI_MODULE._hindsight_submit(self.args(derived_batch=str(path)))
        finally: CLI_MODULE._client = original
        self.assertEqual(2, result["submitted"]); self.assertEqual("acknowledged", result["status"])
        self.assertEqual("shared", client.items[0]["observation_scopes"])
        self.assertEqual("shared", client.items[1]["observation_scopes"])
        audit = self.audit.read_text(encoding="utf-8")
        self.assertNotIn(body, audit); self.assertNotIn("configured-token", audit)
        self.assertIn("project_root", audit); self.assertIn("document_ids", audit)

    def test_derived_identifier_words_do_not_trigger_filesystem_path_exclusions(self):
        source = self.root / "sidecar.json"
        source.write_text("sidecar", encoding="utf-8")
        record = {
            "document_id": "kb:demo:graph:webapp:generated-document-route",
            "content": "Verified route capsule.",
            "tags": ["user:ada", "project:demo", "kind:graph_projection", "scope:webapp", "trust:derived", "knowledge:component"],
            "metadata": {
                "operator": "ada", "project_slug": "demo", "source_path": "sidecar.json",
                "source_sha256": __import__("hashlib").sha256(source.read_bytes()).hexdigest(),
                "knowledge_layer": "component", "verification_status": "derived",
                "generator": "test", "generator_version": "1",
            },
        }
        path = self.state / "generated-document-derived.json"
        path.write_text(json.dumps([record]), encoding="utf-8")
        run = json.loads(self.run_path.read_text())
        run.update({
            "derived_batch_path": str(path),
            "derived_batch_sha256": __import__("hashlib").sha256(path.read_bytes()).hexdigest(),
            "derived_document_ids": [record["document_id"]],
            "derived_item_count": 1,
            "derived_total_bytes": len(record["content"].encode()),
        })

        items = CLI_MODULE._derived_items(
            self.args(derived_batch=str(path)), run, {"project_slug": "demo"}, "ada", self.root.resolve(), set()
        )

        self.assertEqual(record["document_id"], items[0]["document_id"])

    def test_dossier_and_casefold_or_outside_provenance_are_checked(self):
        source = self.root / "dossier-source.md"; source.write_text("source", encoding="utf-8")
        digest = __import__("hashlib").sha256(source.read_bytes()).hexdigest()
        record = {"document_id": "kb:demo:dossier:overview", "content": "Dossier safe.", "tags": ["user:ada", "project:demo", "kind:dossier", "scope:wiki", "trust:derived", "knowledge:decision"], "metadata": {"operator": "ada", "project_slug": "demo", "source_path": "dossier-source.md", "source_sha256": digest, "knowledge_layer": "decision", "verification_status": "derived", "generator": "curator", "generator_version": "1"}}
        path = self.state / "dossier.json"; path.write_text(json.dumps([record]), encoding="utf-8")
        run = json.loads(self.run_path.read_text()); raw = path.read_bytes(); run.update({"derived_batch_path": str(path), "derived_batch_sha256": __import__("hashlib").sha256(raw).hexdigest(), "derived_document_ids": [record["document_id"]], "derived_item_count": 1, "derived_total_bytes": len(record["content"].encode()), "approved_document_ids": [self.manifest.entries[0].document_id, record["document_id"]], "approved_item_count": 2, "approved_total_bytes": len(b"safe source\n") + len(record["content"].encode())}); self.run_path.write_text(json.dumps(run), encoding="utf-8")
        items = CLI_MODULE._derived_items(self.args(derived_batch=str(path)), run, {"project_slug": "demo"}, "ada", self.root.resolve(), {self.manifest.entries[0].document_id})
        self.assertEqual("kb:demo:dossier:overview", items[0]["document_id"])
        self.assertEqual("shared", items[0]["observation_scopes"])
        class Client:
            def submit_retain(self, bank, submitted_items, operation_id):
                self.items = submitted_items
                return {"operation_id": operation_id, "status": "acknowledged"}
        client = Client(); original = CLI_MODULE._client; CLI_MODULE._client = lambda _: client
        try:
            result = CLI_MODULE._hindsight_submit(self.args(derived_batch=str(path)))
        finally:
            CLI_MODULE._client = original
        self.assertEqual("acknowledged", result["status"])
        self.assertEqual("kind:dossier", next(tag for tag in client.items[1]["tags"] if tag.startswith("kind:")))
        self.assertEqual("shared", client.items[1]["observation_scopes"])
        record["document_id"] = "KB:DEMO:DOSSIER:OVERVIEW"; path.write_text(json.dumps([record]), encoding="utf-8")
        with self.assertRaises(CLI_MODULE.CommandError): CLI_MODULE._derived_items(self.args(derived_batch=str(path)), run, {"project_slug": "demo"}, "ada", self.root.resolve(), {"kb:demo:dossier:overview"})

    def test_derived_batch_allows_future_controlled_values_but_rejects_casefold_collision(self):
        source = self.root / "future-source.md"; source.write_text("facts\n", encoding="utf-8")
        digest = __import__("hashlib").sha256(source.read_bytes()).hexdigest()
        record = {"document_id": "kb:demo:dossier:OVERVIEW", "content": "Future safe.",
                  "tags": ["user:ada", "project:demo", "kind:dossier", "scope:wiki", "trust:reviewed", "knowledge:architecture"],
                  "metadata": {"operator": "ada", "project_slug": "demo", "source_path": "future-source.md", "source_sha256": digest,
                               "knowledge_layer": "architecture", "verification_status": "reviewed", "generator": "curator", "generator_version": "2"}}
        path = self.state / "future-derived.json"; path.write_text(json.dumps([record]), encoding="utf-8")
        raw = path.read_bytes(); run = json.loads(self.run_path.read_text())
        run.update({"derived_batch_path": str(path), "derived_batch_sha256": __import__("hashlib").sha256(raw).hexdigest(),
                    "derived_document_ids": [record["document_id"]], "derived_item_count": 1,
                    "derived_total_bytes": len(record["content"].encode())})
        items = CLI_MODULE._derived_items(self.args(derived_batch=str(path)), run, {"project_slug": "demo"}, "ada", self.root.resolve(), {self.manifest.entries[0].document_id})
        self.assertEqual(record["document_id"], items[0]["document_id"])
        with self.assertRaises(CLI_MODULE.CommandError):
            CLI_MODULE._derived_items(self.args(derived_batch=str(path)), run, {"project_slug": "demo"}, "ada", self.root.resolve(), {"kb:demo:dossier:overview"})

    def test_derived_graph_and_dossier_reject_secret_metadata_or_tags(self):
        source = self.root / "provenance.md"; source.write_text("facts\n", encoding="utf-8")
        digest = __import__("hashlib").sha256(source.read_bytes()).hexdigest()

        def record(kind, identifier):
            return {"document_id": "kb:demo:" + kind + ":" + identifier, "content": "Safe knowledge.",
                    "tags": ["user:ada", "project:demo", "kind:" + ("graph_projection" if kind == "graph" else "dossier"), "scope:wiki", "trust:reviewed", "knowledge:architecture"],
                    "metadata": {"operator": "ada", "project_slug": "demo", "source_path": "provenance.md", "source_sha256": digest,
                                 "knowledge_layer": "architecture", "verification_status": "reviewed", "generator": "test", "generator_version": "1",
                                 "content_hash": "a" * 64, "token_budget": "800", "secret_handling_policy": "reviewed"}}

        for kind, bad_field, value in (("graph", "clientSecret", GITHUB_TOKEN_CANARY),
                                       ("dossier", "tag", "token:" + GITHUB_TOKEN_CANARY)):
            item = record(kind, "unsafe-" + kind)
            if bad_field == "tag":
                item["tags"].append(value)
            else:
                item["metadata"][bad_field] = value
            path = self.state / (kind + "-unsafe.json"); path.write_text(json.dumps([item]), encoding="utf-8")
            raw = path.read_bytes(); run = json.loads(self.run_path.read_text())
            run.update({"derived_batch_path": str(path), "derived_batch_sha256": __import__("hashlib").sha256(raw).hexdigest(),
                        "derived_document_ids": [item["document_id"]], "derived_item_count": 1,
                        "derived_total_bytes": len(item["content"].encode())})
            with self.subTest(kind=kind):
                with self.assertRaises(CLI_MODULE.CommandError):
                    CLI_MODULE._derived_items(self.args(derived_batch=str(path)), run, {"project_slug": "demo"}, "ada", self.root.resolve(), set())

    def test_derived_batch_rejects_outside_source_and_mismatched_control_metadata(self):
        outside = Path(self.temp.name) / "outside.md"; outside.write_text("outside\n", encoding="utf-8")
        digest = __import__("hashlib").sha256(outside.read_bytes()).hexdigest()
        record = {"document_id": "kb:demo:dossier:outside", "content": "Safe dossier.",
                  "tags": ["user:ada", "project:demo", "kind:dossier", "scope:wiki", "trust:derived", "knowledge:decision"],
                  "metadata": {"operator": "ada", "project_slug": "demo", "source_path": str(outside), "source_sha256": digest,
                               "knowledge_layer": "different", "verification_status": "derived", "generator": "curator", "generator_version": "1"}}
        path = self.state / "outside-derived.json"; path.write_text(json.dumps([record]), encoding="utf-8")
        raw = path.read_bytes(); run = json.loads(self.run_path.read_text())
        run.update({"derived_batch_path": str(path), "derived_batch_sha256": __import__("hashlib").sha256(raw).hexdigest(),
                    "derived_document_ids": [record["document_id"]], "derived_item_count": 1,
                    "derived_total_bytes": len(record["content"].encode())})
        with self.assertRaises(CLI_MODULE.CommandError):
            CLI_MODULE._derived_items(self.args(derived_batch=str(path)), run, {"project_slug": "demo"}, "ada", self.root.resolve(), set())

    def test_dossier_accepts_exact_multi_source_evidence(self):
        source_a = self.root / "a.md"; source_b = self.root / "b.md"
        source_a.write_text("A\n", encoding="utf-8"); source_b.write_text("B\n", encoding="utf-8")
        evidence = [{"source_path": "a.md", "source_sha256": __import__("hashlib").sha256(source_a.read_bytes()).hexdigest()},
                    {"source_path": "b.md", "source_sha256": __import__("hashlib").sha256(source_b.read_bytes()).hexdigest()}]
        evidence_text = json.dumps(evidence, separators=(",", ":"), sort_keys=True)
        record = {"document_id": "kb:demo:dossier:multi", "content": "Combined safe dossier.",
                  "tags": ["user:ada", "project:demo", "kind:dossier", "scope:wiki", "trust:derived", "knowledge:decision", "topic:future"],
                  "metadata": {"operator": "ada", "project_slug": "demo", "source_paths": json.dumps(["a.md", "b.md"], separators=(",", ":")),
                               "evidence": evidence_text, "source_sha256": __import__("hashlib").sha256(evidence_text.encode()).hexdigest(),
                               "knowledge_layer": "decision", "verification_status": "derived", "generator": "curator", "generator_version": "1"}}
        path = self.state / "multi.json"; path.write_text(json.dumps([record]), encoding="utf-8")
        raw = path.read_bytes(); run = json.loads(self.run_path.read_text())
        run.update({"derived_batch_path": str(path), "derived_batch_sha256": __import__("hashlib").sha256(raw).hexdigest(), "derived_document_ids": [record["document_id"]], "derived_item_count": 1, "derived_total_bytes": len(record["content"].encode())})
        items = CLI_MODULE._derived_items(self.args(derived_batch=str(path)), run, {"project_slug": "demo"}, "ada", self.root.resolve(), set())
        self.assertEqual("kb:demo:dossier:multi", items[0]["document_id"])

    def test_derived_event_timestamp_requires_unset_or_timezone(self):
        source = self.root / "timed.md"; source.write_text("facts\n", encoding="utf-8")
        digest = __import__("hashlib").sha256(source.read_bytes()).hexdigest()
        record = {"document_id": "kb:demo:dossier:timed", "content": "Safe.", "event_timestamp": "2026-09-01T10:00:00",
                  "tags": ["user:ada", "project:demo", "kind:dossier", "scope:wiki", "trust:derived", "knowledge:decision"],
                  "metadata": {"operator": "ada", "project_slug": "demo", "source_path": "timed.md", "source_sha256": digest, "knowledge_layer": "decision", "verification_status": "derived", "generator": "curator", "generator_version": "1"}}
        path = self.state / "timed.json"; path.write_text(json.dumps([record]), encoding="utf-8")
        raw = path.read_bytes(); run = json.loads(self.run_path.read_text())
        run.update({"derived_batch_path": str(path), "derived_batch_sha256": __import__("hashlib").sha256(raw).hexdigest(), "derived_document_ids": [record["document_id"]], "derived_item_count": 1, "derived_total_bytes": len(record["content"].encode())})
        with self.assertRaises(CLI_MODULE.CommandError):
            CLI_MODULE._derived_items(self.args(derived_batch=str(path)), run, {"project_slug": "demo"}, "ada", self.root.resolve(), set())

    def test_main_returns_nonzero_for_safe_terminal_failure(self):
        original_parser = CLI_MODULE._parser
        result_handler = staticmethod(lambda args: {"status": "timed_out"})
        parser = type("Parser", (), {"parse_args": lambda self, argv: type("Args", (), {"handler": result_handler})()})()
        CLI_MODULE._parser = lambda: parser
        try: self.assertEqual(2, CLI_MODULE.main([]))
        finally: CLI_MODULE._parser = original_parser

    def test_manifest_submit_rejects_stale_operator_tag_and_metadata_at_point_of_use(self):
        metadata = dict(self.manifest.entries[0].metadata)
        metadata["operator"] = "old"
        stale_entry = dataclasses.replace(
            self.manifest.entries[0],
            tags=tuple("user:old" if tag == "user:ada" else tag for tag in self.manifest.entries[0].tags),
            metadata=tuple(sorted(metadata.items())),
        )
        stale_manifest = Manifest((stale_entry,), (), "")

        with self.assertRaises(CLI_MODULE.CommandError):
            CLI_MODULE._manifest_items(stale_manifest, self.root, self.stage, "ada", {"run_id": "run-1"})

    def test_consolidate_rejects_generic_action_without_exact_target_before_network(self):
        run = json.loads(self.run_path.read_text(encoding="utf-8"))
        run["approved_targets"]["hindsight_consolidate"]["manifest_sha256"] = "0" * 64
        self.run_path.write_text(json.dumps(run), encoding="utf-8")
        original = CLI_MODULE._client
        CLI_MODULE._client = lambda _: self.fail("target mismatch must precede network")
        try:
            with self.assertRaises(CLI_MODULE.CommandError):
                CLI_MODULE._hindsight_consolidate(self.args())
        finally:
            CLI_MODULE._client = original

    def test_consolidate_reports_terminal_failure_cancel_and_timeout_without_resubmit(self):
        for terminal in ("failed", "cancelled", "timed_out"):
            with self.subTest(terminal=terminal):
                audit = self.state / ("audit-" + terminal + ".jsonl")
                class Client:
                    def __init__(self): self.submits = 0
                    def consolidate(self, bank):
                        self.submits += 1
                        return {"operation_id": "op-" + terminal, "status": "acknowledged"}
                    def wait_operation(self, bank, operation_id, deadline_seconds):
                        return {"operation_id": operation_id, "status": terminal}
                client = Client(); original = CLI_MODULE._client; CLI_MODULE._client = lambda _: client
                try:
                    result = CLI_MODULE._hindsight_consolidate(self.args(audit=str(audit)))
                finally:
                    CLI_MODULE._client = original
                self.assertEqual(terminal, result["status"])
                self.assertEqual(1, client.submits)
                phases = [json.loads(line)["phase"] for line in audit.read_text(encoding="utf-8").splitlines()]
                self.assertEqual(["intended", "acknowledged", terminal], phases)

    def test_knowledge_ensure_polls_terminal_audits_three_phases_and_returns_body(self):
        class Client:
            def get_knowledge_tree(self, bank): return {"roots": []}
            def create_knowledge_page(self, bank, page):
                return {"page_id": "page-1", "mental_model_id": "model-1", "operation_id": "page-op", "status": "acknowledged"}
            def wait_operation(self, bank, operation_id, deadline_seconds):
                return {"operation_id": operation_id, "status": "completed"}
            def get_knowledge_page(self, bank, page_id):
                return {"id": page_id, "name": "Architecture", "body": "# Architecture\nGrounded body.\n", "markdown": "---\n---\n# Architecture\nGrounded body.\n"}

        original = CLI_MODULE._client; CLI_MODULE._client = lambda _: Client()
        try:
            result = CLI_MODULE._knowledge_ensure(self.args())
        finally:
            CLI_MODULE._client = original
        self.assertEqual("knowledge_pages_ensured", result["status"])
        self.assertEqual("completed", result["created"][0]["status"])
        self.assertEqual("# Architecture\nGrounded body.\n", result["created"][0]["page"]["body"])
        events = [json.loads(line) for line in self.audit.read_text(encoding="utf-8").splitlines()]
        self.assertEqual(["intended", "acknowledged", "completed"], [event["phase"] for event in events])
        self.assertNotIn("Grounded body", self.audit.read_text(encoding="utf-8"))

    def test_knowledge_ensure_validates_and_inspects_an_existing_page_without_creating_it(self):
        class Client:
            def __init__(self): self.creates = 0
            def get_knowledge_tree(self, bank):
                return {"roots": [{"id": "page-1", "kind": "page", "name": "Architecture", "parent_id": None,
                                    "mental_model_id": "model-1", "description": "How is it built?", "tags": [], "children": []}]}
            def get_mental_model(self, bank, model_id):
                return {"id": model_id, "name": "Architecture", "source_query": "How is it built?", "tags": [],
                        "max_tokens": 4096, "trigger": {"mode": "delta"}, "content": "Grounded body."}
            def get_knowledge_page(self, bank, page_id):
                return {"id": page_id, "name": "Architecture", "description": "How is it built?", "tags": [],
                        "body": "# Architecture\nGrounded body.\n", "markdown": "---\n---\n# Architecture\nGrounded body.\n"}
            def create_knowledge_page(self, bank, page):
                self.creates += 1
                raise AssertionError("an exact existing page must not be recreated")

        client = Client(); original = CLI_MODULE._client; CLI_MODULE._client = lambda _: client
        try:
            result = CLI_MODULE._knowledge_ensure(self.args())
        finally:
            CLI_MODULE._client = original

        self.assertEqual(0, client.creates)
        self.assertEqual("verified", result["existing"][0]["status"])
        self.assertEqual("# Architecture\nGrounded body.\n", result["existing"][0]["page"]["body"])

    def test_knowledge_ensure_rejects_existing_page_configuration_drift(self):
        class Client:
            def get_knowledge_tree(self, bank):
                return {"roots": [{"id": "page-1", "kind": "page", "name": "Architecture", "parent_id": None,
                                    "mental_model_id": "model-1", "description": "Stale query", "tags": [], "children": []}]}
            def get_mental_model(self, bank, model_id):
                return {"id": model_id, "name": "Architecture", "source_query": "Stale query", "tags": [],
                        "max_tokens": 4096, "trigger": {"mode": "delta"}, "content": "Stale body."}
            def get_knowledge_page(self, bank, page_id):
                raise AssertionError("configuration drift must stop before accepting the body")
            def create_knowledge_page(self, bank, page):
                raise AssertionError("configuration drift must not create a duplicate")

        original = CLI_MODULE._client; CLI_MODULE._client = lambda _: Client()
        try:
            with self.assertRaises(CLI_MODULE.PartialCommandError) as caught:
                CLI_MODULE._knowledge_ensure(self.args())
        finally:
            CLI_MODULE._client = original

        self.assertEqual("configuration_mismatch", caught.exception.result["status"])
        self.assertEqual("Architecture", caught.exception.result["page_name"])

    def test_knowledge_specs_are_required_and_refresh_target_mismatch_stops_before_network(self):
        with self.assertRaises(CLI_MODULE.CommandError):
            CLI_MODULE._knowledge_specs({})
        run = json.loads(self.run_path.read_text(encoding="utf-8"))
        run["approved_targets"]["knowledge_pages_refresh"]["page_id"] = "different-page"
        self.run_path.write_text(json.dumps(run), encoding="utf-8")
        original = CLI_MODULE._client
        CLI_MODULE._client = lambda _: self.fail("refresh target mismatch must precede network")
        try:
            with self.assertRaises(CLI_MODULE.CommandError):
                CLI_MODULE._knowledge_refresh(self.args())
        finally:
            CLI_MODULE._client = original

    def test_knowledge_ensure_target_mismatch_stops_before_network(self):
        run = json.loads(self.run_path.read_text(encoding="utf-8"))
        run["approved_targets"]["knowledge_pages_ensure"]["page_specs"][0]["source_query"] = "Different query"
        self.run_path.write_text(json.dumps(run), encoding="utf-8")
        original = CLI_MODULE._client
        CLI_MODULE._client = lambda _: self.fail("ensure target mismatch must precede network")
        try:
            with self.assertRaises(CLI_MODULE.CommandError):
                CLI_MODULE._knowledge_ensure(self.args())
        finally:
            CLI_MODULE._client = original

    def test_knowledge_ensure_terminal_timeout_is_partial_and_never_resubmits(self):
        class Client:
            def __init__(self): self.creates = 0
            def get_knowledge_tree(self, bank): return {"roots": []}
            def create_knowledge_page(self, bank, page):
                self.creates += 1
                return {"page_id": "page-1", "mental_model_id": "model-1", "operation_id": "page-op", "status": "acknowledged"}
            def wait_operation(self, bank, operation_id, deadline_seconds): return {"operation_id": operation_id, "status": "timed_out"}

        client = Client(); original = CLI_MODULE._client; CLI_MODULE._client = lambda _: client
        try:
            with self.assertRaises(CLI_MODULE.PartialCommandError) as caught:
                CLI_MODULE._knowledge_ensure(self.args())
        finally:
            CLI_MODULE._client = original
        self.assertEqual(1, client.creates)
        self.assertEqual("timed_out", caught.exception.result["failed"]["status"])
        self.assertEqual("timed_out", json.loads(self.audit.read_text(encoding="utf-8").splitlines()[-1])["phase"])

    def test_knowledge_refresh_requires_exact_page_and_model_polls_and_returns_page_body(self):
        class Client:
            def refresh_mental_model(self, bank, model_id): return {"operation_id": "refresh-op", "status": "acknowledged"}
            def wait_operation(self, bank, operation_id, deadline_seconds): return {"operation_id": operation_id, "status": "completed"}
            def get_knowledge_page(self, bank, page_id): return {"id": page_id, "body": "# Refreshed\n"}

        original = CLI_MODULE._client; CLI_MODULE._client = lambda _: Client()
        try:
            result = CLI_MODULE._knowledge_refresh(self.args())
        finally:
            CLI_MODULE._client = original
        self.assertEqual("completed", result["status"])
        self.assertEqual("# Refreshed\n", result["page"]["body"])
        events = [json.loads(line) for line in self.audit.read_text(encoding="utf-8").splitlines()]
        self.assertEqual(["intended", "acknowledged", "completed"], [event["phase"] for event in events])
        self.assertNotIn("Refreshed", self.audit.read_text(encoding="utf-8"))
