"""Small, deliberately boring Hindsight HTTP client.

It keeps the bearer credential in this process only.  Values returned by the
server are treated as untrusted diagnostics and are scrubbed before a caller
can put them in CLI output or an audit record.
"""

import json
import re
import time
from dataclasses import dataclass
from typing import Any, Callable, Dict, Mapping, Optional
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlencode, urlsplit
from urllib.request import Request, urlopen


_DROP_KEYS = {"content", "originaltext", "items", "payload", "taskpayload", "rawbody", "body", "data"}
_SECRET_KEYS = {"token", "apitoken", "apikey", "authorization", "password", "secret", "credential", "privatekey", "accesstoken", "refreshtoken", "bearertoken", "clientsecret", "signingsecret", "webhooksecret"}
_TERMINAL = {"completed", "failed", "cancelled"}
_PENDING = {"pending", "processing"}
_MUTATION_PENDING = _PENDING | {"queued"}
_CREDENTIAL_VALUE = re.compile(
    r"(?:-----BEGIN (?P<pem_label>(?:[A-Z0-9]+ )*(?:PRIVATE KEY|CERTIFICATE))-----[\s\S]*?-----END (?P=pem_label)-----|\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\b|"
    r"\b(?:ghp_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|sk-[A-Za-z0-9]{20,}|xox(?:b|p|a|r|s)-[A-Za-z0-9-]{16,}|AKIA[0-9A-Z]{16})\b|"
    r"\bBearer\s+[A-Za-z0-9._~+/=-]{16,}|[\"']?\b(?:api[_. -]?(?:token|key)|access[_. -]?token|refresh[_. -]?token|(?:client|signing|webhook)[_. -]?secret|password|secret|credential)\b[\"']?\s*[:=]\s*(?:\"(?:\\.|[^\"\\\n])*\"|'(?:\\.|[^'\\\n])*'|[^\s,'\"]+))",
    re.IGNORECASE,
)
_PLACEHOLDER_VALUE = re.compile(
    r"(?:<(?:TOKEN|API_KEY|API_TOKEN|YOUR_[A-Z0-9_]+|[A-Z][A-Z0-9_]*(?:_TOKEN|_KEY|_SECRET))>|\$\{[A-Z][A-Z0-9_]*\}|YOUR_[A-Z0-9_]+|EXAMPLE_[A-Z0-9_]+|CHANGEME|REDACTED|\[REDACTED\])",
    re.IGNORECASE,
)
_CAMEL = re.compile(r"([a-z0-9])([A-Z])")
_DOCUMENT_SUMMARY_FIELDS = {
    "id", "bank_id", "content_hash", "created_at", "updated_at",
    "memory_unit_count", "text_length", "tags", "metadata",
    "document_metadata", "observation_scopes",
}
_SUCCESS_BODY_KEYS = {"content", "originaltext", "payload", "taskpayload", "rawbody", "body"}
CANONICAL_HINDSIGHT_API_URL = "https://hindsight.persephone.cc"


def _redact_credential_match(match: re.Match) -> str:
    text = match.group(0)
    if re.search(r"[\"']?\b(?:api[_. -]?(?:token|key)|access[_. -]?token|refresh[_. -]?token|(?:client|signing|webhook)[_. -]?secret|password|secret|credential)\b[\"']?\s*[:=]", text, re.IGNORECASE):
        assigned = re.split(r"[:=]", text, maxsplit=1)[1].strip(" '\"")
        if _PLACEHOLDER_VALUE.fullmatch(assigned.rstrip(".,;:!?")):
            return text
    return "<redacted>"


def _safe_text(value: Any, token: Optional[str] = None) -> str:
    text = str(value)
    if token:
        text = text.replace(token, "<redacted>")
    stripped = text.strip()
    if stripped.startswith(("{", "[")):
        try:
            structured = json.loads(stripped)
        except (TypeError, ValueError):
            pass
        else:
            if isinstance(structured, (Mapping, list)):
                return json.dumps(sanitize(structured, token), ensure_ascii=False, separators=(",", ":"))[:512]
    return _CREDENTIAL_VALUE.sub(_redact_credential_match, text)[:512]


def _semantic_key(value: Any) -> str:
    return re.sub(r"[^a-z0-9]+", "", _CAMEL.sub(r"\1_\2", str(value)).casefold())


def sanitize(value: Any, token: Optional[str] = None) -> Any:
    """Return a bounded diagnostic representation with data-bearing fields gone."""
    if isinstance(value, Mapping):
        answer = {}
        for key, child in value.items():
            safe_key = _safe_text(key, token)
            folded = _semantic_key(safe_key)
            if folded in _DROP_KEYS:
                continue
            if folded in _SECRET_KEYS:
                answer[safe_key] = "<redacted>"
            else:
                answer[safe_key] = sanitize(child, token)
        return answer
    if isinstance(value, (list, tuple)):
        return [sanitize(item, token) for item in value[:100]]
    if isinstance(value, str):
        return _safe_text(value, token)
    if value is None or isinstance(value, (int, float, bool)):
        return value
    return _safe_text(value, token)


def _sanitize_success_value(value: Any, token: Optional[str] = None) -> Any:
    """Preserve successful API structure while removing bodies and credentials."""
    if isinstance(value, Mapping):
        answer = {}
        for key, child in value.items():
            safe_key = _safe_text(key, token)
            folded = _semantic_key(safe_key)
            if folded in _SUCCESS_BODY_KEYS:
                continue
            if folded in _SECRET_KEYS:
                answer[safe_key] = "<redacted>"
            else:
                answer[safe_key] = _sanitize_success_value(child, token)
        return answer
    if isinstance(value, (list, tuple)):
        return [_sanitize_success_value(item, token) for item in value[:100]]
    if isinstance(value, str):
        return _safe_text(value, token)
    if value is None or isinstance(value, (int, float, bool)):
        return value
    return _safe_text(value, token)


def _document_summary(value: Mapping[str, Any], token: Optional[str] = None) -> Dict[str, Any]:
    identifier = value.get("id")
    if not isinstance(identifier, str) or not identifier:
        raise TransportError("Hindsight returned a document item without an ID")
    return {
        key: _sanitize_success_value(value[key], token)
        for key in _DOCUMENT_SUMMARY_FIELDS
        if key in value
    }


@dataclass
class TransportError(Exception):
    """Safe error suitable for displaying or recording locally."""

    message: str
    status_code: Optional[int] = None
    operation_id: Optional[str] = None
    uncertain: bool = False

    def __str__(self) -> str:
        return self.message

    def safe_result(self) -> Dict[str, Any]:
        result: Dict[str, Any] = {"status": "uncertain" if self.uncertain else "failed", "message": self.message}
        if self.status_code is not None:
            result["http_status"] = self.status_code
        if self.operation_id:
            result["operation_id"] = self.operation_id
        return result


def load_hindsight_config(path: str) -> Dict[str, str]:
    """Read the team config and require its canonical Hindsight endpoint."""
    try:
        with open(path, "r", encoding="utf-8") as handle:
            data = json.load(handle)
    except (OSError, ValueError) as error:
        raise TransportError("Hindsight configuration could not be read") from error
    if not isinstance(data, Mapping):
        raise TransportError("Hindsight configuration must be a JSON object")
    api_url = data.get("apiUrl", data.get("hindsightApiUrl"))
    api_token = data.get("apiToken", data.get("hindsightApiToken"))
    if not isinstance(api_url, str) or not api_url or not isinstance(api_token, str) or not api_token:
        raise TransportError("Hindsight configuration requires API URL and token fields")
    if api_url.rstrip("/") != CANONICAL_HINDSIGHT_API_URL:
        raise TransportError("Hindsight configuration does not target the canonical Hindsight endpoint")
    return {"api_url": CANONICAL_HINDSIGHT_API_URL, "api_token": api_token}


class HindsightTransport:
    def __init__(self, api_url: str, api_token: str, *, opener: Optional[Callable[..., Any]] = None,
                 timeout: float = 30.0, clock: Callable[[], float] = time.monotonic,
                 sleeper: Callable[[float], None] = time.sleep) -> None:
        split = urlsplit(api_url)
        if split.scheme not in {"http", "https"} or not split.netloc or split.username or split.password or split.query or split.fragment:
            raise ValueError("api_url must be an http(s) origin without credentials, query, or fragment")
        if not isinstance(api_token, str) or not api_token:
            raise ValueError("api_token is required")
        if not isinstance(timeout, (int, float)) or timeout <= 0:
            raise ValueError("timeout must be positive")
        self._base_url = api_url.rstrip("/")
        self._token = api_token
        self.timeout = float(timeout)
        self._opener = opener or urlopen
        self._clock = clock
        self._sleeper = sleeper

    def safe_config(self) -> Dict[str, Any]:
        return {"api_url": self._base_url, "authenticated": True}

    @staticmethod
    def _segment(value: str, label: str) -> str:
        if not isinstance(value, str) or not value:
            raise ValueError(label + " is required")
        return quote(value, safe="")

    @staticmethod
    def _jsonable(value: Any, label: str) -> None:
        try:
            json.dumps(value, ensure_ascii=False)
        except (TypeError, ValueError) as error:
            raise ValueError(label + " must be JSON-compatible") from error

    def _url(self, bank_id: str, suffix: str) -> str:
        return self._base_url + "/v1/default/banks/" + self._segment(bank_id, "bank_id") + suffix

    def _request(self, method: str, bank_id: str, suffix: str, body: Optional[Mapping[str, Any]] = None,
                 timeout: Optional[float] = None) -> Dict[str, Any]:
        data = None
        headers = {"Authorization": "Bearer " + self._token, "Accept": "application/json"}
        if body is not None:
            self._jsonable(body, "request body")
            data = json.dumps(body, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
            headers["Content-Type"] = "application/json"
        request = Request(self._url(bank_id, suffix), data=data, headers=headers, method=method)
        try:
            response = self._opener(request, timeout=self.timeout if timeout is None else timeout)
            try:
                raw = response.read()
            finally:
                close = getattr(response, "close", None)
                if close:
                    close()
        except HTTPError as error:
            try:
                raw = error.read()
                decoded = json.loads(raw.decode("utf-8")) if raw else {}
            except Exception:
                decoded = {}
            safe = sanitize(decoded, self._token)
            message = safe.get("message") if isinstance(safe, Mapping) else None
            raise TransportError(_safe_text(message or "Hindsight HTTP request failed", self._token), error.code) from error
        except (URLError, OSError, TimeoutError) as error:
            raise TransportError("Hindsight request acknowledgement is uncertain") from error
        try:
            decoded = json.loads(raw.decode("utf-8")) if raw else {}
        except (UnicodeDecodeError, ValueError) as error:
            raise TransportError("Hindsight returned invalid JSON") from error
        if not isinstance(decoded, Mapping):
            raise TransportError("Hindsight returned an invalid response")
        return dict(decoded)

    def submit_retain(self, bank_id: str, items: Any, operation_id: str) -> Dict[str, Any]:
        if not isinstance(items, list) or not items:
            raise ValueError("items must be a nonempty list")
        if not isinstance(operation_id, str) or not operation_id:
            raise ValueError("operation_id is required")
        self._jsonable(items, "items")
        try:
            result = self._request("POST", bank_id, "/memories", {"items": items, "async": True, "operation_id": operation_id})
        except TransportError as error:
            error.operation_id = operation_id
            error.uncertain = error.status_code is None
            raise
        actual = result.get("operation_id")
        if actual is not None and actual != operation_id:
            raise TransportError("Hindsight returned a mismatched operation ID", operation_id=operation_id, uncertain=True)
        result["operation_id"] = operation_id
        return self._mutation_ack(result, operation_id)

    def get_operation(self, bank_id: str, operation_id: str, *, timeout: Optional[float] = None) -> Dict[str, Any]:
        result = self._request("GET", bank_id, "/operations/" + self._segment(operation_id, "operation_id") + "?include_payload=false", timeout=timeout)
        # Do not surface a payload even if a proxy/server disregards the query.
        result.pop("task_payload", None)
        result.pop("payload", None)
        actual = result.get("operation_id", result.get("id"))
        if actual is not None and actual != operation_id:
            raise TransportError("Hindsight returned a mismatched operation ID", operation_id=operation_id)
        return _operation_summary(result, operation_id, self._token)

    def list_documents(self, bank_id: str, *, limit: Optional[int] = None,
                       offset: Optional[int] = None) -> Dict[str, Any]:
        if limit is not None and (isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 100):
            raise ValueError("document page limit must be between 1 and 100")
        if offset is not None and (isinstance(offset, bool) or not isinstance(offset, int) or offset < 0):
            raise ValueError("document page offset must be non-negative")
        query = {key: value for key, value in (("limit", limit), ("offset", offset)) if value is not None}
        suffix = "/documents" + (("?" + urlencode(query)) if query else "")
        result = self._request("GET", bank_id, suffix)
        raw_items = result.get("items")
        if not isinstance(raw_items, list) or not all(isinstance(item, Mapping) for item in raw_items):
            raise TransportError("Hindsight returned an invalid document page")
        page: Dict[str, Any] = {"items": [_document_summary(item, self._token) for item in raw_items]}
        for key in ("total", "limit", "offset"):
            value = result.get(key)
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise TransportError("Hindsight returned invalid document pagination")
            page[key] = value
        return page

    def consolidate(self, bank_id: str) -> Dict[str, Any]:
        return self._post_mutation(bank_id, "/consolidate", {})

    def get_knowledge_tree(self, bank_id: str) -> Dict[str, Any]:
        return dict(sanitize(self._request("GET", bank_id, "/knowledge-base/tree"), self._token))

    def get_knowledge_page(self, bank_id: str, page_id: str) -> Dict[str, Any]:
        result = self._request("GET", bank_id, "/knowledge-base/pages/" + self._segment(page_id, "page_id"))
        actual = result.get("id")
        if actual != page_id:
            raise TransportError("Hindsight returned a mismatched knowledge page ID")
        page: Dict[str, Any] = {"id": page_id}
        for key in ("name", "type", "description", "timestamp"):
            if key in result and (result[key] is None or isinstance(result[key], str)):
                page[key] = sanitize(result[key], self._token)
        tags = result.get("tags")
        if isinstance(tags, list) and all(isinstance(tag, str) for tag in tags):
            page["tags"] = sanitize(tags, self._token)
        for key in ("body", "markdown"):
            if key in result and (result[key] is None or isinstance(result[key], str)):
                page[key] = result[key]
        if "markdown" not in page:
            raise TransportError("Hindsight returned an invalid knowledge page")
        return page

    def get_mental_model(self, bank_id: str, model_id: str) -> Dict[str, Any]:
        result = self._request("GET", bank_id, "/mental-models/" + self._segment(model_id, "model_id") + "?detail=content")
        actual = result.get("id")
        if actual != model_id:
            raise TransportError("Hindsight returned a mismatched mental model ID")
        model: Dict[str, Any] = {"id": model_id}
        for key in ("name", "source_query", "last_refreshed_at", "last_memory_seen_at"):
            if key in result and (result[key] is None or isinstance(result[key], str)):
                model[key] = sanitize(result[key], self._token)
        if "content" in result and (result["content"] is None or isinstance(result["content"], str)):
            model["content"] = result["content"]
        else:
            raise TransportError("Hindsight returned an invalid mental model")
        tags = result.get("tags")
        if isinstance(tags, list) and all(isinstance(tag, str) for tag in tags):
            model["tags"] = _sanitize_success_value(tags, self._token)
        else:
            raise TransportError("Hindsight returned invalid mental model tags")
        max_tokens = result.get("max_tokens")
        if max_tokens is not None and (isinstance(max_tokens, bool) or not isinstance(max_tokens, int) or max_tokens <= 0):
            raise TransportError("Hindsight returned an invalid mental model token budget")
        model["max_tokens"] = max_tokens
        trigger = result.get("trigger")
        if trigger is not None and not isinstance(trigger, Mapping):
            raise TransportError("Hindsight returned an invalid mental model trigger")
        model["trigger"] = _sanitize_success_value(trigger, self._token)
        return model

    def create_knowledge_page(self, bank_id: str, page: Mapping[str, Any]) -> Dict[str, Any]:
        if not isinstance(page, Mapping) or not isinstance(page.get("name"), str) or not page["name"] or not isinstance(page.get("source_query"), str) or not page["source_query"]:
            raise ValueError("knowledge page requires name and source_query")
        result = self._post_mutation(bank_id, "/knowledge-base/pages", dict(page))
        if result.get("status") in {"acknowledged", "completed"}:
            required = ("page_id", "mental_model_id", "operation_id")
            if not all(isinstance(result.get(key), str) and result[key] for key in required):
                raise TransportError("Hindsight returned an incomplete knowledge page acknowledgement", operation_id=result.get("operation_id"), uncertain=True)
        return result

    def refresh_mental_model(self, bank_id: str, model_id: str) -> Dict[str, Any]:
        return self._post_mutation(bank_id, "/mental-models/" + self._segment(model_id, "model_id") + "/refresh", {})

    def _post_mutation(self, bank_id: str, suffix: str, body: Mapping[str, Any]) -> Dict[str, Any]:
        try:
            result = self._request("POST", bank_id, suffix, body)
        except TransportError as error:
            if error.status_code is None:
                error.uncertain = True
            raise
        return self._mutation_ack(result, result.get("operation_id", result.get("id")))

    def _mutation_ack(self, result: Mapping[str, Any], operation_id: Optional[str]) -> Dict[str, Any]:
        answer: Dict[str, Any] = {}
        for key in ("operation_id", "page_id", "mental_model_id"):
            if isinstance(result.get(key), str) and result[key]:
                answer[key] = _safe_text(result[key], self._token)
        if isinstance(result.get("deduplicated"), bool):
            answer["deduplicated"] = result["deduplicated"]
        state = result.get("status")
        if state in _MUTATION_PENDING:
            if not isinstance(operation_id, str) or not operation_id:
                raise TransportError("Hindsight returned a pending mutation without an operation ID", uncertain=True)
            answer["operation_id"] = operation_id; answer["remote_status"] = state; answer["status"] = "acknowledged"
            return answer
        if state in _TERMINAL:
            answer["operation_id"] = operation_id
            answer["status"] = state
            return answer
        if state is None and isinstance(operation_id, str) and operation_id:
            answer["operation_id"] = operation_id; answer["status"] = "acknowledged"
            return answer
        raise TransportError("Hindsight returned an unknown mutation status", operation_id=operation_id, uncertain=True)

    def wait_operation(self, bank_id: str, operation_id: str, *, deadline_seconds: float = 300.0,
                       initial_backoff: float = 1.0, max_backoff: float = 30.0) -> Dict[str, Any]:
        if deadline_seconds <= 0 or initial_backoff <= 0 or max_backoff <= 0:
            raise ValueError("polling durations must be positive")
        end = self._clock() + deadline_seconds
        delay = min(initial_backoff, 60.0, max_backoff)
        while True:
            remaining = end - self._clock()
            if remaining <= 0:
                return {"operation_id": operation_id, "status": "timed_out"}
            status = self.get_operation(bank_id, operation_id, timeout=min(self.timeout, remaining))
            state = status.get("status")
            if state in _TERMINAL:
                return _operation_summary(status, operation_id, self._token)
            if state not in _PENDING:
                raise TransportError("Hindsight returned an unknown operation status", operation_id=operation_id)
            remaining = end - self._clock()
            if remaining <= 0:
                return {"operation_id": operation_id, "status": "timed_out"}
            self._sleeper(min(delay, remaining, 60.0))
            delay = min(delay * 2, max_backoff, 60.0)


def _operation_summary(value: Mapping[str, Any], operation_id: str, token: Optional[str] = None) -> Dict[str, Any]:
    result: Dict[str, Any] = {"operation_id": operation_id, "status": value.get("status")}
    for key in ("updated_at", "created_at"):
        if isinstance(value.get(key), (str, int, float, bool)) or value.get(key) is None:
            if key in value:
                result[key] = value[key]
    if value.get("status") in {"failed", "cancelled"} and isinstance(value.get("error_message"), str):
        result["error_message"] = _safe_text(value["error_message"], token)
    for key in ("total_tokens", "input_tokens", "output_tokens", "content_hash"):
        if isinstance(value.get(key), (str, int, float)) and not isinstance(value.get(key), bool):
            result[key] = value[key]
    progress = value.get("progress")
    if isinstance(progress, Mapping):
        allowed = {key: sanitize(progress[key], token) for key in ("stage", "at", "processed", "total") if key in progress}
        if allowed:
            result["progress"] = allowed
    return result
