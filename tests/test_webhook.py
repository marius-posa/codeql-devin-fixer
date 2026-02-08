"""Unit tests for scripts/webhook.py.

Covers: _sign_payload, send_webhook, main CLI.
"""

import hashlib
import hmac
import json
import os
import sys
from unittest.mock import patch, MagicMock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from scripts.webhook import _sign_payload, send_webhook


class TestSignPayload:
    def test_produces_sha256_prefix(self):
        sig = _sign_payload(b"hello", "secret")
        assert sig.startswith("sha256=")

    def test_deterministic(self):
        sig1 = _sign_payload(b"data", "key")
        sig2 = _sign_payload(b"data", "key")
        assert sig1 == sig2

    def test_different_secrets_differ(self):
        sig1 = _sign_payload(b"data", "key1")
        sig2 = _sign_payload(b"data", "key2")
        assert sig1 != sig2

    def test_matches_manual_hmac(self):
        payload = b'{"event": "test"}'
        secret = "mysecret"
        expected = "sha256=" + hmac.new(
            secret.encode(), payload, hashlib.sha256
        ).hexdigest()
        assert _sign_payload(payload, secret) == expected


class TestSendWebhook:
    @patch("scripts.webhook.requests.post")
    def test_successful_delivery(self, mock_post):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_post.return_value = mock_resp
        result = send_webhook("http://example.com/hook", "scan_started", {"repo": "test"})
        assert result is True
        mock_post.assert_called_once()

    @patch("scripts.webhook.requests.post")
    def test_includes_event_header(self, mock_post):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_post.return_value = mock_resp
        send_webhook("http://example.com/hook", "scan_completed", {})
        call_kwargs = mock_post.call_args
        headers = call_kwargs.kwargs.get("headers") or call_kwargs[1].get("headers")
        assert headers["X-CodeQL-Fixer-Event"] == "scan_completed"

    @patch("scripts.webhook.requests.post")
    def test_includes_signature_when_secret_set(self, mock_post):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_post.return_value = mock_resp
        send_webhook("http://example.com/hook", "scan_started", {}, secret="s3cret")
        call_kwargs = mock_post.call_args
        headers = call_kwargs.kwargs.get("headers") or call_kwargs[1].get("headers")
        assert "X-Hub-Signature-256" in headers
        assert headers["X-Hub-Signature-256"].startswith("sha256=")

    @patch("scripts.webhook.requests.post")
    def test_no_signature_without_secret(self, mock_post):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_post.return_value = mock_resp
        send_webhook("http://example.com/hook", "scan_started", {})
        call_kwargs = mock_post.call_args
        headers = call_kwargs.kwargs.get("headers") or call_kwargs[1].get("headers")
        assert "X-Hub-Signature-256" not in headers

    @patch("scripts.webhook.time.sleep")
    @patch("scripts.webhook.requests.post")
    def test_retries_on_server_error(self, mock_post, mock_sleep):
        fail_resp = MagicMock()
        fail_resp.status_code = 500
        fail_resp.text = "Internal Server Error"
        ok_resp = MagicMock()
        ok_resp.status_code = 200
        mock_post.side_effect = [fail_resp, ok_resp]
        result = send_webhook("http://example.com/hook", "scan_started", {})
        assert result is True
        assert mock_post.call_count == 2

    @patch("scripts.webhook.time.sleep")
    @patch("scripts.webhook.requests.post")
    def test_returns_false_after_max_retries(self, mock_post, mock_sleep):
        fail_resp = MagicMock()
        fail_resp.status_code = 500
        fail_resp.text = "Internal Server Error"
        mock_post.return_value = fail_resp
        result = send_webhook("http://example.com/hook", "scan_started", {})
        assert result is False
        assert mock_post.call_count == 3

    @patch("scripts.webhook.requests.post")
    def test_payload_contains_event_and_timestamp(self, mock_post):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_post.return_value = mock_resp
        send_webhook("http://example.com/hook", "session_created", {"session_id": "s1"})
        call_kwargs = mock_post.call_args
        payload = json.loads(call_kwargs.kwargs.get("data") or call_kwargs[1].get("data"))
        assert payload["event"] == "session_created"
        assert "timestamp" in payload
        assert payload["session_id"] == "s1"
