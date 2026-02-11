"""Tests for the GitHub App Flask endpoints.

Covers: /healthz, /api/github/webhook, /api/github/scan,
        /api/github/installations, /api/github/installations/<id>/repos.
"""

import hashlib
import hmac
import json
import os
import sys
from unittest.mock import patch, MagicMock

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from github_app.app import create_app
from github_app.config import AppConfig


def _make_config(tmp_path):
    key_file = tmp_path / "test.pem"
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives import serialization

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    key_file.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        )
    )
    return AppConfig(
        app_id=12345,
        private_key_path=str(key_file),
        webhook_secret="test-webhook-secret",
        devin_api_key="test-devin-key",
    )


@pytest.fixture()
def app_client(tmp_path):
    config = _make_config(tmp_path)
    app = create_app(config)
    app.config["TESTING"] = True
    with app.test_client() as client:
        yield client, config


def _sign_payload(payload_bytes: bytes, secret: str) -> str:
    return "sha256=" + hmac.new(
        secret.encode(), payload_bytes, hashlib.sha256
    ).hexdigest()


class TestHealthEndpoint:
    @patch("github_app.auth.GitHubAppAuth.get_app_info")
    def test_healthy(self, mock_info, app_client):
        client, _ = app_client
        mock_info.return_value = {"name": "test-app"}
        resp = client.get("/healthz")
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["status"] == "ok"
        assert data["app_name"] == "test-app"
        assert data["app_id"] == 12345

    @patch("github_app.auth.GitHubAppAuth.get_app_info")
    def test_unhealthy(self, mock_info, app_client):
        client, _ = app_client
        mock_info.side_effect = Exception("connection refused")
        resp = client.get("/healthz")
        assert resp.status_code == 503
        data = resp.get_json()
        assert data["status"] == "error"


class TestWebhookEndpoint:
    def test_rejects_missing_signature(self, app_client):
        client, _ = app_client
        resp = client.post(
            "/api/github/webhook",
            data=b"{}",
            content_type="application/json",
        )
        assert resp.status_code == 401

    def test_rejects_invalid_signature(self, app_client):
        client, _ = app_client
        resp = client.post(
            "/api/github/webhook",
            data=b"{}",
            content_type="application/json",
            headers={"X-Hub-Signature-256": "sha256=bad"},
        )
        assert resp.status_code == 401

    def test_accepts_valid_push_event(self, app_client):
        client, config = app_client
        payload = json.dumps({
            "ref": "refs/heads/main",
            "repository": {"full_name": "owner/repo", "default_branch": "main"},
            "installation": {"id": 1},
            "pusher": {"name": "dev"},
            "commits": [{"id": "abc"}],
        }).encode()
        sig = _sign_payload(payload, config.webhook_secret)
        resp = client.post(
            "/api/github/webhook",
            data=payload,
            content_type="application/json",
            headers={
                "X-Hub-Signature-256": sig,
                "X-GitHub-Event": "push",
                "X-GitHub-Delivery": "test-delivery-1",
            },
        )
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["status"] == "scan_eligible"

    def test_accepts_valid_installation_event(self, app_client):
        client, config = app_client
        payload = json.dumps({
            "action": "created",
            "installation": {"id": 42, "account": {"login": "testuser"}},
            "repositories": [{"full_name": "testuser/repo1"}],
        }).encode()
        sig = _sign_payload(payload, config.webhook_secret)
        resp = client.post(
            "/api/github/webhook",
            data=payload,
            content_type="application/json",
            headers={
                "X-Hub-Signature-256": sig,
                "X-GitHub-Event": "installation",
                "X-GitHub-Delivery": "test-delivery-2",
            },
        )
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["status"] == "installed"

    def test_ignores_unhandled_event(self, app_client):
        client, config = app_client
        payload = json.dumps({"action": "starred"}).encode()
        sig = _sign_payload(payload, config.webhook_secret)
        resp = client.post(
            "/api/github/webhook",
            data=payload,
            content_type="application/json",
            headers={
                "X-Hub-Signature-256": sig,
                "X-GitHub-Event": "star",
                "X-GitHub-Delivery": "test-delivery-3",
            },
        )
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["status"] == "ignored"


class TestManualScanEndpoint:
    def test_requires_repository(self, app_client):
        client, _ = app_client
        resp = client.post(
            "/api/github/scan",
            json={"installation_id": 1},
        )
        assert resp.status_code == 400
        assert "repository" in resp.get_json()["error"]

    def test_requires_installation_id(self, app_client):
        client, _ = app_client
        resp = client.post(
            "/api/github/scan",
            json={"repository": "owner/repo"},
        )
        assert resp.status_code == 400
        assert "installation_id" in resp.get_json()["error"]

    @patch("github_app.app.trigger_scan")
    @patch("github_app.auth.GitHubAppAuth.get_installation_token")
    def test_triggers_scan(self, mock_token, mock_scan, app_client):
        client, _ = app_client
        mock_token.return_value = "ghs_test"
        mock_scan.return_value = {"status": "completed", "steps": []}
        resp = client.post(
            "/api/github/scan",
            json={
                "repository": "owner/repo",
                "installation_id": 42,
                "dry_run": True,
            },
        )
        assert resp.status_code == 200
        mock_scan.assert_called_once()
        call_args = mock_scan.call_args[0][0]
        assert call_args["target_repo"] == "https://github.com/owner/repo"
        assert call_args["dry_run"] is True

    @patch("github_app.auth.GitHubAppAuth.get_installation_token")
    def test_handles_token_error(self, mock_token, app_client):
        client, _ = app_client
        mock_token.side_effect = Exception("bad credentials")
        resp = client.post(
            "/api/github/scan",
            json={"repository": "owner/repo", "installation_id": 42},
        )
        assert resp.status_code == 400
        assert "Token error" in resp.get_json()["error"]


class TestInstallationsEndpoint:
    @patch("github_app.auth.GitHubAppAuth.list_installations")
    def test_lists_installations(self, mock_list, app_client):
        client, _ = app_client
        mock_list.return_value = [
            {
                "id": 1,
                "account": {"login": "org1", "type": "Organization"},
                "target_type": "Organization",
                "created_at": "2025-01-01T00:00:00Z",
                "app_slug": "codeql-fixer",
            },
        ]
        resp = client.get("/api/github/installations")
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["total"] == 1
        assert data["installations"][0]["account"] == "org1"

    @patch("github_app.auth.GitHubAppAuth.list_installations")
    def test_handles_error(self, mock_list, app_client):
        client, _ = app_client
        mock_list.side_effect = Exception("API error")
        resp = client.get("/api/github/installations")
        assert resp.status_code == 500


class TestInstallationReposEndpoint:
    @patch("github_app.auth.GitHubAppAuth.get_installation_repos")
    def test_lists_repos(self, mock_repos, app_client):
        client, _ = app_client
        mock_repos.return_value = [
            {
                "full_name": "org/repo1",
                "private": False,
                "default_branch": "main",
                "language": "Python",
                "html_url": "https://github.com/org/repo1",
            },
        ]
        resp = client.get("/api/github/installations/1/repos")
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["total"] == 1
        assert data["repositories"][0]["full_name"] == "org/repo1"

    @patch("github_app.auth.GitHubAppAuth.get_installation_repos")
    def test_handles_error(self, mock_repos, app_client):
        client, _ = app_client
        mock_repos.side_effect = Exception("token expired")
        resp = client.get("/api/github/installations/1/repos")
        assert resp.status_code == 500
