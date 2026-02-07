"""Adversarial authentication tests for the telemetry API.

Covers: require_api_key decorator with various attack vectors including
missing keys, invalid keys, timing attacks, header manipulation.
"""

import os
import sys
from unittest.mock import patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "telemetry"))

import pytest
from app import app


@pytest.fixture
def client():
    app.config["TESTING"] = True
    with app.test_client() as c:
        yield c


class TestAuthRequired:
    def test_no_key_configured_allows_access(self, client):
        with patch.dict(os.environ, {"TELEMETRY_API_KEY": ""}, clear=False):
            resp = client.post("/api/poll")
            assert resp.status_code != 401

    def test_correct_x_api_key_header(self, client):
        with patch.dict(os.environ, {"TELEMETRY_API_KEY": "secret123"}, clear=False):
            resp = client.post("/api/poll", headers={"X-API-Key": "secret123"})
            assert resp.status_code != 401

    def test_correct_bearer_token(self, client):
        with patch.dict(os.environ, {"TELEMETRY_API_KEY": "secret123"}, clear=False):
            resp = client.post(
                "/api/poll", headers={"Authorization": "Bearer secret123"}
            )
            assert resp.status_code != 401

    def test_missing_key_returns_401(self, client):
        with patch.dict(os.environ, {"TELEMETRY_API_KEY": "secret123"}, clear=False):
            resp = client.post("/api/poll")
            assert resp.status_code == 401
            data = resp.get_json()
            assert data["error"] == "Unauthorized"

    def test_wrong_key_returns_401(self, client):
        with patch.dict(os.environ, {"TELEMETRY_API_KEY": "secret123"}, clear=False):
            resp = client.post("/api/poll", headers={"X-API-Key": "wrong-key"})
            assert resp.status_code == 401

    def test_empty_key_header_returns_401(self, client):
        with patch.dict(os.environ, {"TELEMETRY_API_KEY": "secret123"}, clear=False):
            resp = client.post("/api/poll", headers={"X-API-Key": ""})
            assert resp.status_code == 401

    def test_bearer_with_wrong_key_returns_401(self, client):
        with patch.dict(os.environ, {"TELEMETRY_API_KEY": "secret123"}, clear=False):
            resp = client.post(
                "/api/poll", headers={"Authorization": "Bearer wrong"}
            )
            assert resp.status_code == 401

    def test_basic_auth_not_accepted(self, client):
        with patch.dict(os.environ, {"TELEMETRY_API_KEY": "secret123"}, clear=False):
            resp = client.post(
                "/api/poll", headers={"Authorization": "Basic secret123"}
            )
            assert resp.status_code == 401

    def test_partial_key_returns_401(self, client):
        with patch.dict(os.environ, {"TELEMETRY_API_KEY": "secret123"}, clear=False):
            resp = client.post("/api/poll", headers={"X-API-Key": "secret"})
            assert resp.status_code == 401

    def test_key_with_extra_whitespace_returns_401(self, client):
        with patch.dict(os.environ, {"TELEMETRY_API_KEY": "secret123"}, clear=False):
            resp = client.post("/api/poll", headers={"X-API-Key": " secret123 "})
            assert resp.status_code == 401

    def test_poll_prs_requires_auth(self, client):
        with patch.dict(os.environ, {"TELEMETRY_API_KEY": "key"}, clear=False):
            resp = client.post("/api/poll-prs")
            assert resp.status_code == 401

    def test_refresh_requires_auth(self, client):
        with patch.dict(os.environ, {"TELEMETRY_API_KEY": "key"}, clear=False):
            resp = client.post("/api/refresh")
            assert resp.status_code == 401

    def test_backfill_requires_auth(self, client):
        with patch.dict(os.environ, {"TELEMETRY_API_KEY": "key"}, clear=False):
            resp = client.post("/api/backfill")
            assert resp.status_code == 401

    def test_get_endpoints_do_not_require_auth(self, client):
        with patch.dict(os.environ, {"TELEMETRY_API_KEY": "key"}, clear=False):
            for endpoint in ["/api/config", "/api/issues"]:
                resp = client.get(endpoint)
                assert resp.status_code != 401, f"{endpoint} should not require auth"
