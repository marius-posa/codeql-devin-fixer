"""Unit tests for the telemetry Flask application (telemetry/app.py).

Covers: API endpoints, pagination, cache behaviour, auth decorator.
"""

import json
import os
import sys
import tempfile
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "telemetry"))

import pytest
from app import app, _paginate, _Cache, _load_runs_from_disk


@pytest.fixture
def client():
    app.config["TESTING"] = True
    with app.test_client() as c:
        yield c


@pytest.fixture
def sample_run():
    return {
        "target_repo": "https://github.com/owner/repo",
        "fork_url": "https://github.com/fork-owner/repo",
        "run_number": 1,
        "run_id": "abc123",
        "run_url": "https://github.com/owner/repo/actions/runs/abc123",
        "run_label": "run-1",
        "timestamp": "2026-01-01T00:00:00Z",
        "issues_found": 3,
        "severity_breakdown": {"high": 2, "medium": 1},
        "category_breakdown": {"injection": 2, "xss": 1},
        "batches_created": 1,
        "sessions": [
            {
                "session_id": "s1",
                "session_url": "https://app.devin.ai/sessions/s1",
                "batch_id": 1,
                "status": "created",
                "issue_ids": ["CQLF-R1-0001"],
            }
        ],
        "issue_fingerprints": [],
        "zero_issue_run": False,
    }


class TestPaginate:
    def test_first_page(self):
        result = _paginate([1, 2, 3, 4, 5], page=1, per_page=2)
        assert result["items"] == [1, 2]
        assert result["page"] == 1
        assert result["total"] == 5
        assert result["pages"] == 3

    def test_last_page(self):
        result = _paginate([1, 2, 3, 4, 5], page=3, per_page=2)
        assert result["items"] == [5]

    def test_empty_list(self):
        result = _paginate([], page=1, per_page=10)
        assert result["items"] == []
        assert result["total"] == 0
        assert result["pages"] == 1

    def test_single_page(self):
        result = _paginate([1, 2], page=1, per_page=10)
        assert result["items"] == [1, 2]
        assert result["pages"] == 1

    def test_beyond_last_page(self):
        result = _paginate([1, 2, 3], page=100, per_page=2)
        assert result["items"] == []


class TestCache:
    def test_invalidate_clears_runs(self):
        c = _Cache()
        c._runs = [{"a": 1}]
        c._runs_fingerprint = "something"
        c.invalidate_runs()
        assert c._runs == []
        assert c._runs_fingerprint == ""

    def test_set_and_get_prs(self):
        c = _Cache()
        c.set_prs([{"pr": 1}])
        assert c._prs == [{"pr": 1}]
        assert c._prs_ts > 0

    def test_set_and_get_polled_sessions(self):
        c = _Cache()
        assert c.get_polled_sessions() is None
        c.set_polled_sessions([{"s": 1}])
        assert c._sessions_polled == [{"s": 1}]
        assert c._sessions_ts > 0


class TestLoadRunsFromDisk:
    def test_loads_json_files(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            runs_dir = Path(tmpdir)
            (runs_dir / "run1.json").write_text(json.dumps({"run_number": 1}))
            (runs_dir / "run2.json").write_text(json.dumps({"run_number": 2}))
            with patch("app.RUNS_DIR", runs_dir):
                runs = _load_runs_from_disk()
                assert len(runs) == 2
                assert all("_file" in r for r in runs)

    def test_skips_invalid_json(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            runs_dir = Path(tmpdir)
            (runs_dir / "good.json").write_text(json.dumps({"run_number": 1}))
            (runs_dir / "bad.json").write_text("not json{{{")
            with patch("app.RUNS_DIR", runs_dir):
                runs = _load_runs_from_disk()
                assert len(runs) == 1

    def test_empty_directory(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            runs_dir = Path(tmpdir)
            with patch("app.RUNS_DIR", runs_dir):
                runs = _load_runs_from_disk()
                assert runs == []

    def test_nonexistent_directory(self):
        with patch("app.RUNS_DIR", Path("/nonexistent/path")):
            runs = _load_runs_from_disk()
            assert runs == []


class TestApiEndpoints:
    @patch("app.cache")
    def test_api_runs_returns_paginated(self, mock_cache, client):
        mock_cache.get_runs.return_value = [
            {"run_number": i, "timestamp": f"2026-01-0{i}T00:00:00Z"}
            for i in range(1, 4)
        ]
        resp = client.get("/api/runs?page=1&per_page=2")
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["total"] == 3
        assert len(data["items"]) == 2

    @patch("app.cache")
    def test_api_stats_returns_json(self, mock_cache, client):
        mock_cache.get_runs.return_value = []
        mock_cache.get_prs.return_value = []
        resp = client.get("/api/stats")
        assert resp.status_code == 200
        data = resp.get_json()
        assert "repos_scanned" in data
        assert "total_issues" in data

    @patch("app.cache")
    def test_api_repos_returns_list(self, mock_cache, client):
        mock_cache.get_runs.return_value = []
        mock_cache.get_prs.return_value = []
        resp = client.get("/api/repos")
        assert resp.status_code == 200
        data = resp.get_json()
        assert isinstance(data, list)

    @patch("app.cache")
    def test_api_sessions_returns_paginated(self, mock_cache, client):
        mock_cache.get_runs.return_value = []
        mock_cache.get_prs.return_value = []
        resp = client.get("/api/sessions")
        assert resp.status_code == 200
        data = resp.get_json()
        assert "items" in data
        assert "total" in data

    @patch("app.cache")
    def test_api_prs_returns_paginated(self, mock_cache, client):
        mock_cache.get_runs.return_value = []
        mock_cache.get_prs.return_value = []
        resp = client.get("/api/prs")
        assert resp.status_code == 200
        data = resp.get_json()
        assert "items" in data

    def test_api_config_returns_status(self, client):
        resp = client.get("/api/config")
        assert resp.status_code == 200
        data = resp.get_json()
        assert "github_token_set" in data
        assert "auth_required" in data

    @patch("app.cache")
    def test_api_issues_returns_paginated(self, mock_cache, client):
        mock_cache.get_runs.return_value = []
        resp = client.get("/api/issues")
        assert resp.status_code == 200
        data = resp.get_json()
        assert "items" in data

    @patch("app.cache")
    def test_api_sla_returns_json(self, mock_cache, client):
        mock_cache.get_runs.return_value = []
        resp = client.get("/api/sla")
        assert resp.status_code == 200
        data = resp.get_json()
        assert "total_breached" in data
        assert "total_on_track" in data
        assert "time_to_fix_by_severity" in data

    @patch("app.cache")
    def test_api_dispatch_preflight_requires_target_repo(self, mock_cache, client):
        resp = client.get("/api/dispatch/preflight")
        assert resp.status_code == 400
        data = resp.get_json()
        assert "error" in data

    def test_api_config_includes_oauth_status(self, client):
        resp = client.get("/api/config")
        assert resp.status_code == 200
        data = resp.get_json()
        assert "oauth_configured" in data

    @patch("app.cache")
    def test_api_report_pdf_returns_pdf(self, mock_cache, client):
        mock_cache.get_runs.return_value = []
        mock_cache.get_prs.return_value = []
        resp = client.get("/api/report/pdf")
        assert resp.status_code == 200
        assert resp.content_type == "application/pdf"
        assert resp.data[:5] == b"%PDF-"

    @patch("app.cache")
    def test_api_report_pdf_with_repo_filter(self, mock_cache, client):
        mock_cache.get_runs.return_value = [
            {"target_repo": "https://github.com/owner/repo", "timestamp": "2026-01-01T00:00:00Z",
             "issues_found": 1, "severity_breakdown": {"high": 1}, "category_breakdown": {},
             "sessions": [], "issue_fingerprints": [], "zero_issue_run": False},
        ]
        mock_cache.get_prs.return_value = []
        resp = client.get("/api/report/pdf?repo=https://github.com/owner/repo")
        assert resp.status_code == 200
        assert "owner-repo" in resp.headers.get("Content-Disposition", "")


class TestOAuth:
    def test_login_returns_400_when_not_configured(self, client):
        with patch("oauth.is_oauth_configured", return_value=False):
            resp = client.get("/login")
            assert resp.status_code == 400
            data = resp.get_json()
            assert "error" in data

    def test_logout_clears_session(self, client):
        with client.session_transaction() as sess:
            sess["gh_user"] = {"login": "test"}
        resp = client.get("/logout")
        assert resp.status_code == 302
        with client.session_transaction() as sess:
            assert "gh_user" not in sess

    def test_api_me_when_logged_out(self, client):
        resp = client.get("/api/me")
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["logged_in"] is False

    def test_api_me_when_logged_in(self, client):
        with client.session_transaction() as sess:
            sess["gh_user"] = {"login": "testuser", "avatar_url": "https://example.com/avatar.png"}
        resp = client.get("/api/me")
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["logged_in"] is True
        assert data["user"]["login"] == "testuser"


class TestPdfReport:
    def test_generate_pdf_returns_bytes(self):
        from pdf_report import generate_pdf
        stats = {
            "repos_scanned": 1, "total_runs": 2, "total_issues": 5,
            "latest_issues": 3, "sessions_created": 1, "sessions_finished": 1,
            "prs_total": 1, "prs_merged": 0, "fix_rate": 20,
            "severity_breakdown": {"high": 3, "medium": 2},
            "category_breakdown": {"injection": 3, "xss": 2},
        }
        issues = [
            {"rule_id": "js/sql-injection", "severity_tier": "high",
             "status": "open", "cwe_family": "injection",
             "file": "src/db.js", "start_line": 42, "appearances": 3},
        ]
        pdf = generate_pdf(stats, issues)
        assert isinstance(pdf, bytes)
        assert pdf[:5] == b"%PDF-"

    def test_generate_pdf_empty(self):
        from pdf_report import generate_pdf
        pdf = generate_pdf({}, [])
        assert pdf[:5] == b"%PDF-"

    def test_generate_pdf_with_repo_filter(self):
        from pdf_report import generate_pdf
        pdf = generate_pdf({}, [], repo_filter="https://github.com/owner/repo")
        assert isinstance(pdf, bytes)
        assert len(pdf) > 100


class TestFilterByUserAccess:
    def test_no_user_returns_all(self, client):
        from oauth import filter_by_user_access
        with client.application.test_request_context():
            items = [{"target_repo": "r1"}, {"target_repo": "r2"}]
            result = filter_by_user_access(items)
            assert len(result) == 2

    def test_filters_when_user_logged_in(self, client):
        from oauth import filter_by_user_access
        with client.session_transaction() as sess:
            sess["gh_user"] = {"login": "testuser"}
            sess["gh_repos"] = ["owner/repo"]
        with client.application.test_request_context():
            from flask import session
            session["gh_user"] = {"login": "testuser"}
            session["gh_repos"] = ["owner/repo"]
            with patch("oauth.is_oauth_configured", return_value=True):
                items = [{"target_repo": "owner/repo"}, {"target_repo": "other/repo"}]
                result = filter_by_user_access(items)
                assert len(result) == 1
                assert result[0]["target_repo"] == "owner/repo"
