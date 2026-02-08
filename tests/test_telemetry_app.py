"""Unit tests for the telemetry Flask application (telemetry/app.py).

Covers: API endpoints, pagination, auth decorator.
Updated for SQLite-backed storage.
"""

import json
import os
import pathlib
import sys
import tempfile
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "telemetry"))

import pytest

_tmp_dir = tempfile.mkdtemp()
_test_db_path = os.path.join(_tmp_dir, "test_app.db")
os.environ["TELEMETRY_DB_PATH"] = _test_db_path

import database
database.DB_PATH = pathlib.Path(_test_db_path)
from database import get_connection, init_db, insert_run, upsert_pr
from app import app, _paginate, _load_registry, _save_registry, _load_orchestrator_state, _load_orchestrator_registry


def _seed_db(runs=None, prs=None):
    conn = get_connection(pathlib.Path(_test_db_path))
    init_db(conn)
    if runs:
        for r in runs:
            insert_run(conn, r, r.get("_file", "test.json"))
    if prs:
        for p in prs:
            upsert_pr(conn, p)
    conn.commit()
    conn.close()


def _clear_db():
    conn = get_connection(pathlib.Path(_test_db_path))
    for tbl in ["pr_issue_ids", "prs", "session_issue_ids", "sessions", "issues", "runs", "metadata"]:
        try:
            conn.execute(f"DELETE FROM {tbl}")
        except Exception:
            pass
    conn.commit()
    conn.close()


@pytest.fixture(autouse=True)
def clean_db():
    _clear_db()
    yield
    _clear_db()


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


class TestApiEndpoints:
    def test_api_runs_returns_paginated(self, client, sample_run):
        _seed_db(runs=[
            {**sample_run, "run_label": f"run-{i}", "run_number": i}
            for i in range(1, 4)
        ])
        resp = client.get("/api/runs?page=1&per_page=2")
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["total"] == 3
        assert len(data["items"]) == 2

    def test_api_stats_returns_json(self, client):
        resp = client.get("/api/stats")
        assert resp.status_code == 200
        data = resp.get_json()
        assert "repos_scanned" in data
        assert "total_issues" in data

    def test_api_repos_returns_list(self, client):
        resp = client.get("/api/repos")
        assert resp.status_code == 200
        data = resp.get_json()
        assert isinstance(data, list)

    def test_api_sessions_returns_paginated(self, client):
        resp = client.get("/api/sessions")
        assert resp.status_code == 200
        data = resp.get_json()
        assert "items" in data
        assert "total" in data

    def test_api_prs_returns_paginated(self, client):
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

    def test_api_issues_returns_paginated(self, client):
        resp = client.get("/api/issues")
        assert resp.status_code == 200
        data = resp.get_json()
        assert "items" in data

    def test_api_sla_returns_json(self, client):
        resp = client.get("/api/sla")
        assert resp.status_code == 200
        data = resp.get_json()
        assert "total_breached" in data
        assert "total_on_track" in data
        assert "time_to_fix_by_severity" in data

    def test_api_dispatch_preflight_requires_target_repo(self, client):
        resp = client.get("/api/dispatch/preflight")
        assert resp.status_code == 400
        data = resp.get_json()
        assert "error" in data

    def test_api_stats_accepts_period(self, client):
        _seed_db(runs=[
            {"target_repo": "r", "fork_url": "", "run_number": 1,
             "run_label": "old", "timestamp": "2020-01-01T00:00:00Z",
             "issues_found": 1, "severity_breakdown": {}, "category_breakdown": {},
             "batches_created": 0, "sessions": [], "issue_fingerprints": []},
            {"target_repo": "r", "fork_url": "", "run_number": 2,
             "run_label": "new", "timestamp": "2099-01-01T00:00:00Z",
             "issues_found": 2, "severity_breakdown": {}, "category_breakdown": {},
             "batches_created": 0, "sessions": [], "issue_fingerprints": []},
        ])
        resp = client.get("/api/stats?period=7d")
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["period"] == "7d"
        assert data["total_runs"] == 1

    def test_api_registry_get(self, client):
        with patch("app.REGISTRY_PATH", Path("/nonexistent")):
            resp = client.get("/api/registry")
            assert resp.status_code == 200
            data = resp.get_json()
            assert "repos" in data
            assert data["repos"] == []

    def test_api_config_includes_oauth_status(self, client):
        resp = client.get("/api/config")
        assert resp.status_code == 200
        data = resp.get_json()
        assert "oauth_configured" in data

    def test_api_report_pdf_returns_pdf(self, client):
        resp = client.get("/api/report/pdf")
        assert resp.status_code == 200
        assert resp.content_type == "application/pdf"
        assert resp.data[:5] == b"%PDF-"

    def test_api_report_pdf_with_repo_filter(self, client, sample_run):
        _seed_db(runs=[sample_run])
        resp = client.get("/api/report/pdf?repo=https://github.com/owner/repo")
        assert resp.status_code == 200
        assert "owner-repo" in resp.headers.get("Content-Disposition", "")

    def test_api_issues_search_requires_q(self, client):
        resp = client.get("/api/issues/search")
        assert resp.status_code == 400
        data = resp.get_json()
        assert "error" in data


class TestRegistryEndpoints:
    def test_load_registry_missing_file(self):
        with patch("app.REGISTRY_PATH", Path("/nonexistent/file.json")):
            data = _load_registry()
            assert data["repos"] == []
            assert data["version"] == "1.0"

    def test_load_registry_reads_file(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump({"version": "1.0", "repos": [{"repo": "test"}]}, f)
            f.flush()
            with patch("app.REGISTRY_PATH", Path(f.name)):
                data = _load_registry()
                assert len(data["repos"]) == 1
            os.unlink(f.name)

    def test_save_and_load_registry(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            f.write("{}")
            f.flush()
            with patch("app.REGISTRY_PATH", Path(f.name)):
                _save_registry({"version": "1.0", "repos": [{"repo": "a"}]})
                data = _load_registry()
                assert data["repos"] == [{"repo": "a"}]
            os.unlink(f.name)


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


class TestOrchestratorEndpoints:
    def test_orchestrator_status_returns_json(self, client):
        resp = client.get("/api/orchestrator/status")
        assert resp.status_code == 200
        data = resp.get_json()
        assert "issue_state_breakdown" in data
        assert "rate_limit" in data
        assert "objective_progress" in data
        assert "timestamp" in data

    def test_orchestrator_status_rate_limit_shape(self, client):
        resp = client.get("/api/orchestrator/status")
        data = resp.get_json()
        rl = data["rate_limit"]
        assert "used" in rl
        assert "max" in rl
        assert "remaining" in rl
        assert "period_hours" in rl
        assert rl["remaining"] == rl["max"] - rl["used"]

    def test_orchestrator_history_returns_paginated(self, client):
        resp = client.get("/api/orchestrator/history")
        assert resp.status_code == 200
        data = resp.get_json()
        assert "items" in data
        assert "total" in data
        assert "page" in data

    def test_orchestrator_history_with_fingerprint(self, client):
        resp = client.get("/api/orchestrator/history?fingerprint=abc123")
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["fingerprint"] == "abc123"
        assert "entries" in data

    def test_orchestrator_plan_runs(self, client):
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = type("R", (), {
                "returncode": 0,
                "stdout": json.dumps({"eligible_issues": 0, "batches": []}),
                "stderr": "",
            })()
            resp = client.get("/api/orchestrator/plan")
            assert resp.status_code == 200

    def test_orchestrator_plan_failure(self, client):
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = type("R", (), {
                "returncode": 1,
                "stdout": "",
                "stderr": "error",
            })()
            resp = client.get("/api/orchestrator/plan")
            assert resp.status_code == 500

    def test_orchestrator_scan_requires_env(self, client, monkeypatch):
        monkeypatch.setenv("TELEMETRY_API_KEY", "test-key")
        monkeypatch.delenv("GITHUB_TOKEN", raising=False)
        monkeypatch.delenv("ACTION_REPO", raising=False)
        resp = client.post(
            "/api/orchestrator/scan",
            headers={"X-API-Key": "test-key"},
            json={},
        )
        assert resp.status_code == 400
        data = resp.get_json()
        assert "Missing env vars" in data["error"]

    def test_orchestrator_dispatch_requires_env(self, client, monkeypatch):
        monkeypatch.setenv("TELEMETRY_API_KEY", "test-key")
        monkeypatch.delenv("DEVIN_API_KEY", raising=False)
        resp = client.post(
            "/api/orchestrator/dispatch",
            headers={"X-API-Key": "test-key"},
            json={},
        )
        assert resp.status_code == 400
        data = resp.get_json()
        assert "DEVIN_API_KEY" in data["error"]

    def test_orchestrator_scan_dry_run_bypasses_env_check(self, client, monkeypatch):
        monkeypatch.setenv("TELEMETRY_API_KEY", "test-key")
        monkeypatch.delenv("GITHUB_TOKEN", raising=False)
        monkeypatch.delenv("ACTION_REPO", raising=False)
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = type("R", (), {
                "returncode": 0,
                "stdout": json.dumps({"dry_run": True, "total_repos": 0, "results": []}),
                "stderr": "",
            })()
            resp = client.post(
                "/api/orchestrator/scan",
                headers={"X-API-Key": "test-key"},
                json={"dry_run": True},
            )
            assert resp.status_code == 200

    def test_load_orchestrator_state_missing_file(self):
        with patch("app._ORCHESTRATOR_STATE_PATH") as mock_path:
            mock_path.exists.return_value = False
            state = _load_orchestrator_state()
            assert state["last_cycle"] is None
            assert state["dispatch_history"] == {}

    def test_load_orchestrator_registry_missing_file(self):
        with patch("app._ORCHESTRATOR_REGISTRY_PATH") as mock_path:
            mock_path.exists.return_value = False
            reg = _load_orchestrator_registry()
            assert reg["repos"] == []

    def test_orchestrator_cycle_requires_env(self, client, monkeypatch):
        monkeypatch.setenv("TELEMETRY_API_KEY", "test-key")
        monkeypatch.delenv("GITHUB_TOKEN", raising=False)
        monkeypatch.delenv("ACTION_REPO", raising=False)
        resp = client.post(
            "/api/orchestrator/cycle",
            headers={"X-API-Key": "test-key"},
            json={},
        )
        assert resp.status_code == 400
        data = resp.get_json()
        assert "Missing env vars" in data["error"]

    def test_orchestrator_cycle_requires_devin_key(self, client, monkeypatch):
        monkeypatch.setenv("TELEMETRY_API_KEY", "test-key")
        monkeypatch.setenv("GITHUB_TOKEN", "tok")
        monkeypatch.setenv("ACTION_REPO", "owner/repo")
        monkeypatch.delenv("DEVIN_API_KEY", raising=False)
        resp = client.post(
            "/api/orchestrator/cycle",
            headers={"X-API-Key": "test-key"},
            json={},
        )
        assert resp.status_code == 400
        data = resp.get_json()
        assert "DEVIN_API_KEY" in data["error"]

    def test_orchestrator_cycle_dry_run(self, client, monkeypatch):
        monkeypatch.setenv("TELEMETRY_API_KEY", "test-key")
        monkeypatch.delenv("GITHUB_TOKEN", raising=False)
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = type("R", (), {
                "returncode": 0,
                "stdout": json.dumps({"scan": {"triggered": 0}, "dispatch": {"sessions_created": 0}}),
                "stderr": "",
            })()
            resp = client.post(
                "/api/orchestrator/cycle",
                headers={"X-API-Key": "test-key"},
                json={"dry_run": True},
            )
            assert resp.status_code == 200
            data = resp.get_json()
            assert "scan" in data

    def test_orchestrator_config_get(self, client):
        with patch("app._load_orchestrator_registry", return_value={"orchestrator": {"global_session_limit": 10}, "repos": []}):
            resp = client.get("/api/orchestrator/config")
            assert resp.status_code == 200
            data = resp.get_json()
            assert data["global_session_limit"] == 10
            assert "global_session_limit_period_hours" in data
            assert "objectives" in data
            assert "alert_on_objective_met" in data

    def test_orchestrator_config_get_defaults(self, client):
        with patch("app._load_orchestrator_registry", return_value={"orchestrator": {}, "repos": []}):
            resp = client.get("/api/orchestrator/config")
            assert resp.status_code == 200
            data = resp.get_json()
            assert data["global_session_limit"] == 20
            assert data["global_session_limit_period_hours"] == 24
            assert data["objectives"] == []
            assert data["alert_on_objective_met"] is False

    def test_orchestrator_config_put_requires_auth(self, client, monkeypatch):
        monkeypatch.setenv("TELEMETRY_API_KEY", "test-key")
        resp = client.put(
            "/api/orchestrator/config",
            json={"global_session_limit": 5},
        )
        assert resp.status_code == 401

    def test_orchestrator_config_put_requires_body(self, client, monkeypatch):
        monkeypatch.setenv("TELEMETRY_API_KEY", "test-key")
        resp = client.put(
            "/api/orchestrator/config",
            headers={"X-API-Key": "test-key"},
        )
        assert resp.status_code == 400

    def test_orchestrator_config_put_updates(self, client, monkeypatch):
        monkeypatch.setenv("TELEMETRY_API_KEY", "test-key")
        import tempfile
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump({"orchestrator": {"global_session_limit": 20}, "repos": []}, f)
            f.flush()
            with patch("app._ORCHESTRATOR_REGISTRY_PATH", Path(f.name)), \
                 patch("app._load_orchestrator_registry", return_value={"orchestrator": {"global_session_limit": 20}, "repos": []}):
                resp = client.put(
                    "/api/orchestrator/config",
                    headers={"X-API-Key": "test-key"},
                    json={"global_session_limit": 5, "global_session_limit_period_hours": 12},
                )
                assert resp.status_code == 200
                data = resp.get_json()
                assert data["global_session_limit"] == 5
                assert data["global_session_limit_period_hours"] == 12
            os.unlink(f.name)
