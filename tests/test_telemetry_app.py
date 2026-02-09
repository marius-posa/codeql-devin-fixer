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
from app import app
from helpers import _paginate
from routes.registry import _load_registry, _save_registry, REGISTRY_PATH
from routes.orchestrator import _load_orchestrator_state, _load_orchestrator_registry


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
    for tbl in ["pr_issue_ids", "prs", "session_issue_ids", "sessions", "issues", "runs", "metadata", "orchestrator_kv", "dispatch_history", "rate_limiter_timestamps", "scan_schedule"]:
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
        with patch("routes.registry.REGISTRY_PATH", Path("/nonexistent")):
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
        with patch("routes.registry.REGISTRY_PATH", Path("/nonexistent/file.json")):
            data = _load_registry()
            assert data["repos"] == []
            assert data["version"] == "1.0"

    def test_load_registry_reads_file(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump({"version": "1.0", "repos": [{"repo": "test"}]}, f)
            f.flush()
            with patch("routes.registry.REGISTRY_PATH", Path(f.name)):
                data = _load_registry()
                assert len(data["repos"]) == 1
            os.unlink(f.name)

    def test_save_and_load_registry(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            f.write("{}")
            f.flush()
            with patch("routes.registry.REGISTRY_PATH", Path(f.name)):
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
        with patch("routes.orchestrator.subprocess.run") as mock_run:
            mock_run.return_value = type("R", (), {
                "returncode": 0,
                "stdout": json.dumps({"eligible_issues": 0, "batches": []}),
                "stderr": "",
            })()
            resp = client.get("/api/orchestrator/plan")
            assert resp.status_code == 200

    def test_orchestrator_plan_failure(self, client):
        with patch("routes.orchestrator.subprocess.run") as mock_run:
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
        with patch("routes.orchestrator.subprocess.run") as mock_run:
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

    def test_load_orchestrator_state_empty_db(self):
        with patch("routes.orchestrator._ORCHESTRATOR_STATE_PATH") as mock_path:
            mock_path.exists.return_value = False
            state = _load_orchestrator_state()
            assert state["last_cycle"] is None
            assert state["dispatch_history"] == {}

    def test_load_orchestrator_registry_missing_file(self):
        with patch("routes.orchestrator._ORCHESTRATOR_REGISTRY_PATH") as mock_path:
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
        with patch("routes.orchestrator.subprocess.run") as mock_run:
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
        with patch("routes.orchestrator._load_orchestrator_registry", return_value={"orchestrator": {"global_session_limit": 10}, "repos": []}):
            resp = client.get("/api/orchestrator/config")
            assert resp.status_code == 200
            data = resp.get_json()
            assert data["global_session_limit"] == 10
            assert "global_session_limit_period_hours" in data
            assert "objectives" in data
            assert "alert_on_objective_met" in data

    def test_orchestrator_config_get_defaults(self, client):
        with patch("routes.orchestrator._load_orchestrator_registry", return_value={"orchestrator": {}, "repos": []}):
            resp = client.get("/api/orchestrator/config")
            assert resp.status_code == 200
            data = resp.get_json()
            assert data["global_session_limit"] == 20
            assert data["global_session_limit_period_hours"] == 24
            assert data["objectives"] == []
            assert data["alert_on_objective_met"] is False
            assert data["alert_on_verified_fix"] is True
            assert data["alert_severities"] == ["critical", "high"]
            assert data["alert_webhook_url"] == ""

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
            with patch("routes.orchestrator._ORCHESTRATOR_REGISTRY_PATH", Path(f.name)), \
                 patch("routes.orchestrator._load_orchestrator_registry", return_value={"orchestrator": {"global_session_limit": 20}, "repos": []}):
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

    def test_orchestrator_config_put_alert_fields(self, client, monkeypatch):
        monkeypatch.setenv("TELEMETRY_API_KEY", "test-key")
        import tempfile
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump({"orchestrator": {}, "repos": []}, f)
            f.flush()
            with patch("routes.orchestrator._ORCHESTRATOR_REGISTRY_PATH", Path(f.name)), \
                 patch("routes.orchestrator._load_orchestrator_registry", return_value={"orchestrator": {}, "repos": []}):
                resp = client.put(
                    "/api/orchestrator/config",
                    headers={"X-API-Key": "test-key"},
                    json={
                        "alert_on_verified_fix": False,
                        "alert_severities": ["critical"],
                    },
                )
                assert resp.status_code == 200
                data = resp.get_json()
                assert data["alert_on_verified_fix"] is False
                assert data["alert_severities"] == ["critical"]
            os.unlink(f.name)

    def test_orchestrator_fix_rates_returns_json(self, client):
        resp = client.get("/api/orchestrator/fix-rates")
        assert resp.status_code == 200
        data = resp.get_json()
        assert "overall" in data
        assert "by_cwe_family" in data
        assert "by_repo" in data
        assert "by_severity" in data
        assert "total" in data["overall"]
        assert "fixed" in data["overall"]
        assert "fix_rate" in data["overall"]

    def test_orchestrator_fix_rates_empty_db(self, client):
        resp = client.get("/api/orchestrator/fix-rates")
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["overall"]["total"] == 0
        assert data["overall"]["fixed"] == 0
        assert data["overall"]["fix_rate"] == 0.0


class TestRegistryRepoEndpoints:
    def test_registry_add_repo_includes_new_fields(self, client, monkeypatch):
        monkeypatch.setenv("TELEMETRY_API_KEY", "test-key")
        import tempfile
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump({"version": "1.0", "repos": []}, f)
            f.flush()
            with patch("routes.registry.REGISTRY_PATH", Path(f.name)):
                resp = client.post(
                    "/api/registry/repos",
                    headers={"X-API-Key": "test-key"},
                    json={
                        "repo": "https://github.com/test/repo",
                        "importance": "high",
                        "importance_score": 80,
                        "max_sessions_per_cycle": 10,
                        "auto_scan": False,
                        "tags": ["web"],
                    },
                )
                assert resp.status_code == 201
                data = resp.get_json()
                assert data["importance"] == "high"
                assert data["importance_score"] == 80
                assert data["max_sessions_per_cycle"] == 10
                assert data["auto_scan"] is False
                assert data["tags"] == ["web"]
                assert data["auto_dispatch"] is True
            os.unlink(f.name)

    def test_registry_update_repo_by_index(self, client, monkeypatch):
        monkeypatch.setenv("TELEMETRY_API_KEY", "test-key")
        import tempfile
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump({
                "version": "1.0",
                "repos": [{"repo": "https://github.com/test/repo", "enabled": True, "importance": "low"}],
            }, f)
            f.flush()
            with patch("routes.registry.REGISTRY_PATH", Path(f.name)):
                resp = client.put(
                    "/api/registry/repos/0",
                    headers={"X-API-Key": "test-key"},
                    json={"importance": "critical", "importance_score": 95, "tags": ["core"]},
                )
                assert resp.status_code == 200
                data = resp.get_json()
                assert data["importance"] == "critical"
                assert data["importance_score"] == 95
                assert data["tags"] == ["core"]
                assert data["repo"] == "https://github.com/test/repo"
            os.unlink(f.name)

    def test_registry_update_repo_invalid_index(self, client, monkeypatch):
        monkeypatch.setenv("TELEMETRY_API_KEY", "test-key")
        import tempfile
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump({"version": "1.0", "repos": []}, f)
            f.flush()
            with patch("routes.registry.REGISTRY_PATH", Path(f.name)):
                resp = client.put(
                    "/api/registry/repos/5",
                    headers={"X-API-Key": "test-key"},
                    json={"importance": "high"},
                )
                assert resp.status_code == 404
            os.unlink(f.name)

    def test_registry_update_repo_requires_auth(self, client, monkeypatch):
        monkeypatch.setenv("TELEMETRY_API_KEY", "test-key")
        resp = client.put(
            "/api/registry/repos/0",
            json={"importance": "high"},
        )
        assert resp.status_code == 401

    def test_registry_update_repo_requires_body(self, client, monkeypatch):
        monkeypatch.setenv("TELEMETRY_API_KEY", "test-key")
        import tempfile
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump({"version": "1.0", "repos": [{"repo": "test"}]}, f)
            f.flush()
            with patch("routes.registry.REGISTRY_PATH", Path(f.name)):
                resp = client.put(
                    "/api/registry/repos/0",
                    headers={"X-API-Key": "test-key"},
                )
                assert resp.status_code == 400
            os.unlink(f.name)

    def test_registry_add_repo_rejects_invalid_importance(self, client, monkeypatch):
        monkeypatch.setenv("TELEMETRY_API_KEY", "test-key")
        import tempfile
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump({"version": "1.0", "repos": []}, f)
            f.flush()
            with patch("routes.registry.REGISTRY_PATH", Path(f.name)):
                resp = client.post(
                    "/api/registry/repos",
                    headers={"X-API-Key": "test-key"},
                    json={"repo": "https://github.com/t/r", "importance": "invalid"},
                )
                assert resp.status_code == 400
                assert "importance" in resp.get_json()["error"]
            os.unlink(f.name)

    def test_registry_add_repo_rejects_invalid_score(self, client, monkeypatch):
        monkeypatch.setenv("TELEMETRY_API_KEY", "test-key")
        import tempfile
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump({"version": "1.0", "repos": []}, f)
            f.flush()
            with patch("routes.registry.REGISTRY_PATH", Path(f.name)):
                resp = client.post(
                    "/api/registry/repos",
                    headers={"X-API-Key": "test-key"},
                    json={"repo": "https://github.com/t/r", "importance_score": 200},
                )
                assert resp.status_code == 400
                assert "importance_score" in resp.get_json()["error"]
            os.unlink(f.name)

    def test_registry_update_repo_rejects_invalid_schedule(self, client, monkeypatch):
        monkeypatch.setenv("TELEMETRY_API_KEY", "test-key")
        import tempfile
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump({"version": "1.0", "repos": [{"repo": "test"}]}, f)
            f.flush()
            with patch("routes.registry.REGISTRY_PATH", Path(f.name)):
                resp = client.put(
                    "/api/registry/repos/0",
                    headers={"X-API-Key": "test-key"},
                    json={"schedule": "every_minute"},
                )
                assert resp.status_code == 400
                assert "schedule" in resp.get_json()["error"]
            os.unlink(f.name)


class TestDemoDataEndpoints:
    def test_demo_data_status_returns_json(self, client):
        resp = client.get("/api/demo-data")
        assert resp.status_code == 200
        data = resp.get_json()
        assert "loaded" in data
        assert data["loaded"] is False

    def test_demo_data_load_requires_auth(self, client, monkeypatch):
        monkeypatch.setenv("TELEMETRY_API_KEY", "test-key")
        resp = client.post("/api/demo-data")
        assert resp.status_code == 401

    def test_demo_data_load_and_clear_cycle(self, client):
        resp = client.post("/api/demo-data")
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["loaded"] is True
        assert "stats" in data
        assert data["stats"]["runs"] > 0

        status_resp = client.get("/api/demo-data")
        assert status_resp.get_json()["loaded"] is True

        del_resp = client.delete("/api/demo-data")
        assert del_resp.status_code == 200
        del_data = del_resp.get_json()
        assert del_data["loaded"] is False
        assert del_data["stats"]["runs_deleted"] > 0

    def test_demo_data_load_twice_returns_conflict(self, client):
        client.post("/api/demo-data")
        resp = client.post("/api/demo-data")
        assert resp.status_code == 409
        data = resp.get_json()
        assert "error" in data

    def test_demo_data_clear_requires_auth(self, client, monkeypatch):
        monkeypatch.setenv("TELEMETRY_API_KEY", "test-key")
        resp = client.delete("/api/demo-data")
        assert resp.status_code == 401

    def test_demo_data_reset_requires_auth(self, client, monkeypatch):
        monkeypatch.setenv("TELEMETRY_API_KEY", "test-key")
        resp = client.post("/api/demo-data/reset")
        assert resp.status_code == 401

    def test_demo_data_reset_regenerates(self, client):
        resp = client.post("/api/demo-data/reset")
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["loaded"] is True
        assert data["stats"]["runs"] > 0

    def test_demo_data_files_returns_json(self, client):
        resp = client.get("/api/demo-data/files")
        assert resp.status_code == 200
        data = resp.get_json()
        assert "runs" in data
        assert isinstance(data["runs"], list)

    def test_demo_data_files_update_requires_auth(self, client, monkeypatch):
        monkeypatch.setenv("TELEMETRY_API_KEY", "test-key")
        resp = client.put("/api/demo-data/files", json={"runs": []})
        assert resp.status_code == 401

    def test_demo_data_files_update_requires_body(self, client):
        resp = client.put("/api/demo-data/files")
        assert resp.status_code == 400

    def test_demo_data_files_update_requires_runs(self, client):
        resp = client.put(
            "/api/demo-data/files",
            json={"prs": []},
        )
        assert resp.status_code == 400
        data = resp.get_json()
        assert "'runs' array is required" in data["error"]

    def test_demo_data_files_update_saves(self, client):
        resp = client.put(
            "/api/demo-data/files",
            json={
                "runs": [{
                    "run_number": 1,
                    "run_label": "run-1",
                    "timestamp": "2026-01-01T00:00:00Z",
                    "target_repo": "https://github.com/test/repo",
                    "issues_found": 0,
                    "sessions": [],
                }],
                "prs": [],
            },
        )
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["saved"] is True


class TestOrchestratorObjectives:
    def test_objectives_round_trip(self, client, monkeypatch):
        monkeypatch.setenv("TELEMETRY_API_KEY", "test-key")
        import tempfile
        objectives = [
            {"objective": "Fix all critical XSS", "target_count": 10, "severity": "critical"},
            {"objective": "Reduce injection backlog", "target_count": 5},
        ]
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump({"orchestrator": {}, "repos": []}, f)
            f.flush()
            with patch("routes.orchestrator._ORCHESTRATOR_REGISTRY_PATH", Path(f.name)), \
                 patch("routes.orchestrator._load_orchestrator_registry", return_value={"orchestrator": {}, "repos": []}):
                resp = client.put(
                    "/api/orchestrator/config",
                    headers={"X-API-Key": "test-key"},
                    json={"objectives": objectives},
                )
                assert resp.status_code == 200
                data = resp.get_json()
                assert len(data["objectives"]) == 2
                assert data["objectives"][0]["objective"] == "Fix all critical XSS"
                assert data["objectives"][0]["target_count"] == 10
                assert data["objectives"][0]["severity"] == "critical"
                assert data["objectives"][1]["objective"] == "Reduce injection backlog"
            os.unlink(f.name)


class TestAuditLogEndpoints:
    def test_audit_log_get_requires_auth(self, client, monkeypatch):
        monkeypatch.setenv("TELEMETRY_API_KEY", "test-key")
        resp = client.get("/api/audit-log")
        assert resp.status_code == 401

    def test_audit_log_get_returns_paginated(self, client, monkeypatch):
        monkeypatch.setenv("TELEMETRY_API_KEY", "test-key")
        resp = client.get("/api/audit-log", headers={"X-API-Key": "test-key"})
        assert resp.status_code == 200
        data = resp.get_json()
        assert "items" in data
        assert "total" in data
        assert "page" in data

    def test_audit_log_get_with_action_filter(self, client, monkeypatch):
        monkeypatch.setenv("TELEMETRY_API_KEY", "test-key")
        resp = client.get("/api/audit-log?action=poll_sessions", headers={"X-API-Key": "test-key"})
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["total"] == 0

    def test_audit_log_get_with_user_filter(self, client, monkeypatch):
        monkeypatch.setenv("TELEMETRY_API_KEY", "test-key")
        resp = client.get("/api/audit-log?user=testuser", headers={"X-API-Key": "test-key"})
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["total"] == 0

    def test_audit_log_export_requires_auth(self, client, monkeypatch):
        monkeypatch.setenv("TELEMETRY_API_KEY", "test-key")
        resp = client.post("/api/audit-log/export", json={})
        assert resp.status_code == 401

    def test_audit_log_export_with_auth(self, client, monkeypatch):
        monkeypatch.setenv("TELEMETRY_API_KEY", "test-key")
        resp = client.post(
            "/api/audit-log/export",
            headers={"X-API-Key": "test-key"},
            json={},
        )
        assert resp.status_code == 200
        data = resp.get_json()
        assert "entries" in data
        assert "file" in data


class TestServerSideSessions:
    def test_session_type_is_cachelib(self):
        assert app.config["SESSION_TYPE"] == "cachelib"

    def test_session_cookie_httponly(self):
        assert app.config["SESSION_COOKIE_HTTPONLY"] is True

    def test_session_cookie_samesite(self):
        assert app.config["SESSION_COOKIE_SAMESITE"] == "Lax"

    def test_session_not_permanent(self):
        assert app.config["SESSION_PERMANENT"] is False

    def test_session_data_persists_server_side(self, client):
        with client.session_transaction() as sess:
            sess["gh_user"] = {"login": "testuser"}
        resp = client.get("/api/me")
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["logged_in"] is True
        assert data["user"]["login"] == "testuser"

    def test_logout_clears_server_session(self, client):
        with client.session_transaction() as sess:
            sess["gh_user"] = {"login": "testuser"}
            sess["gh_token"] = "ghp_fake_token"
        resp = client.get("/logout")
        assert resp.status_code == 302
        with client.session_transaction() as sess:
            assert "gh_user" not in sess
            assert "gh_token" not in sess


class TestCorsConfiguration:
    def test_cors_default_restricts_origins(self):
        from app import _cors_origins
        assert isinstance(_cors_origins, list)
        for origin in _cors_origins:
            assert "localhost" in origin or "127.0.0.1" in origin

    def test_cors_env_override(self, monkeypatch):
        monkeypatch.setenv("CORS_ORIGINS", "https://example.com,https://other.com")
        raw = os.environ.get("CORS_ORIGINS", "")
        origins = [o.strip() for o in raw.split(",") if o.strip()]
        assert origins == ["https://example.com", "https://other.com"]

    def test_cors_headers_present_on_response(self, client):
        resp = client.get("/api/config")
        assert resp.status_code == 200
        assert "X-Content-Type-Options" in resp.headers
        assert resp.headers["X-Content-Type-Options"] == "nosniff"
        assert resp.headers["X-Frame-Options"] == "DENY"
