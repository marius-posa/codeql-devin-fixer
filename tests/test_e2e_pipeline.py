"""End-to-end tests for the telemetry API pipeline and orchestrator flow.

Covers:
- Full data pipeline: seed → query → verify consistency across endpoints
- PR linking flow: insert runs + PRs → link → verify session-PR associations
- Dispatch preflight with seeded data
- db_connection context manager
- clean_session_id helper
- Consolidated registry loading (orchestrator reuses registry blueprint)
- Orchestrator fix-rates computation with seeded issues
"""

import json
import os
import pathlib
import sys
import tempfile
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "telemetry"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scripts"))

import pytest

_tmp_dir = tempfile.mkdtemp()
_test_db_path = os.path.join(_tmp_dir, "test_e2e.db")
os.environ["TELEMETRY_DB_PATH"] = _test_db_path

import database
database.DB_PATH = pathlib.Path(_test_db_path)

from database import (
    db_connection,
    get_connection,
    init_db,
    insert_run,
    upsert_pr,
    query_all_sessions,
    query_all_prs,
    update_session,
)
from devin_api import clean_session_id, TERMINAL_STATUSES, DEVIN_API_BASE, MAX_RETRIES
from app import app


def _make_run(run_number=1, repo="https://github.com/owner/repo", sessions=None):
    base_sessions = sessions or [
        {
            "session_id": f"devin-sess-{run_number}",
            "session_url": f"https://app.devin.ai/sessions/sess-{run_number}",
            "batch_id": 1,
            "status": "finished",
            "issue_ids": [f"CQLF-R{run_number}-0001"],
            "pr_url": "",
        }
    ]
    return {
        "target_repo": repo,
        "fork_url": "https://github.com/fork-owner/repo",
        "run_number": run_number,
        "run_id": f"id-{run_number}",
        "run_url": f"https://github.com/owner/repo/actions/runs/{run_number}",
        "run_label": f"owner_repo_run_{run_number}_20260101_120000",
        "timestamp": f"2026-01-{run_number:02d}T12:00:00Z",
        "issues_found": 2,
        "severity_breakdown": {"high": 1, "medium": 1},
        "category_breakdown": {"injection": 1, "xss": 1},
        "batches_created": 1,
        "sessions": base_sessions,
        "issue_fingerprints": [
            {
                "fingerprint": f"fp-{run_number}-a",
                "id": f"CQLF-R{run_number}-0001",
                "rule_id": "js/sql-injection",
                "severity_tier": "high",
                "cwe_family": "injection",
                "file": "src/db.js",
                "start_line": 42,
                "description": "SQL injection",
                "resolution": "Use parameterized queries",
                "code_churn": 5,
            },
            {
                "fingerprint": f"fp-{run_number}-b",
                "id": f"CQLF-R{run_number}-0002",
                "rule_id": "js/xss",
                "severity_tier": "medium",
                "cwe_family": "xss",
                "file": "src/view.js",
                "start_line": 10,
                "description": "XSS in template",
                "resolution": "Escape output",
                "code_churn": 2,
            },
        ],
        "zero_issue_run": False,
    }


def _seed(runs=None, prs=None, db_path=None):
    conn = get_connection(pathlib.Path(db_path or _test_db_path))
    init_db(conn)
    if runs:
        for r in runs:
            insert_run(conn, r, r.get("_file", f"run_{r['run_number']}.json"))
    if prs:
        for p in prs:
            upsert_pr(conn, p)
    conn.commit()
    conn.close()


def _clear():
    conn = get_connection(pathlib.Path(_test_db_path))
    for tbl in [
        "pr_issue_ids", "prs", "session_issue_ids", "sessions",
        "issues", "runs", "metadata", "orchestrator_kv",
        "dispatch_history", "rate_limiter_timestamps", "scan_schedule",
        "audit_log",
    ]:
        try:
            conn.execute(f"DELETE FROM {tbl}")
        except Exception:
            pass
    conn.commit()
    conn.close()


@pytest.fixture(autouse=True)
def clean_db():
    _clear()
    yield
    _clear()


@pytest.fixture
def client():
    app.config["TESTING"] = True
    with app.test_client() as c:
        yield c


class TestCleanSessionId:
    def test_strips_devin_prefix(self):
        assert clean_session_id("devin-abc123") == "abc123"

    def test_no_prefix_unchanged(self):
        assert clean_session_id("abc123") == "abc123"

    def test_empty_string(self):
        assert clean_session_id("") == ""

    def test_devin_only(self):
        assert clean_session_id("devin-") == ""

    def test_double_prefix(self):
        assert clean_session_id("devin-devin-abc") == "devin-abc"


class TestTerminalStatuses:
    def test_contains_expected(self):
        for s in ("finished", "blocked", "expired", "failed", "canceled",
                   "cancelled", "stopped", "error"):
            assert s in TERMINAL_STATUSES

    def test_running_not_terminal(self):
        assert "running" not in TERMINAL_STATUSES
        assert "created" not in TERMINAL_STATUSES


class TestConsolidatedConstants:
    def test_devin_api_base(self):
        assert DEVIN_API_BASE == "https://api.devin.ai/v1"

    def test_max_retries(self):
        assert MAX_RETRIES == 3


class TestDbConnectionContextManager:
    def test_yields_connection(self):
        with db_connection(pathlib.Path(_test_db_path)) as conn:
            assert conn is not None
            result = conn.execute("SELECT 1").fetchone()
            assert result[0] == 1

    def test_closes_after_exit(self):
        with db_connection(pathlib.Path(_test_db_path)) as conn:
            pass
        with pytest.raises(Exception):
            conn.execute("SELECT 1")

    def test_closes_on_exception(self):
        try:
            with db_connection(pathlib.Path(_test_db_path)) as conn:
                raise ValueError("test error")
        except ValueError:
            pass
        with pytest.raises(Exception):
            conn.execute("SELECT 1")


class TestFullDataPipeline:
    def test_seed_and_query_runs(self, client):
        _seed(runs=[_make_run(1), _make_run(2), _make_run(3)])
        resp = client.get("/api/runs?page=1&per_page=10")
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["total"] == 3
        assert len(data["items"]) == 3

    def test_runs_include_sessions(self, client):
        _seed(runs=[_make_run(1)])
        resp = client.get("/api/runs?page=1&per_page=10")
        data = resp.get_json()
        run = data["items"][0]
        assert "sessions" in run
        assert len(run["sessions"]) >= 1

    def test_sessions_endpoint_consistent(self, client):
        _seed(runs=[_make_run(1), _make_run(2)])
        resp = client.get("/api/sessions?page=1&per_page=10")
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["total"] == 2

    def test_stats_reflect_seeded_data(self, client):
        _seed(runs=[_make_run(1), _make_run(2)])
        resp = client.get("/api/stats")
        data = resp.get_json()
        assert data["total_runs"] == 2
        assert data["repos_scanned"] == 1
        assert data["total_issues"] >= 2

    def test_repos_endpoint_groups(self, client):
        _seed(runs=[
            _make_run(1, repo="https://github.com/a/b"),
            _make_run(2, repo="https://github.com/a/b"),
            _make_run(3, repo="https://github.com/c/d"),
        ])
        resp = client.get("/api/repos")
        data = resp.get_json()
        assert len(data) == 2
        repos = {r["repo"] for r in data}
        assert repos == {"https://github.com/a/b", "https://github.com/c/d"}

    def test_issues_endpoint(self, client):
        _seed(runs=[_make_run(1)])
        resp = client.get("/api/issues")
        data = resp.get_json()
        assert data["total"] >= 2
        fps = {i["fingerprint"] for i in data["items"]}
        assert "fp-1-a" in fps
        assert "fp-1-b" in fps

    def test_issues_search(self, client):
        _seed(runs=[_make_run(1)])
        resp = client.get("/api/issues/search?q=injection")
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["total"] >= 1

    def test_repo_detail_endpoint(self, client):
        _seed(runs=[_make_run(1)])
        resp = client.get("/api/repo/owner/repo")
        assert resp.status_code == 200
        data = resp.get_json()
        assert "stats" in data
        assert data["stats"]["total_runs"] == 1
        assert "runs" in data
        assert "sessions" in data
        assert "issues" in data

    def test_sla_endpoint(self, client):
        _seed(runs=[_make_run(1)])
        resp = client.get("/api/sla")
        assert resp.status_code == 200
        data = resp.get_json()
        assert "total_breached" in data
        assert "total_on_track" in data


class TestPrLinkingPipeline:
    def test_prs_seeded_and_queryable(self, client):
        _seed(
            runs=[_make_run(1)],
            prs=[{
                "pr_number": 42,
                "title": "Fix injection",
                "html_url": "https://github.com/fork-owner/repo/pull/42",
                "state": "open",
                "merged": False,
                "created_at": "2026-01-01T00:00:00Z",
                "repo": "fork-owner/repo",
                "user": "devin-ai[bot]",
                "session_id": "sess-1",
                "issue_ids": ["CQLF-R1-0001"],
            }],
        )
        resp = client.get("/api/prs?page=1&per_page=10")
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["total"] == 1
        assert data["items"][0]["title"] == "Fix injection"

    def test_sessions_include_linked_prs(self, client):
        _seed(
            runs=[_make_run(1)],
            prs=[{
                "pr_number": 42,
                "title": "Fix injection",
                "html_url": "https://github.com/fork-owner/repo/pull/42",
                "state": "open",
                "merged": False,
                "created_at": "2026-01-01T00:00:00Z",
                "repo": "fork-owner/repo",
                "user": "devin-ai[bot]",
                "session_id": "devin-sess-1",
                "issue_ids": ["CQLF-R1-0001"],
            }],
        )
        conn = get_connection(pathlib.Path(_test_db_path))
        update_session(conn, "devin-sess-1", pr_url="https://github.com/fork-owner/repo/pull/42")
        conn.commit()
        conn.close()
        resp = client.get("/api/sessions?page=1&per_page=10")
        data = resp.get_json()
        session = data["items"][0]
        assert "prs" in session or session.get("pr_url", "") != ""

    def test_dispatch_preflight_counts_open_prs(self, client):
        _seed(
            runs=[_make_run(1)],
            prs=[{
                "pr_number": 42,
                "title": "Fix",
                "html_url": "https://github.com/fork-owner/repo/pull/42",
                "state": "open",
                "merged": False,
                "created_at": "2026-01-01T00:00:00Z",
                "repo": "fork-owner/repo",
                "user": "devin",
                "session_id": "sess-1",
                "issue_ids": [],
            }],
        )
        conn = get_connection(pathlib.Path(_test_db_path))
        update_session(conn, "devin-sess-1", pr_url="https://github.com/fork-owner/repo/pull/42")
        conn.commit()
        conn.close()
        resp = client.get("/api/dispatch/preflight?target_repo=https://github.com/owner/repo")
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["target_repo"] == "https://github.com/owner/repo"
        assert "open_prs" in data


class TestRegistryConsolidation:
    def test_orchestrator_uses_registry_load(self):
        from routes.registry import _load_registry, REGISTRY_PATH
        from routes.orchestrator import _load_orchestrator_registry
        with patch("routes.registry.REGISTRY_PATH", Path("/nonexistent")):
            reg = _load_registry()
            orch_reg = _load_orchestrator_registry()
            assert reg["repos"] == orch_reg["repos"]

    def test_orchestrator_config_endpoint_reads_registry(self, client):
        reg_data = {
            "orchestrator": {"global_session_limit": 15},
            "repos": [{"repo": "https://github.com/a/b"}],
        }
        with patch("routes.orchestrator._load_orchestrator_registry", return_value=reg_data):
            resp = client.get("/api/orchestrator/config")
            assert resp.status_code == 200
            data = resp.get_json()
            assert data["global_session_limit"] == 15

    def test_orchestrator_config_update_uses_shared_save(self, client, monkeypatch):
        monkeypatch.setenv("TELEMETRY_API_KEY", "test-key")
        reg_data = {"orchestrator": {}, "repos": []}
        saved = {}

        def mock_save(data):
            saved["data"] = data

        with patch("routes.orchestrator._load_orchestrator_registry", return_value=reg_data):
            with patch("routes.orchestrator._save_orchestrator_registry", side_effect=mock_save):
                resp = client.put(
                    "/api/orchestrator/config",
                    headers={"X-API-Key": "test-key"},
                    json={"global_session_limit": 25},
                )
                assert resp.status_code == 200
                assert saved["data"]["orchestrator"]["global_session_limit"] == 25


class TestOrchestratorFixRatesPipeline:
    def test_fix_rates_with_seeded_data(self, client):
        _seed(runs=[_make_run(1), _make_run(2)])
        resp = client.get("/api/orchestrator/fix-rates")
        assert resp.status_code == 200
        data = resp.get_json()
        assert "overall" in data
        assert "by_cwe_family" in data
        assert "by_repo" in data
        assert "by_severity" in data
        assert data["overall"]["total"] >= 2

    def test_fix_rates_empty_db(self, client):
        resp = client.get("/api/orchestrator/fix-rates")
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["overall"]["total"] == 0
        assert data["overall"]["fix_rate"] == 0.0

    def test_fix_rates_breakdown_shape(self, client):
        _seed(runs=[_make_run(1)])
        resp = client.get("/api/orchestrator/fix-rates")
        data = resp.get_json()
        for entry in data["by_cwe_family"]:
            assert "name" in entry
            assert "total" in entry
            assert "fixed" in entry
            assert "fix_rate" in entry


class TestAuditLogPipeline:
    def test_poll_creates_audit_entry(self, client, monkeypatch):
        monkeypatch.setenv("TELEMETRY_API_KEY", "test-key")
        _seed(runs=[_make_run(1)])
        with patch("routes.api.poll_devin_sessions_db", return_value=([], {"polled": 0, "skipped_terminal": 0, "errors": []})):
            with patch("routes.api.fetch_prs_from_github_to_db", return_value=0):
                with patch("routes.api.link_prs_to_sessions_db"):
                    resp = client.post(
                        "/api/poll",
                        headers={"X-API-Key": "test-key"},
                    )
                    assert resp.status_code == 200

        resp = client.get(
            "/api/audit-log",
            headers={"X-API-Key": "test-key"},
        )
        assert resp.status_code == 200
        data = resp.get_json()
        actions = [e["action"] for e in data["items"]]
        assert "poll_sessions" in actions


class TestMultiRepoE2E:
    def test_cross_repo_stats(self, client):
        _seed(runs=[
            _make_run(1, repo="https://github.com/a/b"),
            _make_run(2, repo="https://github.com/c/d"),
            _make_run(3, repo="https://github.com/a/b"),
        ])
        resp = client.get("/api/stats")
        data = resp.get_json()
        assert data["total_runs"] == 3
        assert data["repos_scanned"] == 2

    def test_repo_detail_isolates_data(self, client):
        _seed(runs=[
            _make_run(1, repo="https://github.com/a/b"),
            _make_run(2, repo="https://github.com/c/d"),
        ])
        resp = client.get("/api/repo/a/b")
        data = resp.get_json()
        assert data["stats"]["total_runs"] == 1
        resp2 = client.get("/api/repo/c/d")
        data2 = resp2.get_json()
        assert data2["stats"]["total_runs"] == 1

    def test_issues_filter_by_repo(self, client):
        _seed(runs=[
            _make_run(1, repo="https://github.com/a/b"),
            _make_run(2, repo="https://github.com/c/d"),
        ])
        resp = client.get("/api/issues?repo=https://github.com/a/b")
        data = resp.get_json()
        for item in data["items"]:
            assert item["target_repo"] == "https://github.com/a/b"
