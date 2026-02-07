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
    def test_api_dispatch_preflight_requires_target_repo(self, mock_cache, client):
        resp = client.get("/api/dispatch/preflight")
        assert resp.status_code == 400
        data = resp.get_json()
        assert "error" in data
