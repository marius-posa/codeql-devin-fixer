"""Unit tests for telemetry services (github_service.py and devin_service.py).

Covers: collect_session_ids, match_pr_to_session, link_prs_to_sessions,
fetch_prs_from_github (mocked), poll_devin_sessions (mocked),
save_session_updates.
"""

import json
import os
import sys
import tempfile
from pathlib import Path
from unittest.mock import patch, MagicMock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "telemetry"))

from github_service import (
    collect_session_ids,
    match_pr_to_session,
    fetch_prs_from_github,
    link_prs_to_sessions,
)
from devin_service import poll_devin_sessions, save_session_updates


class TestCollectSessionIds:
    def test_empty_runs(self):
        assert collect_session_ids([]) == set()

    def test_extracts_ids(self):
        runs = [{"sessions": [{"session_id": "abc"}, {"session_id": "def"}]}]
        result = collect_session_ids(runs)
        assert result == {"abc", "def"}

    def test_strips_devin_prefix(self):
        runs = [{"sessions": [{"session_id": "devin-abc123"}]}]
        result = collect_session_ids(runs)
        assert "abc123" in result

    def test_skips_dry_run(self):
        runs = [{"sessions": [{"session_id": "dry-run"}]}]
        assert collect_session_ids(runs) == set()

    def test_skips_empty_ids(self):
        runs = [{"sessions": [{"session_id": ""}, {}]}]
        assert collect_session_ids(runs) == set()

    def test_multiple_runs(self):
        runs = [
            {"sessions": [{"session_id": "s1"}]},
            {"sessions": [{"session_id": "s2"}, {"session_id": "s1"}]},
        ]
        result = collect_session_ids(runs)
        assert result == {"s1", "s2"}


class TestMatchPrToSession:
    def test_match_found(self):
        assert match_pr_to_session("fixes session abc123", {"abc123"}) == "abc123"

    def test_no_match(self):
        assert match_pr_to_session("no session here", {"xyz"}) == ""

    def test_empty_body(self):
        assert match_pr_to_session("", {"abc"}) == ""

    def test_none_body(self):
        assert match_pr_to_session(None, {"abc"}) == ""

    def test_empty_session_ids(self):
        assert match_pr_to_session("abc", set()) == ""


class TestLinkPrsToSessions:
    def test_links_by_session_id(self):
        sessions = [{"session_id": "s1", "issue_ids": []}]
        prs = [{"session_id": "s1", "html_url": "https://pr/1", "issue_ids": []}]
        result = link_prs_to_sessions(sessions, prs)
        assert result[0]["pr_url"] == "https://pr/1"

    def test_links_by_issue_id(self):
        sessions = [{"session_id": "s1", "issue_ids": ["CQLF-R1-0001"]}]
        prs = [{"session_id": "", "html_url": "https://pr/1", "issue_ids": ["CQLF-R1-0001"]}]
        result = link_prs_to_sessions(sessions, prs)
        assert result[0]["pr_url"] == "https://pr/1"

    def test_preserves_existing_pr_url(self):
        sessions = [{"session_id": "s1", "pr_url": "https://existing", "issue_ids": []}]
        prs = [{"session_id": "s1", "html_url": "https://new", "issue_ids": []}]
        result = link_prs_to_sessions(sessions, prs)
        assert result[0]["pr_url"] == "https://existing"

    def test_strips_devin_prefix_for_matching(self):
        sessions = [{"session_id": "devin-abc", "issue_ids": []}]
        prs = [{"session_id": "abc", "html_url": "https://pr/1", "issue_ids": []}]
        result = link_prs_to_sessions(sessions, prs)
        assert result[0]["pr_url"] == "https://pr/1"

    def test_no_match_leaves_empty(self):
        sessions = [{"session_id": "s1", "issue_ids": []}]
        prs = [{"session_id": "s2", "html_url": "https://pr/1", "issue_ids": []}]
        result = link_prs_to_sessions(sessions, prs)
        assert result[0].get("pr_url", "") == ""


class TestFetchPrsFromGithub:
    @patch("github_service.requests.get")
    def test_returns_empty_without_token(self, mock_get):
        with patch.dict(os.environ, {"GITHUB_TOKEN": ""}, clear=False):
            result = fetch_prs_from_github([])
            assert result == []
            mock_get.assert_not_called()

    @patch("github_service.requests.get")
    def test_filters_non_cqlf_prs(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = [
            {
                "number": 1,
                "title": "unrelated PR",
                "body": "nothing here",
                "html_url": "https://github.com/o/r/pull/1",
                "state": "open",
                "merged_at": None,
                "created_at": "2026-01-01",
                "user": {"login": "devin-ai"},
            }
        ]
        mock_get.return_value = mock_resp

        runs = [{"fork_url": "https://github.com/o/r", "target_repo": ""}]
        with patch.dict(os.environ, {"GITHUB_TOKEN": "test-token"}, clear=False):
            result = fetch_prs_from_github(runs)
            assert result == []

    @patch("github_service.requests.get")
    def test_includes_cqlf_prs(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = [
            {
                "number": 1,
                "title": "fix(security): resolve CQLF-R1-0001",
                "body": "",
                "html_url": "https://github.com/o/r/pull/1",
                "state": "open",
                "merged_at": None,
                "created_at": "2026-01-01",
                "user": {"login": "devin-ai"},
            }
        ]
        mock_get.return_value = mock_resp

        runs = [{"fork_url": "https://github.com/o/r", "target_repo": ""}]
        with patch.dict(os.environ, {"GITHUB_TOKEN": "test-token"}, clear=False):
            result = fetch_prs_from_github(runs)
            assert len(result) == 1
            assert result[0]["issue_ids"] == ["CQLF-R1-0001"]


class TestPollDevinSessions:
    @patch("devin_service.requests.get")
    def test_updates_status_from_api(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "status_enum": "finished",
            "structured_output": {"pull_request_url": "https://pr/1"},
        }
        mock_get.return_value = mock_resp

        sessions = [{"session_id": "s1", "status": "created"}]
        with patch.dict(os.environ, {"DEVIN_API_KEY": "test-key"}, clear=False):
            result = poll_devin_sessions(sessions)
            assert result[0]["status"] == "finished"
            assert result[0]["pr_url"] == "https://pr/1"

    def test_returns_unchanged_without_api_key(self):
        sessions = [{"session_id": "s1", "status": "created"}]
        with patch.dict(os.environ, {"DEVIN_API_KEY": ""}, clear=False):
            result = poll_devin_sessions(sessions)
            assert result == sessions

    @patch("devin_service.requests.get")
    def test_skips_dry_run_sessions(self, mock_get):
        sessions = [{"session_id": "dry-run", "status": "created"}]
        with patch.dict(os.environ, {"DEVIN_API_KEY": "key"}, clear=False):
            result = poll_devin_sessions(sessions)
            assert result[0]["status"] == "created"
            mock_get.assert_not_called()

    @patch("devin_service.requests.get")
    def test_handles_api_error_gracefully(self, mock_get):
        import requests as req
        mock_get.side_effect = req.exceptions.ConnectionError("fail")
        sessions = [{"session_id": "s1", "status": "created"}]
        with patch.dict(os.environ, {"DEVIN_API_KEY": "key"}, clear=False):
            result = poll_devin_sessions(sessions)
            assert len(result) == 1
            assert result[0]["status"] == "created"

    @patch("devin_service.requests.get")
    def test_extracts_pr_from_result_field(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "status_enum": "finished",
            "result": {"pull_request_url": "https://pr/2"},
        }
        mock_get.return_value = mock_resp

        sessions = [{"session_id": "s1", "status": "created"}]
        with patch.dict(os.environ, {"DEVIN_API_KEY": "key"}, clear=False):
            result = poll_devin_sessions(sessions)
            assert result[0]["pr_url"] == "https://pr/2"


class TestSaveSessionUpdates:
    def test_writes_updated_status(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            runs_dir = Path(tmpdir)
            run_data = {
                "run_label": "run-1",
                "sessions": [{"session_id": "s1", "status": "created"}],
            }
            (runs_dir / "run1.json").write_text(json.dumps(run_data))

            sessions = [
                {"session_id": "s1", "status": "finished", "run_label": "run-1", "pr_url": "https://pr/1"}
            ]
            with patch("devin_service.RUNS_DIR", runs_dir):
                result = save_session_updates(sessions)
                assert result is True

            updated = json.loads((runs_dir / "run1.json").read_text())
            assert updated["sessions"][0]["status"] == "finished"
            assert updated["sessions"][0]["pr_url"] == "https://pr/1"

    def test_no_change_returns_false(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            runs_dir = Path(tmpdir)
            run_data = {
                "run_label": "run-1",
                "sessions": [{"session_id": "s1", "status": "finished"}],
            }
            (runs_dir / "run1.json").write_text(json.dumps(run_data))

            sessions = [
                {"session_id": "s1", "status": "finished", "run_label": "run-1"}
            ]
            with patch("devin_service.RUNS_DIR", runs_dir):
                result = save_session_updates(sessions)
                assert result is False
