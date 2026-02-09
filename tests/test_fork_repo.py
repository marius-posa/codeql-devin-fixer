"""Unit tests for fork_repo.py functions.

Covers: check_fork_exists (mocked), parse_repo_url edge cases,
normalize_repo_url edge cases, resolve_owner (mocked).
"""

import os
import sys
from unittest.mock import patch, MagicMock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from scripts.fork_repo import (
    check_fork_exists, parse_repo_url, normalize_repo_url, resolve_owner,
    create_fork, sync_fork, _write_outputs,
)


class TestCheckForkExists:
    @patch("scripts.fork_repo.request_with_retry")
    def test_fork_found_with_matching_parent(self, mock_req):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "fork": True,
            "parent": {"full_name": "upstream-owner/repo"},
            "html_url": "https://github.com/my-user/repo",
        }
        mock_req.return_value = mock_resp

        result = check_fork_exists("token", "upstream-owner", "repo", "my-user")
        assert result is not None
        assert result["fork"] is True

    @patch("scripts.fork_repo.request_with_retry")
    def test_fork_found_case_insensitive(self, mock_req):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "fork": True,
            "parent": {"full_name": "Upstream-Owner/Repo"},
        }
        mock_req.return_value = mock_resp

        result = check_fork_exists("token", "upstream-owner", "repo", "my-user")
        assert result is not None

    @patch("scripts.fork_repo.request_with_retry")
    def test_not_a_fork(self, mock_req):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"fork": False}
        mock_req.return_value = mock_resp

        result = check_fork_exists("token", "owner", "repo", "my-user")
        assert result is None

    @patch("scripts.fork_repo.request_with_retry")
    def test_fork_wrong_parent(self, mock_req):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "fork": True,
            "parent": {"full_name": "different-owner/repo"},
        }
        mock_req.return_value = mock_resp

        result = check_fork_exists("token", "upstream-owner", "repo", "my-user")
        assert result is None

    @patch("scripts.fork_repo.request_with_retry")
    def test_fork_no_parent_still_returned(self, mock_req):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"fork": True, "parent": {}}
        mock_req.return_value = mock_resp

        result = check_fork_exists("token", "owner", "repo", "my-user")
        assert result is not None

    @patch("scripts.fork_repo.request_with_retry")
    def test_repo_not_found_404(self, mock_req):
        mock_resp = MagicMock()
        mock_resp.status_code = 404
        mock_req.return_value = mock_resp

        result = check_fork_exists("token", "owner", "repo", "my-user")
        assert result is None

    @patch("scripts.fork_repo.request_with_retry")
    def test_no_token_omits_auth_header(self, mock_req):
        mock_resp = MagicMock()
        mock_resp.status_code = 404
        mock_req.return_value = mock_resp

        check_fork_exists("", "owner", "repo", "my-user")
        call_kwargs = mock_req.call_args
        headers = call_kwargs.kwargs.get("headers", {})
        assert "Authorization" not in headers

    @patch("scripts.fork_repo.request_with_retry")
    def test_with_token_includes_auth_header(self, mock_req):
        mock_resp = MagicMock()
        mock_resp.status_code = 404
        mock_req.return_value = mock_resp

        check_fork_exists("my-token", "owner", "repo", "my-user")
        call_kwargs = mock_req.call_args
        headers = call_kwargs.kwargs.get("headers", {})
        assert headers["Authorization"] == "token my-token"


class TestParseRepoUrlEdgeCases:
    def test_url_with_trailing_path(self):
        owner, repo = parse_repo_url("https://github.com/owner/repo")
        assert owner == "owner"
        assert repo == "repo"

    def test_shorthand_with_dots_and_hyphens(self):
        owner, repo = parse_repo_url("my-org.io/my-repo.js")
        assert owner == "my-org.io"
        assert repo == "my-repo.js"

    def test_url_with_git_suffix(self):
        owner, repo = parse_repo_url("https://github.com/owner/repo.git")
        assert owner == "owner"
        assert repo == "repo"

    def test_url_with_trailing_slash_and_git(self):
        owner, repo = parse_repo_url("https://github.com/owner/repo.git/")
        assert owner == "owner"
        assert repo == "repo"


class TestNormalizeRepoUrlEdgeCases:
    def test_already_normalized(self):
        assert normalize_repo_url("https://github.com/o/r") == "https://github.com/o/r"

    def test_http_preserved(self):
        assert normalize_repo_url("http://github.com/o/r") == "http://github.com/o/r"

    def test_non_github_url(self):
        result = normalize_repo_url("https://gitlab.com/o/r")
        assert result == "https://gitlab.com/o/r"


class TestResolveOwner:
    def test_fallback_used_when_provided(self):
        assert resolve_owner("token", "my-user") == "my-user"

    @patch("scripts.fork_repo.request_with_retry")
    def test_api_call_when_no_fallback(self, mock_req):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"login": "api-user"}
        mock_resp.raise_for_status.return_value = None
        mock_req.return_value = mock_resp

        result = resolve_owner("token", "")
        assert result == "api-user"

    @patch("scripts.fork_repo.request_with_retry")
    def test_api_failure_returns_empty(self, mock_req):
        import requests
        mock_req.side_effect = requests.exceptions.RequestException("fail")

        result = resolve_owner("token", "")
        assert result == ""


class TestCreateFork:
    @patch("scripts.fork_repo.time.sleep")
    @patch("scripts.fork_repo.request_with_retry")
    def test_creates_fork_and_waits_for_ready(self, mock_req, mock_sleep):
        fork_resp = MagicMock()
        fork_resp.status_code = 202
        fork_resp.json.return_value = {
            "html_url": "https://github.com/my-user/repo",
            "url": "https://api.github.com/repos/my-user/repo",
        }
        fork_resp.raise_for_status.return_value = None

        check_resp = MagicMock()
        check_resp.status_code = 200
        check_resp.json.return_value = {
            "html_url": "https://github.com/my-user/repo",
            "size": 100,
        }

        mock_req.side_effect = [fork_resp, check_resp]
        result = create_fork("token", "owner", "repo")
        assert result["html_url"] == "https://github.com/my-user/repo"
        assert mock_req.call_count == 2

    @patch("scripts.fork_repo.time.sleep")
    @patch("scripts.fork_repo.request_with_retry")
    def test_returns_fork_data_after_timeout(self, mock_req, mock_sleep):
        fork_resp = MagicMock()
        fork_resp.status_code = 202
        fork_resp.json.return_value = {
            "html_url": "https://github.com/my-user/repo",
            "url": "https://api.github.com/repos/my-user/repo",
        }
        fork_resp.raise_for_status.return_value = None

        check_resp = MagicMock()
        check_resp.status_code = 200
        check_resp.json.return_value = {"size": 0}

        mock_req.side_effect = [fork_resp] + [check_resp] * 12
        result = create_fork("token", "owner", "repo")
        assert result["html_url"] == "https://github.com/my-user/repo"


class TestSyncFork:
    @patch("scripts.fork_repo.request_with_retry")
    def test_sync_success(self, mock_req):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"message": "Successfully fetched and fast-forwarded"}
        mock_req.return_value = mock_resp

        sync_fork("token", "my-user", "repo", "main")
        mock_req.assert_called_once()

    @patch("scripts.fork_repo.request_with_retry")
    def test_sync_already_up_to_date(self, mock_req):
        mock_resp = MagicMock()
        mock_resp.status_code = 409
        mock_resp.json.return_value = {"message": "already up to date"}
        mock_req.return_value = mock_resp

        sync_fork("token", "my-user", "repo", "main")

    @patch("scripts.fork_repo.request_with_retry")
    def test_sync_warning_on_error(self, mock_req, capfd):
        mock_resp = MagicMock()
        mock_resp.status_code = 422
        mock_resp.text = "unprocessable"
        mock_req.return_value = mock_resp

        sync_fork("token", "my-user", "repo", "main")
        captured = capfd.readouterr()
        assert "WARNING" in captured.err


class TestWriteOutputs:
    def test_writes_to_github_output(self, tmp_path):
        output_file = tmp_path / "output.txt"
        with patch.dict(os.environ, {"GITHUB_OUTPUT": str(output_file)}):
            _write_outputs("https://github.com/user/repo", "user", "repo")

        content = output_file.read_text()
        assert "fork_url=https://github.com/user/repo" in content
        assert "fork_owner=user" in content
        assert "fork_repo=repo" in content

    def test_prints_fork_url_without_github_output(self, capfd):
        with patch.dict(os.environ, {}, clear=False):
            if "GITHUB_OUTPUT" in os.environ:
                del os.environ["GITHUB_OUTPUT"]
            _write_outputs("https://github.com/user/repo", "user", "repo")
        captured = capfd.readouterr()
        assert "FORK_URL=https://github.com/user/repo" in captured.err
