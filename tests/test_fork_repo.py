"""Unit tests for fork_repo.py functions.

Covers: check_fork_exists (mocked), parse_repo_url edge cases,
normalize_repo_url edge cases, resolve_owner (mocked).
"""

import os
import sys
from unittest.mock import patch, MagicMock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from scripts.fork_repo import check_fork_exists, parse_repo_url, normalize_repo_url, resolve_owner


class TestCheckForkExists:
    @patch("scripts.fork_repo.requests.get")
    def test_fork_found_with_matching_parent(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "fork": True,
            "parent": {"full_name": "upstream-owner/repo"},
            "html_url": "https://github.com/my-user/repo",
        }
        mock_get.return_value = mock_resp

        result = check_fork_exists("token", "upstream-owner", "repo", "my-user")
        assert result is not None
        assert result["fork"] is True

    @patch("scripts.fork_repo.requests.get")
    def test_fork_found_case_insensitive(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "fork": True,
            "parent": {"full_name": "Upstream-Owner/Repo"},
        }
        mock_get.return_value = mock_resp

        result = check_fork_exists("token", "upstream-owner", "repo", "my-user")
        assert result is not None

    @patch("scripts.fork_repo.requests.get")
    def test_not_a_fork(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"fork": False}
        mock_get.return_value = mock_resp

        result = check_fork_exists("token", "owner", "repo", "my-user")
        assert result is None

    @patch("scripts.fork_repo.requests.get")
    def test_fork_wrong_parent(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "fork": True,
            "parent": {"full_name": "different-owner/repo"},
        }
        mock_get.return_value = mock_resp

        result = check_fork_exists("token", "upstream-owner", "repo", "my-user")
        assert result is None

    @patch("scripts.fork_repo.requests.get")
    def test_fork_no_parent_still_returned(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"fork": True, "parent": {}}
        mock_get.return_value = mock_resp

        result = check_fork_exists("token", "owner", "repo", "my-user")
        assert result is not None

    @patch("scripts.fork_repo.requests.get")
    def test_repo_not_found_404(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.status_code = 404
        mock_get.return_value = mock_resp

        result = check_fork_exists("token", "owner", "repo", "my-user")
        assert result is None

    @patch("scripts.fork_repo.requests.get")
    def test_no_token_omits_auth_header(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.status_code = 404
        mock_get.return_value = mock_resp

        check_fork_exists("", "owner", "repo", "my-user")
        call_kwargs = mock_get.call_args
        headers = call_kwargs.kwargs.get("headers") or call_kwargs[1].get("headers")
        assert "Authorization" not in headers

    @patch("scripts.fork_repo.requests.get")
    def test_with_token_includes_auth_header(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.status_code = 404
        mock_get.return_value = mock_resp

        check_fork_exists("my-token", "owner", "repo", "my-user")
        call_kwargs = mock_get.call_args
        headers = call_kwargs.kwargs.get("headers") or call_kwargs[1].get("headers")
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

    @patch("scripts.fork_repo.requests.get")
    def test_api_call_when_no_fallback(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"login": "api-user"}
        mock_resp.raise_for_status.return_value = None
        mock_get.return_value = mock_resp

        result = resolve_owner("token", "")
        assert result == "api-user"

    @patch("scripts.fork_repo.requests.get")
    def test_api_failure_returns_empty(self, mock_get):
        import requests
        mock_get.side_effect = requests.exceptions.ConnectionError("fail")

        result = resolve_owner("token", "")
        assert result == ""
