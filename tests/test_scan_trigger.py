"""Tests for github_app/scan_trigger.py.

Covers: repo URL validation and command injection prevention (CQLF-R34-0001).
"""

import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from github_app.scan_trigger import _validate_repo_url, _run_clone


class TestValidateRepoUrl:
    def test_valid_https_url(self):
        _validate_repo_url("https://github.com/owner/repo")

    def test_valid_https_url_with_git_suffix(self):
        _validate_repo_url("https://github.com/owner/repo.git")

    def test_valid_url_with_dots_and_hyphens(self):
        _validate_repo_url("https://github.com/my-org/my.repo-name")

    def test_rejects_command_injection_via_semicolon(self):
        with pytest.raises(ValueError):
            _validate_repo_url("https://github.com/owner/repo; cat /etc/passwd")

    def test_rejects_command_injection_via_backtick(self):
        with pytest.raises(ValueError):
            _validate_repo_url("https://github.com/owner/repo`whoami`")

    def test_rejects_command_injection_via_pipe(self):
        with pytest.raises(ValueError):
            _validate_repo_url("https://github.com/owner/repo | rm -rf /")

    def test_rejects_non_github_url(self):
        with pytest.raises(ValueError):
            _validate_repo_url("https://evil.com/owner/repo")

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
