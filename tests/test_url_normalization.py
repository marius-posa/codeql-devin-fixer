"""Tests for repo URL normalization across scripts."""

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from scripts.fork_repo import normalize_repo_url, parse_repo_url
from scripts.dispatch_devin import validate_repo_url


class TestNormalizeRepoUrl:
    def test_shorthand_owner_repo(self):
        assert normalize_repo_url("marius-posa/dvpwa") == "https://github.com/marius-posa/dvpwa"

    def test_full_url_unchanged(self):
        assert normalize_repo_url("https://github.com/owner/repo") == "https://github.com/owner/repo"

    def test_trailing_slash_stripped(self):
        assert normalize_repo_url("https://github.com/owner/repo/") == "https://github.com/owner/repo"

    def test_dot_git_suffix_stripped(self):
        assert normalize_repo_url("https://github.com/owner/repo.git") == "https://github.com/owner/repo"

    def test_shorthand_with_dots(self):
        assert normalize_repo_url("org.name/repo.name") == "https://github.com/org.name/repo.name"

    def test_shorthand_with_hyphens(self):
        assert normalize_repo_url("my-org/my-repo") == "https://github.com/my-org/my-repo"

    def test_whitespace_trimmed(self):
        assert normalize_repo_url("  owner/repo  ") == "https://github.com/owner/repo"

    def test_shorthand_with_git_suffix(self):
        assert normalize_repo_url("owner/repo.git") == "https://github.com/owner/repo"


class TestParseRepoUrl:
    def test_full_url(self):
        assert parse_repo_url("https://github.com/owner/repo") == ("owner", "repo")

    def test_shorthand(self):
        assert parse_repo_url("marius-posa/dvpwa") == ("marius-posa", "dvpwa")

    def test_url_with_git_suffix(self):
        assert parse_repo_url("https://github.com/owner/repo.git") == ("owner", "repo")

    def test_shorthand_with_whitespace(self):
        assert parse_repo_url("  owner/repo  ") == ("owner", "repo")


class TestValidateRepoUrl:
    def test_shorthand_normalized(self):
        assert validate_repo_url("marius-posa/dvpwa") == "https://github.com/marius-posa/dvpwa"

    def test_full_url_unchanged(self):
        assert validate_repo_url("https://github.com/owner/repo") == "https://github.com/owner/repo"

    def test_trailing_slash_stripped(self):
        assert validate_repo_url("https://github.com/owner/repo/") == "https://github.com/owner/repo"

    def test_dot_git_suffix_stripped(self):
        assert validate_repo_url("https://github.com/owner/repo.git") == "https://github.com/owner/repo"

    def test_shorthand_with_whitespace(self):
        assert validate_repo_url("  owner/repo  ") == "https://github.com/owner/repo"
