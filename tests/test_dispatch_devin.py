"""Unit tests for dispatch_devin.py functions.

Covers: build_batch_prompt, validate_repo_url (extended), create_devin_session (mocked).
"""

import json
import os
import sys
from unittest.mock import patch, MagicMock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from scripts.dispatch_devin import build_batch_prompt, validate_repo_url, create_devin_session


class TestBuildBatchPrompt:
    def _batch(self, issues=None, family="injection", tier="critical", batch_id=1):
        if issues is None:
            issues = [{
                "id": "CQLF-R1-0001",
                "rule_id": "js/sql-injection",
                "rule_name": "SqlInjection",
                "rule_description": "SQL injection vulnerability",
                "rule_help": "Use parameterized queries.",
                "message": "User input flows to SQL query.",
                "severity_score": 9.8,
                "severity_tier": "critical",
                "cwes": ["cwe-89"],
                "cwe_family": "injection",
                "locations": [{"file": "src/db.js", "start_line": 42}],
            }]
        return {
            "batch_id": batch_id,
            "cwe_family": family,
            "severity_tier": tier,
            "max_severity_score": 9.8,
            "issue_count": len(issues),
            "file_count": 1,
            "issues": issues,
        }

    def test_prompt_contains_repo_url(self):
        prompt = build_batch_prompt(self._batch(), "https://github.com/owner/repo", "main")
        assert "https://github.com/owner/repo" in prompt

    def test_prompt_contains_branch(self):
        prompt = build_batch_prompt(self._batch(), "https://github.com/owner/repo", "develop")
        assert "develop" in prompt

    def test_prompt_contains_issue_ids(self):
        prompt = build_batch_prompt(self._batch(), "https://github.com/owner/repo", "main")
        assert "CQLF-R1-0001" in prompt

    def test_prompt_contains_category(self):
        prompt = build_batch_prompt(self._batch(), "https://github.com/owner/repo", "main")
        assert "injection" in prompt

    def test_prompt_contains_severity(self):
        prompt = build_batch_prompt(self._batch(), "https://github.com/owner/repo", "main")
        assert "CRITICAL" in prompt

    def test_prompt_contains_file_list(self):
        prompt = build_batch_prompt(self._batch(), "https://github.com/owner/repo", "main")
        assert "src/db.js" in prompt

    def test_prompt_contains_rule_description(self):
        prompt = build_batch_prompt(self._batch(), "https://github.com/owner/repo", "main")
        assert "SQL injection vulnerability" in prompt

    def test_prompt_contains_rule_help(self):
        prompt = build_batch_prompt(self._batch(), "https://github.com/owner/repo", "main")
        assert "parameterized queries" in prompt

    def test_prompt_contains_pr_title(self):
        prompt = build_batch_prompt(self._batch(), "https://github.com/owner/repo", "main")
        assert "fix(" in prompt
        assert "resolve injection security issues" in prompt

    def test_is_own_repo_true_no_fork_caveat(self):
        prompt = build_batch_prompt(
            self._batch(), "https://github.com/owner/repo", "main", is_own_repo=True
        )
        assert "not the upstream" not in prompt
        assert "Create a PR on https://github.com/owner/repo" in prompt

    def test_is_own_repo_false_fork_caveat(self):
        prompt = build_batch_prompt(
            self._batch(), "https://github.com/owner/repo", "main", is_own_repo=False
        )
        assert "not the upstream" in prompt
        assert "fork repo" in prompt

    def test_multiple_issues(self):
        issues = [
            {
                "id": f"CQLF-R1-{i:04d}",
                "rule_id": "js/sql-injection",
                "rule_name": "SqlInjection",
                "rule_description": "",
                "rule_help": "",
                "message": f"Issue {i}",
                "severity_score": 9.0,
                "severity_tier": "critical",
                "cwes": ["cwe-89"],
                "cwe_family": "injection",
                "locations": [{"file": f"src/file{i}.js", "start_line": i * 10}],
            }
            for i in range(1, 6)
        ]
        batch = self._batch(issues=issues)
        prompt = build_batch_prompt(batch, "https://github.com/owner/repo", "main")
        for i in range(1, 6):
            assert f"CQLF-R1-{i:04d}" in prompt
            assert f"src/file{i}.js" in prompt

    def test_missing_optional_fields(self):
        issues = [{
            "id": "CQLF-R1-0001",
            "rule_id": "r1",
            "rule_name": "Rule1",
            "rule_description": "",
            "rule_help": "",
            "message": "something",
            "severity_score": 5.0,
            "severity_tier": "medium",
            "cwes": [],
            "cwe_family": "other",
            "locations": [],
        }]
        batch = self._batch(issues=issues, family="other", tier="medium")
        prompt = build_batch_prompt(batch, "https://github.com/owner/repo", "main")
        assert "CQLF-R1-0001" in prompt

    def test_locations_without_file(self):
        issues = [{
            "id": "CQLF-R1-0001",
            "rule_id": "r1",
            "rule_name": "Rule1",
            "rule_description": "",
            "rule_help": "",
            "message": "msg",
            "severity_score": 7.0,
            "severity_tier": "high",
            "cwes": ["cwe-89"],
            "cwe_family": "injection",
            "locations": [{"file": "", "start_line": 0}],
        }]
        batch = self._batch(issues=issues)
        prompt = build_batch_prompt(batch, "https://github.com/owner/repo", "main")
        assert "CQLF-R1-0001" in prompt


class TestValidateRepoUrlExtended:
    def test_non_github_url_passes_with_warning(self, capsys):
        result = validate_repo_url("https://gitlab.com/owner/repo")
        assert result == "https://gitlab.com/owner/repo"
        captured = capsys.readouterr()
        assert "WARNING" in captured.out

    def test_http_url_preserved(self):
        result = validate_repo_url("http://github.com/owner/repo")
        assert result == "http://github.com/owner/repo"

    def test_complex_owner_repo_names(self):
        result = validate_repo_url("my-org.io/my-repo.js")
        assert result == "https://github.com/my-org.io/my-repo.js"

    def test_empty_string_warns(self, capsys):
        result = validate_repo_url("")
        captured = capsys.readouterr()
        assert "WARNING" in captured.out


class TestCreateDevinSession:
    @patch("scripts.dispatch_devin.requests.post")
    def test_successful_creation(self, mock_post):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"session_id": "sess-123", "url": "https://app.devin.ai/sessions/sess-123"}
        mock_resp.raise_for_status.return_value = None
        mock_post.return_value = mock_resp

        batch = {
            "batch_id": 1,
            "cwe_family": "injection",
            "severity_tier": "critical",
            "issues": [{"id": "CQLF-R1-0001"}],
        }
        result = create_devin_session("fake-key", "fix stuff", batch)
        assert result["session_id"] == "sess-123"
        mock_post.assert_called_once()
        call_kwargs = mock_post.call_args
        payload = call_kwargs.kwargs.get("json") or call_kwargs[1].get("json")
        assert payload["idempotent"] is True
        assert "codeql-fix" in payload["tags"]

    @patch("scripts.dispatch_devin.requests.post")
    @patch("scripts.dispatch_devin.time.sleep")
    def test_retry_on_failure(self, mock_sleep, mock_post):
        import requests as req
        mock_post.side_effect = [
            req.exceptions.ConnectionError("connection error"),
            req.exceptions.ConnectionError("connection error"),
            MagicMock(
                status_code=200,
                json=MagicMock(return_value={"session_id": "s1", "url": "u1"}),
                raise_for_status=MagicMock(),
            ),
        ]
        batch = {"batch_id": 1, "cwe_family": "xss", "severity_tier": "high", "issues": []}
        result = create_devin_session("key", "prompt", batch)
        assert result["session_id"] == "s1"
        assert mock_post.call_count == 3

    @patch("scripts.dispatch_devin.requests.post")
    @patch("scripts.dispatch_devin.time.sleep")
    def test_raises_after_max_retries(self, mock_sleep, mock_post):
        import requests as req
        mock_post.side_effect = req.exceptions.ConnectionError("fail")
        batch = {"batch_id": 1, "cwe_family": "xss", "severity_tier": "high", "issues": []}
        try:
            create_devin_session("key", "prompt", batch)
            assert False, "Should have raised"
        except req.exceptions.ConnectionError:
            pass
        assert mock_post.call_count == 3

    @patch("scripts.dispatch_devin.requests.post")
    def test_max_acu_included_when_set(self, mock_post):
        mock_resp = MagicMock()
        mock_resp.json.return_value = {"session_id": "s1", "url": "u1"}
        mock_resp.raise_for_status.return_value = None
        mock_post.return_value = mock_resp

        batch = {"batch_id": 1, "cwe_family": "xss", "severity_tier": "high", "issues": []}
        create_devin_session("key", "prompt", batch, max_acu=50)
        payload = mock_post.call_args.kwargs.get("json") or mock_post.call_args[1].get("json")
        assert payload["max_acu_limit"] == 50

    @patch("scripts.dispatch_devin.requests.post")
    def test_max_acu_omitted_when_none(self, mock_post):
        mock_resp = MagicMock()
        mock_resp.json.return_value = {"session_id": "s1", "url": "u1"}
        mock_resp.raise_for_status.return_value = None
        mock_post.return_value = mock_resp

        batch = {"batch_id": 1, "cwe_family": "xss", "severity_tier": "high", "issues": []}
        create_devin_session("key", "prompt", batch, max_acu=None)
        payload = mock_post.call_args.kwargs.get("json") or mock_post.call_args[1].get("json")
        assert "max_acu_limit" not in payload
