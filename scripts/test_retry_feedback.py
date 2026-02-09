#!/usr/bin/env python3
"""Tests for retry_feedback.py - Send Message retry-with-feedback."""

import sys
import os
import unittest
from unittest.mock import MagicMock, patch

sys.path.insert(0, os.path.dirname(__file__))

from retry_feedback import (
    _build_feedback_message,
    _build_followup_prompt,
    create_session,
    get_session,
    process_retry_batch,
    retry_with_feedback,
    send_message,
)


class TestSendMessage(unittest.TestCase):
    @patch("devin_api.requests.request")
    def test_send_message(self, mock_req):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"detail": "Message sent"}
        mock_resp.raise_for_status = MagicMock()
        mock_req.return_value = mock_resp

        result = send_message("test-key", "session-123", "Fix these issues")
        self.assertEqual(result["detail"], "Message sent")

        args = mock_req.call_args
        self.assertEqual(args[0][0], "POST")
        self.assertIn("/sessions/session-123/message", args[0][1])
        payload = args[1].get("json") or args.kwargs.get("json")
        self.assertEqual(payload["message"], "Fix these issues")


class TestGetSession(unittest.TestCase):
    @patch("devin_api.requests.request")
    def test_get_session(self, mock_req):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "session_id": "s1",
            "status_enum": "finished",
        }
        mock_resp.raise_for_status = MagicMock()
        mock_req.return_value = mock_resp

        result = get_session("test-key", "s1")
        self.assertEqual(result["status_enum"], "finished")


class TestCreateSession(unittest.TestCase):
    @patch("devin_api.requests.request")
    def test_create_session(self, mock_req):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "session_id": "new-session",
            "url": "https://app.devin.ai/sessions/new-session",
        }
        mock_resp.raise_for_status = MagicMock()
        mock_req.return_value = mock_resp

        result = create_session(
            "test-key",
            "Fix these issues",
            tags=["retry", "cwe-injection"],
            title="Retry: injection",
        )
        self.assertEqual(result["session_id"], "new-session")

        payload = mock_req.call_args[1].get("json") or mock_req.call_args.kwargs.get("json")
        self.assertEqual(payload["prompt"], "Fix these issues")
        self.assertIn("retry", payload["tags"])
        self.assertFalse(payload["idempotent"])


class TestBuildFeedbackMessage(unittest.TestCase):
    def test_basic_feedback(self):
        msg = _build_feedback_message("3 issues remain unresolved.")
        self.assertIn("Verification Results", msg)
        self.assertIn("3 issues remain", msg)
        self.assertIn("Action Required", msg)

    def test_feedback_with_remaining_issues(self):
        issues = [
            {
                "rule_id": "js/sql-injection",
                "locations": [{"file": "app.js", "start_line": 42}],
                "message": "SQL injection vulnerability found",
            }
        ]
        msg = _build_feedback_message("Issues found.", issues)
        self.assertIn("js/sql-injection", msg)
        self.assertIn("app.js:42", msg)


class TestBuildFollowupPrompt(unittest.TestCase):
    def test_basic_followup(self):
        prompt = _build_followup_prompt(
            original_prompt="Fix SQL injection in app.js",
            verification_results="1 issue still present",
            previous_pr_url="https://github.com/org/repo/pull/1",
            attempt_number=2,
        )
        self.assertIn("Retry Attempt 2", prompt)
        self.assertIn("Previous PR", prompt)
        self.assertIn("Fix SQL injection", prompt)
        self.assertIn("1 issue still present", prompt)

    def test_followup_with_remaining_issues(self):
        issues = [
            {
                "rule_id": "js/sql-injection",
                "rule_name": "SQL Injection",
                "cwes": ["cwe-89"],
                "locations": [{"file": "app.js", "start_line": 42}],
                "message": "Tainted data flows to SQL query",
            },
        ]
        prompt = _build_followup_prompt(
            original_prompt="Fix issues",
            verification_results="Partial fix",
            remaining_issues=issues,
        )
        self.assertIn("SQL Injection", prompt)
        self.assertIn("cwe-89", prompt)
        self.assertIn("app.js", prompt)


class TestRetryWithFeedback(unittest.TestCase):
    def test_max_retries_exceeded(self):
        result = retry_with_feedback(
            api_key="test-key",
            session_id="s1",
            batch={"batch_id": 1, "cwe_family": "injection", "severity_tier": "high"},
            original_prompt="Fix injection",
            verification_results="Issues remain",
            attempt_number=3,
            max_retry_attempts=2,
        )
        self.assertEqual(result["action"], "max_retries_exceeded")
        self.assertEqual(result["attempt"], 3)

    @patch("retry_feedback.send_message")
    @patch("retry_feedback.get_session")
    def test_send_to_active_session(self, mock_get, mock_send):
        mock_get.return_value = {"status_enum": "running"}
        mock_send.return_value = {"detail": "sent"}

        result = retry_with_feedback(
            api_key="test-key",
            session_id="s1",
            batch={"batch_id": 1, "cwe_family": "xss"},
            original_prompt="Fix XSS",
            verification_results="2 issues remain",
            attempt_number=1,
        )
        self.assertEqual(result["action"], "message_sent")
        mock_send.assert_called_once()
        msg = mock_send.call_args[0][2]
        self.assertIn("Verification Results", msg)

    @patch("retry_feedback.create_session")
    @patch("retry_feedback.get_session")
    def test_create_followup_for_terminal(self, mock_get, mock_create):
        mock_get.return_value = {"status_enum": "finished"}
        mock_create.return_value = {
            "session_id": "new-s",
            "url": "https://app.devin.ai/sessions/new-s",
        }

        result = retry_with_feedback(
            api_key="test-key",
            session_id="s1",
            batch={"batch_id": 1, "cwe_family": "injection", "severity_tier": "high"},
            original_prompt="Fix injection",
            verification_results="Issues remain",
            previous_pr_url="https://github.com/org/repo/pull/1",
            attempt_number=1,
        )
        self.assertEqual(result["action"], "followup_created")
        self.assertEqual(result["session_id"], "new-s")
        self.assertEqual(result["attempt"], 2)
        self.assertEqual(result["original_session_id"], "s1")

        call_kwargs = mock_create.call_args.kwargs
        self.assertIn("retry", call_kwargs["tags"])
        self.assertIn("attempt-2", call_kwargs["tags"])


class TestProcessRetryBatch(unittest.TestCase):
    @patch("retry_feedback.retry_with_feedback")
    def test_process_batch(self, mock_retry):
        mock_retry.return_value = {
            "action": "followup_created",
            "session_id": "new-s",
            "batch_id": 1,
            "attempt": 2,
        }

        outcomes = [
            {
                "batch_id": 1,
                "session_id": "s1",
                "status": "finished",
                "pr_url": "https://github.com/org/repo/pull/1",
            },
        ]
        batches = [
            {"batch_id": 1, "cwe_family": "injection", "severity_tier": "high"},
        ]
        prompts = {1: "Fix injection issues"}

        results = process_retry_batch(
            api_key="test-key",
            outcomes=outcomes,
            batches=batches,
            prompts=prompts,
        )
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["action"], "followup_created")

    @patch("retry_feedback.retry_with_feedback")
    def test_process_batch_skips_no_pr(self, mock_retry):
        outcomes = [
            {
                "batch_id": 1,
                "session_id": "s1",
                "status": "failed",
                "pr_url": "",
            },
        ]
        batches = [{"batch_id": 1, "cwe_family": "xss", "severity_tier": "medium"}]
        prompts = {1: "Fix XSS"}

        results = process_retry_batch(
            api_key="test-key",
            outcomes=outcomes,
            batches=batches,
            prompts=prompts,
        )
        self.assertEqual(len(results), 0)
        mock_retry.assert_not_called()


if __name__ == "__main__":
    unittest.main()
