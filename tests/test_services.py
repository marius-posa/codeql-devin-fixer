"""Unit tests for telemetry services (github_service.py and devin_service.py).

Covers: match_pr_to_session.
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "telemetry"))

from github_service import match_pr_to_session


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
