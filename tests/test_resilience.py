"""Tests for resilience improvements (MP-16).

Covers retry utilities, exponential backoff, SARIF size limits,
telemetry file naming, zero-issue flagging, and GIT_ASKPASS helper.
"""

import json
import os
import stat
import sys
import tempfile
from unittest.mock import MagicMock, patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scripts"))

from scripts.retry_utils import exponential_backoff_delay, request_with_retry
from scripts.parse_sarif import parse_sarif, SARIF_MAX_SIZE_BYTES
from scripts.persist_logs import _create_askpass_script


class TestExponentialBackoffDelay:
    def test_delay_increases_with_attempt(self):
        d1 = exponential_backoff_delay(1, base=2.0, max_jitter=0.0)
        d2 = exponential_backoff_delay(2, base=2.0, max_jitter=0.0)
        d3 = exponential_backoff_delay(3, base=2.0, max_jitter=0.0)
        assert d1 == 4.0
        assert d2 == 8.0
        assert d3 == 16.0

    def test_jitter_adds_randomness(self):
        delays = set()
        for _ in range(20):
            delays.add(exponential_backoff_delay(1, base=2.0, max_jitter=1.0))
        assert len(delays) > 1

    def test_zero_jitter_is_deterministic(self):
        d1 = exponential_backoff_delay(2, base=1.0, max_jitter=0.0)
        d2 = exponential_backoff_delay(2, base=1.0, max_jitter=0.0)
        assert d1 == d2 == 4.0

    def test_jitter_within_bounds(self):
        for _ in range(100):
            d = exponential_backoff_delay(1, base=2.0, max_jitter=1.0)
            assert 4.0 <= d <= 5.0


class TestRequestWithRetry:
    def test_success_on_first_try(self):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        with patch("scripts.retry_utils.requests.request", return_value=mock_resp) as mock_req:
            resp = request_with_retry("GET", "https://example.com", timeout=5)
            assert resp.status_code == 200
            assert mock_req.call_count == 1

    def test_retries_on_502(self):
        fail_resp = MagicMock()
        fail_resp.status_code = 502
        ok_resp = MagicMock()
        ok_resp.status_code = 200
        with patch("scripts.retry_utils.requests.request", side_effect=[fail_resp, ok_resp]):
            with patch("scripts.retry_utils.time.sleep"):
                resp = request_with_retry(
                    "GET", "https://example.com", max_retries=2,
                    base_delay=0.01, max_jitter=0.0, timeout=5,
                )
                assert resp.status_code == 200

    def test_returns_last_response_on_exhausted_retries(self):
        fail_resp = MagicMock()
        fail_resp.status_code = 503
        with patch("scripts.retry_utils.requests.request", return_value=fail_resp):
            with patch("scripts.retry_utils.time.sleep"):
                resp = request_with_retry(
                    "GET", "https://example.com", max_retries=2,
                    base_delay=0.01, max_jitter=0.0, timeout=5,
                )
                assert resp.status_code == 503

    def test_retries_on_connection_error(self):
        import requests as req
        ok_resp = MagicMock()
        ok_resp.status_code = 200
        with patch(
            "scripts.retry_utils.requests.request",
            side_effect=[req.exceptions.ConnectionError("fail"), ok_resp],
        ):
            with patch("scripts.retry_utils.time.sleep"):
                resp = request_with_retry(
                    "GET", "https://example.com", max_retries=2,
                    base_delay=0.01, max_jitter=0.0, timeout=5,
                )
                assert resp.status_code == 200

    def test_raises_on_exhausted_connection_errors(self):
        import requests as req
        import pytest
        with patch(
            "scripts.retry_utils.requests.request",
            side_effect=req.exceptions.ConnectionError("fail"),
        ):
            with patch("scripts.retry_utils.time.sleep"):
                with pytest.raises(req.exceptions.ConnectionError):
                    request_with_retry(
                        "GET", "https://example.com", max_retries=2,
                        base_delay=0.01, max_jitter=0.0, timeout=5,
                    )

    def test_no_retry_on_non_retryable_status(self):
        resp_404 = MagicMock()
        resp_404.status_code = 404
        with patch("scripts.retry_utils.requests.request", return_value=resp_404) as mock_req:
            resp = request_with_retry("GET", "https://example.com", timeout=5)
            assert resp.status_code == 404
            assert mock_req.call_count == 1


class TestSarifFileSizeLimit:
    def test_rejects_oversized_sarif(self):
        import pytest
        with tempfile.NamedTemporaryFile(suffix=".sarif", delete=False) as f:
            f.write(b"x" * (SARIF_MAX_SIZE_BYTES + 1))
            f.flush()
            path = f.name
        try:
            with pytest.raises(ValueError, match="SARIF file too large"):
                parse_sarif(path)
        finally:
            os.unlink(path)

    def test_accepts_normal_sarif(self):
        sarif = {
            "version": "2.1.0",
            "runs": [{
                "tool": {"driver": {"name": "CodeQL", "rules": []}},
                "results": [],
            }],
        }
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".sarif", delete=False,
        ) as f:
            json.dump(sarif, f)
            path = f.name
        try:
            issues = parse_sarif(path)
            assert issues == []
        finally:
            os.unlink(path)


class TestTelemetryFileNaming:
    def test_uses_run_id_when_available(self):
        from scripts.persist_telemetry import push_telemetry
        record = {
            "target_repo": "https://github.com/owner/repo",
            "run_number": 5,
            "run_id": "12345678",
        }
        with patch("scripts.persist_telemetry.request_with_retry") as mock_req:
            mock_resp = MagicMock()
            mock_resp.status_code = 201
            mock_req.return_value = mock_resp
            push_telemetry("fake-token", "owner/action-repo", record)
            call_args = mock_req.call_args
            url = call_args[0][1]
            assert "run_12345678_" in url

    def test_falls_back_to_run_number(self):
        from scripts.persist_telemetry import push_telemetry
        record = {
            "target_repo": "https://github.com/owner/repo",
            "run_number": 42,
            "run_id": "",
        }
        with patch("scripts.persist_telemetry.request_with_retry") as mock_req:
            mock_resp = MagicMock()
            mock_resp.status_code = 201
            mock_req.return_value = mock_resp
            push_telemetry("fake-token", "owner/action-repo", record)
            call_args = mock_req.call_args
            url = call_args[0][1]
            assert "run_42_" in url


class TestZeroIssueFlagging:
    def test_zero_issues_flagged(self):
        from scripts.persist_telemetry import build_telemetry_record
        with tempfile.TemporaryDirectory() as tmpdir:
            with open(os.path.join(tmpdir, "issues.json"), "w") as f:
                json.dump([], f)
            with open(os.path.join(tmpdir, "batches.json"), "w") as f:
                json.dump([], f)
            with open(os.path.join(tmpdir, "sessions.json"), "w") as f:
                json.dump([], f)

            with patch.dict(os.environ, {
                "TARGET_REPO": "https://github.com/o/r",
                "FORK_URL": "",
                "RUN_NUMBER": "1",
                "RUN_ID": "111",
                "RUN_LABEL": "test",
                "ACTION_REPO": "o/a",
            }):
                record = build_telemetry_record(tmpdir)
                assert record["issues_found"] == 0

    def test_nonzero_issues_not_flagged(self):
        from scripts.persist_telemetry import build_telemetry_record
        with tempfile.TemporaryDirectory() as tmpdir:
            issues = [{"severity_tier": "high", "cwe_family": "xss", "fingerprint": "abc",
                        "id": "I1", "rule_id": "r1", "locations": [{"file": "a.js", "start_line": 1}]}]
            with open(os.path.join(tmpdir, "issues.json"), "w") as f:
                json.dump(issues, f)
            with open(os.path.join(tmpdir, "batches.json"), "w") as f:
                json.dump([], f)
            with open(os.path.join(tmpdir, "sessions.json"), "w") as f:
                json.dump([], f)

            with patch.dict(os.environ, {
                "TARGET_REPO": "https://github.com/o/r",
                "FORK_URL": "",
                "RUN_NUMBER": "1",
                "RUN_ID": "111",
                "RUN_LABEL": "test",
                "ACTION_REPO": "o/a",
            }):
                record = build_telemetry_record(tmpdir)
                assert record["issues_found"] == 1


class TestCreateAskpassScript:
    def test_creates_executable_file(self):
        path = _create_askpass_script()
        try:
            assert os.path.isfile(path)
            mode = os.stat(path).st_mode
            assert mode & stat.S_IXUSR
        finally:
            os.unlink(path)

    def test_script_reads_env_var(self):
        path = _create_askpass_script()
        try:
            with open(path) as f:
                content = f.read()
            assert "#!/bin/sh" in content
            assert '"$GIT_ASKPASS_TOKEN"' in content
        finally:
            os.unlink(path)

    def test_owner_only_permissions(self):
        path = _create_askpass_script()
        try:
            mode = os.stat(path).st_mode
            assert mode & stat.S_IRWXU
            assert not (mode & stat.S_IRWXG)
            assert not (mode & stat.S_IRWXO)
        finally:
            os.unlink(path)

    def test_uses_workspace_dir(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = _create_askpass_script(workspace_dir=tmpdir)
            try:
                assert path.startswith(tmpdir)
                assert os.path.isfile(path)
            finally:
                os.unlink(path)

    def test_falls_back_when_workspace_dir_missing(self):
        path = _create_askpass_script(workspace_dir="/nonexistent/dir")
        try:
            assert os.path.isfile(path)
        finally:
            os.unlink(path)
