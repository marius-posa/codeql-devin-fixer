"""Tests for scripts/verify_results.py -- new functionality for MP-35."""

import json
import os
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scripts"))

from verify_results import (
    extract_session_id_from_body,
    find_original_issues_from_telemetry,
    load_original_fingerprints,
)


class TestLoadOriginalFingerprintsFormats:
    def test_envelope_issues_format(self):
        with tempfile.NamedTemporaryFile(suffix=".json", mode="w", delete=False) as f:
            json.dump({
                "schema_version": "1.0",
                "issues": [{
                    "id": "CQLF-R1-0001",
                    "fingerprint": "abc123",
                    "rule_id": "js/xss",
                    "severity_tier": "high",
                    "cwe_family": "xss",
                    "locations": [{"file": "app.js", "start_line": 10}],
                    "message": "XSS vulnerability",
                }],
            }, f)
            f.flush()
            fps = load_original_fingerprints(f.name)
        os.unlink(f.name)
        assert len(fps) == 1
        assert fps[0]["fingerprint"] == "abc123"
        assert fps[0]["file"] == "app.js"
        assert fps[0]["start_line"] == 10

    def test_telemetry_fingerprints_format(self):
        with tempfile.NamedTemporaryFile(suffix=".json", mode="w", delete=False) as f:
            json.dump({
                "issue_fingerprints": [{
                    "id": "CQLF-R5-0001",
                    "fingerprint": "def456",
                    "rule_id": "py/sql-injection",
                    "severity_tier": "high",
                    "cwe_family": "injection",
                    "file": "views.py",
                    "start_line": 42,
                }],
            }, f)
            f.flush()
            fps = load_original_fingerprints(f.name)
        os.unlink(f.name)
        assert len(fps) == 1
        assert fps[0]["fingerprint"] == "def456"
        assert fps[0]["file"] == "views.py"
        assert fps[0]["start_line"] == 42

    def test_flat_list_format(self):
        with tempfile.NamedTemporaryFile(suffix=".json", mode="w", delete=False) as f:
            json.dump([{
                "id": "I1",
                "fingerprint": "fp1",
                "rule_id": "r1",
                "severity_tier": "medium",
                "cwe_family": "xss",
                "file": "a.js",
                "start_line": 5,
            }], f)
            f.flush()
            fps = load_original_fingerprints(f.name)
        os.unlink(f.name)
        assert len(fps) == 1
        assert fps[0]["file"] == "a.js"
        assert fps[0]["start_line"] == 5

    def test_locations_take_precedence_over_top_level(self):
        with tempfile.NamedTemporaryFile(suffix=".json", mode="w", delete=False) as f:
            json.dump([{
                "id": "I1",
                "fingerprint": "fp1",
                "rule_id": "r1",
                "severity_tier": "medium",
                "cwe_family": "xss",
                "file": "top_level.js",
                "start_line": 1,
                "locations": [{"file": "nested.js", "start_line": 99}],
            }], f)
            f.flush()
            fps = load_original_fingerprints(f.name)
        os.unlink(f.name)
        assert fps[0]["file"] == "nested.js"
        assert fps[0]["start_line"] == 99

    def test_empty_dict_returns_empty(self):
        with tempfile.NamedTemporaryFile(suffix=".json", mode="w", delete=False) as f:
            json.dump({"unknown_key": []}, f)
            f.flush()
            fps = load_original_fingerprints(f.name)
        os.unlink(f.name)
        assert fps == []


class TestFindOriginalIssuesFromTelemetry:
    def test_finds_matching_run(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            record = {
                "run_number": 22,
                "issue_fingerprints": [
                    {"id": "CQLF-R22-0001", "fingerprint": "abc", "rule_id": "r1",
                     "severity_tier": "high", "cwe_family": "xss",
                     "file": "a.js", "start_line": 10},
                ],
            }
            with open(os.path.join(tmpdir, "run_22.json"), "w") as f:
                json.dump(record, f)

            result = find_original_issues_from_telemetry(tmpdir, "22")
            assert result != ""
            with open(result) as f:
                data = json.load(f)
            assert "issue_fingerprints" in data
            assert len(data["issue_fingerprints"]) == 1
            assert data["issue_fingerprints"][0]["fingerprint"] == "abc"

    def test_no_matching_run(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            record = {"run_number": 10, "issue_fingerprints": [{"fingerprint": "x"}]}
            with open(os.path.join(tmpdir, "run_10.json"), "w") as f:
                json.dump(record, f)

            result = find_original_issues_from_telemetry(tmpdir, "99")
            assert result == ""

    def test_skips_verification_files(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            record = {"run_number": 5, "issue_fingerprints": [{"fingerprint": "x"}]}
            with open(os.path.join(tmpdir, "verification_sess1.json"), "w") as f:
                json.dump(record, f)

            result = find_original_issues_from_telemetry(tmpdir, "5")
            assert result == ""

    def test_nonexistent_directory(self):
        result = find_original_issues_from_telemetry("/nonexistent/path", "1")
        assert result == ""

    def test_skips_invalid_json(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            with open(os.path.join(tmpdir, "bad.json"), "w") as f:
                f.write("not json{{{")

            result = find_original_issues_from_telemetry(tmpdir, "1")
            assert result == ""

    def test_run_number_string_int_match(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            record = {
                "run_number": 15,
                "issue_fingerprints": [{"fingerprint": "fp1", "id": "I1"}],
            }
            with open(os.path.join(tmpdir, "run_15.json"), "w") as f:
                json.dump(record, f)

            result = find_original_issues_from_telemetry(tmpdir, "15")
            assert result != ""


class TestExtractSessionIdFromBody:
    def test_devin_url(self):
        body = "Created by https://app.devin.ai/sessions/abc123def456 for fixing issues"
        assert extract_session_id_from_body(body) == "abc123def456"

    def test_session_id_field(self):
        body = "session_id: abc123-def456-789"
        assert extract_session_id_from_body(body) == "abc123-def456-789"

    def test_no_session_id(self):
        body = "Just a regular PR description with no session info"
        assert extract_session_id_from_body(body) == ""

    def test_devin_url_takes_precedence(self):
        body = (
            "devin.ai/sessions/aaa111bbb222\n"
            "session_id: ccc333ddd444"
        )
        assert extract_session_id_from_body(body) == "aaa111bbb222"

    def test_empty_body(self):
        assert extract_session_id_from_body("") == ""
