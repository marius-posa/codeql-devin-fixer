"""Unit tests for telemetry/verification.py and the /api/verification endpoint."""

import json
import os
import sys
import tempfile
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "telemetry"))

import pytest
from verification import (
    load_verification_records,
    build_session_verification_map,
    build_fingerprint_fix_map,
    aggregate_verification_stats,
)
from app import app


@pytest.fixture
def client():
    app.config["TESTING"] = True
    with app.test_client() as c:
        yield c


def _record(
    session_id="sess1",
    pr_url="https://github.com/o/r/pull/10",
    pr_number="10",
    verified_at="2026-02-01T00:00:00Z",
    fixed=None,
    still_present=None,
    cwe_family="injection",
    source_run_number="5",
):
    fixed = fixed or []
    still_present = still_present or []
    total = len(fixed) + len(still_present)
    return {
        "session_id": session_id,
        "pr_url": pr_url,
        "pr_number": pr_number,
        "verified_at": verified_at,
        "cwe_family": cwe_family,
        "source_run_number": source_run_number,
        "verified_fixed": [
            {"fingerprint": fp, "id": f"I-{i}", "rule_id": "r1",
             "severity_tier": "high", "cwe_family": cwe_family, "file": "a.js"}
            for i, fp in enumerate(fixed)
        ],
        "still_present": [
            {"fingerprint": fp, "id": f"I-{i}", "rule_id": "r1",
             "severity_tier": "high", "cwe_family": cwe_family, "file": "a.js"}
            for i, fp in enumerate(still_present)
        ],
        "summary": {
            "total_targeted": total,
            "fixed_count": len(fixed),
            "remaining_count": len(still_present),
            "fix_rate": round(len(fixed) / max(total, 1) * 100, 1),
        },
    }


class TestLoadVerificationRecords:
    def test_loads_verification_files_only(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            d = Path(tmpdir)
            (d / "verification_1.json").write_text(json.dumps({"session_id": "s1"}))
            (d / "run_data.json").write_text(json.dumps({"run_number": 1}))
            (d / "verification_2.json").write_text(json.dumps({"session_id": "s2"}))
            records = load_verification_records(d)
            assert len(records) == 2
            ids = {r["session_id"] for r in records}
            assert ids == {"s1", "s2"}

    def test_adds_file_metadata(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            d = Path(tmpdir)
            (d / "verification_abc.json").write_text(json.dumps({"x": 1}))
            records = load_verification_records(d)
            assert records[0]["_file"] == "verification_abc.json"

    def test_skips_invalid_json(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            d = Path(tmpdir)
            (d / "verification_good.json").write_text(json.dumps({"ok": True}))
            (d / "verification_bad.json").write_text("not json{{{")
            records = load_verification_records(d)
            assert len(records) == 1

    def test_empty_directory(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            assert load_verification_records(Path(tmpdir)) == []

    def test_nonexistent_directory(self):
        assert load_verification_records(Path("/nonexistent/path")) == []

    def test_sorted_order(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            d = Path(tmpdir)
            (d / "verification_b.json").write_text(json.dumps({"order": 2}))
            (d / "verification_a.json").write_text(json.dumps({"order": 1}))
            records = load_verification_records(d)
            assert records[0]["order"] == 1
            assert records[1]["order"] == 2


class TestBuildSessionVerificationMap:
    def test_single_record_all_fixed(self):
        rec = _record(session_id="s1", fixed=["fp1", "fp2"], still_present=[])
        result = build_session_verification_map([rec])
        assert "s1" in result
        s = result["s1"]
        assert s["fixed_count"] == 2
        assert s["total_targeted"] == 2
        assert s["label"] == "verified-fix"
        assert s["fix_rate"] == 100.0
        assert set(s["fixed_fingerprints"]) == {"fp1", "fp2"}

    def test_partial_fix(self):
        rec = _record(session_id="s2", fixed=["fp1"], still_present=["fp2"])
        result = build_session_verification_map([rec])
        assert result["s2"]["label"] == "codeql-partial-fix"
        assert result["s2"]["fixed_count"] == 1
        assert result["s2"]["remaining_count"] == 1

    def test_no_fixes(self):
        rec = _record(session_id="s3", fixed=[], still_present=["fp1", "fp2"])
        result = build_session_verification_map([rec])
        assert result["s3"]["label"] == "codeql-needs-work"
        assert result["s3"]["fixed_count"] == 0

    def test_empty_records(self):
        assert build_session_verification_map([]) == {}

    def test_skips_record_without_session_id(self):
        rec = _record(session_id="", fixed=["fp1"])
        assert build_session_verification_map([rec]) == {}

    def test_preserves_metadata(self):
        rec = _record(session_id="s1", pr_url="http://pr/1", pr_number="42",
                       cwe_family="xss", source_run_number="7", fixed=["fp1"])
        result = build_session_verification_map([rec])
        s = result["s1"]
        assert s["pr_url"] == "http://pr/1"
        assert s["pr_number"] == "42"
        assert s["cwe_family"] == "xss"
        assert s["source_run_number"] == "7"


class TestBuildFingerprintFixMap:
    def test_maps_fixed_fingerprints(self):
        rec = _record(session_id="s1", pr_url="http://pr/1",
                       verified_at="2026-02-01T00:00:00Z",
                       fixed=["fp1", "fp2"])
        result = build_fingerprint_fix_map([rec])
        assert "fp1" in result
        assert result["fp1"]["fixed_by_session"] == "s1"
        assert result["fp1"]["fixed_by_pr"] == "http://pr/1"
        assert result["fp1"]["verified_at"] == "2026-02-01T00:00:00Z"

    def test_does_not_include_still_present(self):
        rec = _record(fixed=["fp1"], still_present=["fp2"])
        result = build_fingerprint_fix_map([rec])
        assert "fp1" in result
        assert "fp2" not in result

    def test_first_fix_wins(self):
        rec1 = _record(session_id="s1", pr_url="pr1", verified_at="t1", fixed=["fp1"])
        rec2 = _record(session_id="s2", pr_url="pr2", verified_at="t2", fixed=["fp1"])
        result = build_fingerprint_fix_map([rec1, rec2])
        assert result["fp1"]["fixed_by_session"] == "s1"

    def test_empty_records(self):
        assert build_fingerprint_fix_map([]) == {}

    def test_skips_empty_fingerprint(self):
        rec = {
            "session_id": "s1", "pr_url": "", "verified_at": "",
            "verified_fixed": [{"fingerprint": "", "id": "I1"}],
            "still_present": [], "summary": {},
        }
        result = build_fingerprint_fix_map([rec])
        assert result == {}


class TestAggregateVerificationStats:
    def test_single_fully_verified(self):
        rec = _record(fixed=["fp1", "fp2"], still_present=[])
        stats = aggregate_verification_stats([rec])
        assert stats["total_verifications"] == 1
        assert stats["total_issues_fixed"] == 2
        assert stats["total_issues_targeted"] == 2
        assert stats["fully_verified_prs"] == 1
        assert stats["partial_fix_prs"] == 0
        assert stats["overall_fix_rate"] == 100.0

    def test_mixed_records(self):
        rec1 = _record(session_id="s1", fixed=["fp1", "fp2"], still_present=[])
        rec2 = _record(session_id="s2", fixed=["fp3"], still_present=["fp4"])
        rec3 = _record(session_id="s3", fixed=[], still_present=["fp5"])
        stats = aggregate_verification_stats([rec1, rec2, rec3])
        assert stats["total_verifications"] == 3
        assert stats["total_issues_fixed"] == 3
        assert stats["total_issues_remaining"] == 2
        assert stats["total_issues_targeted"] == 5
        assert stats["fully_verified_prs"] == 1
        assert stats["partial_fix_prs"] == 1
        assert stats["overall_fix_rate"] == 60.0

    def test_empty_records(self):
        stats = aggregate_verification_stats([])
        assert stats["total_verifications"] == 0
        assert stats["total_issues_fixed"] == 0
        assert stats["overall_fix_rate"] == 0.0

    def test_zero_targeted_fix_rate(self):
        rec = _record(fixed=[], still_present=[])
        stats = aggregate_verification_stats([rec])
        assert stats["overall_fix_rate"] == 0.0


class TestApiVerificationEndpoint:
    @patch("app.load_verification_records")
    def test_returns_stats_records_session_map(self, mock_load, client):
        rec = _record(session_id="s1", fixed=["fp1"], still_present=["fp2"])
        mock_load.return_value = [rec]
        resp = client.get("/api/verification")
        assert resp.status_code == 200
        data = resp.get_json()
        assert "stats" in data
        assert "records" in data
        assert "session_map" in data
        assert data["stats"]["total_verifications"] == 1
        assert data["stats"]["total_issues_fixed"] == 1
        assert "s1" in data["session_map"]

    @patch("app.load_verification_records")
    def test_empty_verification(self, mock_load, client):
        mock_load.return_value = []
        resp = client.get("/api/verification")
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["stats"]["total_verifications"] == 0
        assert data["records"]["items"] == []
        assert data["session_map"] == {}

    @patch("app.load_verification_records")
    def test_records_paginated(self, mock_load, client):
        recs = [_record(session_id=f"s{i}", fixed=["fp"]) for i in range(5)]
        mock_load.return_value = recs
        resp = client.get("/api/verification?page=1&per_page=2")
        data = resp.get_json()
        assert len(data["records"]["items"]) == 2
        assert data["records"]["total"] == 5
        assert data["records"]["pages"] == 3


class TestApiIssuesVerificationEnrichment:
    @patch("app.load_verification_records")
    @patch("app.cache")
    def test_issues_enriched_with_fix_attribution(self, mock_cache, mock_load, client):
        mock_cache.get_runs.return_value = [{
            "target_repo": "r1",
            "run_number": 1,
            "timestamp": "2026-01-01T00:00:00Z",
            "issue_fingerprints": [{
                "fingerprint": "fp1",
                "id": "I1",
                "rule_id": "r1",
                "severity_tier": "high",
                "cwe_family": "xss",
                "file": "a.js",
                "start_line": 1,
            }],
        }]
        rec = _record(session_id="s1", pr_url="http://pr/1",
                       verified_at="2026-02-01T00:00:00Z", fixed=["fp1"])
        mock_load.return_value = [rec]
        resp = client.get("/api/issues")
        assert resp.status_code == 200
        data = resp.get_json()
        items = data["items"]
        assert len(items) == 1
        assert items[0]["fixed_by_session"] == "s1"
        assert items[0]["fixed_by_pr"] == "http://pr/1"
        assert items[0]["verified_at"] == "2026-02-01T00:00:00Z"

    @patch("app.load_verification_records")
    @patch("app.cache")
    def test_issues_without_verification_unchanged(self, mock_cache, mock_load, client):
        mock_cache.get_runs.return_value = [{
            "target_repo": "r1",
            "run_number": 1,
            "timestamp": "2026-01-01T00:00:00Z",
            "issue_fingerprints": [{
                "fingerprint": "fp_no_match",
                "id": "I1",
                "rule_id": "r1",
                "severity_tier": "high",
                "cwe_family": "xss",
                "file": "a.js",
                "start_line": 1,
            }],
        }]
        mock_load.return_value = []
        resp = client.get("/api/issues")
        assert resp.status_code == 200
        data = resp.get_json()
        items = data["items"]
        assert len(items) == 1
        assert "fixed_by_session" not in items[0]
