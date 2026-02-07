"""Unit tests for telemetry modules.

Covers: aggregation.py (aggregate_sessions, aggregate_stats, build_repos_dict),
issue_tracking.py (edge cases extending existing coverage).
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "telemetry"))

from aggregation import aggregate_sessions, aggregate_stats, build_repos_dict
from issue_tracking import track_issues_across_runs, _parse_ts


class TestAggregateSessions:
    def test_empty_runs(self):
        assert aggregate_sessions([]) == []

    def test_single_run_single_session(self):
        runs = [{
            "target_repo": "owner/repo",
            "fork_url": "https://github.com/me/repo",
            "run_number": 1,
            "run_id": "abc",
            "run_url": "https://github.com/...",
            "run_label": "run-1",
            "timestamp": "2026-01-01T00:00:00Z",
            "sessions": [{
                "session_id": "s1",
                "session_url": "https://app.devin.ai/sessions/s1",
                "batch_id": 1,
                "status": "created",
                "issue_ids": ["I1", "I2"],
                "pr_url": "",
            }],
        }]
        result = aggregate_sessions(runs)
        assert len(result) == 1
        assert result[0]["session_id"] == "s1"
        assert result[0]["target_repo"] == "owner/repo"
        assert result[0]["run_number"] == 1
        assert result[0]["issue_ids"] == ["I1", "I2"]

    def test_multiple_runs_multiple_sessions(self):
        runs = [
            {
                "target_repo": "r1",
                "run_number": 1,
                "timestamp": "t1",
                "sessions": [
                    {"session_id": "s1", "status": "finished"},
                    {"session_id": "s2", "status": "created"},
                ],
            },
            {
                "target_repo": "r2",
                "run_number": 2,
                "timestamp": "t2",
                "sessions": [{"session_id": "s3", "status": "finished"}],
            },
        ]
        result = aggregate_sessions(runs)
        assert len(result) == 3
        ids = {s["session_id"] for s in result}
        assert ids == {"s1", "s2", "s3"}

    def test_run_with_no_sessions(self):
        runs = [{"target_repo": "r1", "run_number": 1, "sessions": []}]
        assert aggregate_sessions(runs) == []

    def test_missing_session_fields_default(self):
        runs = [{"sessions": [{}]}]
        result = aggregate_sessions(runs)
        assert len(result) == 1
        assert result[0]["session_id"] == ""
        assert result[0]["status"] == "unknown"


class TestAggregateStats:
    def _run(self, repo="r1", issues=5, severity=None, category=None, ts="2026-01-01"):
        return {
            "target_repo": repo,
            "issues_found": issues,
            "severity_breakdown": severity or {"high": issues},
            "category_breakdown": category or {"injection": issues},
            "timestamp": ts,
        }

    def test_empty_inputs(self):
        stats = aggregate_stats([], [], [])
        assert stats["repos_scanned"] == 0
        assert stats["total_issues"] == 0
        assert stats["sessions_created"] == 0

    def test_single_run(self):
        runs = [self._run()]
        sessions = [{"session_id": "s1", "status": "finished", "pr_url": "http://pr"}]
        prs = [{"state": "open", "merged": False}]
        stats = aggregate_stats(runs, sessions, prs)
        assert stats["repos_scanned"] == 1
        assert stats["total_issues"] == 5
        assert stats["sessions_created"] == 1
        assert stats["sessions_finished"] == 1
        assert stats["sessions_with_pr"] == 1
        assert stats["prs_open"] == 1

    def test_multiple_repos(self):
        runs = [self._run("r1"), self._run("r2")]
        stats = aggregate_stats(runs, [], [])
        assert stats["repos_scanned"] == 2

    def test_pr_stats(self):
        prs = [
            {"state": "closed", "merged": True},
            {"state": "closed", "merged": True},
            {"state": "open", "merged": False},
            {"state": "closed", "merged": False},
        ]
        stats = aggregate_stats([], [], prs)
        assert stats["prs_merged"] == 2
        assert stats["prs_open"] == 1
        assert stats["prs_closed"] == 1
        assert stats["fix_rate"] == 50.0

    def test_latest_issues_uses_most_recent_run(self):
        runs = [
            self._run("r1", issues=10, ts="2026-01-01"),
            self._run("r1", issues=3, ts="2026-01-02"),
        ]
        stats = aggregate_stats(runs, [], [])
        assert stats["total_issues"] == 13
        assert stats["latest_issues"] == 3

    def test_severity_aggregation(self):
        runs = [
            self._run(severity={"critical": 2, "high": 3}),
            self._run(severity={"critical": 1, "medium": 4}),
        ]
        stats = aggregate_stats(runs, [], [])
        assert stats["severity_breakdown"]["critical"] == 3
        assert stats["severity_breakdown"]["high"] == 3
        assert stats["severity_breakdown"]["medium"] == 4

    def test_zero_prs_fix_rate(self):
        stats = aggregate_stats([], [], [])
        assert stats["fix_rate"] == 0.0


class TestBuildReposDict:
    def _run(self, repo="r1", issues=5, fork="https://github.com/me/r1", ts="2026-01-01"):
        return {
            "target_repo": repo,
            "fork_url": fork,
            "issues_found": issues,
            "severity_breakdown": {"high": issues},
            "category_breakdown": {"injection": issues},
            "timestamp": ts,
        }

    def test_empty_inputs(self):
        assert build_repos_dict([], [], []) == []

    def test_single_repo(self):
        runs = [self._run()]
        result = build_repos_dict(runs, [], [])
        assert len(result) == 1
        assert result[0]["repo"] == "r1"
        assert result[0]["runs"] == 1
        assert result[0]["issues_found"] == 5

    def test_multiple_repos_sorted_by_last_run(self):
        runs = [
            self._run("r1", ts="2026-01-01"),
            self._run("r2", ts="2026-01-02"),
        ]
        result = build_repos_dict(runs, [], [])
        assert result[0]["repo"] == "r2"
        assert result[1]["repo"] == "r1"

    def test_sessions_counted_per_repo(self):
        runs = [self._run("r1")]
        sessions = [
            {"target_repo": "r1", "session_id": "s1", "status": "finished"},
            {"target_repo": "r1", "session_id": "s2", "status": "created"},
        ]
        result = build_repos_dict(runs, sessions, [])
        assert result[0]["sessions_created"] == 2
        assert result[0]["sessions_finished"] == 1

    def test_prs_matched_by_fork_url(self):
        runs = [self._run("r1", fork="https://github.com/me/r1")]
        prs = [
            {"repo": "me/r1", "state": "closed", "merged": True},
            {"repo": "me/r1", "state": "open", "merged": False},
        ]
        result = build_repos_dict(runs, [], prs)
        assert result[0]["prs_total"] == 2
        assert result[0]["prs_merged"] == 1
        assert result[0]["prs_open"] == 1

    def test_run_with_no_repo_skipped(self):
        runs = [{"target_repo": "", "issues_found": 5, "severity_breakdown": {}, "category_breakdown": {}, "timestamp": "t"}]
        result = build_repos_dict(runs, [], [])
        assert result == []

    def test_severity_accumulated_across_runs(self):
        runs = [
            self._run("r1", ts="2026-01-01"),
            self._run("r1", ts="2026-01-02"),
        ]
        result = build_repos_dict(runs, [], [])
        assert result[0]["severity_breakdown"]["high"] == 10


class TestTrackIssuesEdgeCases:
    def _run(self, run_number, repo, fingerprints, ts=None):
        return {
            "run_number": run_number,
            "target_repo": repo,
            "timestamp": ts or f"2026-01-01T00:00:{run_number:02d}Z",
            "issue_fingerprints": fingerprints,
        }

    def _fp(self, fingerprint, issue_id="I1", rule="r1", severity="high", family="xss"):
        return {
            "fingerprint": fingerprint,
            "id": issue_id,
            "rule_id": rule,
            "severity_tier": severity,
            "cwe_family": family,
            "file": "a.js",
            "start_line": 1,
        }

    def test_empty_fingerprint_skipped(self):
        runs = [self._run(1, "r", [{"fingerprint": "", "id": "I1", "rule_id": "r1",
                                     "severity_tier": "high", "cwe_family": "xss",
                                     "file": "a.js", "start_line": 1}])]
        result = track_issues_across_runs(runs)
        assert result == []

    def test_multiple_repos_tracked_independently(self):
        fp_a = self._fp("aaa")
        runs = [
            self._run(1, "repo-a", [fp_a], "2026-01-01T00:00:01Z"),
            self._run(1, "repo-b", [fp_a], "2026-01-01T00:00:02Z"),
        ]
        result = track_issues_across_runs(runs)
        assert len(result) == 1
        assert result[0]["appearances"] == 2

    def test_issue_appearing_in_non_consecutive_runs(self):
        fp = self._fp("aaa")
        runs = [
            self._run(1, "r", [fp], "2026-01-01T00:00:01Z"),
            self._run(2, "r", [], "2026-01-01T00:00:02Z"),
            self._run(3, "r", [fp], "2026-01-01T00:00:03Z"),
        ]
        result = track_issues_across_runs(runs)
        assert len(result) == 1
        assert result[0]["status"] == "recurring"
        assert result[0]["appearances"] == 2

    def test_result_fields_complete(self):
        fp = self._fp("aaa", issue_id="I42", rule="js/xss", severity="critical", family="xss")
        runs = [self._run(1, "r", [fp])]
        result = track_issues_across_runs(runs)
        r = result[0]
        assert r["fingerprint"] == "aaa"
        assert r["rule_id"] == "js/xss"
        assert r["severity_tier"] == "critical"
        assert r["cwe_family"] == "xss"
        assert r["first_seen_run"] == 1
        assert r["last_seen_run"] == 1
        assert r["latest_issue_id"] == "I42"

    def test_single_run_no_fingerprints(self):
        runs = [self._run(1, "r", [])]
        result = track_issues_across_runs(runs)
        assert result == []

    def test_new_metadata_fields_default(self):
        fp = self._fp("aaa")
        runs = [self._run(1, "r", [fp])]
        result = track_issues_across_runs(runs)
        r = result[0]
        assert r["description"] == ""
        assert r["resolution"] == ""
        assert r["code_churn"] == 0
        assert r["fix_duration_hours"] is None

    def test_new_metadata_fields_populated(self):
        fp = self._fp("bbb")
        fp["description"] = "SQL injection via user input"
        fp["resolution"] = "Use parameterized queries"
        fp["code_churn"] = 42
        runs = [self._run(1, "r", [fp])]
        result = track_issues_across_runs(runs)
        r = result[0]
        assert r["description"] == "SQL injection via user input"
        assert r["resolution"] == "Use parameterized queries"
        assert r["code_churn"] == 42

    def test_fix_duration_hours_calculated_for_fixed(self):
        fp = self._fp("ccc")
        runs = [
            self._run(1, "r", [fp], "2026-01-01T00:00:00Z"),
            self._run(2, "r", [fp], "2026-01-01T06:00:00Z"),
            self._run(3, "r", [], "2026-01-01T12:00:00Z"),
        ]
        result = track_issues_across_runs(runs)
        assert len(result) == 1
        assert result[0]["status"] == "fixed"
        assert result[0]["fix_duration_hours"] == 6.0

    def test_fix_duration_hours_none_for_recurring(self):
        fp = self._fp("ddd")
        runs = [
            self._run(1, "r", [fp], "2026-01-01T00:00:00Z"),
            self._run(2, "r", [fp], "2026-01-02T00:00:00Z"),
        ]
        result = track_issues_across_runs(runs)
        assert result[0]["status"] == "recurring"
        assert result[0]["fix_duration_hours"] is None


class TestParseTs:
    def test_standard_format(self):
        dt = _parse_ts("2026-01-15T10:30:00Z")
        assert dt is not None
        assert dt.year == 2026
        assert dt.month == 1
        assert dt.hour == 10

    def test_fractional_seconds_format(self):
        dt = _parse_ts("2026-01-15T10:30:00.123456Z")
        assert dt is not None
        assert dt.year == 2026

    def test_empty_string(self):
        assert _parse_ts("") is None

    def test_invalid_string(self):
        assert _parse_ts("not-a-date") is None
