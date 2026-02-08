"""Unit tests for telemetry modules.

Covers: aggregation.py (aggregate_sessions, aggregate_stats, build_repos_dict),
issue_tracking.py (edge cases extending existing coverage).
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "telemetry"))

from datetime import datetime, timezone

from aggregation import aggregate_sessions, aggregate_stats, build_repos_dict, compute_sla_summary
from issue_tracking import track_issues_across_runs, _parse_ts, compute_sla_status, DEFAULT_SLA_HOURS


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


class TestSlaFieldsInTrackedIssues:
    def _run(self, run_number, repo, fingerprints, ts=None):
        return {
            "run_number": run_number,
            "target_repo": repo,
            "timestamp": ts or f"2026-01-01T00:00:{run_number:02d}Z",
            "issue_fingerprints": fingerprints,
        }

    def _fp(self, fingerprint, severity="high"):
        return {
            "fingerprint": fingerprint,
            "id": "I1",
            "rule_id": "r1",
            "severity_tier": severity,
            "cwe_family": "xss",
            "file": "a.js",
            "start_line": 1,
        }

    def test_new_issue_has_sla_fields(self):
        runs = [self._run(1, "r", [self._fp("aaa")])]
        result = track_issues_across_runs(runs)
        r = result[0]
        assert "sla_status" in r
        assert "sla_limit_hours" in r
        assert "sla_hours_elapsed" in r
        assert "sla_hours_remaining" in r
        assert "found_at" in r
        assert "fixed_at" in r
        assert r["found_at"] is not None
        assert r["fixed_at"] is None

    def test_fixed_issue_has_fixed_at(self):
        fp = self._fp("bbb")
        runs = [
            self._run(1, "r", [fp], "2026-01-01T00:00:00Z"),
            self._run(2, "r", [fp], "2026-01-01T02:00:00Z"),
            self._run(3, "r", [], "2026-01-01T06:00:00Z"),
        ]
        result = track_issues_across_runs(runs)
        r = result[0]
        assert r["status"] == "fixed"
        assert r["fixed_at"] == "2026-01-01T02:00:00Z"
        assert r["sla_status"] == "met"

    def test_sla_limit_matches_severity(self):
        runs = [self._run(1, "r", [self._fp("ccc", "critical")])]
        result = track_issues_across_runs(runs)
        assert result[0]["sla_limit_hours"] == 48


class TestComputeSlaStatus:
    def test_on_track(self):
        found = datetime.now(timezone.utc)
        result = compute_sla_status("high", found, None, {"high": 100})
        assert result["sla_status"] == "on-track"
        assert result["sla_limit_hours"] == 100

    def test_at_risk(self):
        now = datetime.now(timezone.utc)
        from datetime import timedelta
        found = now - timedelta(hours=80)
        result = compute_sla_status("high", found, None, {"high": 100})
        assert result["sla_status"] == "at-risk"
        assert result["sla_limit_hours"] == 100

    def test_breached_open(self):
        found = datetime(2020, 1, 1, 0, 0, tzinfo=timezone.utc)
        result = compute_sla_status("high", found, None)
        assert result["sla_status"] == "breached"
        assert result["sla_hours_remaining"] < 0

    def test_met_fixed_within_sla(self):
        found = datetime(2026, 1, 1, 0, 0, tzinfo=timezone.utc)
        fixed = datetime(2026, 1, 1, 10, 0, tzinfo=timezone.utc)
        result = compute_sla_status("high", found, fixed)
        assert result["sla_status"] == "met"
        assert result["sla_hours_elapsed"] == 10.0

    def test_breached_fixed_after_sla(self):
        found = datetime(2026, 1, 1, 0, 0, tzinfo=timezone.utc)
        fixed = datetime(2026, 1, 10, 0, 0, tzinfo=timezone.utc)
        result = compute_sla_status("critical", found, fixed)
        assert result["sla_status"] == "breached"

    def test_at_risk_boundary_exactly_75_percent(self):
        from datetime import timedelta
        now = datetime.now(timezone.utc)
        found = now - timedelta(hours=75)
        result = compute_sla_status("high", found, None, {"high": 100})
        assert result["sla_status"] == "at-risk"

    def test_unknown_severity(self):
        found = datetime(2026, 1, 1, 0, 0, tzinfo=timezone.utc)
        result = compute_sla_status("exotic", found, None)
        assert result["sla_status"] == "unknown"

    def test_none_found_at(self):
        result = compute_sla_status("high", None, None)
        assert result["sla_status"] == "unknown"

    def test_default_thresholds(self):
        assert DEFAULT_SLA_HOURS["critical"] == 48
        assert DEFAULT_SLA_HOURS["high"] == 96
        assert DEFAULT_SLA_HOURS["medium"] == 168
        assert DEFAULT_SLA_HOURS["low"] == 336


class TestComputeSlaSummary:
    def test_empty_issues(self):
        result = compute_sla_summary([])
        assert result["total_breached"] == 0
        assert result["total_on_track"] == 0
        assert result["time_to_fix_by_severity"] == {}

    def test_counts_by_status(self):
        issues = [
            {"sla_status": "on-track", "severity_tier": "high"},
            {"sla_status": "on-track", "severity_tier": "high"},
            {"sla_status": "breached", "severity_tier": "critical"},
            {"sla_status": "met", "severity_tier": "medium", "fix_duration_hours": 10.0},
        ]
        result = compute_sla_summary(issues)
        assert result["total_on_track"] == 2
        assert result["total_breached"] == 1
        assert result["total_met"] == 1

    def test_time_to_fix_stats(self):
        issues = [
            {"sla_status": "met", "severity_tier": "high", "fix_duration_hours": 5.0},
            {"sla_status": "met", "severity_tier": "high", "fix_duration_hours": 15.0},
            {"sla_status": "met", "severity_tier": "high", "fix_duration_hours": 10.0},
        ]
        result = compute_sla_summary(issues)
        ttf = result["time_to_fix_by_severity"]["high"]
        assert ttf["count"] == 3
        assert ttf["min"] == 5.0
        assert ttf["max"] == 15.0
        assert ttf["avg"] == 10.0
        assert ttf["median"] == 10.0

    def test_median_even_count(self):
        issues = [
            {"sla_status": "met", "severity_tier": "high", "fix_duration_hours": 4.0},
            {"sla_status": "met", "severity_tier": "high", "fix_duration_hours": 6.0},
            {"sla_status": "met", "severity_tier": "high", "fix_duration_hours": 10.0},
            {"sla_status": "met", "severity_tier": "high", "fix_duration_hours": 20.0},
        ]
        result = compute_sla_summary(issues)
        ttf = result["time_to_fix_by_severity"]["high"]
        assert ttf["median"] == 8.0

    def test_by_severity_breakdown(self):
        issues = [
            {"sla_status": "on-track", "severity_tier": "critical"},
            {"sla_status": "breached", "severity_tier": "critical"},
        ]
        result = compute_sla_summary(issues)
        assert result["by_severity"]["critical"]["on-track"] == 1
        assert result["by_severity"]["critical"]["breached"] == 1


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
