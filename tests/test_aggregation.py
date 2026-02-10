"""Tests for telemetry/aggregation.py -- compute_sla_summary with SLA edge cases."""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "telemetry"))

from aggregation import compute_sla_summary


class TestComputeSlaSummaryBasic:
    def test_empty_issues_list(self):
        result = compute_sla_summary([])
        assert result["by_status"] == {}
        assert result["by_severity"] == {}
        assert result["time_to_fix_by_severity"] == {}
        assert result["total_breached"] == 0
        assert result["total_at_risk"] == 0
        assert result["total_on_track"] == 0
        assert result["total_met"] == 0

    def test_single_on_track_issue(self):
        issues = [{"sla_status": "on-track", "severity_tier": "high"}]
        result = compute_sla_summary(issues)
        assert result["total_on_track"] == 1
        assert result["total_breached"] == 0
        assert result["by_status"]["on-track"] == 1
        assert result["by_severity"]["high"]["on-track"] == 1

    def test_single_breached_issue(self):
        issues = [{"sla_status": "breached", "severity_tier": "critical"}]
        result = compute_sla_summary(issues)
        assert result["total_breached"] == 1
        assert result["by_severity"]["critical"]["breached"] == 1

    def test_single_met_issue(self):
        issues = [{"sla_status": "met", "severity_tier": "low"}]
        result = compute_sla_summary(issues)
        assert result["total_met"] == 1

    def test_single_at_risk_issue(self):
        issues = [{"sla_status": "at-risk", "severity_tier": "medium"}]
        result = compute_sla_summary(issues)
        assert result["total_at_risk"] == 1
        assert result["by_severity"]["medium"]["at-risk"] == 1


class TestComputeSlaSummaryMultipleSeverities:
    def test_mixed_severities_and_statuses(self):
        issues = [
            {"sla_status": "on-track", "severity_tier": "critical"},
            {"sla_status": "breached", "severity_tier": "critical"},
            {"sla_status": "on-track", "severity_tier": "high"},
            {"sla_status": "at-risk", "severity_tier": "high"},
            {"sla_status": "met", "severity_tier": "medium"},
            {"sla_status": "on-track", "severity_tier": "low"},
        ]
        result = compute_sla_summary(issues)
        assert result["total_on_track"] == 3
        assert result["total_breached"] == 1
        assert result["total_at_risk"] == 1
        assert result["total_met"] == 1
        assert result["by_severity"]["critical"]["on-track"] == 1
        assert result["by_severity"]["critical"]["breached"] == 1
        assert result["by_severity"]["high"]["on-track"] == 1
        assert result["by_severity"]["high"]["at-risk"] == 1

    def test_all_severities_breached(self):
        issues = [
            {"sla_status": "breached", "severity_tier": "critical"},
            {"sla_status": "breached", "severity_tier": "high"},
            {"sla_status": "breached", "severity_tier": "medium"},
            {"sla_status": "breached", "severity_tier": "low"},
        ]
        result = compute_sla_summary(issues)
        assert result["total_breached"] == 4
        assert result["total_on_track"] == 0
        assert len(result["by_severity"]) == 4


class TestComputeSlaSummaryTimeToFix:
    def test_single_fix_duration(self):
        issues = [
            {"sla_status": "met", "severity_tier": "high", "fix_duration_hours": 10.0},
        ]
        result = compute_sla_summary(issues)
        ttf = result["time_to_fix_by_severity"]
        assert "high" in ttf
        assert ttf["high"]["count"] == 1
        assert ttf["high"]["min"] == 10.0
        assert ttf["high"]["max"] == 10.0
        assert ttf["high"]["avg"] == 10.0
        assert ttf["high"]["median"] == 10.0

    def test_multiple_fix_durations_same_severity(self):
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

    def test_even_count_median(self):
        issues = [
            {"sla_status": "met", "severity_tier": "medium", "fix_duration_hours": 2.0},
            {"sla_status": "met", "severity_tier": "medium", "fix_duration_hours": 8.0},
        ]
        result = compute_sla_summary(issues)
        ttf = result["time_to_fix_by_severity"]["medium"]
        assert ttf["count"] == 2
        assert ttf["median"] == 5.0

    def test_fix_durations_across_severities(self):
        issues = [
            {"sla_status": "met", "severity_tier": "critical", "fix_duration_hours": 3.0},
            {"sla_status": "met", "severity_tier": "high", "fix_duration_hours": 12.0},
            {"sla_status": "met", "severity_tier": "high", "fix_duration_hours": 24.0},
        ]
        result = compute_sla_summary(issues)
        ttf = result["time_to_fix_by_severity"]
        assert "critical" in ttf
        assert "high" in ttf
        assert ttf["critical"]["count"] == 1
        assert ttf["high"]["count"] == 2

    def test_no_fix_duration_excluded_from_ttf(self):
        issues = [
            {"sla_status": "on-track", "severity_tier": "high"},
            {"sla_status": "met", "severity_tier": "high", "fix_duration_hours": 10.0},
        ]
        result = compute_sla_summary(issues)
        ttf = result["time_to_fix_by_severity"]
        assert ttf["high"]["count"] == 1

    def test_none_fix_duration_excluded(self):
        issues = [
            {"sla_status": "met", "severity_tier": "low", "fix_duration_hours": None},
            {"sla_status": "met", "severity_tier": "low", "fix_duration_hours": 5.0},
        ]
        result = compute_sla_summary(issues)
        assert result["time_to_fix_by_severity"]["low"]["count"] == 1


class TestComputeSlaSummaryEdgeCases:
    def test_missing_sla_status_defaults_to_unknown(self):
        issues = [{"severity_tier": "high"}]
        result = compute_sla_summary(issues)
        assert result["by_status"].get("unknown", 0) == 1

    def test_missing_severity_tier_excluded_from_by_severity(self):
        issues = [{"sla_status": "on-track"}]
        result = compute_sla_summary(issues)
        assert result["by_severity"] == {}
        assert result["total_on_track"] == 1

    def test_empty_severity_tier_excluded(self):
        issues = [{"sla_status": "breached", "severity_tier": ""}]
        result = compute_sla_summary(issues)
        assert result["by_severity"] == {}
        assert result["total_breached"] == 1

    def test_uppercase_severity_normalized(self):
        issues = [{"sla_status": "on-track", "severity_tier": "HIGH"}]
        result = compute_sla_summary(issues)
        assert "high" in result["by_severity"]

    def test_mixed_case_severity_grouped(self):
        issues = [
            {"sla_status": "on-track", "severity_tier": "High"},
            {"sla_status": "breached", "severity_tier": "HIGH"},
            {"sla_status": "met", "severity_tier": "high"},
        ]
        result = compute_sla_summary(issues)
        assert len(result["by_severity"]) == 1
        assert "high" in result["by_severity"]
        high = result["by_severity"]["high"]
        assert high["on-track"] == 1
        assert high["breached"] == 1
        assert high["met"] == 1

    def test_fix_duration_with_missing_severity_excluded_from_ttf(self):
        issues = [
            {"sla_status": "met", "fix_duration_hours": 10.0},
        ]
        result = compute_sla_summary(issues)
        assert result["time_to_fix_by_severity"] == {}

    def test_fix_duration_zero(self):
        issues = [
            {"sla_status": "met", "severity_tier": "low", "fix_duration_hours": 0.0},
        ]
        result = compute_sla_summary(issues)
        assert result["time_to_fix_by_severity"]["low"]["min"] == 0.0

    def test_large_number_of_issues(self):
        issues = [
            {"sla_status": "on-track", "severity_tier": "medium", "fix_duration_hours": float(i)}
            for i in range(100)
        ]
        result = compute_sla_summary(issues)
        assert result["total_on_track"] == 100
        ttf = result["time_to_fix_by_severity"]["medium"]
        assert ttf["count"] == 100
        assert ttf["min"] == 0.0
        assert ttf["max"] == 99.0
