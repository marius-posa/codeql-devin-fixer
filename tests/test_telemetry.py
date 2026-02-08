"""Unit tests for telemetry modules.

Covers: aggregation.py (compute_sla_summary),
issue_tracking.py (compute_sla_status, _parse_ts).
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "telemetry"))

from datetime import datetime, timezone

from aggregation import compute_sla_summary
from issue_tracking import _parse_ts, compute_sla_status, DEFAULT_SLA_HOURS


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
