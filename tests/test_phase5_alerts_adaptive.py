"""Unit tests for Phase 5: GitHub App alerts and adaptive features.

Covers:
- github_app/alerts.py: alert formatting and delivery
- Cooldown logic in orchestrator.py
- Adaptive scan frequency in orchestrator.py
- Fix pattern collection in orchestrator.py
- Webhook handler registry update
"""

import json
import os
import sys
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "telemetry"))

from scripts.orchestrator import (
    _cooldown_remaining_hours,
    should_skip_issue,
    _is_scan_due,
    _check_commit_velocity,
    _collect_fix_examples,
    COOLDOWN_HOURS,
    ADAPTIVE_COMMIT_THRESHOLD,
)
from scripts.fix_learning import FixLearning
from github_app.alerts import (
    send_verified_fix_alert,
    send_objective_met_alert,
    send_sla_breach_alert,
    send_cycle_summary_alert,
    process_cycle_alerts,
)
from github_app.webhook_handler import _update_registry_installation_id


class TestCooldownRemainingHours:
    def test_no_failures_returns_zero(self):
        history = {"consecutive_failures": 0}
        assert _cooldown_remaining_hours(history) == 0.0

    def test_missing_failures_returns_zero(self):
        history = {}
        assert _cooldown_remaining_hours(history) == 0.0

    def test_no_last_dispatched_returns_zero(self):
        history = {"consecutive_failures": 1}
        assert _cooldown_remaining_hours(history) == 0.0

    def test_first_failure_24h_cooldown(self):
        now = datetime.now(timezone.utc)
        one_hour_ago = (now - timedelta(hours=1)).isoformat()
        history = {"consecutive_failures": 1, "last_dispatched": one_hour_ago}
        remaining = _cooldown_remaining_hours(history)
        assert 22 < remaining < 24

    def test_second_failure_72h_cooldown(self):
        now = datetime.now(timezone.utc)
        one_hour_ago = (now - timedelta(hours=1)).isoformat()
        history = {"consecutive_failures": 2, "last_dispatched": one_hour_ago}
        remaining = _cooldown_remaining_hours(history)
        assert 70 < remaining < 72

    def test_third_failure_168h_cooldown(self):
        now = datetime.now(timezone.utc)
        one_hour_ago = (now - timedelta(hours=1)).isoformat()
        history = {"consecutive_failures": 3, "last_dispatched": one_hour_ago}
        remaining = _cooldown_remaining_hours(history)
        assert 166 < remaining < 168

    def test_beyond_schedule_uses_last_entry(self):
        now = datetime.now(timezone.utc)
        one_hour_ago = (now - timedelta(hours=1)).isoformat()
        history = {"consecutive_failures": 10, "last_dispatched": one_hour_ago}
        remaining = _cooldown_remaining_hours(history)
        assert 166 < remaining < 168

    def test_cooldown_elapsed_returns_zero(self):
        now = datetime.now(timezone.utc)
        long_ago = (now - timedelta(hours=200)).isoformat()
        history = {"consecutive_failures": 1, "last_dispatched": long_ago}
        assert _cooldown_remaining_hours(history) == 0.0

    def test_custom_schedule(self):
        now = datetime.now(timezone.utc)
        one_hour_ago = (now - timedelta(hours=1)).isoformat()
        history = {"consecutive_failures": 1, "last_dispatched": one_hour_ago}
        remaining = _cooldown_remaining_hours(history, cooldown_schedule=[48])
        assert 46 < remaining < 48


class TestShouldSkipIssueCooldown:
    def _fl(self):
        return FixLearning(runs=[])

    def test_cooldown_active_skips(self):
        now = datetime.now(timezone.utc)
        one_hour_ago = (now - timedelta(hours=1)).isoformat()
        issue = {"fingerprint": "fp1", "severity_tier": "high", "cwe_family": "injection"}
        history = {
            "fp1": {
                "dispatch_count": 1,
                "consecutive_failures": 1,
                "last_dispatched": one_hour_ago,
            }
        }
        skip, reason = should_skip_issue(issue, "new", history, self._fl())
        assert skip is True
        assert "cooldown_active" in reason

    def test_cooldown_elapsed_allows(self):
        now = datetime.now(timezone.utc)
        long_ago = (now - timedelta(hours=200)).isoformat()
        issue = {"fingerprint": "fp1", "severity_tier": "high", "cwe_family": "injection"}
        history = {
            "fp1": {
                "dispatch_count": 1,
                "consecutive_failures": 1,
                "last_dispatched": long_ago,
            }
        }
        skip, reason = should_skip_issue(issue, "new", history, self._fl())
        assert skip is False

    def test_needs_human_review_after_many_failures(self):
        now = datetime.now(timezone.utc)
        long_ago = (now - timedelta(hours=200)).isoformat()
        issue = {"fingerprint": "fp1", "severity_tier": "high", "cwe_family": "injection"}
        history = {
            "fp1": {
                "dispatch_count": 2,
                "consecutive_failures": 4,
                "last_dispatched": long_ago,
            }
        }
        skip, reason = should_skip_issue(issue, "new", history, self._fl())
        assert skip is True
        assert "needs_human_review" in reason


class TestAdaptiveScanFrequency:
    def test_scan_due_by_schedule(self):
        repo_config = {
            "repo": "https://github.com/owner/repo",
            "enabled": True,
            "auto_scan": True,
            "schedule": "weekly",
        }
        old = (datetime.now(timezone.utc) - timedelta(days=8)).isoformat()
        schedule = {"https://github.com/owner/repo": {"last_scan": old}}
        assert _is_scan_due(repo_config, schedule) is True

    def test_scan_not_due_by_schedule(self):
        repo_config = {
            "repo": "https://github.com/owner/repo",
            "enabled": True,
            "auto_scan": True,
            "schedule": "weekly",
        }
        recent = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat()
        schedule = {"https://github.com/owner/repo": {"last_scan": recent}}
        assert _is_scan_due(repo_config, schedule) is False

    def test_disabled_repo_never_due(self):
        repo_config = {
            "repo": "https://github.com/owner/repo",
            "enabled": False,
            "auto_scan": True,
            "schedule": "weekly",
        }
        assert _is_scan_due(repo_config, {}) is False

    def test_no_auto_scan_never_due(self):
        repo_config = {
            "repo": "https://github.com/owner/repo",
            "enabled": True,
            "auto_scan": False,
            "schedule": "weekly",
        }
        assert _is_scan_due(repo_config, {}) is False

    def test_no_last_scan_always_due(self):
        repo_config = {
            "repo": "https://github.com/owner/repo",
            "enabled": True,
            "auto_scan": True,
            "schedule": "weekly",
        }
        assert _is_scan_due(repo_config, {}) is True

    @patch("scripts.orchestrator._check_commit_velocity", return_value=60)
    def test_adaptive_scan_high_velocity(self, mock_velocity):
        repo_config = {
            "repo": "https://github.com/owner/repo",
            "enabled": True,
            "auto_scan": True,
            "schedule": "weekly",
        }
        recent = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat()
        schedule = {"https://github.com/owner/repo": {"last_scan": recent}}
        assert _is_scan_due(repo_config, schedule, "token") is True

    @patch("scripts.orchestrator._check_commit_velocity", return_value=10)
    def test_adaptive_scan_low_velocity(self, mock_velocity):
        repo_config = {
            "repo": "https://github.com/owner/repo",
            "enabled": True,
            "auto_scan": True,
            "schedule": "weekly",
        }
        recent = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat()
        schedule = {"https://github.com/owner/repo": {"last_scan": recent}}
        assert _is_scan_due(repo_config, schedule, "token") is False


class TestCheckCommitVelocity:
    def test_returns_none_without_token(self):
        assert _check_commit_velocity("https://github.com/o/r", "2026-01-01", "") is None

    @patch("scripts.orchestrator._HAS_REQUESTS", False)
    def test_returns_none_without_requests(self):
        assert _check_commit_velocity("https://github.com/o/r", "2026-01-01", "tok") is None

    def test_returns_none_for_invalid_url(self):
        assert _check_commit_velocity("not-a-url", "2026-01-01", "tok") is None


class TestSendVerifiedFixAlert:
    def test_returns_event_info(self):
        issue = {
            "rule_id": "js/sql-injection",
            "severity_tier": "high",
            "cwe_family": "injection",
            "file": "src/db.js",
            "start_line": 42,
            "target_repo": "https://github.com/owner/repo",
            "fingerprint": "fp1",
        }
        result = send_verified_fix_alert(issue, "https://github.com/owner/repo/pull/1", {})
        assert result["event"] == "fix_verified"
        assert isinstance(result["webhook"], bool)

    @patch("github_app.alerts.send_webhook", return_value=True)
    def test_sends_webhook(self, mock_wh):
        issue = {
            "rule_id": "js/sql-injection",
            "severity_tier": "high",
            "cwe_family": "injection",
            "file": "src/db.js",
            "start_line": 42,
            "target_repo": "https://github.com/owner/repo",
            "fingerprint": "fp1",
        }
        with patch("github_app.alerts._webhook_url", return_value="http://hook.test"):
            result = send_verified_fix_alert(issue, "pr_url", {"summary": {"fix_rate": 90}})
        assert result["webhook"] is True


class TestSendObjectiveMetAlert:
    def test_returns_event_info(self):
        obj = {"objective": "zero-critical", "description": "No critical issues"}
        result = send_objective_met_alert(obj)
        assert result["event"] == "objective_met"

    @patch("github_app.alerts.send_webhook", return_value=True)
    def test_sends_webhook(self, mock_wh):
        obj = {"objective": "zero-critical"}
        with patch("github_app.alerts._webhook_url", return_value="http://hook.test"):
            result = send_objective_met_alert(obj)
        assert result["webhook"] is True


class TestSendSlaBreachAlert:
    def test_returns_event_info(self):
        issue = {
            "rule_id": "js/xss",
            "severity_tier": "high",
            "cwe_family": "xss",
            "file": "src/view.js",
            "start_line": 10,
            "fingerprint": "fp2",
            "sla_status": "breached",
        }
        result = send_sla_breach_alert(issue)
        assert result["event"] == "sla_breach"


class TestSendCycleSummaryAlert:
    def test_returns_event_info(self):
        cycle = {
            "scan": {"triggered": 2},
            "dispatch": {"sessions_created": 1, "sessions_failed": 0},
            "alerts": {"verified_fixes_alerted": 0, "objectives_newly_met": 0, "sla_breaches_alerted": 0},
            "dry_run": False,
        }
        result = send_cycle_summary_alert(cycle)
        assert result["event"] == "cycle_completed"

    def test_handles_none_sub_dicts(self):
        cycle = {"scan": None, "dispatch": None, "alerts": None, "dry_run": True}
        result = send_cycle_summary_alert(cycle)
        assert result["event"] == "cycle_completed"


class TestProcessCycleAlerts:
    def test_no_alerts_when_disabled(self):
        result = process_cycle_alerts(
            all_issues=[], fp_fix_map={}, objectives=[],
            previous_objective_progress=[], alert_config={"alert_on_verified_fix": False},
        )
        assert result["verified_fixes_alerted"] == 0
        assert result["objectives_newly_met"] == 0

    def test_detects_newly_met_objective(self):
        current = [{"objective": "zero-critical", "met": True}]
        previous = [{"objective": "zero-critical", "met": False}]
        result = process_cycle_alerts(
            all_issues=[], fp_fix_map={}, objectives=current,
            previous_objective_progress=previous,
            alert_config={"alert_on_verified_fix": False},
        )
        assert result["objectives_newly_met"] == 1

    def test_no_alert_for_already_met_objective(self):
        current = [{"objective": "zero-critical", "met": True}]
        previous = [{"objective": "zero-critical", "met": True}]
        result = process_cycle_alerts(
            all_issues=[], fp_fix_map={}, objectives=current,
            previous_objective_progress=previous,
            alert_config={"alert_on_verified_fix": False},
        )
        assert result["objectives_newly_met"] == 0

    def test_sla_breach_alert(self):
        issues = [{
            "fingerprint": "fp1",
            "severity_tier": "high",
            "cwe_family": "injection",
            "sla_status": "breached",
            "rule_id": "js/sql-injection",
            "file": "src/db.js",
            "start_line": 42,
        }]
        result = process_cycle_alerts(
            all_issues=issues, fp_fix_map={}, objectives=[],
            previous_objective_progress=[],
            alert_config={"alert_on_verified_fix": False, "alert_severities": ["critical", "high"]},
        )
        assert result["sla_breaches_alerted"] == 1

    def test_sla_breach_not_alerted_for_low_severity(self):
        issues = [{
            "fingerprint": "fp1",
            "severity_tier": "low",
            "cwe_family": "other",
            "sla_status": "breached",
            "rule_id": "js/info-leak",
            "file": "src/util.js",
            "start_line": 5,
        }]
        result = process_cycle_alerts(
            all_issues=issues, fp_fix_map={}, objectives=[],
            previous_objective_progress=[],
            alert_config={"alert_on_verified_fix": False, "alert_severities": ["critical", "high"]},
        )
        assert result["sla_breaches_alerted"] == 0


class TestUpdateRegistryInstallationId:
    def test_updates_matching_repo(self, tmp_path):
        registry = {
            "version": "2.0",
            "repos": [
                {"repo": "https://github.com/org/repo1"},
                {"repo": "https://github.com/org/repo2"},
            ],
        }
        reg_path = tmp_path / "repo_registry.json"
        reg_path.write_text(json.dumps(registry))

        with patch("github_app.webhook_handler.REGISTRY_PATH", reg_path):
            _update_registry_installation_id(42, ["org/repo1"])

        updated = json.loads(reg_path.read_text())
        assert updated["repos"][0]["installation_id"] == 42
        assert "installation_id" not in updated["repos"][1]

    def test_no_change_for_unknown_repo(self, tmp_path):
        registry = {
            "version": "2.0",
            "repos": [{"repo": "https://github.com/org/repo1"}],
        }
        reg_path = tmp_path / "repo_registry.json"
        reg_path.write_text(json.dumps(registry))

        with patch("github_app.webhook_handler.REGISTRY_PATH", reg_path):
            _update_registry_installation_id(42, ["org/unknown"])

        updated = json.loads(reg_path.read_text())
        assert "installation_id" not in updated["repos"][0]

    def test_no_crash_if_registry_missing(self, tmp_path):
        missing = tmp_path / "missing_registry.json"
        with patch("github_app.webhook_handler.REGISTRY_PATH", missing):
            _update_registry_installation_id(42, ["org/repo1"])

    def test_handles_empty_args(self):
        _update_registry_installation_id(None, [])
        _update_registry_installation_id(42, [])
        _update_registry_installation_id(None, ["org/repo"])


class TestCollectFixExamples:
    def test_returns_empty_without_token(self):
        assert _collect_fix_examples([], {}, "") == []

    def test_returns_empty_without_matching_prs(self):
        fp_fix_map = {"fp1": {"fixed_by_pr": "https://github.com/o/r/pull/1"}}
        prs = [{"html_url": "https://github.com/o/r/pull/2", "merged": True}]
        result = _collect_fix_examples(prs, fp_fix_map, "token")
        assert result == []


class TestCooldownConstants:
    def test_cooldown_schedule_has_entries(self):
        assert len(COOLDOWN_HOURS) >= 3

    def test_cooldown_increasing(self):
        for i in range(len(COOLDOWN_HOURS) - 1):
            assert COOLDOWN_HOURS[i] < COOLDOWN_HOURS[i + 1]

    def test_adaptive_threshold_positive(self):
        assert ADAPTIVE_COMMIT_THRESHOLD > 0
