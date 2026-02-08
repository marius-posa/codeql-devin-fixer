"""Alert formatting and delivery for the CodeQL Devin Fixer orchestrator.

Sends notifications when important lifecycle events occur:

- **fix_verified** -- a critical/high issue was confirmed fixed by CodeQL re-analysis.
- **objective_met** -- all target issues for an orchestrator objective are resolved.
- **sla_breach** -- an issue has exceeded its SLA response window.
- **cycle_completed** -- an orchestrator cycle finished (scan + dispatch summary).

Alerts are delivered via two channels:

1. **Webhook events** (always, when ``WEBHOOK_URL`` is configured) -- uses the
   existing ``scripts/webhook.py`` infrastructure.
2. **GitHub Issues** (opt-in for high-severity verified fixes) -- creates an issue
   on the target repository using a GitHub App installation token.
"""

from __future__ import annotations

import logging
import os
import sys
import pathlib
from typing import Any

log = logging.getLogger(__name__)

_SCRIPTS_DIR = pathlib.Path(__file__).resolve().parent.parent / "scripts"
if str(_SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS_DIR))

from github_utils import gh_headers, parse_repo_url  # noqa: E402

try:
    from retry_utils import request_with_retry  # noqa: E402
    _HAS_REQUESTS = True
except ImportError:
    _HAS_REQUESTS = False

try:
    from webhook import send_webhook  # noqa: E402
    _HAS_WEBHOOK = True
except ImportError:
    _HAS_WEBHOOK = False


def _webhook_url() -> str:
    return os.environ.get("WEBHOOK_URL", "")


def _webhook_secret() -> str:
    return os.environ.get("WEBHOOK_SECRET", "")


def send_verified_fix_alert(
    issue: dict[str, Any],
    pr_url: str,
    verification_record: dict[str, Any],
    github_token: str = "",
    create_github_issue: bool = False,
) -> dict[str, Any]:
    """Notify that a security issue has been verified as fixed.

    Parameters
    ----------
    issue:
        Issue dict with at least ``rule_id``, ``severity_tier``, ``cwe_family``,
        ``file``, ``start_line``, and ``target_repo``.
    pr_url:
        URL of the PR that fixed the issue.
    verification_record:
        Verification summary dict (from ``verification.py``).
    github_token:
        GitHub token for creating an issue on the target repo (optional).
    create_github_issue:
        Whether to also create a GitHub Issue on the target repo.
    """
    result: dict[str, Any] = {"event": "fix_verified", "webhook": False, "github_issue": False}

    summary = verification_record.get("summary", verification_record)
    fix_rate = summary.get("fix_rate", 0)

    data = {
        "rule_id": issue.get("rule_id", ""),
        "severity_tier": issue.get("severity_tier", ""),
        "cwe_family": issue.get("cwe_family", ""),
        "file": issue.get("file", ""),
        "start_line": issue.get("start_line", 0),
        "target_repo": issue.get("target_repo", ""),
        "pr_url": pr_url,
        "fix_rate": fix_rate,
        "fingerprint": issue.get("fingerprint", ""),
    }

    url = _webhook_url()
    if url and _HAS_WEBHOOK:
        ok = send_webhook(url, "fix_verified", data, _webhook_secret())
        result["webhook"] = ok

    if create_github_issue and github_token and _HAS_REQUESTS:
        gh_result = _create_verified_fix_github_issue(issue, pr_url, summary, github_token)
        result["github_issue"] = gh_result.get("created", False)
        if gh_result.get("html_url"):
            result["github_issue_url"] = gh_result["html_url"]

    return result


def _create_verified_fix_github_issue(
    issue: dict[str, Any],
    pr_url: str,
    summary: dict[str, Any],
    github_token: str,
) -> dict[str, Any]:
    """Create a GitHub Issue on the target repo announcing a verified fix."""
    target_repo = issue.get("target_repo", "")
    if not target_repo:
        return {"created": False, "error": "no target_repo"}

    try:
        owner, repo = parse_repo_url(target_repo)
    except ValueError as e:
        log.warning("Cannot parse repo URL for alert: %s", e)
        return {"created": False, "error": str(e)}

    rule_id = issue.get("rule_id", "unknown")
    severity = issue.get("severity_tier", "unknown").upper()
    family = issue.get("cwe_family", "unknown")
    file_path = issue.get("file", "unknown")
    start_line = issue.get("start_line", 0)
    fix_rate = summary.get("fix_rate", 0)

    title = f"[CodeQL Fixer] Verified fix: {rule_id} ({severity})"
    body = (
        f"## Verified Security Fix\n\n"
        f"**Issue:** {rule_id} ({family})\n"
        f"**Severity:** {severity}\n"
        f"**File:** {file_path}:{start_line}\n"
        f"**PR:** {pr_url}\n"
        f"**Fix Rate:** {fix_rate}%\n\n"
        f"This issue has been verified as fixed by CodeQL re-analysis."
    )

    api_url = f"https://api.github.com/repos/{owner}/{repo}/issues"
    try:
        resp = request_with_retry(
            "POST", api_url,
            headers=gh_headers(github_token),
            json={"title": title, "body": body, "labels": ["security", "verified-fix"]},
            timeout=30,
        )
        if resp.status_code in (201, 200):
            data = resp.json()
            return {"created": True, "html_url": data.get("html_url", "")}
        log.warning("GitHub Issue creation returned %d: %s", resp.status_code, resp.text[:200])
        return {"created": False, "error": f"HTTP {resp.status_code}"}
    except Exception as e:
        log.warning("Failed to create GitHub Issue: %s", e)
        return {"created": False, "error": str(e)}


def send_objective_met_alert(
    objective: dict[str, Any],
    target_repo: str = "",
    github_token: str = "",
) -> dict[str, Any]:
    """Notify that an orchestrator objective has been met."""
    result: dict[str, Any] = {"event": "objective_met", "webhook": False}

    data = {
        "objective": objective.get("objective", objective.get("name", "")),
        "description": objective.get("description", ""),
        "target_severity": objective.get("target_severity", ""),
        "current_count": objective.get("current_count", 0),
        "target_count": objective.get("target_count", 0),
        "target_repo": target_repo,
    }

    url = _webhook_url()
    if url and _HAS_WEBHOOK:
        ok = send_webhook(url, "objective_met", data, _webhook_secret())
        result["webhook"] = ok

    return result


def send_sla_breach_alert(
    issue: dict[str, Any],
    target_repo: str = "",
) -> dict[str, Any]:
    """Notify that an issue has breached its SLA."""
    result: dict[str, Any] = {"event": "sla_breach", "webhook": False}

    data = {
        "rule_id": issue.get("rule_id", ""),
        "severity_tier": issue.get("severity_tier", ""),
        "cwe_family": issue.get("cwe_family", ""),
        "file": issue.get("file", ""),
        "start_line": issue.get("start_line", 0),
        "fingerprint": issue.get("fingerprint", ""),
        "target_repo": target_repo or issue.get("target_repo", ""),
        "sla_status": issue.get("sla_status", "breached"),
    }

    url = _webhook_url()
    if url and _HAS_WEBHOOK:
        ok = send_webhook(url, "sla_breach", data, _webhook_secret())
        result["webhook"] = ok

    return result


def send_cycle_summary_alert(
    cycle_results: dict[str, Any],
) -> dict[str, Any]:
    """Send a summary of the orchestrator cycle."""
    result: dict[str, Any] = {"event": "cycle_completed", "webhook": False}

    scan_data = cycle_results.get("scan", {}) or {}
    dispatch_data = cycle_results.get("dispatch", {}) or {}
    alerts_data = cycle_results.get("alerts", {}) or {}

    data = {
        "scans_triggered": scan_data.get("triggered", 0) if isinstance(scan_data, dict) else 0,
        "sessions_created": dispatch_data.get("sessions_created", 0) if isinstance(dispatch_data, dict) else 0,
        "sessions_failed": dispatch_data.get("sessions_failed", 0) if isinstance(dispatch_data, dict) else 0,
        "verified_fixes_found": alerts_data.get("verified_fixes_alerted", 0),
        "objectives_met": alerts_data.get("objectives_newly_met", 0),
        "sla_breaches": alerts_data.get("sla_breaches_alerted", 0),
        "dry_run": cycle_results.get("dry_run", False),
    }

    url = _webhook_url()
    if url and _HAS_WEBHOOK:
        ok = send_webhook(url, "cycle_completed", data, _webhook_secret())
        result["webhook"] = ok

    return result


def process_cycle_alerts(
    all_issues: list[dict[str, Any]],
    fp_fix_map: dict[str, dict[str, Any]],
    objectives: list[dict[str, Any]],
    previous_objective_progress: list[dict[str, Any]],
    alert_config: dict[str, Any],
    github_token: str = "",
) -> dict[str, Any]:
    """Process all alerts that should fire after a cycle.

    Parameters
    ----------
    all_issues:
        Full list of issues with ``derived_state`` already set.
    fp_fix_map:
        Fingerprint -> fix attribution mapping from verification records.
    objectives:
        Current objective progress dicts (with ``met`` field).
    previous_objective_progress:
        Objective progress from the previous cycle (to detect newly met).
    alert_config:
        Registry ``orchestrator`` section with ``alert_on_verified_fix``,
        ``alert_severities``, etc.
    github_token:
        GitHub token for creating issues (optional).
    """
    results: dict[str, Any] = {
        "verified_fixes_alerted": 0,
        "objectives_newly_met": 0,
        "sla_breaches_alerted": 0,
        "alerts": [],
    }

    alert_on_fix = alert_config.get("alert_on_verified_fix", False)
    alert_severities = set(alert_config.get("alert_severities", ["critical", "high"]))

    if alert_on_fix:
        for issue in all_issues:
            fp = issue.get("fingerprint", "")
            if fp not in fp_fix_map:
                continue
            severity = issue.get("severity_tier", "")
            if severity not in alert_severities:
                continue

            fix_info = fp_fix_map[fp]
            pr_url = fix_info.get("fixed_by_pr", "")
            alert_result = send_verified_fix_alert(
                issue, pr_url, fix_info,
                github_token=github_token,
                create_github_issue=True,
            )
            results["verified_fixes_alerted"] += 1
            results["alerts"].append(alert_result)

    prev_met = {
        p.get("objective", p.get("name", "")): p.get("met", False)
        for p in previous_objective_progress
    }
    for obj in objectives:
        obj_name = obj.get("objective", obj.get("name", ""))
        if obj.get("met") and not prev_met.get(obj_name, False):
            alert_result = send_objective_met_alert(obj, github_token=github_token)
            results["objectives_newly_met"] += 1
            results["alerts"].append(alert_result)

    for issue in all_issues:
        if issue.get("sla_status") == "breached":
            severity = issue.get("severity_tier", "")
            if severity in alert_severities:
                alert_result = send_sla_breach_alert(issue)
                results["sla_breaches_alerted"] += 1
                results["alerts"].append(alert_result)

    return results
