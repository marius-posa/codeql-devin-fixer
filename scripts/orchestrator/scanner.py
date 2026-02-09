"""Scan triggering and scheduling logic.

Handles determining which repos are due for scanning, triggering
CodeQL scans via GitHub Actions workflow dispatch, and adaptive
commit-velocity-based scheduling.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import datetime, timedelta, timezone
from typing import Any

from . import state as _state

from issue_tracking import _parse_ts  # noqa: E402
from github_utils import gh_headers, parse_repo_url  # noqa: E402

try:
    from retry_utils import request_with_retry  # noqa: E402
    _HAS_REQUESTS = True
except ImportError:
    _HAS_REQUESTS = False

SCHEDULE_INTERVALS: dict[str, timedelta] = {
    "hourly": timedelta(hours=1),
    "daily": timedelta(days=1),
    "weekly": timedelta(weeks=1),
    "biweekly": timedelta(weeks=2),
    "monthly": timedelta(days=30),
}


ADAPTIVE_COMMIT_THRESHOLD = 50


def _check_commit_velocity(
    repo_url: str,
    since_iso: str,
    github_token: str = "",
) -> int | None:
    """Return number of commits on the default branch since *since_iso*.

    Returns ``None`` if the API call fails or requests is unavailable.
    """
    if not _HAS_REQUESTS or not github_token:
        return None
    try:
        owner, repo = parse_repo_url(repo_url)
    except ValueError:
        return None
    api_url = f"https://api.github.com/repos/{owner}/{repo}/commits"
    params = {"since": since_iso, "per_page": "1"}
    try:
        resp = request_with_retry(
            "HEAD", api_url,
            headers=gh_headers(github_token),
            params=params,
            timeout=15,
        )
        if resp.status_code != 200:
            return None
        link = resp.headers.get("Link", "")
        if 'rel="last"' in link:
            import re as _re
            m = _re.search(r'[&?]page=(\d+)>;\s*rel="last"', link)
            if m:
                return int(m.group(1))
        return 1
    except Exception:
        return None


def _is_scan_due(
    repo_config: dict[str, Any],
    scan_schedule: dict[str, dict[str, Any]],
    github_token: str = "",
) -> bool:
    repo_url = repo_config.get("repo", "")
    if not repo_config.get("enabled", True):
        return False
    if not repo_config.get("auto_scan", True):
        return False

    schedule_name = repo_config.get("schedule", "weekly")
    interval = SCHEDULE_INTERVALS.get(schedule_name, timedelta(weeks=1))

    entry = scan_schedule.get(repo_url, {})
    last_scan_str = entry.get("last_scan", "")
    if not last_scan_str:
        return True

    last_scan = _parse_ts(last_scan_str)
    if last_scan is None:
        return True

    if datetime.now(timezone.utc) - last_scan >= interval:
        return True

    threshold = repo_config.get(
        "adaptive_commit_threshold", ADAPTIVE_COMMIT_THRESHOLD,
    )
    if threshold and github_token:
        commit_count = _check_commit_velocity(
            repo_url, last_scan_str, github_token,
        )
        if commit_count is not None and commit_count >= threshold:
            return True

    return False


def _resolve_target_repo(
    repo_url: str,
    github_token: str,
    action_repo: str,
) -> str:
    """Return *repo_url* if the token can access it, otherwise fall back to
    a same-named fork under the workflow owner's account.

    The workflow owner is derived from *action_repo* (e.g. ``user/codeql-devin-fixer``
    gives ``user``).  If a fork ``user/{repo_name}`` exists, its URL is returned
    so that downstream scans operate on a repo the token can actually reach.
    """
    try:
        owner, repo_name = parse_repo_url(repo_url)
    except ValueError:
        return repo_url

    headers = gh_headers(github_token)

    check = request_with_retry(
        "GET",
        f"https://api.github.com/repos/{owner}/{repo_name}",
        headers=headers,
        timeout=30,
    )
    if check.status_code == 200:
        return repo_url

    workflow_owner = action_repo.split("/")[0] if "/" in action_repo else ""
    if not workflow_owner or workflow_owner.lower() == owner.lower():
        return repo_url

    fork_check = request_with_retry(
        "GET",
        f"https://api.github.com/repos/{workflow_owner}/{repo_name}",
        headers=headers,
        timeout=30,
    )
    if fork_check.status_code == 200:
        fork_url = f"https://github.com/{workflow_owner}/{repo_name}"
        print(f"No access to {repo_url}, using fork: {fork_url}")
        return fork_url

    return repo_url


def _trigger_scan(
    repo_config: dict[str, Any],
    github_token: str,
    action_repo: str,
    dry_run: bool = False,
) -> dict[str, Any]:
    repo_url = repo_config.get("repo", "")
    if dry_run:
        return {"repo": repo_url, "status": "dry-run"}

    if not _HAS_REQUESTS:
        return {"repo": repo_url, "status": "error", "message": "requests library not available"}

    resolved_url = _resolve_target_repo(repo_url, github_token, action_repo)

    inputs = {
        "target_repo": resolved_url,
        "mode": "orchestrator",
        "severity_threshold": repo_config.get("severity_threshold", "low"),
        "dry_run": "false",
    }
    overrides = repo_config.get("overrides", {})
    if overrides.get("languages"):
        langs = overrides["languages"]
        inputs["languages"] = ",".join(langs) if isinstance(langs, list) else langs
    default_branch = repo_config.get("default_branch", "main")
    if default_branch:
        inputs["default_branch"] = default_branch

    url = f"https://api.github.com/repos/{action_repo}/actions/workflows/codeql-fixer.yml/dispatches"
    payload = {"ref": "main", "inputs": inputs}

    try:
        resp = request_with_retry(
            "POST", url, headers=gh_headers(github_token), json=payload, timeout=30,
        )
        if resp.status_code == 204:
            result: dict[str, Any] = {"repo": repo_url, "status": "triggered"}
            if resolved_url != repo_url:
                result["resolved_repo"] = resolved_url
            return result
        return {
            "repo": repo_url,
            "status": "error",
            "message": f"HTTP {resp.status_code}: {resp.text[:200]}",
        }
    except Exception as e:
        return {"repo": repo_url, "status": "error", "message": str(e)}


def cmd_scan(args: argparse.Namespace) -> int:
    repo_filter = args.repo or ""
    dry_run = args.dry_run
    output_json = args.json

    github_token = os.environ.get("GH_PAT", "") or os.environ.get("GITHUB_TOKEN", "")
    action_repo = os.environ.get("ACTION_REPO", "")

    if not github_token and not dry_run:
        print("ERROR: GH_PAT or GITHUB_TOKEN environment variable is required (use --dry-run to skip)", file=sys.stderr)
        return 1
    if not action_repo and not dry_run:
        print("ERROR: ACTION_REPO environment variable is required (use --dry-run to skip)", file=sys.stderr)
        return 1

    registry = _state.load_registry()
    state = _state.load_state()
    scan_schedule = state.get("scan_schedule", {})

    results: list[dict[str, Any]] = []
    for repo_entry in registry.get("repos", []):
        repo_url = repo_entry.get("repo", "")
        if repo_filter and repo_url != repo_filter:
            continue

        repo_config = _state.get_repo_config(registry, repo_url)
        if not _is_scan_due(repo_config, scan_schedule, github_token):
            results.append({"repo": repo_url, "status": "not_due"})
            continue

        result = _trigger_scan(repo_config, github_token, action_repo, dry_run)
        results.append(result)

        if result["status"] == "triggered":
            scan_schedule.setdefault(repo_url, {})
            scan_schedule[repo_url]["last_scan"] = datetime.now(timezone.utc).isoformat()
            if not output_json:
                print(f"Triggered scan for {repo_url}")
        elif result["status"] == "dry-run":
            if not output_json:
                print(f"[DRY RUN] Would trigger scan for {repo_url}")
        else:
            if not output_json:
                print(f"ERROR scanning {repo_url}: {result.get('message', '')}", file=sys.stderr)

    state["scan_schedule"] = scan_schedule
    _state.save_state(state)

    triggered = len([r for r in results if r["status"] == "triggered"])
    skipped = len([r for r in results if r["status"] == "not_due"])
    dry_run_count = len([r for r in results if r["status"] == "dry-run"])
    errors = len([r for r in results if r["status"] == "error"])

    summary = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "repo_filter": repo_filter,
        "dry_run": dry_run,
        "total_repos": len(results),
        "triggered": triggered,
        "skipped_not_due": skipped,
        "dry_run_count": dry_run_count,
        "errors": errors,
        "results": results,
    }

    if output_json:
        print(json.dumps(summary, indent=2))
    else:
        if not dry_run:
            print(f"\nScan summary: {triggered} triggered, {skipped} not due, {errors} errors")
        else:
            print(f"\n[DRY RUN] Scan summary: {dry_run_count} would trigger, {skipped} not due")

    return 1 if errors > 0 and triggered == 0 and dry_run_count == 0 else 0
