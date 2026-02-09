"""CLI argument parsing, command routing, and output formatting.

Contains the ``main()`` entry point, argparse setup for all sub-commands,
the ``cmd_plan``, ``cmd_status``, and ``cmd_cycle`` commands, and the
human-readable print helpers.
"""

from __future__ import annotations

import argparse
import io
import json
import logging
import os
import sys
from contextlib import redirect_stdout
from datetime import datetime, timezone
from typing import Any

from . import state as _state
from . import alerts as _alerts
from .scanner import cmd_scan
from .dispatcher import cmd_dispatch, cmd_ingest, _collect_fix_examples

try:
    from logging_config import setup_logging
except ImportError:
    from scripts.logging_config import setup_logging

logger = setup_logging(__name__)


def cmd_plan(args: argparse.Namespace) -> int:
    repo_filter = args.repo or ""
    output_json = args.json

    data = _state._compute_eligible_issues(repo_filter)
    eligible = data["eligible"]
    skipped = data["skipped"]
    all_issues = data["all_issues"]
    rate_limiter = data["rate_limiter"]
    objectives = data["objectives"]
    registry = data["registry"]
    global_limit = data["global_limit"]
    remaining_capacity = data["remaining_capacity"]

    plan_batches: list[dict[str, Any]] = []
    sessions_planned = 0

    repos_seen: dict[str, int] = {}
    for issue in eligible:
        if sessions_planned >= remaining_capacity:
            break
        repo_url = issue.get("target_repo", "")
        repo_config = _state.get_repo_config(registry, repo_url)
        repo_limit = repo_config.get("max_sessions_per_cycle", 5)
        repo_sessions = repos_seen.get(repo_url, 0)
        if repo_sessions >= repo_limit:
            continue

        plan_batches.append({
            "fingerprint": issue.get("fingerprint", ""),
            "priority_score": issue.get("priority_score", 0),
            **_state._issue_summary(issue),
        })
        repos_seen[repo_url] = repo_sessions + 1
        sessions_planned += 1

    plan = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "repo_filter": repo_filter,
        "total_issues": len(all_issues),
        "eligible_issues": len(eligible),
        "skipped_issues": len(skipped),
        "sessions_planned": sessions_planned,
        "rate_limit_remaining": remaining_capacity,
        "rate_limit_max": global_limit,
        "rate_limit_period_hours": rate_limiter.period_hours,
        "planned_dispatches": plan_batches,
        "skipped": skipped,
        "objective_progress": [
            obj.progress(all_issues) for obj in objectives
        ],
    }

    if output_json:
        print(json.dumps(plan, indent=2))
    else:
        _print_plan(plan)

    return 0


def cmd_status(args: argparse.Namespace) -> int:
    repo_filter = args.repo or ""
    output_json = args.json

    registry = _state.load_registry()
    orch_config = registry.get("orchestrator", {})
    state = _state.load_state()

    objectives = [
        _state.Objective.from_dict(o) for o in orch_config.get("objectives", [])
    ]

    rate_limiter = _state.RateLimiter.from_dict(
        {**state.get("rate_limiter", {}),
         "max_sessions": orch_config.get("global_session_limit", 20),
         "period_hours": orch_config.get("global_session_limit_period_hours", 24)}
    )

    global_state = _state.build_global_issue_state(repo_filter)
    issues = global_state["issues"]
    sessions = global_state["sessions"]
    prs = global_state["prs"]

    state_counts: dict[str, int] = {}
    for issue in issues:
        derived = issue.get("derived_state", issue.get("status", "new"))
        state_counts[derived] = state_counts.get(derived, 0) + 1

    session_status_counts: dict[str, int] = {}
    for s in sessions:
        st = s.get("status", "unknown")
        session_status_counts[st] = session_status_counts.get(st, 0) + 1

    repos: dict[str, dict[str, int]] = {}
    for issue in issues:
        repo_url = issue.get("target_repo", "")
        if repo_url not in repos:
            repos[repo_url] = {"total": 0, "new": 0, "recurring": 0, "fixed": 0, "verified_fixed": 0}
        repos[repo_url]["total"] += 1
        derived = issue.get("derived_state", issue.get("status", "new"))
        if derived in repos[repo_url]:
            repos[repo_url][derived] += 1

    dispatch_history = state.get("dispatch_history", {})

    status_data = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "repo_filter": repo_filter,
        "issue_state_breakdown": state_counts,
        "total_issues": len(issues),
        "session_status_breakdown": session_status_counts,
        "total_sessions": len(sessions),
        "total_prs": len(prs),
        "prs_merged": sum(1 for p in prs if p.get("merged")),
        "prs_open": sum(1 for p in prs if p.get("state") == "open" and not p.get("merged")),
        "rate_limit": {
            "used": rate_limiter.recent_count(),
            "max": rate_limiter.max_sessions,
            "remaining": rate_limiter.max_sessions - rate_limiter.recent_count(),
            "period_hours": rate_limiter.period_hours,
        },
        "dispatch_history_entries": len(dispatch_history),
        "last_cycle": state.get("last_cycle"),
        "repos": repos,
        "objective_progress": [
            obj.progress(issues) for obj in objectives
        ],
    }

    if output_json:
        print(json.dumps(status_data, indent=2))
    else:
        _print_status(status_data)

    return 0


def cmd_cycle(args: argparse.Namespace) -> int:
    """Full orchestrator cycle: scan due repos, update state, dispatch, alert."""
    repo_filter = args.repo or ""
    dry_run = args.dry_run
    output_json = args.json

    now = datetime.now(timezone.utc).isoformat()
    cycle_results: dict[str, Any] = {
        "timestamp": now,
        "repo_filter": repo_filter,
        "dry_run": dry_run,
        "scan": None,
        "dispatch": None,
        "alerts": None,
        "fix_examples_collected": 0,
    }

    scan_args = argparse.Namespace(
        repo=repo_filter,
        dry_run=dry_run,
        json=True,
    )
    if not output_json:
        logger.info("=" * 60)
        logger.info("ORCHESTRATOR CYCLE")
        logger.info("=" * 60)
        logger.info("Started: %s", now)
        logger.info("")
        logger.info("--- Phase 1: Scanning ---")

    scan_buf = io.StringIO()
    with redirect_stdout(scan_buf):
        scan_exit = cmd_scan(scan_args)
    scan_output = scan_buf.getvalue().strip()
    try:
        cycle_results["scan"] = json.loads(scan_output)
    except (json.JSONDecodeError, ValueError):
        cycle_results["scan"] = {"raw": scan_output, "exit_code": scan_exit}

    if not output_json:
        scan_data = cycle_results["scan"]
        if isinstance(scan_data, dict) and "triggered" in scan_data:
            logger.info("  Scans triggered: %d", scan_data.get('triggered', 0))
            logger.info("  Repos not due: %d", scan_data.get('skipped_not_due', 0))
            if scan_data.get("errors"):
                logger.info("  Errors: %s", scan_data['errors'])
        logger.info("")
        logger.info("--- Phase 2: Dispatching ---")

    dispatch_args = argparse.Namespace(
        repo=repo_filter,
        dry_run=dry_run,
        json=True,
        max_sessions=getattr(args, "max_sessions", None),
    )

    dispatch_buf = io.StringIO()
    with redirect_stdout(dispatch_buf):
        dispatch_exit = cmd_dispatch(dispatch_args)
    dispatch_output = dispatch_buf.getvalue().strip()
    try:
        cycle_results["dispatch"] = json.loads(dispatch_output)
    except (json.JSONDecodeError, ValueError):
        cycle_results["dispatch"] = {"raw": dispatch_output, "exit_code": dispatch_exit}

    if not output_json:
        dispatch_data = cycle_results["dispatch"]
        if isinstance(dispatch_data, dict) and "sessions_created" in dispatch_data:
            logger.info("  Sessions created: %d", dispatch_data.get('sessions_created', 0))
            if dispatch_data.get("sessions_failed"):
                logger.info("  Sessions failed: %s", dispatch_data['sessions_failed'])
            logger.info("  Rate limit remaining: %s", dispatch_data.get('rate_limit_remaining', '?'))
        elif isinstance(dispatch_data, dict) and "status" in dispatch_data:
            logger.info("  %s", dispatch_data.get('message', dispatch_data.get('status', '')))
        logger.info("")
        logger.info("--- Phase 3: Alerts & Learning ---")

    registry = _state.load_registry()
    orch_config = registry.get("orchestrator", {})
    state = _state.load_state()

    global_state = _state.build_global_issue_state(repo_filter)
    all_issues = global_state["issues"]
    fp_fix_map = global_state["fp_fix_map"]
    prs = global_state["prs"]

    objectives = [_state.Objective.from_dict(o) for o in orch_config.get("objectives", [])]
    current_progress = [obj.progress(all_issues) for obj in objectives]
    previous_progress = state.get("objective_progress", [])

    github_token = os.environ.get("GITHUB_TOKEN", "")

    cycle_results["alerts"] = _alerts.process_cycle_alerts(
        all_issues, fp_fix_map, current_progress, previous_progress,
        orch_config, github_token, dry_run=dry_run,
    )

    if github_token and not dry_run:
        examples = _collect_fix_examples(prs, fp_fix_map, github_token)
        cycle_results["fix_examples_collected"] = len(examples)
        if examples:
            fix_examples_path = _state.RUNS_DIR / "fix_examples.json"
            existing: list[dict[str, Any]] = []
            if fix_examples_path.exists():
                try:
                    with open(fix_examples_path) as f:
                        existing = json.load(f)
                except (json.JSONDecodeError, OSError):
                    pass
            existing_urls = {e.get("pr_url") for e in existing}
            for ex in examples:
                if ex["pr_url"] not in existing_urls:
                    existing.append(ex)
            with open(fix_examples_path, "w") as f:
                json.dump(existing, f, indent=2)
                f.write("\n")

    state["last_cycle"] = now
    state["objective_progress"] = current_progress
    _state.save_state(state)

    _alerts.send_cycle_summary(cycle_results, dry_run=dry_run)

    if not output_json:
        alerts_data = cycle_results.get("alerts") or {}
        if isinstance(alerts_data, dict) and not alerts_data.get("dry_run"):
            vf = alerts_data.get("verified_fixes_alerted", 0)
            om = alerts_data.get("objectives_newly_met", 0)
            sb = alerts_data.get("sla_breaches_alerted", 0)
            logger.info("  Verified fix alerts: %d", vf)
            logger.info("  Objectives newly met: %d", om)
            logger.info("  SLA breach alerts: %d", sb)
        fe = cycle_results.get("fix_examples_collected", 0)
        if fe:
            logger.info("  Fix examples collected: %d", fe)
        logger.info("")
        logger.info("Cycle complete.")
    else:
        print(json.dumps(cycle_results, indent=2))

    return 0


def _print_plan(plan: dict[str, Any]) -> None:
    logger.info("=" * 60)
    logger.info("ORCHESTRATOR DISPATCH PLAN")
    logger.info("=" * 60)
    logger.info("Generated: %s", plan['timestamp'])
    if plan["repo_filter"]:
        logger.info("Filter: %s", plan['repo_filter'])
    logger.info("")
    logger.info("Total issues in DB:    %d", plan['total_issues'])
    logger.info("Eligible for dispatch: %d", plan['eligible_issues'])
    logger.info("Skipped:               %d", plan['skipped_issues'])
    logger.info("Sessions planned:      %d", plan['sessions_planned'])
    logger.info("Rate limit:            %d/%d remaining (%dh window)",
                plan['rate_limit_remaining'], plan['rate_limit_max'],
                plan['rate_limit_period_hours'])
    logger.info("")

    if plan["objective_progress"]:
        logger.info("--- Objective Progress ---")
        for obj in plan["objective_progress"]:
            status = "MET" if obj["met"] else "IN PROGRESS"
            logger.info("  %s: %d issues (%s, target: %d)",
                        obj['objective'], obj['current_count'], status, obj['target_count'])
        logger.info("")

    if plan["planned_dispatches"]:
        logger.info("--- Planned Dispatches ---")
        logger.info("%-4s %-8s %-10s %-20s %-40s %s", "#", "Score", "Severity", "Family", "Repo", "File")
        logger.info("-" * 120)
        for i, d in enumerate(plan["planned_dispatches"], 1):
            repo_short = d.get("target_repo", "")
            if "github.com/" in repo_short:
                repo_short = repo_short.split("github.com/")[-1]
            logger.info(
                "%-4d %-8.4f %-10s %-20s %-40s %s",
                i, d.get('priority_score', 0),
                d.get('severity_tier', ''),
                d.get('cwe_family', ''),
                repo_short,
                d.get('file', ''),
            )
    else:
        logger.info("No dispatches planned.")

    if plan["skipped"]:
        reasons: dict[str, int] = {}
        for s in plan["skipped"]:
            r = s.get("reason", "unknown")
            reasons[r] = reasons.get(r, 0) + 1
        logger.info("")
        logger.info("--- Skip Reasons ---")
        for reason, count in sorted(reasons.items(), key=lambda x: -x[1]):
            logger.info("  %s: %d", reason, count)


def _print_status(data: dict[str, Any]) -> None:
    logger.info("=" * 60)
    logger.info("ORCHESTRATOR STATUS")
    logger.info("=" * 60)
    logger.info("Timestamp: %s", data['timestamp'])
    if data["repo_filter"]:
        logger.info("Filter: %s", data['repo_filter'])
    if data["last_cycle"]:
        logger.info("Last cycle: %s", data['last_cycle'])
    logger.info("")

    logger.info("--- Issue State ---")
    for state_name, count in sorted(data["issue_state_breakdown"].items()):
        logger.info("  %s: %d", state_name, count)
    logger.info("  TOTAL: %d", data['total_issues'])
    logger.info("")

    logger.info("--- Sessions ---")
    for status, count in sorted(data["session_status_breakdown"].items()):
        logger.info("  %s: %d", status, count)
    logger.info("  TOTAL: %d", data['total_sessions'])
    logger.info("")

    logger.info("--- Pull Requests ---")
    logger.info("  Total: %d", data['total_prs'])
    logger.info("  Merged: %d", data['prs_merged'])
    logger.info("  Open: %d", data['prs_open'])
    logger.info("")

    rl = data["rate_limit"]
    logger.info("--- Rate Limit ---")
    logger.info("  Used: %d/%d (%dh window)", rl['used'], rl['max'], rl['period_hours'])
    logger.info("  Remaining: %d", rl['remaining'])
    logger.info("")

    if data["objective_progress"]:
        logger.info("--- Objective Progress ---")
        for obj in data["objective_progress"]:
            status = "MET" if obj["met"] else "IN PROGRESS"
            logger.info("  %s: %d issues (%s, target: %d)",
                        obj['objective'], obj['current_count'], status, obj['target_count'])
        logger.info("")

    if data["repos"]:
        logger.info("--- Per-Repo Summary ---")
        logger.info("%-50s %-7s %-7s %-10s %-7s %s", "Repo", "Total", "New", "Recurring", "Fixed", "Verified")
        logger.info("-" * 100)
        for repo_url, counts in sorted(data["repos"].items()):
            repo_short = repo_url
            if "github.com/" in repo_short:
                repo_short = repo_short.split("github.com/")[-1]
            logger.info(
                "%-50s %-7d %-7d %-10d %-7d %d",
                repo_short,
                counts.get('total', 0),
                counts.get('new', 0),
                counts.get('recurring', 0),
                counts.get('fixed', 0),
                counts.get('verified_fixed', 0),
            )


def _print_dispatch_summary(summary: dict[str, Any]) -> None:
    logger.info("=" * 60)
    logger.info("ORCHESTRATOR DISPATCH SUMMARY")
    logger.info("=" * 60)
    logger.info("Timestamp: %s", summary['timestamp'])
    if summary["repo_filter"]:
        logger.info("Filter: %s", summary['repo_filter'])
    if summary["dry_run"]:
        logger.info("Mode: DRY RUN")
    logger.info("")
    logger.info("Eligible issues:    %d", summary['total_eligible'])
    logger.info("Batches formed:     %d", summary['batches_formed'])
    logger.info("Sessions created:   %d", summary['sessions_created'])
    if summary["sessions_failed"]:
        logger.info("Sessions failed:    %d", summary['sessions_failed'])
    if summary["sessions_dry_run"]:
        logger.info("Sessions (dry-run): %d", summary['sessions_dry_run'])
    logger.info("Rate limit remain:  %d", summary['rate_limit_remaining'])
    logger.info("")

    if summary["results"]:
        logger.info("--- Dispatch Results ---")
        logger.info("%-4s %-20s %-8s %-15s %s", "#", "Family", "Issues", "Status", "Session URL")
        logger.info("-" * 100)
        for r in summary["results"]:
            url = r.get("session_url", "") or ""
            logger.info(
                "%-4d %-20s %-8d %-15s %s",
                r['batch_id'], r['cwe_family'],
                r['issue_count'], r['status'], url,
            )


def main() -> int:
    parser = argparse.ArgumentParser(
        description="CodeQL Devin Fixer Orchestrator",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    subparsers = parser.add_subparsers(dest="command", help="Orchestrator command")

    ingest_parser = subparsers.add_parser(
        "ingest", help="Record scan results without dispatching sessions",
    )
    ingest_parser.add_argument("--batches", required=True, help="Path to batches.json")
    ingest_parser.add_argument("--issues", required=True, help="Path to issues.json")
    ingest_parser.add_argument("--run-label", required=True, help="Run label identifier")
    ingest_parser.add_argument("--target-repo", required=True, help="Target repository URL")

    plan_parser = subparsers.add_parser(
        "plan", help="Compute dispatch plan (dry-run)",
    )
    plan_parser.add_argument("--repo", default="", help="Filter by repository URL")
    plan_parser.add_argument("--json", action="store_true", help="Output as JSON")

    status_parser = subparsers.add_parser(
        "status", help="Show global issue state and session status",
    )
    status_parser.add_argument("--repo", default="", help="Filter by repository URL")
    status_parser.add_argument("--json", action="store_true", help="Output as JSON")

    dispatch_parser = subparsers.add_parser(
        "dispatch", help="Create Devin sessions for eligible CodeQL issues",
    )
    dispatch_parser.add_argument("--repo", default="", help="Filter by repository URL")
    dispatch_parser.add_argument("--json", action="store_true", help="Output as JSON")
    dispatch_parser.add_argument(
        "--dry-run", action="store_true",
        help="Show what would be dispatched without creating sessions",
    )
    dispatch_parser.add_argument("--max-sessions", type=int, default=None, help="Override maximum sessions to create")

    scan_parser = subparsers.add_parser(
        "scan", help="Trigger CodeQL scans for repos due for scanning",
    )
    scan_parser.add_argument("--repo", default="", help="Filter by repository URL")
    scan_parser.add_argument("--json", action="store_true", help="Output as JSON")
    scan_parser.add_argument(
        "--dry-run", action="store_true",
        help="Show what would be scanned without triggering workflows",
    )

    cycle_parser = subparsers.add_parser(
        "cycle", help="Full orchestrator cycle: scan due repos, then dispatch",
    )
    cycle_parser.add_argument("--repo", default="", help="Filter by repository URL")
    cycle_parser.add_argument("--json", action="store_true", help="Output as JSON")
    cycle_parser.add_argument(
        "--dry-run", action="store_true",
        help="Run the full cycle in dry-run mode",
    )
    cycle_parser.add_argument("--max-sessions", type=int, default=None, help="Override maximum sessions to create")

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return 1

    commands = {
        "ingest": cmd_ingest,
        "plan": cmd_plan,
        "status": cmd_status,
        "dispatch": cmd_dispatch,
        "scan": cmd_scan,
        "cycle": cmd_cycle,
    }

    return commands[args.command](args)


if __name__ == "__main__":
    sys.exit(main())
