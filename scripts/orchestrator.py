#!/usr/bin/env python3
"""Orchestrator engine for the CodeQL Devin Fixer pipeline.

Provides a global decision layer between issue discovery and session
dispatch.  Instead of dispatching Devin sessions immediately after each
CodeQL scan, the orchestrator records results and makes cross-repo
dispatch decisions based on priority scoring, deduplication, rate
limiting, and configurable objectives.

CLI Commands
------------
ingest   Record scan results without dispatching sessions.
plan     Compute a dry-run dispatch plan (shows what would be dispatched).
status   Show global issue state and session status.

Usage
-----
::

    python scripts/orchestrator.py ingest \\
        --batches output/batches.json \\
        --issues output/issues.json \\
        --run-label run-42-2026-02-08 \\
        --target-repo https://github.com/owner/repo

    python scripts/orchestrator.py plan [--repo URL] [--json]
    python scripts/orchestrator.py status [--repo URL] [--json]
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import pathlib
import sys
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any

_SCRIPTS_DIR = pathlib.Path(__file__).resolve().parent
_ROOT_DIR = _SCRIPTS_DIR.parent
_TELEMETRY_DIR = _ROOT_DIR / "telemetry"

if str(_SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS_DIR))
if str(_TELEMETRY_DIR) not in sys.path:
    sys.path.insert(0, str(_TELEMETRY_DIR))

from database import get_connection, init_db, insert_run, query_all_sessions, query_all_prs, query_issues  # noqa: E402
from issue_tracking import _parse_ts  # noqa: E402
from verification import load_verification_records, build_fingerprint_fix_map  # noqa: E402
from fix_learning import FixLearning  # noqa: E402

REGISTRY_PATH = _ROOT_DIR / "repo_registry.json"
STATE_PATH = _TELEMETRY_DIR / "orchestrator_state.json"
RUNS_DIR = _TELEMETRY_DIR / "runs"

MAX_DISPATCH_ATTEMPTS_DEFAULT = 3


@dataclass
class RateLimiter:
    max_sessions: int = 20
    period_hours: int = 24
    created_timestamps: list[str] = field(default_factory=list)

    def can_create_session(self) -> bool:
        cutoff = datetime.now(timezone.utc) - timedelta(hours=self.period_hours)
        recent = [
            t for t in self.created_timestamps
            if _parse_ts(t) and _parse_ts(t) > cutoff  # type: ignore[operator]
        ]
        return len(recent) < self.max_sessions

    def recent_count(self) -> int:
        cutoff = datetime.now(timezone.utc) - timedelta(hours=self.period_hours)
        return sum(
            1 for t in self.created_timestamps
            if _parse_ts(t) and _parse_ts(t) > cutoff  # type: ignore[operator]
        )

    def record_session(self) -> None:
        self.created_timestamps.append(
            datetime.now(timezone.utc).isoformat()
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "max_sessions": self.max_sessions,
            "period_hours": self.period_hours,
            "created_timestamps": self.created_timestamps,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> RateLimiter:
        return cls(
            max_sessions=data.get("max_sessions", 20),
            period_hours=data.get("period_hours", 24),
            created_timestamps=data.get("created_timestamps", []),
        )


@dataclass
class Objective:
    name: str = ""
    description: str = ""
    target_severity: str = ""
    target_count: int = 0
    target_reduction_pct: int = 0
    priority: int = 1

    def progress(self, current_issues: list[dict[str, Any]]) -> dict[str, Any]:
        matching = [
            i for i in current_issues
            if i.get("severity_tier") == self.target_severity
            and i.get("derived_state", i.get("status")) in ("new", "recurring")
        ]
        return {
            "objective": self.name,
            "description": self.description,
            "current_count": len(matching),
            "target_count": self.target_count,
            "met": len(matching) <= self.target_count,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Objective:
        return cls(
            name=data.get("name", ""),
            description=data.get("description", ""),
            target_severity=data.get("target_severity", ""),
            target_count=data.get("target_count", 0),
            target_reduction_pct=data.get("target_reduction_pct", 0),
            priority=data.get("priority", 1),
        )


def load_registry() -> dict[str, Any]:
    if not REGISTRY_PATH.exists():
        return {"version": "2.0", "defaults": {}, "orchestrator": {}, "repos": []}
    with open(REGISTRY_PATH) as f:
        return json.load(f)


def load_state() -> dict[str, Any]:
    if not STATE_PATH.exists():
        return {
            "last_cycle": None,
            "rate_limiter": {},
            "dispatch_history": {},
            "objective_progress": [],
            "scan_schedule": {},
        }
    try:
        with open(STATE_PATH) as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError):
        return {
            "last_cycle": None,
            "rate_limiter": {},
            "dispatch_history": {},
            "objective_progress": [],
            "scan_schedule": {},
        }


def save_state(state: dict[str, Any]) -> None:
    STATE_PATH.parent.mkdir(parents=True, exist_ok=True)
    with open(STATE_PATH, "w") as f:
        json.dump(state, f, indent=2)
        f.write("\n")


def get_repo_config(registry: dict[str, Any], repo_url: str) -> dict[str, Any]:
    for repo in registry.get("repos", []):
        if repo.get("repo") == repo_url:
            merged = dict(registry.get("defaults", {}))
            merged.update(repo)
            merged.update(repo.get("overrides", {}))
            return merged
    defaults = dict(registry.get("defaults", {}))
    defaults["repo"] = repo_url
    defaults.setdefault("importance", "medium")
    defaults.setdefault("importance_score", 50)
    defaults.setdefault("max_sessions_per_cycle", 5)
    return defaults


def _build_fp_to_tracking_ids(
    issues: list[dict[str, Any]],
) -> dict[str, set[str]]:
    mapping: dict[str, set[str]] = {}
    for issue in issues:
        fp = issue.get("fingerprint", "")
        if not fp:
            continue
        if fp not in mapping:
            mapping[fp] = set()
        lid = issue.get("latest_issue_id", "")
        if lid:
            mapping[fp].add(lid)
    return mapping


def _derive_issue_state(
    issue: dict[str, Any],
    sessions: list[dict[str, Any]],
    prs: list[dict[str, Any]],
    fp_fix_map: dict[str, dict[str, Any]],
    dispatch_history: dict[str, dict[str, Any]],
    fp_to_tracking_ids: dict[str, set[str]] | None = None,
) -> str:
    fp = issue.get("fingerprint", "")
    base_status = issue.get("status", "new")

    tracking_ids = set()
    if fp_to_tracking_ids and fp in fp_to_tracking_ids:
        tracking_ids = fp_to_tracking_ids[fp]
    lid = issue.get("latest_issue_id", "")
    if lid:
        tracking_ids.add(lid)

    if fp in fp_fix_map:
        return "verified_fixed"

    for pr in prs:
        if pr.get("merged") and _pr_matches_issue(pr, sessions, fp, tracking_ids):
            return "pr_merged"

    for pr in prs:
        if pr.get("state") == "open" and not pr.get("merged") and _pr_matches_issue(pr, sessions, fp, tracking_ids):
            return "pr_open"

    for s in sessions:
        if _session_matches_issue(s, fp, tracking_ids) and s.get("status") not in ("finished", "stopped", "error", "failed"):
            if s.get("session_id") and s.get("session_id") != "dry-run":
                return "session_dispatched"

    if base_status == "fixed":
        return "fixed"

    return base_status


def _session_matches_issue(
    session: dict[str, Any],
    fingerprint: str,
    tracking_ids: set[str],
) -> bool:
    session_ids = set(session.get("issue_ids", []))
    if fingerprint and fingerprint in session_ids:
        return True
    return bool(tracking_ids & session_ids)


def _session_fingerprints(session: dict[str, Any]) -> set[str]:
    return set(session.get("issue_ids", []))


def _pr_matches_issue(
    pr: dict[str, Any],
    sessions: list[dict[str, Any]],
    fingerprint: str,
    tracking_ids: set[str],
) -> bool:
    all_ids = _collect_pr_ids(pr, sessions)
    if fingerprint and fingerprint in all_ids:
        return True
    return bool(tracking_ids & all_ids)


def _pr_fingerprints(
    pr: dict[str, Any], sessions: list[dict[str, Any]]
) -> set[str]:
    return _collect_pr_ids(pr, sessions)


def _collect_pr_ids(
    pr: dict[str, Any], sessions: list[dict[str, Any]]
) -> set[str]:
    ids: set[str] = set()
    pr_url = pr.get("html_url", "")
    session_id = pr.get("session_id", "")
    for iid in pr.get("issue_ids", []):
        if iid:
            ids.add(iid)
    for s in sessions:
        sid = s.get("session_id", "")
        if not sid:
            continue
        if s.get("pr_url") == pr_url:
            ids.update(s.get("issue_ids", []))
        clean_sid = sid.replace("devin-", "") if sid.startswith("devin-") else sid
        if session_id and clean_sid == session_id:
            ids.update(s.get("issue_ids", []))
    return ids


def should_skip_issue(
    issue: dict[str, Any],
    derived_state: str,
    dispatch_history: dict[str, dict[str, Any]],
    fix_learning: FixLearning,
    max_dispatch_attempts: int = MAX_DISPATCH_ATTEMPTS_DEFAULT,
) -> tuple[bool, str]:
    if derived_state in ("fixed", "verified_fixed"):
        return True, "already_resolved"

    if derived_state == "session_dispatched":
        return True, "session_active"

    if derived_state == "pr_open":
        return True, "pr_awaiting_review"

    if derived_state == "pr_merged":
        return True, "pr_merged_awaiting_verification"

    fp = issue.get("fingerprint", "")
    history = dispatch_history.get(fp, {})
    dispatch_count = history.get("dispatch_count", 0)
    if dispatch_count >= max_dispatch_attempts:
        return True, f"max_attempts_reached ({dispatch_count})"

    family = issue.get("cwe_family", "other")
    if fix_learning.should_skip_family(family):
        return True, f"low_fix_rate_family ({family})"

    return False, ""


SEVERITY_WEIGHTS: dict[str, float] = {
    "critical": 1.0,
    "high": 0.75,
    "medium": 0.5,
    "low": 0.25,
}


def compute_issue_priority(
    issue: dict[str, Any],
    repo_config: dict[str, Any],
    objectives: list[Objective],
    fix_learning: FixLearning,
) -> float:
    repo_importance = repo_config.get("importance_score", 50) / 100.0
    severity_weight = SEVERITY_WEIGHTS.get(
        issue.get("severity_tier", ""), 0.1
    )

    appearances = issue.get("appearances", 1)
    recurrence_bonus = min(appearances * 0.05, 0.3)

    sla_urgency = 0.0
    sla_status = issue.get("sla_status", "")
    if sla_status == "breached":
        sla_urgency = 0.4
    elif sla_status == "at-risk":
        sla_urgency = 0.2

    family = issue.get("cwe_family", "other")
    rates = fix_learning.family_fix_rates()
    family_stats = rates.get(family)
    if family_stats and family_stats.total_sessions > 0:
        feasibility = family_stats.fix_rate
    else:
        feasibility = 0.5

    score = (
        repo_importance * 0.35
        + severity_weight * 0.30
        + sla_urgency * 0.15
        + feasibility * 0.10
        + recurrence_bonus * 0.10
    )

    objective_boost = 0.0
    for obj in objectives:
        if issue.get("severity_tier") == obj.target_severity:
            progress = obj.progress([issue])
            if not progress["met"]:
                objective_boost = max(
                    objective_boost, 0.15 * (1.0 / max(obj.priority, 1))
                )
    score += objective_boost

    return round(score, 4)


def build_global_issue_state(
    repo_filter: str = "",
) -> dict[str, Any]:
    conn = get_connection()
    try:
        init_db(conn)
        issues = query_issues(conn, target_repo=repo_filter)
        sessions = query_all_sessions(conn, target_repo=repo_filter)
        prs = query_all_prs(conn)

        verification_records = load_verification_records(RUNS_DIR)
        fp_fix_map = build_fingerprint_fix_map(verification_records)

        state = load_state()
        dispatch_history = state.get("dispatch_history", {})

        fp_to_tracking_ids = _build_fp_to_tracking_ids(issues)

        for issue in issues:
            derived = _derive_issue_state(
                issue, sessions, prs, fp_fix_map, dispatch_history,
                fp_to_tracking_ids,
            )
            issue["derived_state"] = derived

        return {
            "issues": issues,
            "sessions": sessions,
            "prs": prs,
            "fp_fix_map": fp_fix_map,
            "dispatch_history": dispatch_history,
        }
    finally:
        conn.close()


def cmd_ingest(args: argparse.Namespace) -> int:
    batches_path = args.batches
    issues_path = args.issues
    run_label = args.run_label
    target_repo = args.target_repo

    if not batches_path or not os.path.isfile(batches_path):
        print(f"ERROR: Batches file not found: {batches_path}")
        return 1
    if not issues_path or not os.path.isfile(issues_path):
        print(f"ERROR: Issues file not found: {issues_path}")
        return 1

    with open(batches_path) as f:
        batches_data = json.load(f)
    with open(issues_path) as f:
        issues_data = json.load(f)

    batches = batches_data.get("batches", batches_data if isinstance(batches_data, list) else [])
    issues = issues_data.get("issues", issues_data if isinstance(issues_data, list) else [])

    severity_breakdown: dict[str, int] = {}
    category_breakdown: dict[str, int] = {}
    for issue in issues:
        sev = issue.get("severity_tier", "unknown")
        severity_breakdown[sev] = severity_breakdown.get(sev, 0) + 1
        fam = issue.get("cwe_family", "other")
        category_breakdown[fam] = category_breakdown.get(fam, 0) + 1

    run_number = ""
    if run_label:
        parts = run_label.split("-")
        for i, p in enumerate(parts):
            if p.isdigit() and i > 0 and parts[i - 1] == "run":
                run_number = p
                break

    issue_fingerprints = []
    for issue in issues:
        fp = issue.get("fingerprint", "")
        if not fp:
            fp = _fallback_fingerprint(issue)
        issue_fingerprints.append({
            "id": issue.get("id", ""),
            "fingerprint": fp,
            "rule_id": issue.get("rule_id", ""),
            "severity_tier": issue.get("severity_tier", "unknown"),
            "cwe_family": issue.get("cwe_family", "other"),
            "file": _issue_file(issue),
            "start_line": _issue_start_line(issue),
            "description": issue.get("message", ""),
        })

    telemetry_record: dict[str, Any] = {
        "target_repo": target_repo,
        "fork_url": "",
        "run_number": int(run_number) if run_number else 0,
        "run_id": "",
        "run_url": "",
        "run_label": run_label,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "issues_found": len(issues),
        "batches_created": len(batches),
        "zero_issue_run": len(issues) == 0,
        "severity_breakdown": severity_breakdown,
        "category_breakdown": category_breakdown,
        "sessions": [],
        "issue_fingerprints": issue_fingerprints,
    }

    conn = get_connection()
    try:
        init_db(conn)
        result = insert_run(conn, telemetry_record)
        conn.commit()

        if result is not None:
            print(f"Ingested {len(issues)} issues ({len(batches)} batches) for {target_repo}")
            print(f"Run label: {run_label}")
            print(f"DB row ID: {result}")
        else:
            print(f"Run {run_label} already exists in DB (skipped)")

        state = load_state()
        state["last_cycle"] = datetime.now(timezone.utc).isoformat()
        scan_schedule = state.setdefault("scan_schedule", {})
        scan_schedule[target_repo] = {
            "last_scan": datetime.now(timezone.utc).isoformat(),
            "run_label": run_label,
        }
        save_state(state)

    finally:
        conn.close()

    return 0


def cmd_plan(args: argparse.Namespace) -> int:
    repo_filter = args.repo or ""
    output_json = args.json

    registry = load_registry()
    orch_config = registry.get("orchestrator", {})
    state = load_state()

    objectives = [
        Objective.from_dict(o) for o in orch_config.get("objectives", [])
    ]

    rate_limiter = RateLimiter.from_dict(
        {**state.get("rate_limiter", {}),
         "max_sessions": orch_config.get("global_session_limit", 20),
         "period_hours": orch_config.get("global_session_limit_period_hours", 24)}
    )

    dispatch_history = state.get("dispatch_history", {})
    fl = FixLearning.from_telemetry_dir(str(RUNS_DIR))

    global_state = build_global_issue_state(repo_filter)
    issues = global_state["issues"]

    eligible: list[dict[str, Any]] = []
    skipped: list[dict[str, Any]] = []

    for issue in issues:
        derived = issue.get("derived_state", issue.get("status", "new"))
        skip, reason = should_skip_issue(
            issue, derived, dispatch_history, fl,
        )
        if skip:
            skipped.append({"fingerprint": issue.get("fingerprint", ""), "reason": reason, **_issue_summary(issue)})
        else:
            eligible.append(issue)

    for issue in eligible:
        repo_url = issue.get("target_repo", "")
        repo_config = get_repo_config(registry, repo_url)
        issue["priority_score"] = compute_issue_priority(
            issue, repo_config, objectives, fl,
        )

    eligible.sort(key=lambda x: x.get("priority_score", 0), reverse=True)

    plan_batches: list[dict[str, Any]] = []
    sessions_planned = 0
    global_limit = orch_config.get("global_session_limit", 20)
    remaining_capacity = global_limit - rate_limiter.recent_count()

    repos_seen: dict[str, int] = {}
    for issue in eligible:
        if sessions_planned >= remaining_capacity:
            break
        repo_url = issue.get("target_repo", "")
        repo_config = get_repo_config(registry, repo_url)
        repo_limit = repo_config.get("max_sessions_per_cycle", 5)
        repo_sessions = repos_seen.get(repo_url, 0)
        if repo_sessions >= repo_limit:
            continue

        plan_batches.append({
            "fingerprint": issue.get("fingerprint", ""),
            "priority_score": issue.get("priority_score", 0),
            **_issue_summary(issue),
        })
        repos_seen[repo_url] = repo_sessions + 1
        sessions_planned += 1

    plan = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "repo_filter": repo_filter,
        "total_issues": len(issues),
        "eligible_issues": len(eligible),
        "skipped_issues": len(skipped),
        "sessions_planned": sessions_planned,
        "rate_limit_remaining": remaining_capacity,
        "rate_limit_max": global_limit,
        "rate_limit_period_hours": rate_limiter.period_hours,
        "planned_dispatches": plan_batches,
        "skipped": skipped,
        "objective_progress": [
            obj.progress(issues) for obj in objectives
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

    registry = load_registry()
    orch_config = registry.get("orchestrator", {})
    state = load_state()

    objectives = [
        Objective.from_dict(o) for o in orch_config.get("objectives", [])
    ]

    rate_limiter = RateLimiter.from_dict(
        {**state.get("rate_limiter", {}),
         "max_sessions": orch_config.get("global_session_limit", 20),
         "period_hours": orch_config.get("global_session_limit_period_hours", 24)}
    )

    global_state = build_global_issue_state(repo_filter)
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


def _issue_file(issue: dict[str, Any]) -> str:
    locs = issue.get("locations", [])
    if locs:
        return locs[0].get("file", "")
    return issue.get("file", "")


def _issue_start_line(issue: dict[str, Any]) -> int:
    locs = issue.get("locations", [])
    if locs:
        return locs[0].get("start_line", 0)
    return issue.get("start_line", 0)


def _issue_summary(issue: dict[str, Any]) -> dict[str, Any]:
    return {
        "rule_id": issue.get("rule_id", ""),
        "severity_tier": issue.get("severity_tier", ""),
        "cwe_family": issue.get("cwe_family", ""),
        "file": issue.get("file", _issue_file(issue)),
        "target_repo": issue.get("target_repo", ""),
        "derived_state": issue.get("derived_state", issue.get("status", "")),
        "appearances": issue.get("appearances", 1),
    }


def _fallback_fingerprint(issue: dict[str, Any]) -> str:
    rule_id = issue.get("rule_id", "")
    file_path = _issue_file(issue)
    start_line = str(_issue_start_line(issue))
    raw = f"{rule_id}|{file_path}|{start_line}"
    return hashlib.sha256(raw.encode()).hexdigest()[:20]


def _print_plan(plan: dict[str, Any]) -> None:
    print("=" * 60)
    print("ORCHESTRATOR DISPATCH PLAN")
    print("=" * 60)
    print(f"Generated: {plan['timestamp']}")
    if plan["repo_filter"]:
        print(f"Filter: {plan['repo_filter']}")
    print()
    print(f"Total issues in DB:    {plan['total_issues']}")
    print(f"Eligible for dispatch: {plan['eligible_issues']}")
    print(f"Skipped:               {plan['skipped_issues']}")
    print(f"Sessions planned:      {plan['sessions_planned']}")
    print(f"Rate limit:            {plan['rate_limit_remaining']}/{plan['rate_limit_max']} remaining ({plan['rate_limit_period_hours']}h window)")
    print()

    if plan["objective_progress"]:
        print("--- Objective Progress ---")
        for obj in plan["objective_progress"]:
            status = "MET" if obj["met"] else "IN PROGRESS"
            print(f"  {obj['objective']}: {obj['current_count']} issues ({status}, target: {obj['target_count']})")
        print()

    if plan["planned_dispatches"]:
        print("--- Planned Dispatches ---")
        print(f"{'#':<4} {'Score':<8} {'Severity':<10} {'Family':<20} {'Repo':<40} {'File'}")
        print("-" * 120)
        for i, d in enumerate(plan["planned_dispatches"], 1):
            repo_short = d.get("target_repo", "")
            if "github.com/" in repo_short:
                repo_short = repo_short.split("github.com/")[-1]
            print(
                f"{i:<4} {d.get('priority_score', 0):<8.4f} "
                f"{d.get('severity_tier', ''):<10} "
                f"{d.get('cwe_family', ''):<20} "
                f"{repo_short:<40} "
                f"{d.get('file', '')}"
            )
    else:
        print("No dispatches planned.")

    if plan["skipped"]:
        reasons: dict[str, int] = {}
        for s in plan["skipped"]:
            r = s.get("reason", "unknown")
            reasons[r] = reasons.get(r, 0) + 1
        print()
        print("--- Skip Reasons ---")
        for reason, count in sorted(reasons.items(), key=lambda x: -x[1]):
            print(f"  {reason}: {count}")


def _print_status(data: dict[str, Any]) -> None:
    print("=" * 60)
    print("ORCHESTRATOR STATUS")
    print("=" * 60)
    print(f"Timestamp: {data['timestamp']}")
    if data["repo_filter"]:
        print(f"Filter: {data['repo_filter']}")
    if data["last_cycle"]:
        print(f"Last cycle: {data['last_cycle']}")
    print()

    print("--- Issue State ---")
    for state_name, count in sorted(data["issue_state_breakdown"].items()):
        print(f"  {state_name}: {count}")
    print(f"  TOTAL: {data['total_issues']}")
    print()

    print("--- Sessions ---")
    for status, count in sorted(data["session_status_breakdown"].items()):
        print(f"  {status}: {count}")
    print(f"  TOTAL: {data['total_sessions']}")
    print()

    print("--- Pull Requests ---")
    print(f"  Total: {data['total_prs']}")
    print(f"  Merged: {data['prs_merged']}")
    print(f"  Open: {data['prs_open']}")
    print()

    rl = data["rate_limit"]
    print("--- Rate Limit ---")
    print(f"  Used: {rl['used']}/{rl['max']} ({rl['period_hours']}h window)")
    print(f"  Remaining: {rl['remaining']}")
    print()

    if data["objective_progress"]:
        print("--- Objective Progress ---")
        for obj in data["objective_progress"]:
            status = "MET" if obj["met"] else "IN PROGRESS"
            print(f"  {obj['objective']}: {obj['current_count']} issues ({status}, target: {obj['target_count']})")
        print()

    if data["repos"]:
        print("--- Per-Repo Summary ---")
        print(f"{'Repo':<50} {'Total':<7} {'New':<7} {'Recurring':<10} {'Fixed':<7} {'Verified'}")
        print("-" * 100)
        for repo_url, counts in sorted(data["repos"].items()):
            repo_short = repo_url
            if "github.com/" in repo_short:
                repo_short = repo_short.split("github.com/")[-1]
            print(
                f"{repo_short:<50} "
                f"{counts.get('total', 0):<7} "
                f"{counts.get('new', 0):<7} "
                f"{counts.get('recurring', 0):<10} "
                f"{counts.get('fixed', 0):<7} "
                f"{counts.get('verified_fixed', 0)}"
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

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return 1

    commands = {
        "ingest": cmd_ingest,
        "plan": cmd_plan,
        "status": cmd_status,
    }

    return commands[args.command](args)


if __name__ == "__main__":
    sys.exit(main())
