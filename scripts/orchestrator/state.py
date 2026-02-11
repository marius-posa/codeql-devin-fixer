"""State persistence, cooldown management, and issue state derivation.

Holds the core data models (RateLimiter, Objective), path constants,
registry/state persistence helpers, issue state derivation logic,
priority scoring, and shared utility functions used across the
orchestrator package.
"""

from __future__ import annotations

import hashlib
import json
import pathlib
import sqlite3
import sys
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any

_PKG_DIR = pathlib.Path(__file__).resolve().parent
_SCRIPTS_DIR = _PKG_DIR.parent
_ROOT_DIR = _SCRIPTS_DIR.parent
_TELEMETRY_DIR = _ROOT_DIR / "telemetry"

if str(_SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS_DIR))
if str(_TELEMETRY_DIR) not in sys.path:
    sys.path.insert(0, str(_TELEMETRY_DIR))

from database import get_connection, is_db_empty, query_all_sessions, query_all_prs, query_issues  # noqa: E402
from database import load_orchestrator_state, save_orchestrator_state, is_orchestrator_state_empty  # noqa: E402
from devin_api import clean_session_id  # noqa: E402
from migrate_json_to_sqlite import migrate_json_files  # noqa: E402
from issue_tracking import _parse_ts  # noqa: E402
from verification import load_verification_records, build_fingerprint_fix_map  # noqa: E402
from fix_learning import FixLearning  # noqa: E402

REGISTRY_PATH = _ROOT_DIR / "repo_registry.json"
STATE_PATH = _TELEMETRY_DIR / "orchestrator_state.json"
RUNS_DIR = _TELEMETRY_DIR / "runs"

MAX_DISPATCH_ATTEMPTS_DEFAULT = 3

COOLDOWN_HOURS: list[int] = [24, 72, 168]

SEVERITY_WEIGHTS: dict[str, float] = {
    "critical": 1.0,
    "high": 0.75,
    "medium": 0.5,
    "low": 0.25,
}


@dataclass
class RateLimiter:
    max_sessions: int = 20
    period_hours: int = 24
    created_timestamps: list[str] = field(default_factory=list)

    def _recent_timestamps(self) -> list[datetime]:
        cutoff = datetime.now(timezone.utc) - timedelta(hours=self.period_hours)
        result: list[datetime] = []
        for t in self.created_timestamps:
            dt = _parse_ts(t)
            if dt and dt > cutoff:
                result.append(dt)
        return result

    def can_create_session(self) -> bool:
        return len(self._recent_timestamps()) < self.max_sessions

    def recent_count(self) -> int:
        return len(self._recent_timestamps())

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


def _migrate_json_state_to_db(conn: sqlite3.Connection) -> None:
    if not STATE_PATH.exists():
        return
    try:
        with open(STATE_PATH) as f:
            data = json.load(f)
    except (json.JSONDecodeError, OSError):
        return
    save_orchestrator_state(conn, data)


def load_state() -> dict[str, Any]:
    conn = get_connection()
    try:
        if is_orchestrator_state_empty(conn):
            _migrate_json_state_to_db(conn)
        return load_orchestrator_state(conn)
    except sqlite3.OperationalError:
        return {
            "last_cycle": None,
            "rate_limiter": {},
            "dispatch_history": {},
            "objective_progress": [],
            "scan_schedule": {},
        }
    finally:
        conn.close()


def save_state(state: dict[str, Any]) -> None:
    conn = get_connection()
    try:
        save_orchestrator_state(conn, state)
    finally:
        conn.close()
    try:
        with open(STATE_PATH, "w") as f:
            json.dump(state, f, indent=2)
            f.write("\n")
    except OSError:
        pass


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

    tracking_ids = set(fp_to_tracking_ids.get(fp, set())) if fp_to_tracking_ids else set()
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
        clean_sid = clean_session_id(sid)
        if session_id and clean_sid == session_id:
            ids.update(s.get("issue_ids", []))
    return ids


def _cooldown_remaining_hours(
    history: dict[str, Any],
    cooldown_schedule: list[int] | None = None,
) -> float:
    """Return hours remaining in cooldown, or 0 if cooldown has elapsed."""
    if cooldown_schedule is None:
        cooldown_schedule = COOLDOWN_HOURS
    failed_count = history.get("consecutive_failures", 0)
    if failed_count <= 0:
        return 0.0
    last_dispatched = history.get("last_dispatched", "")
    if not last_dispatched:
        return 0.0
    last_dt = _parse_ts(last_dispatched)
    if last_dt is None:
        return 0.0
    idx = min(failed_count - 1, len(cooldown_schedule) - 1)
    cooldown_h = cooldown_schedule[idx]
    elapsed = (datetime.now(timezone.utc) - last_dt).total_seconds() / 3600.0
    remaining = cooldown_h - elapsed
    return max(remaining, 0.0)


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

    consecutive_failures = history.get("consecutive_failures", 0)
    if consecutive_failures >= max_dispatch_attempts + 1:
        return True, f"needs_human_review ({consecutive_failures} consecutive failures)"

    if dispatch_count >= max_dispatch_attempts:
        return True, f"max_attempts_reached ({dispatch_count})"

    remaining = _cooldown_remaining_hours(history)
    if remaining > 0:
        return True, f"cooldown_active ({remaining:.0f}h remaining)"

    family = issue.get("cwe_family", "other")
    if fix_learning.should_skip_family(family):
        return True, f"low_fix_rate_family ({family})"

    return False, ""


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


def apply_agent_scores(
    eligible: list[dict[str, Any]],
    agent_decisions: list[dict[str, Any]],
    mode: str = "deterministic",
    agent_weight: float = 0.5,
) -> None:
    """Blend agent scores into eligible issues based on dispatch_scoring_mode.

    Modes:
      deterministic -- keep existing priority_score unchanged (default)
      agent         -- replace priority_score with agent score (normalised 0-1)
      weighted      -- weighted average of deterministic and agent scores
    """
    if mode == "deterministic" or not agent_decisions:
        return

    agent_map = {d["fingerprint"]: d for d in agent_decisions}

    for issue in eligible:
        fp = issue.get("fingerprint", "")
        agent = agent_map.get(fp)
        if not agent:
            continue

        agent_raw = float(agent.get("agent_priority_score", 0))
        agent_norm = agent_raw / 100.0
        det_score = issue.get("priority_score", 0)

        if mode == "agent":
            issue["priority_score"] = round(agent_norm, 4)
        elif mode == "weighted":
            blended = (1.0 - agent_weight) * det_score + agent_weight * agent_norm
            issue["priority_score"] = round(blended, 4)

        issue["agent_priority_score"] = agent_raw
        issue["agent_dispatch"] = agent.get("dispatch", True)
        issue["recommendation_source"] = mode


def _ensure_db_hydrated(conn: sqlite3.Connection) -> None:
    if is_db_empty(conn) and RUNS_DIR.is_dir():
        migrate_json_files(RUNS_DIR, conn)


def build_global_issue_state(
    repo_filter: str = "",
) -> dict[str, Any]:
    conn = get_connection()
    try:
        _ensure_db_hydrated(conn)
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


def _compute_eligible_issues(repo_filter: str = "") -> dict[str, Any]:
    """Compute eligible issues for dispatch (shared by plan and dispatch)."""
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

    scoring_mode = orch_config.get("dispatch_scoring_mode", "deterministic")
    agent_weight = orch_config.get("agent_score_weight", 0.5)
    agent_triage = state.get("agent_triage", {})
    agent_decisions = agent_triage.get("decisions", [])
    apply_agent_scores(eligible, agent_decisions, scoring_mode, agent_weight)

    eligible.sort(key=lambda x: x.get("priority_score", 0), reverse=True)

    global_limit = orch_config.get("global_session_limit", 20)
    remaining_capacity = global_limit - rate_limiter.recent_count()

    return {
        "registry": registry,
        "orch_config": orch_config,
        "state": state,
        "rate_limiter": rate_limiter,
        "objectives": objectives,
        "fl": fl,
        "all_issues": issues,
        "eligible": eligible,
        "skipped": skipped,
        "global_limit": global_limit,
        "remaining_capacity": remaining_capacity,
        "dispatch_scoring_mode": scoring_mode,
    }


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
