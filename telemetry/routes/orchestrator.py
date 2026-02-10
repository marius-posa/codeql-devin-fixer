"""Orchestrator blueprint -- plan, dispatch, scan, cycle, config, agent-triage, and fix-rates."""

import json
import os
import pathlib
import subprocess

from flask import Blueprint, jsonify, request as flask_request

from config import RUNS_DIR
from database import db_connection, get_connection, init_db, query_issues, load_orchestrator_state, is_orchestrator_state_empty, save_orchestrator_state
from verification import load_verification_records, build_fingerprint_fix_map
from helpers import require_api_key, _audit, _paginate, _get_pagination
from extensions import limiter
from routes.registry import _load_registry as _load_orchestrator_registry, _save_registry as _save_orchestrator_registry, REGISTRY_PATH as _ORCHESTRATOR_REGISTRY_PATH

orchestrator_bp = Blueprint("orchestrator", __name__)

_ORCHESTRATOR_DIR = pathlib.Path(__file__).resolve().parent.parent.parent / "scripts"
_ORCHESTRATOR_STATE_PATH = pathlib.Path(__file__).resolve().parent.parent / "orchestrator_state.json"


def _load_orchestrator_state() -> dict:
    with db_connection() as conn:
        try:
            init_db(conn)
            if is_orchestrator_state_empty(conn):
                if _ORCHESTRATOR_STATE_PATH.exists():
                    try:
                        with open(_ORCHESTRATOR_STATE_PATH) as f:
                            data = json.load(f)
                        save_orchestrator_state(conn, data)
                    except (json.JSONDecodeError, OSError):
                        pass
            return load_orchestrator_state(conn)
        except Exception:
            return {
                "last_cycle": None,
                "rate_limiter": {},
                "dispatch_history": {},
                "objective_progress": [],
                "scan_schedule": {},
            }


def _serialize_orch_config(orch_config: dict) -> dict:
    return {
        "global_session_limit": orch_config.get("global_session_limit", 20),
        "global_session_limit_period_hours": orch_config.get("global_session_limit_period_hours", 24),
        "objectives": orch_config.get("objectives", []),
        "alert_on_objective_met": orch_config.get("alert_on_objective_met", False),
        "alert_webhook_url": orch_config.get("alert_webhook_url", ""),
        "alert_on_verified_fix": orch_config.get("alert_on_verified_fix", True),
        "alert_severities": orch_config.get("alert_severities", ["critical", "high"]),
    }



def _normalize_dispatch_entry(entry: dict) -> dict:
    out = dict(entry)
    if not out.get("dispatched_at") and out.get("last_dispatched"):
        out["dispatched_at"] = out["last_dispatched"]
    if not out.get("session_id") and out.get("last_session_id"):
        out["session_id"] = out["last_session_id"]
    if not out.get("session_url") and out.get("session_id"):
        sid = out["session_id"]
        if sid.startswith("devin-"):
            sid = sid[6:]
        out["session_url"] = f"https://app.devin.ai/sessions/{sid}"
    return out


@orchestrator_bp.route("/api/orchestrator/status")
def api_orchestrator_status():
    state = _load_orchestrator_state()
    registry = _load_orchestrator_registry()
    orch_config = registry.get("orchestrator", {})

    max_sessions = orch_config.get("global_session_limit", 20)
    period_hours = orch_config.get("global_session_limit_period_hours", 24)

    rl_data = state.get("rate_limiter", {})
    timestamps = rl_data.get("created_timestamps", rl_data.get("timestamps", []))
    from datetime import datetime, timedelta, timezone
    cutoff = datetime.now(timezone.utc) - timedelta(hours=period_hours)
    used = 0
    for t in timestamps:
        try:
            ts = datetime.fromisoformat(t.replace("Z", "+00:00")) if isinstance(t, str) else None
            if ts and ts > cutoff:
                used += 1
        except (ValueError, TypeError):
            pass

    conn = get_connection()
    try:
        issues = query_issues(conn)
        state_counts: dict[str, int] = {}
        for issue in issues:
            derived = issue.get("derived_state", issue.get("status", "new"))
            state_counts[derived] = state_counts.get(derived, 0) + 1

        objectives = orch_config.get("objectives", [])
        objective_progress = []
        for obj in objectives:
            obj_name = obj.get("objective", "")
            target = obj.get("target_count", 0)
            severity = obj.get("severity", "")
            current = sum(
                1 for i in issues
                if i.get("derived_state") in ("verified_fixed", "fixed")
                and (not severity or i.get("severity_tier") == severity)
            )
            objective_progress.append({
                "objective": obj_name,
                "target_count": target,
                "current_count": current,
                "met": current >= target,
            })

        return jsonify({
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "last_cycle": state.get("last_cycle"),
            "issue_state_breakdown": state_counts,
            "total_issues": len(issues),
            "rate_limit": {
                "used": used,
                "max": max_sessions,
                "remaining": max_sessions - used,
                "period_hours": period_hours,
            },
            "objective_progress": objective_progress,
            "scan_schedule": state.get("scan_schedule", {}),
            "dispatch_history_entries": len(state.get("dispatch_history", {})),
        })
    finally:
        conn.close()


@orchestrator_bp.route("/api/orchestrator/plan")
def api_orchestrator_plan():
    result = subprocess.run(
        ["python3", "-m", "scripts.orchestrator", "plan", "--json"],
        capture_output=True, text=True, timeout=60,
        cwd=str(_ORCHESTRATOR_DIR.parent),
    )
    if result.returncode != 0:
        return jsonify({"error": "Plan computation failed", "stderr": result.stderr[:500]}), 500
    try:
        return jsonify(json.loads(result.stdout))
    except (json.JSONDecodeError, ValueError):
        return jsonify({"error": "Invalid plan output", "raw": result.stdout[:500]}), 500


@orchestrator_bp.route("/api/orchestrator/dispatch", methods=["POST"])
@limiter.limit("5/minute")
@require_api_key
def api_orchestrator_dispatch():
    body = flask_request.get_json(silent=True) or {}
    repo_filter = body.get("repo", "")
    dry_run = body.get("dry_run", False)

    if not dry_run and not os.environ.get("DEVIN_API_KEY"):
        return jsonify({"error": "DEVIN_API_KEY not configured on server"}), 400

    cmd = ["python3", "-m", "scripts.orchestrator", "dispatch", "--json"]
    if repo_filter:
        cmd.extend(["--repo", repo_filter])
    if dry_run:
        cmd.append("--dry-run")

    result = subprocess.run(
        cmd, capture_output=True, text=True, timeout=120,
        cwd=str(_ORCHESTRATOR_DIR.parent),
        env={**os.environ},
    )
    _audit("orchestrator_dispatch", resource=repo_filter, details=json.dumps({"dry_run": dry_run}))
    try:
        return jsonify(json.loads(result.stdout))
    except (json.JSONDecodeError, ValueError):
        if result.returncode != 0:
            return jsonify({"error": "Dispatch failed", "stderr": result.stderr[:500]}), 500
        return jsonify({"error": "Invalid dispatch output", "raw": result.stdout[:500]}), 500


@orchestrator_bp.route("/api/orchestrator/scan", methods=["POST"])
@require_api_key
def api_orchestrator_scan():
    body = flask_request.get_json(silent=True) or {}
    repo_filter = body.get("repo", "")
    dry_run = body.get("dry_run", False)

    if not dry_run:
        missing = [v for v in ("GITHUB_TOKEN", "ACTION_REPO") if not os.environ.get(v)]
        if missing:
            return jsonify({"error": f"Missing env vars: {', '.join(missing)}"}), 400

    cmd = ["python3", "-m", "scripts.orchestrator", "scan", "--json"]
    if repo_filter:
        cmd.extend(["--repo", repo_filter])
    if dry_run:
        cmd.append("--dry-run")

    result = subprocess.run(
        cmd, capture_output=True, text=True, timeout=120,
        cwd=str(_ORCHESTRATOR_DIR.parent),
        env={**os.environ},
    )
    _audit("orchestrator_scan", resource=repo_filter, details=json.dumps({"dry_run": dry_run}))
    try:
        return jsonify(json.loads(result.stdout))
    except (json.JSONDecodeError, ValueError):
        if result.returncode != 0:
            return jsonify({"error": "Scan failed", "stderr": result.stderr[:500]}), 500
        return jsonify({"error": "Invalid scan output", "raw": result.stdout[:500]}), 500


@orchestrator_bp.route("/api/orchestrator/history")
def api_orchestrator_history():
    fingerprint = flask_request.args.get("fingerprint", "")
    state = _load_orchestrator_state()
    dispatch_history = state.get("dispatch_history", {})

    if fingerprint:
        entries = dispatch_history.get(fingerprint, [])
        if not isinstance(entries, list):
            entries = [entries] if entries else []
        entries = [_normalize_dispatch_entry({**e, "fingerprint": fingerprint}) for e in entries]
        return jsonify({"fingerprint": fingerprint, "entries": entries})

    page, per_page = _get_pagination()
    all_entries: list[dict] = []
    for fp, history in dispatch_history.items():
        if isinstance(history, list):
            for entry in history:
                all_entries.append(_normalize_dispatch_entry({**entry, "fingerprint": fp}))
        elif isinstance(history, dict):
            all_entries.append(_normalize_dispatch_entry({**history, "fingerprint": fp}))

    all_entries.sort(key=lambda e: e.get("dispatched_at", ""), reverse=True)
    return jsonify(_paginate(all_entries, page, per_page))


@orchestrator_bp.route("/api/orchestrator/cycle", methods=["POST"])
@limiter.limit("5/minute")
@require_api_key
def api_orchestrator_cycle():
    body = flask_request.get_json(silent=True) or {}
    repo_filter = body.get("repo", "")
    dry_run = body.get("dry_run", False)

    if not dry_run:
        missing = [v for v in ("GITHUB_TOKEN", "ACTION_REPO") if not os.environ.get(v)]
        if missing:
            return jsonify({"error": f"Missing env vars: {', '.join(missing)}"}), 400
        if not os.environ.get("DEVIN_API_KEY"):
            return jsonify({"error": "DEVIN_API_KEY not configured on server"}), 400

    cmd = ["python3", "-m", "scripts.orchestrator", "cycle", "--json"]
    if repo_filter:
        cmd.extend(["--repo", repo_filter])
    if dry_run:
        cmd.append("--dry-run")

    result = subprocess.run(
        cmd, capture_output=True, text=True, timeout=300,
        cwd=str(_ORCHESTRATOR_DIR.parent),
        env={**os.environ},
    )
    _audit("orchestrator_cycle", resource=repo_filter, details=json.dumps({"dry_run": dry_run}))
    try:
        return jsonify(json.loads(result.stdout))
    except (json.JSONDecodeError, ValueError):
        if result.returncode != 0:
            return jsonify({"error": "Cycle failed", "stderr": result.stderr[:500]}), 500
        return jsonify({"error": "Invalid cycle output", "raw": result.stdout[:500]}), 500


@orchestrator_bp.route("/api/orchestrator/config")
def api_orchestrator_config():
    registry = _load_orchestrator_registry()
    orch_config = registry.get("orchestrator", {})
    return jsonify(_serialize_orch_config(orch_config))


@orchestrator_bp.route("/api/orchestrator/config", methods=["PUT"])
@require_api_key
def api_orchestrator_config_update():
    body = flask_request.get_json(silent=True)
    if not body:
        return jsonify({"error": "Request body is required"}), 400

    registry = _load_orchestrator_registry()
    orch_config = registry.get("orchestrator", {})

    allowed_keys = (
        "global_session_limit",
        "global_session_limit_period_hours",
        "objectives",
        "alert_on_objective_met",
        "alert_webhook_url",
        "alert_on_verified_fix",
        "alert_severities",
    )
    for key in allowed_keys:
        if key in body:
            orch_config[key] = body[key]

    registry["orchestrator"] = orch_config
    _save_orchestrator_registry(registry)

    _audit("update_orchestrator_config", details=json.dumps({k: body[k] for k in allowed_keys if k in body}))
    return jsonify(_serialize_orch_config(orch_config))


@orchestrator_bp.route("/api/orchestrator/agent-triage", methods=["POST"])
@limiter.limit("5/minute")
@require_api_key
def api_orchestrator_agent_triage():
    body = flask_request.get_json(silent=True) or {}
    repo_filter = body.get("repo", "")
    dry_run = body.get("dry_run", False)

    if not dry_run and not os.environ.get("DEVIN_API_KEY"):
        return jsonify({"error": "DEVIN_API_KEY not configured on server"}), 400

    cmd = ["python3", "-m", "scripts.orchestrator", "agent-triage", "--json"]
    if repo_filter:
        cmd.extend(["--repo", repo_filter])
    if dry_run:
        cmd.append("--dry-run")

    result = subprocess.run(
        cmd, capture_output=True, text=True, timeout=360,
        cwd=str(_ORCHESTRATOR_DIR.parent),
        env={**os.environ},
    )
    _audit("orchestrator_agent_triage", resource=repo_filter, details=json.dumps({"dry_run": dry_run}))
    try:
        return jsonify(json.loads(result.stdout))
    except (json.JSONDecodeError, ValueError):
        if result.returncode != 0:
            return jsonify({"error": "Agent triage failed", "stderr": result.stderr[:500]}), 500
        return jsonify({"error": "Invalid agent triage output", "raw": result.stdout[:500]}), 500


@orchestrator_bp.route("/api/orchestrator/agent-plan")
def api_orchestrator_agent_plan():
    state = _load_orchestrator_state()
    agent_triage = state.get("agent_triage", {})
    if not agent_triage:
        return jsonify({"status": "no_results", "decisions": [], "message": "No agent triage results available. Run agent triage first."})

    result = subprocess.run(
        ["python3", "-m", "scripts.orchestrator", "plan", "--json"],
        capture_output=True, text=True, timeout=60,
        cwd=str(_ORCHESTRATOR_DIR.parent),
    )
    det_plan = {}
    try:
        det_plan = json.loads(result.stdout)
    except (json.JSONDecodeError, ValueError):
        pass

    det_dispatches = det_plan.get("planned_dispatches", [])
    agent_decisions = agent_triage.get("decisions", [])
    agent_map = {d["fingerprint"]: d for d in agent_decisions if d.get("fingerprint")}

    merged = []
    for dispatch in det_dispatches:
        entry = dict(dispatch)
        fp = entry.get("fingerprint", "")
        agent = agent_map.get(fp)
        if agent:
            entry["agent_priority_score"] = agent.get("agent_priority_score", None)
            entry["agent_reasoning"] = agent.get("reasoning", "")
            entry["agent_dispatch"] = agent.get("dispatch", True)
        else:
            entry["agent_priority_score"] = None
            entry["agent_reasoning"] = ""
            entry["agent_dispatch"] = None
        merged.append(entry)

    return jsonify({
        "timestamp": agent_triage.get("timestamp", ""),
        "session_id": agent_triage.get("session_id", ""),
        "strategy_notes": agent_triage.get("strategy_notes", ""),
        "planned_dispatches": merged,
        "total_issues": det_plan.get("total_issues", 0),
        "eligible_issues": det_plan.get("eligible_issues", 0),
    })


@orchestrator_bp.route("/api/orchestrator/effectiveness")
def api_orchestrator_effectiveness():
    state = _load_orchestrator_state()
    dispatch_history = state.get("dispatch_history", {})
    agent_triage = state.get("agent_triage", {})

    with db_connection() as conn:
        verification_records = load_verification_records(RUNS_DIR)
        fp_fix_map = build_fingerprint_fix_map(verification_records)

    agent_decisions = agent_triage.get("decisions", [])
    agent_fps = {d["fingerprint"] for d in agent_decisions if d.get("dispatch")}
    all_agent_fps = {d["fingerprint"] for d in agent_decisions}

    agent_dispatched = 0
    agent_fixed = 0
    det_dispatched = 0
    det_fixed = 0

    for fp, history in dispatch_history.items():
        source = "deterministic"
        if isinstance(history, dict):
            source = history.get("recommendation_source", "deterministic")
        elif isinstance(history, list) and history:
            last = history[-1] if history else {}
            source = last.get("recommendation_source", "deterministic")

        is_fixed = fp in fp_fix_map

        if source == "agent":
            agent_dispatched += 1
            if is_fixed:
                agent_fixed += 1
        else:
            det_dispatched += 1
            if is_fixed:
                det_fixed += 1

    return jsonify({
        "agent": {
            "recommended": len(agent_fps),
            "not_recommended": len(all_agent_fps) - len(agent_fps),
            "dispatched": agent_dispatched,
            "fixed": agent_fixed,
            "fix_rate": round(agent_fixed / max(agent_dispatched, 1) * 100, 1),
        },
        "deterministic": {
            "dispatched": det_dispatched,
            "fixed": det_fixed,
            "fix_rate": round(det_fixed / max(det_dispatched, 1) * 100, 1),
        },
        "has_agent_data": bool(agent_decisions),
        "timestamp": agent_triage.get("timestamp", ""),
    })


@orchestrator_bp.route("/api/orchestrator/fix-rates")
def api_orchestrator_fix_rates():
    with db_connection() as conn:
        issues = query_issues(conn)
        verification_records = load_verification_records(RUNS_DIR)
        fp_fix_map = build_fingerprint_fix_map(verification_records)

        by_cwe: dict[str, dict] = {}
        by_repo: dict[str, dict] = {}
        by_severity: dict[str, dict] = {}

        for issue in issues:
            fp = issue.get("fingerprint", "")
            cwe = issue.get("cwe_family", "unknown") or "unknown"
            repo = issue.get("target_repo", "unknown") or "unknown"
            sev = issue.get("severity_tier", "unknown") or "unknown"
            is_fixed = fp in fp_fix_map or issue.get("derived_state") in ("fixed", "verified_fixed")

            for _group_key, group_dict, group_val in [
                ("cwe", by_cwe, cwe),
                ("repo", by_repo, repo),
                ("severity", by_severity, sev),
            ]:
                if group_val not in group_dict:
                    group_dict[group_val] = {"total": 0, "fixed": 0}
                group_dict[group_val]["total"] += 1
                if is_fixed:
                    group_dict[group_val]["fixed"] += 1

        def _compute_rates(group_dict: dict) -> list[dict]:
            result = []
            for name, counts in sorted(group_dict.items(), key=lambda x: x[1]["total"], reverse=True):
                total = counts["total"]
                fixed = counts["fixed"]
                rate = round(fixed / max(total, 1) * 100, 1)
                result.append({"name": name, "total": total, "fixed": fixed, "fix_rate": rate})
            return result

        total_issues = len(issues)
        total_fixed = sum(
            1 for i in issues
            if i.get("fingerprint", "") in fp_fix_map
            or i.get("derived_state") in ("fixed", "verified_fixed")
        )
        overall_rate = round(total_fixed / max(total_issues, 1) * 100, 1)

        return jsonify({
            "overall": {"total": total_issues, "fixed": total_fixed, "fix_rate": overall_rate},
            "by_cwe_family": _compute_rates(by_cwe),
            "by_repo": _compute_rates(by_repo),
            "by_severity": _compute_rates(by_severity),
        })
