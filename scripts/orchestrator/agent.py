"""LLM-based orchestrator agent for issue triage and prioritisation.

Creates a Devin session that receives structured issue inventory,
fix rates, SLA deadlines, and ACU budget, then emits dispatch
decisions with per-issue priority scores.  The deterministic
``compute_issue_priority`` remains the fallback when the agent
is unavailable or returns an error.
"""

from __future__ import annotations

import argparse
import json
import os
import time
from datetime import datetime, timezone
from typing import Any

from . import state as _state

try:
    from logging_config import setup_logging
except ImportError:
    from scripts.logging_config import setup_logging

from database import get_connection, init_db, insert_audit_log, auto_export_audit_log  # noqa: E402
from fix_learning import FixLearning  # noqa: E402
from issue_tracking import DEFAULT_SLA_HOURS  # noqa: E402

logger = setup_logging(__name__)

try:
    from devin_api import (  # noqa: E402
        DEVIN_API_BASE,
        clean_session_id,
        request_with_retry,
        TERMINAL_STATUSES,
    )
    _HAS_DEVIN_API = True
except ImportError:
    _HAS_DEVIN_API = False

AGENT_TRIAGE_OUTPUT_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "status": {
            "type": "string",
            "enum": ["triaging", "done", "error"],
            "description": "Current phase of the triage session.",
        },
        "decisions": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "fingerprint": {
                        "type": "string",
                        "description": "Issue fingerprint identifier.",
                    },
                    "priority_score": {
                        "type": "number",
                        "description": "Priority score from 0 to 100.",
                    },
                    "reasoning": {
                        "type": "string",
                        "description": "Brief explanation of the prioritisation decision.",
                    },
                    "dispatch": {
                        "type": "boolean",
                        "description": "Whether this issue should be dispatched.",
                    },
                },
                "required": ["fingerprint", "priority_score", "dispatch"],
            },
            "description": "Per-issue triage decisions.",
        },
        "strategy_notes": {
            "type": "string",
            "description": "Overall strategy observations.",
        },
    },
    "required": ["status", "decisions"],
}


def build_agent_triage_input(
    eligible_issues: list[dict[str, Any]],
    fl: FixLearning,
    orch_config: dict[str, Any],
    rate_limiter_info: dict[str, Any],
) -> dict[str, Any]:
    """Build the structured input payload for the agent triage session."""
    issue_inventory = []
    for issue in eligible_issues:
        entry: dict[str, Any] = {
            "fingerprint": issue.get("fingerprint", ""),
            "rule_id": issue.get("rule_id", ""),
            "severity_tier": issue.get("severity_tier", ""),
            "cwe_family": issue.get("cwe_family", ""),
            "target_repo": issue.get("target_repo", ""),
            "file": _state._issue_file(issue),
            "start_line": _state._issue_start_line(issue),
            "message": issue.get("message", ""),
            "appearances": issue.get("appearances", 1),
            "derived_state": issue.get("derived_state", issue.get("status", "new")),
            "sla_status": issue.get("sla_status", ""),
            "deterministic_score": issue.get("priority_score", 0),
        }
        issue_inventory.append(entry)

    family_rates = fl.family_fix_rates()
    fix_rates: dict[str, Any] = {}
    for family, stats in family_rates.items():
        fix_rates[family] = {
            "fix_rate": round(stats.fix_rate, 3),
            "total_sessions": stats.total_sessions,
            "avg_acu": round(stats.avg_acu, 1) if stats.avg_acu else 0,
        }

    sla_deadlines = {
        f"{k}_hours": v for k, v in DEFAULT_SLA_HOURS.items()
    }

    acu_budget = {
        "remaining_sessions": rate_limiter_info.get("remaining", 0),
        "max_sessions": rate_limiter_info.get("max", 20),
        "period_hours": rate_limiter_info.get("period_hours", 24),
    }

    objectives = orch_config.get("objectives", [])

    return {
        "issue_inventory": issue_inventory,
        "fix_rates": fix_rates,
        "sla_deadlines": sla_deadlines,
        "acu_budget": acu_budget,
        "objectives": objectives,
        "total_issues": len(issue_inventory),
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


def _build_agent_triage_prompt(triage_input: dict[str, Any]) -> str:
    """Build the prompt for the orchestrator agent triage session."""
    parts: list[str] = [
        "You are the Orchestrator Triage Agent for a CodeQL security vulnerability fixer.",
        "",
        "Your task is to analyze the following issue inventory and produce prioritised",
        "dispatch decisions. Consider:",
        "- Actual impact and exploitability of each vulnerability",
        "- Cross-repository patterns (shared dependencies, similar vulnerabilities)",
        "- Historical fix rates per CWE family (focus resources on fixable issues)",
        "- SLA deadlines and urgency (breached/at-risk issues need immediate attention)",
        "- ACU budget constraints (limited sessions available)",
        "- Objective alignment (organizational goals)",
        "",
        "## Structured Input",
        "",
        "```json",
        json.dumps(triage_input, indent=2),
        "```",
        "",
        "## Instructions",
        "",
        "1. Analyze each issue in the inventory",
        "2. Assign a priority_score from 0-100 (higher = more urgent)",
        "3. Decide whether each issue should be dispatched (true/false)",
        "4. Provide brief reasoning for each decision",
        "5. Consider cross-repo correlations -- if multiple repos share the same vulnerability pattern, prioritise fixing at the source",
        "6. Factor in fix rates -- if a CWE family has low historical fix rate, consider whether it's worth the ACU budget",
        "7. Respect SLA deadlines -- breached issues should get higher scores",
        "",
        "Update your structured output with your decisions.",
        "",
        "## Output Schema",
        "",
        "```json",
        json.dumps(AGENT_TRIAGE_OUTPUT_SCHEMA, indent=2),
        "```",
    ]
    return "\n".join(parts)


def create_agent_triage_session(
    api_key: str,
    triage_input: dict[str, Any],
    max_acu: int = 5,
) -> dict[str, Any]:
    """Create a Devin session for orchestrator agent triage."""
    if not _HAS_DEVIN_API:
        raise RuntimeError("devin_api module not available")

    prompt = _build_agent_triage_prompt(triage_input)
    n_issues = triage_input.get("total_issues", 0)

    payload: dict[str, Any] = {
        "prompt": prompt,
        "idempotent": True,
        "tags": ["orchestrator-agent", "triage", f"issues-{n_issues}"],
        "title": f"Orchestrator Triage Agent ({n_issues} issues)",
        "structured_output_schema": AGENT_TRIAGE_OUTPUT_SCHEMA,
    }
    if max_acu:
        payload["max_acu_limit"] = max_acu

    url = f"{DEVIN_API_BASE}/sessions"
    resp = request_with_retry("POST", url, api_key, json_data=payload)
    session_id = resp.get("session_id", "")
    session_url = resp.get("url", "")
    if not session_url and session_id:
        session_url = f"https://app.devin.ai/sessions/{clean_session_id(session_id)}"

    return {
        "session_id": session_id,
        "url": session_url,
        "status": "created",
    }


def poll_agent_session(
    api_key: str,
    session_id: str,
    timeout_seconds: int = 300,
    poll_interval: int = 15,
) -> dict[str, Any]:
    """Poll an agent triage session until terminal or timeout."""
    if not _HAS_DEVIN_API:
        raise RuntimeError("devin_api module not available")

    url = f"{DEVIN_API_BASE}/sessions/{clean_session_id(session_id)}"
    start = time.time()

    while time.time() - start < timeout_seconds:
        resp = request_with_retry("GET", url, api_key)
        status = resp.get("status_enum", resp.get("status", ""))
        if status in TERMINAL_STATUSES:
            structured_output = resp.get("structured_output")
            if isinstance(structured_output, str):
                try:
                    structured_output = json.loads(structured_output)
                except (json.JSONDecodeError, ValueError):
                    structured_output = None
            return {
                "session_id": session_id,
                "status": status,
                "structured_output": structured_output,
                "result": resp.get("result", ""),
            }
        time.sleep(poll_interval)

    return {
        "session_id": session_id,
        "status": "timeout",
        "structured_output": None,
        "result": "",
    }


def parse_agent_decisions(
    structured_output: dict[str, Any] | None,
) -> list[dict[str, Any]]:
    """Extract per-issue decisions from agent structured output."""
    if not structured_output:
        return []
    decisions = structured_output.get("decisions", [])
    parsed: list[dict[str, Any]] = []
    for d in decisions:
        fp = d.get("fingerprint", "")
        if not fp:
            continue
        parsed.append({
            "fingerprint": fp,
            "agent_priority_score": float(d.get("priority_score", 0)),
            "reasoning": d.get("reasoning", ""),
            "dispatch": bool(d.get("dispatch", True)),
        })
    return parsed


def merge_agent_scores(
    plan_dispatches: list[dict[str, Any]],
    agent_decisions: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Merge agent scores into the deterministic plan."""
    agent_map = {d["fingerprint"]: d for d in agent_decisions}
    merged = []
    for dispatch in plan_dispatches:
        entry = dict(dispatch)
        fp = entry.get("fingerprint", "")
        agent = agent_map.get(fp)
        if agent:
            entry["agent_priority_score"] = agent["agent_priority_score"]
            entry["agent_reasoning"] = agent.get("reasoning", "")
            entry["agent_dispatch"] = agent.get("dispatch", True)
        else:
            entry["agent_priority_score"] = None
            entry["agent_reasoning"] = ""
            entry["agent_dispatch"] = None
        merged.append(entry)
    return merged


def save_agent_triage_results(
    decisions: list[dict[str, Any]],
    session_id: str,
    strategy_notes: str = "",
) -> None:
    """Persist agent triage results in orchestrator state."""
    state = _state.load_state()
    state["agent_triage"] = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "session_id": session_id,
        "decisions": decisions,
        "strategy_notes": strategy_notes,
    }
    _state.save_state(state)


def load_agent_triage_results() -> dict[str, Any]:
    """Load the most recent agent triage results from state."""
    state = _state.load_state()
    return state.get("agent_triage", {})


def build_effectiveness_report(
    dispatch_history: dict[str, Any],
    agent_triage: dict[str, Any],
    fp_fix_map: dict[str, Any],
) -> dict[str, Any]:
    """Compare effectiveness of agent vs deterministic recommendations."""
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

    agent_recommended = len(agent_fps)
    agent_not_recommended = len(all_agent_fps) - agent_recommended

    return {
        "agent": {
            "recommended": agent_recommended,
            "not_recommended": agent_not_recommended,
            "dispatched": agent_dispatched,
            "fixed": agent_fixed,
            "fix_rate": round(agent_fixed / max(agent_dispatched, 1) * 100, 1),
        },
        "deterministic": {
            "dispatched": det_dispatched,
            "fixed": det_fixed,
            "fix_rate": round(det_fixed / max(det_dispatched, 1) * 100, 1),
        },
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


def cmd_agent_triage(args: argparse.Namespace) -> int:
    """Run the orchestrator agent triage session."""
    repo_filter = args.repo or ""
    dry_run = args.dry_run
    output_json = args.json

    api_key = os.environ.get("DEVIN_API_KEY", "")
    if not api_key and not dry_run:
        logger.error("DEVIN_API_KEY environment variable is required (use --dry-run to skip)")
        return 1

    if not _HAS_DEVIN_API and not dry_run:
        logger.error("devin_api module not available (missing requests library)")
        return 1

    data = _state._compute_eligible_issues(repo_filter)
    eligible = data["eligible"]
    orch_config = data["orch_config"]
    rate_limiter = data["rate_limiter"]
    fl = data["fl"]

    if not eligible:
        result = {
            "status": "no_issues",
            "message": "No eligible issues for agent triage.",
            "decisions": [],
        }
        if output_json:
            print(json.dumps(result))
        else:
            logger.info("No eligible issues for agent triage.")
        return 0

    rate_limiter_info = {
        "remaining": rate_limiter.max_sessions - rate_limiter.recent_count(),
        "max": rate_limiter.max_sessions,
        "period_hours": rate_limiter.period_hours,
    }

    triage_input = build_agent_triage_input(
        eligible, fl, orch_config, rate_limiter_info,
    )

    if dry_run:
        decisions = []
        for issue in eligible:
            decisions.append({
                "fingerprint": issue.get("fingerprint", ""),
                "agent_priority_score": issue.get("priority_score", 0) * 100,
                "reasoning": "Dry run -- mirroring deterministic score.",
                "dispatch": True,
            })

        result = {
            "status": "dry_run",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "total_issues": len(eligible),
            "decisions": decisions,
            "triage_input_preview": {
                "total_issues": triage_input["total_issues"],
                "fix_rates_families": list(triage_input["fix_rates"].keys()),
                "acu_budget": triage_input["acu_budget"],
            },
        }
        if output_json:
            print(json.dumps(result, indent=2))
        else:
            logger.info("[DRY RUN] Agent triage for %d issues", len(eligible))
            for d in decisions:
                logger.info(
                    "  %s: score=%.1f dispatch=%s",
                    d["fingerprint"][:12],
                    d["agent_priority_score"],
                    d["dispatch"],
                )
        return 0

    triage_session = create_agent_triage_session(api_key, triage_input)
    session_id = triage_session["session_id"]

    if not output_json:
        logger.info("Agent triage session created: %s", triage_session["url"])
        logger.info("Polling for results (timeout: 5min)...")

    poll_result = poll_agent_session(api_key, session_id)
    structured_output = poll_result.get("structured_output")
    decisions = parse_agent_decisions(structured_output)

    strategy_notes = ""
    if structured_output:
        strategy_notes = structured_output.get("strategy_notes", "")

    save_agent_triage_results(decisions, session_id, strategy_notes)

    conn = get_connection()
    try:
        init_db(conn)
        insert_audit_log(
            conn, "orchestrator-agent", "agent_triage",
            resource=repo_filter,
            details=json.dumps({
                "session_id": session_id,
                "issues_triaged": len(decisions),
                "session_status": poll_result.get("status", ""),
            }),
        )
        auto_export_audit_log(conn)
    except Exception:
        logger.warning("audit log write/export failed", exc_info=True)
    finally:
        conn.close()

    result = {
        "status": poll_result.get("status", "unknown"),
        "session_id": session_id,
        "session_url": triage_session["url"],
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "total_issues": len(eligible),
        "decisions_received": len(decisions),
        "decisions": decisions,
        "strategy_notes": strategy_notes,
    }

    if output_json:
        print(json.dumps(result, indent=2))
    else:
        logger.info("Agent triage complete: %d decisions", len(decisions))
        for d in decisions:
            logger.info(
                "  %s: score=%.1f dispatch=%s -- %s",
                d["fingerprint"][:12],
                d["agent_priority_score"],
                d["dispatch"],
                d.get("reasoning", "")[:60],
            )
        if strategy_notes:
            logger.info("Strategy: %s", strategy_notes[:200])

    return 0
