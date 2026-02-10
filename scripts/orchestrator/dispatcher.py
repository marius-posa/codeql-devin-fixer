"""Session dispatch, prompt building, and data ingestion.

Handles forming dispatch batches from eligible issues, building
Devin session prompts, creating sessions via the Devin API,
recording dispatched sessions in telemetry, and ingesting scan
results into the database.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from datetime import datetime, timezone
from typing import Any

from . import state as _state

try:
    from logging_config import setup_logging
except ImportError:
    from scripts.logging_config import setup_logging

from database import get_connection, insert_run, insert_audit_log, auto_export_audit_log  # noqa: E402
from fix_learning import CWE_FIX_HINTS, FixLearning  # noqa: E402
from github_utils import gh_headers, parse_repo_url  # noqa: E402

logger = setup_logging(__name__)

try:
    from dispatch_devin import create_devin_session  # noqa: E402
    _HAS_DISPATCH = True
except ImportError:
    _HAS_DISPATCH = False

try:
    from playbook_manager import PlaybookManager  # noqa: E402
except ImportError:
    try:
        from scripts.playbook_manager import PlaybookManager  # noqa: E402
    except ImportError:
        PlaybookManager = None  # type: ignore[assignment,misc]

try:
    from retry_utils import request_with_retry  # noqa: E402
    _HAS_REQUESTS = True
except ImportError:
    _HAS_REQUESTS = False


def cmd_ingest(args: argparse.Namespace) -> int:
    batches_path = args.batches
    issues_path = args.issues
    run_label = args.run_label
    target_repo = args.target_repo

    if not batches_path or not os.path.isfile(batches_path):
        logger.error("Batches file not found: %s", batches_path)
        return 1
    if not issues_path or not os.path.isfile(issues_path):
        logger.error("Issues file not found: %s", issues_path)
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
            fp = _state._fallback_fingerprint(issue)
        issue_fingerprints.append({
            "id": issue.get("id", ""),
            "fingerprint": fp,
            "rule_id": issue.get("rule_id", ""),
            "severity_tier": issue.get("severity_tier", "unknown"),
            "cwe_family": issue.get("cwe_family", "other"),
            "file": _state._issue_file(issue),
            "start_line": _state._issue_start_line(issue),
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
        result = insert_run(conn, telemetry_record)
        conn.commit()

        if result is not None:
            logger.info("Ingested %d issues (%d batches) for %s",
                        len(issues), len(batches), target_repo)
            logger.info("Run label: %s", run_label)
            logger.info("DB row ID: %s", result)
        else:
            logger.info("Run %s already exists in DB (skipped)", run_label)

        state = _state.load_state()
        state["last_cycle"] = datetime.now(timezone.utc).isoformat()
        scan_schedule = state.setdefault("scan_schedule", {})
        scan_schedule[target_repo] = {
            "last_scan": datetime.now(timezone.utc).isoformat(),
            "run_label": run_label,
        }
        _state.save_state(state)

    finally:
        conn.close()

    return 0


def _form_dispatch_batches(
    eligible: list[dict[str, Any]],
    registry: dict[str, Any],
    rate_limiter: _state.RateLimiter,
    remaining_capacity: int,
) -> list[dict[str, Any]]:
    """Group eligible issues into dispatch batches by repo and CWE family."""
    groups: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for issue in eligible:
        key = (issue.get("target_repo", ""), issue.get("cwe_family", "other"))
        groups.setdefault(key, []).append(issue)

    batches: list[dict[str, Any]] = []
    batch_id = 1
    repos_session_count: dict[str, int] = {}

    sorted_groups = sorted(
        groups.items(),
        key=lambda x: max(i.get("priority_score", 0) for i in x[1]),
        reverse=True,
    )

    for (repo_url, family), group_issues in sorted_groups:
        if len(batches) >= remaining_capacity:
            break
        if not rate_limiter.can_create_session():
            break

        repo_config = _state.get_repo_config(registry, repo_url)
        repo_limit = repo_config.get("max_sessions_per_cycle", 5)
        batch_size = repo_config.get("batch_size", 5)

        if repos_session_count.get(repo_url, 0) >= repo_limit:
            continue

        sorted_issues = sorted(group_issues, key=lambda i: i.get("priority_score", 0), reverse=True)
        batch_issues = sorted_issues[:batch_size]

        best_severity = max(
            (i.get("severity_tier", "low") for i in batch_issues),
            key=lambda s: _state.SEVERITY_WEIGHTS.get(s, 0),
        )

        batch = {
            "batch_id": batch_id,
            "target_repo": repo_url,
            "cwe_family": family,
            "severity_tier": best_severity,
            "issue_count": len(batch_issues),
            "max_severity_score": max(
                _state.SEVERITY_WEIGHTS.get(i.get("severity_tier", "low"), 0) * 10
                for i in batch_issues
            ),
            "issues": [
                {
                    "id": i.get("latest_issue_id", "") or i.get("fingerprint", ""),
                    "rule_id": i.get("rule_id", ""),
                    "rule_name": i.get("rule_id", ""),
                    "severity_tier": i.get("severity_tier", ""),
                    "severity_score": _state.SEVERITY_WEIGHTS.get(i.get("severity_tier", ""), 0) * 10,
                    "cwe_family": i.get("cwe_family", ""),
                    "cwes": [],
                    "locations": [{"file": i.get("file", ""), "start_line": i.get("start_line", 0)}],
                    "message": i.get("description", ""),
                    "fingerprint": i.get("fingerprint", ""),
                }
                for i in batch_issues
            ],
        }

        batches.append(batch)
        batch_id += 1
        repos_session_count[repo_url] = repos_session_count.get(repo_url, 0) + 1

    return batches


def _build_orchestrator_prompt(
    batch: dict[str, Any],
    repo_config: dict[str, Any],
    fl: FixLearning,
) -> str:
    """Build a Devin session prompt from orchestrator batch data.

    Intentionally separate from dispatch_devin.build_batch_prompt because the
    orchestrator operates on aggregated issue state (merged across runs) rather
    than raw SARIF batches.  The two prompt builders share the same essential
    elements (IDs, files, severity, fix hints) but accept different input
    schemas.
    """
    repo_url = batch["target_repo"]
    family = batch["cwe_family"]
    default_branch = repo_config.get("default_branch", "main")
    issues = batch["issues"]

    issue_ids = [i.get("id", "") for i in issues if i.get("id")]
    ids_str = ", ".join(issue_ids) if issue_ids else "N/A"

    parts: list[str] = [
        f"Fix {batch['issue_count']} CodeQL security issue(s) in {repo_url} "
        f"(branch: {default_branch}).",
        "",
        f"Issue IDs: {ids_str}",
        f"Category: {family} | Severity: {batch['severity_tier'].upper()}",
        "",
    ]

    fix_hint = CWE_FIX_HINTS.get(family)
    if fix_hint:
        parts.extend([f"Fix pattern hint: {fix_hint}", ""])

    context = fl.prompt_context_for_family(family)
    if context:
        for line in context.split("\n"):
            if line and not line.startswith("Fix pattern hint"):
                parts.append(line)
        parts.append("")

    parts.extend(["Issues to fix:", ""])

    file_list: set[str] = set()
    for idx, issue in enumerate(issues, 1):
        issue_id = issue.get("id", f"issue-{idx}")
        file_path = ""
        start_line = 0
        for loc in issue.get("locations", []):
            if loc.get("file"):
                file_path = loc["file"]
                start_line = loc.get("start_line", 0)
                file_list.add(file_path)

        loc_str = f"{file_path}:{start_line}" if file_path else "unknown"
        parts.extend([
            f"### {issue_id}: {issue.get('rule_id', 'unknown')}",
            f"- Severity: {issue.get('severity_tier', 'unknown').upper()}",
            f"- Location: {loc_str}",
            f"- Description: {issue.get('message', 'No description')}",
            "",
        ])

    ids_tag = ",".join(issue_ids[:6]) if issue_ids else f"batch-{batch['batch_id']}"
    pr_title = f"fix({ids_tag}): resolve {family} security issues"

    parts.extend([
        "Instructions:",
        f"1. Clone {repo_url} and create a new branch from {default_branch}.",
        "2. Fix ALL the issues listed above.",
        "3. Ensure fixes don't break existing functionality.",
        "4. Run existing tests if available to verify.",
        f"5. Create a PR on {repo_url} with a clear description listing each issue ID fixed.",
        f"6. Title the PR exactly: '{pr_title}'",
        f"7. In the PR body, list each issue ID ({ids_str}) and describe the fix applied.",
        "",
        "Files to focus on:",
    ])
    for f in sorted(file_list):
        parts.append(f"- {f}")

    return "\n".join(parts)


def _record_dispatch_session(
    batch: dict[str, Any],
    session_id: str,
    session_url: str,
) -> None:
    """Record a dispatched session in the telemetry DB."""
    repo_url = batch["target_repo"]
    now = datetime.now(timezone.utc).isoformat()

    issue_ids = [
        i.get("id", "") or i.get("fingerprint", "")
        for i in batch.get("issues", [])
    ]

    run_data: dict[str, Any] = {
        "target_repo": repo_url,
        "fork_url": "",
        "run_number": 0,
        "run_id": "",
        "run_url": "",
        "run_label": f"orchestrator_dispatch_{now.replace(':', '-')}_{batch['batch_id']}",
        "timestamp": now,
        "issues_found": 0,
        "batches_created": 1,
        "zero_issue_run": True,
        "severity_breakdown": {},
        "category_breakdown": {},
        "sessions": [
            {
                "session_id": session_id,
                "session_url": session_url,
                "batch_id": batch["batch_id"],
                "status": "created",
                "issue_ids": issue_ids,
                "pr_url": "",
            }
        ],
        "issue_fingerprints": [],
    }

    conn = get_connection()
    try:
        insert_run(conn, run_data)
        conn.commit()
    finally:
        conn.close()


def cmd_dispatch(args: argparse.Namespace) -> int:
    """Execute the dispatch plan: create Devin sessions for eligible issues."""
    repo_filter = args.repo or ""
    dry_run = args.dry_run
    output_json = args.json
    max_sessions_override = getattr(args, "max_sessions", None)

    api_key = os.environ.get("DEVIN_API_KEY", "")
    if not api_key and not dry_run:
        logger.error("DEVIN_API_KEY environment variable is required (use --dry-run to skip)")
        return 1

    if not _HAS_DISPATCH and not dry_run:
        logger.error("dispatch_devin module not available (missing requests library)")
        return 1

    playbook_mgr = None
    if PlaybookManager is not None:
        playbooks_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "playbooks")
        if os.path.isdir(playbooks_dir):
            playbook_mgr = PlaybookManager(playbooks_dir)
            if api_key and playbook_mgr.available_families:
                synced = playbook_mgr.sync_to_devin_api(api_key)
                if synced:
                    logger.info("Synced %d playbook(s) to Devin API", len(synced))

    data = _state._compute_eligible_issues(repo_filter)
    eligible = data["eligible"]
    registry = data["registry"]
    rate_limiter = data["rate_limiter"]
    fl = data["fl"]
    state = data["state"]
    remaining = data["remaining_capacity"]

    if max_sessions_override is not None:
        remaining = min(remaining, max_sessions_override)

    if not eligible:
        msg = "No eligible issues to dispatch."
        if output_json:
            print(json.dumps({"status": "no_issues", "message": msg, "sessions_created": 0, "sessions_failed": 0, "sessions_dry_run": 0, "total_eligible": 0, "batches_formed": 0, "rate_limit_remaining": remaining, "results": [], "timestamp": datetime.now(timezone.utc).isoformat(), "repo_filter": repo_filter, "dry_run": dry_run}))
        else:
            logger.info("%s", msg)
        return 0

    batches = _form_dispatch_batches(eligible, registry, rate_limiter, remaining)

    if not batches:
        msg = "No batches to dispatch (rate limit or per-repo limits reached)."
        if output_json:
            print(json.dumps({"status": "rate_limited", "message": msg, "sessions_created": 0}))
        else:
            logger.info("%s", msg)
        return 0

    results: list[dict[str, Any]] = []
    dispatch_history = state.get("dispatch_history", {})

    for batch in batches:
        repo_url = batch["target_repo"]
        repo_config = _state.get_repo_config(registry, repo_url)

        prompt = _build_orchestrator_prompt(batch, repo_config, fl)

        if dry_run:
            if not output_json:
                logger.info(
                    "[DRY RUN] Would dispatch batch %d: %s (%d issues) for %s",
                    batch['batch_id'], batch['cwe_family'],
                    batch['issue_count'], repo_url,
                )
            results.append({
                "batch_id": batch["batch_id"],
                "target_repo": repo_url,
                "cwe_family": batch["cwe_family"],
                "issue_count": batch["issue_count"],
                "session_id": "dry-run",
                "session_url": "",
                "status": "dry-run",
            })
            continue

        if not rate_limiter.can_create_session():
            if not output_json:
                logger.warning("Rate limit reached, skipping batch %d", batch['batch_id'])
            results.append({
                "batch_id": batch["batch_id"],
                "target_repo": repo_url,
                "cwe_family": batch["cwe_family"],
                "issue_count": batch["issue_count"],
                "session_id": "",
                "session_url": "",
                "status": "rate_limited",
            })
            continue

        max_acu = fl.compute_acu_budget(batch["cwe_family"])

        playbook_id = ""
        if playbook_mgr:
            playbook_id = playbook_mgr.get_devin_playbook_id(batch["cwe_family"])

        try:
            result = create_devin_session(api_key, prompt, batch, max_acu, playbook_id)
            session_id = result["session_id"]
            session_url = result["url"]
            if not output_json:
                logger.info("Session created for batch %d: %s", batch['batch_id'], session_url)

            rate_limiter.record_session()

            for issue in batch["issues"]:
                fp = issue.get("fingerprint", "")
                if not fp:
                    continue
                if fp not in dispatch_history:
                    dispatch_history[fp] = {"dispatch_count": 0, "fingerprint": fp}
                dispatch_history[fp]["dispatch_count"] += 1
                dispatch_history[fp]["last_dispatched"] = datetime.now(timezone.utc).isoformat()
                dispatch_history[fp]["last_session_id"] = session_id
                dispatch_history[fp]["consecutive_failures"] = 0

            results.append({
                "batch_id": batch["batch_id"],
                "target_repo": repo_url,
                "cwe_family": batch["cwe_family"],
                "issue_count": batch["issue_count"],
                "session_id": session_id,
                "session_url": session_url,
                "status": "created",
            })

            _record_dispatch_session(batch, session_id, session_url)

            time.sleep(2)

        except Exception as e:
            if not output_json:
                logger.error("ERROR creating session for batch %d: %s", batch['batch_id'], e)
            for issue in batch["issues"]:
                fp = issue.get("fingerprint", "")
                if not fp:
                    continue
                if fp not in dispatch_history:
                    dispatch_history[fp] = {"dispatch_count": 0, "fingerprint": fp}
                prev_failures = dispatch_history[fp].get("consecutive_failures", 0)
                dispatch_history[fp]["consecutive_failures"] = prev_failures + 1
                dispatch_history[fp]["last_dispatched"] = datetime.now(timezone.utc).isoformat()
            results.append({
                "batch_id": batch["batch_id"],
                "target_repo": repo_url,
                "cwe_family": batch["cwe_family"],
                "issue_count": batch["issue_count"],
                "session_id": "",
                "session_url": "",
                "status": f"error: {e}",
            })

    state["dispatch_history"] = dispatch_history
    state["rate_limiter"] = rate_limiter.to_dict()
    state["last_cycle"] = datetime.now(timezone.utc).isoformat()
    _state.save_state(state)

    sessions_created = len([r for r in results if r["status"] == "created"])
    sessions_failed = len([r for r in results if r["status"].startswith("error")])
    sessions_dry_run = len([r for r in results if r["status"] == "dry-run"])

    summary = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "repo_filter": repo_filter,
        "dry_run": dry_run,
        "total_eligible": len(eligible),
        "batches_formed": len(batches),
        "sessions_created": sessions_created,
        "sessions_failed": sessions_failed,
        "sessions_dry_run": sessions_dry_run,
        "rate_limit_remaining": rate_limiter.max_sessions - rate_limiter.recent_count(),
        "results": results,
    }

    conn = get_connection()
    try:
        insert_audit_log(
            conn, "orchestrator-cli", "orchestrator_dispatch",
            resource=repo_filter,
            details=json.dumps({"dry_run": dry_run, "sessions_created": sessions_created, "batches": len(batches)}),
        )
        auto_export_audit_log(conn)
    except Exception:
        logger.warning("audit log write/export failed", exc_info=True)
    finally:
        conn.close()

    if output_json:
        print(json.dumps(summary, indent=2))
    else:
        from .cli import _print_dispatch_summary
        _print_dispatch_summary(summary)

    return 1 if sessions_failed > 0 and sessions_created == 0 else 0


def _collect_fix_examples(
    prs: list[dict[str, Any]],
    fp_fix_map: dict[str, dict[str, Any]],
    github_token: str = "",
    max_diff_chars: int = 4000,
) -> list[dict[str, Any]]:
    """Fetch diffs from verified-fix PRs and return fix example records."""
    if not _HAS_REQUESTS or not github_token:
        return []
    examples: list[dict[str, Any]] = []
    seen_prs: set[str] = set()
    for fix_info in fp_fix_map.values():
        pr_url = fix_info.get("fixed_by_pr", "")
        if not pr_url or pr_url in seen_prs:
            continue
        seen_prs.add(pr_url)
        pr_match = None
        for pr in prs:
            if pr.get("html_url") == pr_url:
                pr_match = pr
                break
        if not pr_match or not pr_match.get("merged"):
            continue
        repo_url = pr_match.get("target_repo", "")
        if not repo_url:
            head = pr_match.get("head", {})
            repo_obj = head.get("repo", {}) if isinstance(head, dict) else {}
            if isinstance(repo_obj, dict):
                repo_url = repo_obj.get("html_url", "")
        if not repo_url:
            continue
        try:
            owner, repo = parse_repo_url(repo_url)
        except ValueError:
            continue
        pr_number = pr_match.get("number")
        if not pr_number:
            import re as _re
            m = _re.search(r"/pull/(\d+)", pr_url)
            if m:
                pr_number = int(m.group(1))
        if not pr_number:
            continue
        diff_url = f"https://api.github.com/repos/{owner}/{repo}/pulls/{pr_number}"
        try:
            resp = request_with_retry(
                "GET", diff_url,
                headers={**gh_headers(github_token), "Accept": "application/vnd.github.diff"},
                timeout=30,
            )
            if resp.status_code == 200:
                diff_text = resp.text[:max_diff_chars]
                examples.append({
                    "pr_url": pr_url,
                    "repo": f"{owner}/{repo}",
                    "diff_truncated": diff_text,
                    "fingerprints": [
                        fp for fp, info in fp_fix_map.items()
                        if info.get("fixed_by_pr") == pr_url
                    ],
                })
        except Exception:
            continue
    return examples
