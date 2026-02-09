#!/usr/bin/env python3
"""Push run telemetry to the codeql-devin-fixer repo via the GitHub Contents API.

After each action run, this script collects the run metadata (target repo,
fork URL, issues found, batches created, Devin sessions started) and commits
a JSON file to ``telemetry/runs/`` in the **action repository** (the repo
where codeql-devin-fixer lives, NOT the fork).  This centralises telemetry
across all target repos so the dashboard can aggregate everything.

The file is named ``{owner}_{repo}_run_{number}_{timestamp}.json`` to avoid
collisions across concurrent runs on different targets.

Environment variables
---------------------
GITHUB_TOKEN : str
    PAT with ``repo`` scope -- needed to push to the action repo.
ACTION_REPO : str
    Full name of the action repo, e.g. ``your-username/codeql-devin-fixer``.
TARGET_REPO : str
    HTTPS URL of the target repo that was scanned.
FORK_URL : str
    HTTPS URL of the fork used for scanning.
RUN_NUMBER : str
    GitHub Actions run number.
RUN_LABEL : str
    Timestamped label for this run.
"""

import base64
import json
import os
import sys
from datetime import datetime, timezone
from urllib.parse import urlparse

try:
    from github_utils import gh_headers
    from logging_config import setup_logging
    from parse_sarif import BATCHES_SCHEMA_VERSION, ISSUES_SCHEMA_VERSION
    from retry_utils import request_with_retry
except ImportError:
    from scripts.github_utils import gh_headers
    from scripts.logging_config import setup_logging
    from scripts.parse_sarif import BATCHES_SCHEMA_VERSION, ISSUES_SCHEMA_VERSION
    from scripts.retry_utils import request_with_retry

logger = setup_logging(__name__)


def _repo_short_name(url: str) -> str:
    name = url.rstrip("/")
    parsed = urlparse(name)
    if parsed.hostname == "github.com":
        name = parsed.path.strip("/")
    return name.replace("/", "_")


def load_output_file(output_dir: str, filename: str) -> list | dict | None:
    path = os.path.join(output_dir, filename)
    if os.path.isfile(path):
        with open(path) as f:
            return json.load(f)
    return None


MAX_DIFF_SIZE = 5000


def _collect_fix_examples(
    output_dir: str,
    sessions: list,
    batches: list,
) -> list[dict]:
    """Collect fix diffs from successful sessions to store as fix examples.

    Reads ``fix_diffs.json`` from *output_dir* (produced by a post-session
    diff collection step) and correlates each diff with its CWE family and
    file path.  Only diffs from sessions with ``finished`` or ``stopped``
    status are included.
    """
    diff_data = load_output_file(output_dir, "fix_diffs.json")
    if not diff_data:
        return []
    if not isinstance(diff_data, list):
        diff_data = [diff_data]

    finished_session_ids: set[str] = set()
    session_to_batch: dict[str, int] = {}
    for s in sessions:
        sid = s.get("session_id", "")
        status = s.get("status", "")
        if status in ("finished", "stopped"):
            finished_session_ids.add(sid)
        bid = s.get("batch_id")
        if bid is not None:
            session_to_batch[sid] = bid

    batch_families: dict[int, str] = {}
    batch_files: dict[int, list[str]] = {}
    for b in batches:
        bid = b.get("batch_id")
        if bid is not None:
            batch_families[bid] = b.get("cwe_family", "other")
            files = []
            for issue in b.get("issues", []):
                for loc in issue.get("locations", []):
                    f = loc.get("file", "")
                    if f:
                        files.append(f)
            batch_files[bid] = files

    examples: list[dict] = []
    for entry in diff_data:
        sid = entry.get("session_id", "")
        if sid and sid not in finished_session_ids:
            continue
        diff = entry.get("diff", "")
        if not diff:
            continue
        if len(diff) > MAX_DIFF_SIZE:
            diff = diff[:MAX_DIFF_SIZE]

        bid = session_to_batch.get(sid)
        family = batch_families.get(bid, "other") if bid is not None else entry.get("cwe_family", "other")
        file_path = entry.get("file", "")
        if not file_path and bid is not None:
            files = batch_files.get(bid, [])
            file_path = files[0] if files else ""

        examples.append({
            "cwe_family": family,
            "file": file_path,
            "diff": diff,
            "session_id": sid,
        })
    return examples


def build_telemetry_record(output_dir: str) -> dict:
    target_repo = os.environ.get("TARGET_REPO", "")
    fork_url = os.environ.get("FORK_URL", "")
    run_number = os.environ.get("RUN_NUMBER", "0")
    run_id = os.environ.get("RUN_ID", "")
    run_label = os.environ.get("RUN_LABEL", "")
    action_repo = os.environ.get("ACTION_REPO", "")

    raw_all_issues = load_output_file(output_dir, "all_issues.json") or []
    if isinstance(raw_all_issues, dict) and "schema_version" in raw_all_issues:
        all_issues = raw_all_issues.get("issues", [])
    else:
        all_issues = raw_all_issues if isinstance(raw_all_issues, list) else []

    raw_issues = load_output_file(output_dir, "issues.json") or []
    if isinstance(raw_issues, dict) and "schema_version" in raw_issues:
        v = raw_issues["schema_version"]
        if v != ISSUES_SCHEMA_VERSION:
            logger.error(
                "issues.json schema version '%s' does not match expected '%s'",
                v, ISSUES_SCHEMA_VERSION,
            )
            sys.exit(1)
        issues = raw_issues.get("issues", [])
    else:
        issues = raw_issues if isinstance(raw_issues, list) else []

    if not all_issues:
        all_issues = issues
    raw_batches = load_output_file(output_dir, "batches.json") or []
    if isinstance(raw_batches, dict) and "schema_version" in raw_batches:
        v = raw_batches["schema_version"]
        if v != BATCHES_SCHEMA_VERSION:
            logger.error(
                "batches.json schema version '%s' does not match expected '%s'",
                v, BATCHES_SCHEMA_VERSION,
            )
            sys.exit(1)
        batches = raw_batches.get("batches", [])
    else:
        batches = raw_batches if isinstance(raw_batches, list) else []
    sessions = load_output_file(output_dir, "sessions.json") or []

    severity_breakdown: dict[str, int] = {}
    category_breakdown: dict[str, int] = {}
    issue_fingerprints: list[dict] = []
    for issue in all_issues:
        tier = issue.get("severity_tier", "unknown")
        severity_breakdown[tier] = severity_breakdown.get(tier, 0) + 1
        family = issue.get("cwe_family", "other")
        category_breakdown[family] = category_breakdown.get(family, 0) + 1
        fp = issue.get("fingerprint", "")
        if fp:
            issue_fingerprints.append({
                "id": issue.get("id", ""),
                "fingerprint": fp,
                "rule_id": issue.get("rule_id", ""),
                "severity_tier": tier,
                "cwe_family": family,
                "file": (issue.get("locations") or [{}])[0].get("file", ""),
                "start_line": (issue.get("locations") or [{}])[0].get("start_line", 0),
            })

    session_records = []
    for s in sessions:
        session_records.append({
            "session_id": s.get("session_id", ""),
            "session_url": s.get("url", ""),
            "batch_id": s.get("batch_id"),
            "status": s.get("status", "unknown"),
            "issue_ids": [],
        })
        batch = next((b for b in batches if b.get("batch_id") == s.get("batch_id")), None)
        if batch:
            session_records[-1]["issue_ids"] = [
                i.get("id", "") for i in batch.get("issues", [])
            ]

    fix_examples = _collect_fix_examples(output_dir, sessions, batches)

    if issues and not issue_fingerprints:
        logger.warning(
            "issues.json has entries but none contain a fingerprint. "
            "Cross-run issue tracking will be degraded for this run."
        )
    redact_urls = os.environ.get("REDACT_TELEMETRY_URLS", "false").lower() == "true"

    run_url = ""
    if action_repo and run_id and not redact_urls:
        run_url = f"https://github.com/{action_repo}/actions/runs/{run_id}"

    record: dict = {
        "target_repo": target_repo,
        "fork_url": fork_url if not redact_urls else "",
        "run_number": int(run_number),
        "run_id": run_id,
        "run_url": run_url,
        "run_label": run_label,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "issues_found": len(all_issues),
        "issues_dispatched": len(issues),
        "severity_breakdown": severity_breakdown,
        "category_breakdown": category_breakdown,
        "batches_created": len(batches),
        "sessions": session_records,
        "issue_fingerprints": issue_fingerprints,
        "zero_issue_run": len(all_issues) == 0,
    }
    if fix_examples:
        record["fix_examples"] = fix_examples
    return record


def push_telemetry(token: str, action_repo: str, record: dict) -> bool:
    repo_short = _repo_short_name(record["target_repo"])
    run_id = record.get("run_id", "") or str(record["run_number"])
    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    filename = f"{repo_short}_run_{run_id}_{ts}.json"
    path = f"telemetry/runs/{filename}"

    content_b64 = base64.b64encode(
        json.dumps(record, indent=2).encode()
    ).decode()

    url = f"https://api.github.com/repos/{action_repo}/contents/{path}"
    payload = {
        "message": f"telemetry: {record['target_repo']} run {run_id}",
        "content": content_b64,
    }

    resp = request_with_retry(
        "PUT", url, headers=gh_headers(token), json=payload, timeout=30,
    )
    if resp.status_code in (200, 201):
        logger.info("Telemetry pushed: %s", path)
        return True

    logger.warning("Failed to push telemetry (%d): %s", resp.status_code, resp.text[:200])
    return False


def main() -> None:
    output_dir = sys.argv[1] if len(sys.argv) > 1 else "output"
    token = os.environ.get("GITHUB_TOKEN", "")
    action_repo = os.environ.get("ACTION_REPO", "")

    if not token:
        logger.warning("GITHUB_TOKEN not set; skipping telemetry push")
        return
    if not action_repo:
        logger.warning("ACTION_REPO not set; skipping telemetry push")
        return

    record = build_telemetry_record(output_dir)
    logger.info(
        "Telemetry record: %s | %d issues | %d batches | %d sessions",
        record['target_repo'], record['issues_found'],
        record['batches_created'], len(record['sessions']),
    )

    if record["issues_found"] == 0:
        logger.info("No issues found in this run. Flagging telemetry as zero-issue run.")

    push_telemetry(token, action_repo, record)


if __name__ == "__main__":
    main()
