#!/usr/bin/env python3
"""Compare post-fix SARIF results against original issue fingerprints.

After Devin creates a PR and CodeQL is re-run on the PR branch, this script
compares the new SARIF output against the original issue fingerprints from
the dispatching run.  The result is a per-issue verification report that
records which specific vulnerabilities were resolved and which persist.

The verification data is structured so it can be pushed back into the
telemetry system, giving reviewers granular confidence that fixes work.

Usage
-----
::

    python verify_results.py <new_sarif_path> <original_issues_json> [output_dir]

Environment variables
---------------------
PR_TITLE : str
    Title of the pull request (used to extract issue IDs and CWE family).
PR_NUMBER : str
    PR number for the verification record.
PR_URL : str
    Full URL of the pull request.
SESSION_ID : str
    Devin session ID that created the PR (extracted from PR body).
"""

from __future__ import annotations

import json
import os
import re
import sys
import tempfile
from datetime import datetime, timezone
from typing import Any

try:
    from parse_sarif import compute_fingerprint, parse_sarif
    from pipeline_config import IssueFingerprint
except ImportError:
    from scripts.parse_sarif import compute_fingerprint, parse_sarif
    from scripts.pipeline_config import IssueFingerprint


def extract_issue_ids_from_title(title: str) -> list[str]:
    """Extract CQLF-R*-* issue IDs from a PR title."""
    match = re.search(r"fix\(([^)]+)\)", title)
    if not match:
        return []
    raw = match.group(1)
    return [iid.strip() for iid in raw.split(",") if iid.strip()]


def extract_run_number_from_ids(issue_ids: list[str]) -> str:
    """Extract the run number from issue IDs like CQLF-R22-0001."""
    for iid in issue_ids:
        m = re.match(r"CQLF-R(\d+)-\d+", iid, re.IGNORECASE)
        if m:
            return m.group(1)
    return ""


def extract_cwe_family_from_title(title: str) -> str:
    """Extract the CWE family from a PR title like 'resolve injection security issues'."""
    match = re.search(r"resolve (\S+) security issues", title)
    return match.group(1) if match else ""


def load_original_fingerprints(issues_path: str) -> list[IssueFingerprint]:
    """Load original issue fingerprints from an issues.json file.

    Handles multiple formats:
    - Envelope with ``issues`` key: ``{"schema_version": ..., "issues": [...]}``
    - Envelope with ``issue_fingerprints`` key (telemetry format)
    - Flat list of issues

    For each issue, location data (``file``, ``start_line``) is read from
    ``locations[0]`` if present, otherwise from top-level keys (as stored
    in telemetry fingerprint records).
    """
    with open(issues_path) as f:
        data = json.load(f)
    if isinstance(data, dict) and "issues" in data:
        issues = data["issues"]
    elif isinstance(data, dict) and "issue_fingerprints" in data:
        issues = data["issue_fingerprints"]
    elif isinstance(data, list):
        issues = data
    else:
        return []

    fingerprints: list[IssueFingerprint] = []
    for issue in issues:
        fp = issue.get("fingerprint", "")
        if not fp:
            fp = compute_fingerprint(issue)
        locs = issue.get("locations") or []
        if locs:
            file_val = locs[0].get("file", "")
            line_val = locs[0].get("start_line", 0)
        else:
            file_val = issue.get("file", "")
            line_val = issue.get("start_line", 0)
        fingerprints.append({
            "id": issue.get("id", ""),
            "fingerprint": fp,
            "rule_id": issue.get("rule_id", ""),
            "severity_tier": issue.get("severity_tier", ""),
            "cwe_family": issue.get("cwe_family", ""),
            "file": file_val,
            "start_line": line_val,
            "message": issue.get("message", ""),
        })
    return fingerprints


def compute_new_fingerprints(sarif_path: str) -> set[str]:
    """Parse a SARIF file and return the set of fingerprints found."""
    issues = parse_sarif(sarif_path)
    fps: set[str] = set()
    for issue in issues:
        fp = issue.get("fingerprint", "") or compute_fingerprint(issue)
        if fp:
            fps.add(fp)
    return fps


def find_original_issues(logs_dir: str, run_number: str) -> str:
    """Locate the issues.json file for a given run number in the logs directory.

    Searches ``logs/run-{N}-*/issues.json`` patterns.
    """
    if not os.path.isdir(logs_dir):
        return ""
    for entry in sorted(os.listdir(logs_dir)):
        run_dir = os.path.join(logs_dir, entry)
        if not os.path.isdir(run_dir):
            continue
        if f"run-{run_number}-" in entry or entry == f"run-{run_number}":
            issues_path = os.path.join(run_dir, "issues.json")
            if os.path.isfile(issues_path):
                return issues_path
    return ""


def find_original_issues_from_telemetry(
    telemetry_dir: str, run_number: str,
) -> str:
    """Search telemetry records for original issue fingerprints by run number.

    Returns the path to a temporary JSON file containing the fingerprints,
    or an empty string if no matching record is found.
    """
    if not os.path.isdir(telemetry_dir):
        return ""
    for fname in sorted(os.listdir(telemetry_dir)):
        if not fname.endswith(".json") or fname.startswith("verification_"):
            continue
        fpath = os.path.join(telemetry_dir, fname)
        try:
            with open(fpath) as f:
                data = json.load(f)
            if str(data.get("run_number", "")) == str(run_number):
                fps = data.get("issue_fingerprints", [])
                if fps:
                    out = os.path.join(
                        tempfile.gettempdir(),
                        f".tmp_original_{run_number}.json",
                    )
                    with open(out, "w") as f:
                        json.dump({"issue_fingerprints": fps}, f, indent=2)
                    return out
        except (json.JSONDecodeError, OSError):
            continue
    return ""


def compare_fingerprints(
    original_fps: list[dict[str, Any]],
    new_fps: set[str],
    target_issue_ids: list[str] | None = None,
) -> dict[str, Any]:
    """Compare original issue fingerprints against post-fix scan results.

    Returns a verification report with per-issue status:
    - ``verified_fixed``: fingerprint no longer present in new scan
    - ``still_present``: fingerprint still detected
    - ``not_targeted``: issue was not in the targeted set (if target_issue_ids given)
    """
    targeted_ids = set(target_issue_ids) if target_issue_ids else None

    verified_fixed: list[dict[str, Any]] = []
    still_present: list[dict[str, Any]] = []
    not_targeted: list[dict[str, Any]] = []

    for orig in original_fps:
        entry = {
            "id": orig["id"],
            "fingerprint": orig["fingerprint"],
            "rule_id": orig["rule_id"],
            "severity_tier": orig["severity_tier"],
            "cwe_family": orig["cwe_family"],
            "file": orig["file"],
            "start_line": orig["start_line"],
        }

        if targeted_ids and orig["id"] not in targeted_ids:
            not_targeted.append(entry)
            continue

        if orig["fingerprint"] in new_fps:
            entry["status"] = "still_present"
            still_present.append(entry)
        else:
            entry["status"] = "verified_fixed"
            verified_fixed.append(entry)

    total_targeted = len(verified_fixed) + len(still_present)

    return {
        "verified_fixed": verified_fixed,
        "still_present": still_present,
        "not_targeted": not_targeted,
        "summary": {
            "total_original": len(original_fps),
            "total_targeted": total_targeted,
            "fixed_count": len(verified_fixed),
            "remaining_count": len(still_present),
            "fix_rate": round(
                len(verified_fixed) / max(total_targeted, 1) * 100, 1
            ),
            "new_issues_in_scan": len(
                new_fps - {o["fingerprint"] for o in original_fps}
            ),
        },
    }


def build_verification_record(
    comparison: dict[str, Any],
    pr_title: str = "",
    pr_number: str = "",
    pr_url: str = "",
    session_id: str = "",
    run_number: str = "",
    cwe_family: str = "",
) -> dict[str, Any]:
    """Build a structured verification record for telemetry storage."""
    return {
        "verified_at": datetime.now(timezone.utc).isoformat(),
        "pr_number": pr_number,
        "pr_url": pr_url,
        "pr_title": pr_title,
        "session_id": session_id,
        "source_run_number": run_number,
        "cwe_family": cwe_family,
        "summary": comparison["summary"],
        "verified_fixed": [
            {
                "id": item["id"],
                "fingerprint": item["fingerprint"],
                "rule_id": item["rule_id"],
                "severity_tier": item["severity_tier"],
                "cwe_family": item["cwe_family"],
                "file": item["file"],
            }
            for item in comparison["verified_fixed"]
        ],
        "still_present": [
            {
                "id": item["id"],
                "fingerprint": item["fingerprint"],
                "rule_id": item["rule_id"],
                "severity_tier": item["severity_tier"],
                "cwe_family": item["cwe_family"],
                "file": item["file"],
            }
            for item in comparison["still_present"]
        ],
    }


def format_pr_comment(record: dict[str, Any]) -> str:
    """Format a verification record as a Markdown PR comment."""
    summary = record["summary"]
    lines = ["## CodeQL Fix Verification\n"]

    if summary["fixed_count"] == summary["total_targeted"] and summary["total_targeted"] > 0:
        lines.append(
            f"All **{summary['fixed_count']}** targeted issue(s) "
            f"have been **verified as fixed**.\n"
        )
    elif summary["fixed_count"] > 0:
        lines.append(
            f"**{summary['fixed_count']}/{summary['total_targeted']}** "
            f"targeted issue(s) verified as fixed "
            f"({summary['fix_rate']}% fix rate).\n"
        )
    else:
        lines.append(
            f"**{summary['remaining_count']}** targeted issue(s) "
            f"still detected on this branch.\n"
        )

    if record["verified_fixed"]:
        lines.append("### Fixed Issues\n")
        lines.append("| Issue ID | Rule | Severity | File |")
        lines.append("|----------|------|----------|------|")
        for item in record["verified_fixed"]:
            fname = item["file"].split("/")[-1] if item["file"] else "-"
            lines.append(
                f"| {item['id']} | `{item['rule_id']}` "
                f"| {item['severity_tier']} | {fname} |"
            )

    if record["still_present"]:
        lines.append("\n### Remaining Issues\n")
        lines.append("| Issue ID | Rule | Severity | File |")
        lines.append("|----------|------|----------|------|")
        for item in record["still_present"]:
            fname = item["file"].split("/")[-1] if item["file"] else "-"
            lines.append(
                f"| {item['id']} | `{item['rule_id']}` "
                f"| {item['severity_tier']} | {fname} |"
            )

    if summary["new_issues_in_scan"] > 0:
        lines.append(
            f"\n> **Note:** {summary['new_issues_in_scan']} new issue(s) "
            f"detected that were not in the original scan."
        )

    return "\n".join(lines)


def determine_label(record: dict[str, Any]) -> str:
    """Determine the PR label based on verification results."""
    summary = record["summary"]
    if summary["total_targeted"] == 0:
        return "codeql-needs-work"
    if summary["fixed_count"] == summary["total_targeted"]:
        return "verified-fix"
    if summary["fixed_count"] > 0:
        return "codeql-partial-fix"
    return "codeql-needs-work"


def extract_session_id_from_body(body: str) -> str:
    """Extract a Devin session ID from a PR body.

    Looks for ``devin.ai/sessions/<hex>`` URLs or ``session_id: <hex>``
    patterns commonly found in Devin-generated PR descriptions.
    """
    m = re.search(r"devin\.ai/sessions/([a-f0-9]+)", body)
    if m:
        return m.group(1)
    m = re.search(r"session[_\-]?id[:\s]+([a-f0-9-]+)", body, re.IGNORECASE)
    if m:
        return m.group(1)
    return ""


def main() -> None:
    if len(sys.argv) < 2:
        print(
            "Usage: verify_results.py <new_sarif_path> "
            "[original_issues_json] [output_dir]"
        )
        sys.exit(1)

    sarif_path = sys.argv[1]
    original_issues_path = sys.argv[2] if len(sys.argv) > 2 else ""
    output_dir = sys.argv[3] if len(sys.argv) > 3 else "output"
    os.makedirs(output_dir, exist_ok=True)

    pr_title = os.environ.get("PR_TITLE", "")
    pr_number = os.environ.get("PR_NUMBER", "")
    pr_url = os.environ.get("PR_URL", "")
    session_id = os.environ.get("SESSION_ID", "")
    pr_body = os.environ.get("PR_BODY", "")

    if not session_id and pr_body:
        session_id = extract_session_id_from_body(pr_body)

    issue_ids = extract_issue_ids_from_title(pr_title)
    run_number = extract_run_number_from_ids(issue_ids)
    cwe_family = extract_cwe_family_from_title(pr_title)

    if not original_issues_path:
        repo_root = os.environ.get("GITHUB_WORKSPACE", ".")
        logs_dir = os.path.join(repo_root, "logs")
        if run_number:
            original_issues_path = find_original_issues(logs_dir, run_number)
        if not original_issues_path:
            telemetry_dir = os.path.join(repo_root, "telemetry", "runs")
            if run_number:
                original_issues_path = find_original_issues_from_telemetry(
                    telemetry_dir, run_number,
                )
        if not original_issues_path:
            print("ERROR: Could not locate original issues")
            sys.exit(1)

    print(f"Verification scan: {sarif_path}")
    print(f"Original issues: {original_issues_path}")
    print(f"Issue IDs from PR title: {issue_ids}")
    print(f"Source run: {run_number}")
    print(f"CWE family: {cwe_family}")

    original_fps = load_original_fingerprints(original_issues_path)
    print(f"Loaded {len(original_fps)} original issue fingerprints")

    new_fps = compute_new_fingerprints(sarif_path)
    print(f"Found {len(new_fps)} fingerprints in verification scan")

    comparison = compare_fingerprints(
        original_fps, new_fps,
        target_issue_ids=issue_ids if issue_ids else None,
    )

    record = build_verification_record(
        comparison,
        pr_title=pr_title,
        pr_number=pr_number,
        pr_url=pr_url,
        session_id=session_id,
        run_number=run_number,
        cwe_family=cwe_family,
    )

    with open(os.path.join(output_dir, "verification.json"), "w") as f:
        json.dump(record, f, indent=2)

    comment = format_pr_comment(record)
    with open(os.path.join(output_dir, "verification_comment.md"), "w") as f:
        f.write(comment)

    label = determine_label(record)
    with open(os.path.join(output_dir, "verification_label.txt"), "w") as f:
        f.write(label)

    summary = record["summary"]
    print("\nVerification Results:")
    print(f"  Targeted: {summary['total_targeted']} issues")
    print(f"  Fixed:    {summary['fixed_count']}")
    print(f"  Remaining: {summary['remaining_count']}")
    print(f"  Fix rate:  {summary['fix_rate']}%")
    print(f"  Label:     {label}")

    github_output = os.environ.get("GITHUB_OUTPUT")
    if github_output:
        with open(github_output, "a") as f:
            f.write(f"fixed_count={summary['fixed_count']}\n")
            f.write(f"remaining_count={summary['remaining_count']}\n")
            f.write(f"total_targeted={summary['total_targeted']}\n")
            f.write(f"fix_rate={summary['fix_rate']}\n")
            f.write(f"label={label}\n")
            f.write(f"status={'all-resolved' if label == 'verified-fix' else 'issues-remain'}\n")


if __name__ == "__main__":
    main()
