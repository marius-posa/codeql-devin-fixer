"""Verification data processing for the telemetry system.

Loads verification records (``verification_*.json``) from the runs directory,
correlates them with sessions and issues, and exposes aggregated verification
metrics for the dashboard.
"""

from __future__ import annotations

import json
import pathlib
from typing import Any


def load_verification_records(runs_dir: pathlib.Path) -> list[dict[str, Any]]:
    """Load all verification JSON files from the runs directory."""
    records: list[dict[str, Any]] = []
    if not runs_dir.is_dir():
        return records
    for fp in sorted(runs_dir.glob("verification_*.json")):
        try:
            with open(fp) as f:
                data = json.load(f)
                data["_file"] = fp.name
                records.append(data)
        except (json.JSONDecodeError, OSError):
            continue
    return records


def build_session_verification_map(
    records: list[dict[str, Any]],
) -> dict[str, dict[str, Any]]:
    """Build a mapping from session_id to its verification summary.

    Returns a dict keyed by session_id with values containing:
    - ``verified_at``: timestamp of verification
    - ``pr_url``: URL of the verified PR
    - ``fixed_count``: number of issues verified as fixed
    - ``remaining_count``: number of issues still present
    - ``total_targeted``: total issues targeted
    - ``fix_rate``: percentage of targeted issues fixed
    - ``label``: verification label (verified-fix, codeql-partial-fix, etc.)
    - ``fixed_fingerprints``: list of fingerprints confirmed fixed
    """
    session_map: dict[str, dict[str, Any]] = {}
    for record in records:
        session_id = record.get("session_id", "")
        if not session_id:
            continue
        summary = record.get("summary", {})
        fixed_fps = [
            item.get("fingerprint", "")
            for item in record.get("verified_fixed", [])
            if item.get("fingerprint")
        ]
        fixed_count = summary.get("fixed_count", 0)
        total_targeted = summary.get("total_targeted", 0)
        label = "codeql-needs-work"
        if total_targeted > 0:
            if fixed_count == total_targeted:
                label = "verified-fix"
            elif fixed_count > 0:
                label = "codeql-partial-fix"

        session_map[session_id] = {
            "verified_at": record.get("verified_at", ""),
            "pr_url": record.get("pr_url", ""),
            "pr_number": record.get("pr_number", ""),
            "fixed_count": fixed_count,
            "remaining_count": summary.get("remaining_count", 0),
            "total_targeted": total_targeted,
            "fix_rate": summary.get("fix_rate", 0),
            "label": label,
            "fixed_fingerprints": fixed_fps,
            "cwe_family": record.get("cwe_family", ""),
            "source_run_number": record.get("source_run_number", ""),
        }
    return session_map


def build_fingerprint_fix_map(
    records: list[dict[str, Any]],
) -> dict[str, dict[str, Any]]:
    """Build a mapping from issue fingerprint to fix attribution.

    Returns a dict keyed by fingerprint with values containing:
    - ``fixed_by_session``: session_id that fixed it
    - ``fixed_by_pr``: PR URL that fixed it
    - ``verified_at``: when the fix was verified
    """
    fp_map: dict[str, dict[str, Any]] = {}
    for record in records:
        session_id = record.get("session_id", "")
        pr_url = record.get("pr_url", "")
        verified_at = record.get("verified_at", "")
        for item in record.get("verified_fixed", []):
            fp = item.get("fingerprint", "")
            if not fp:
                continue
            if fp not in fp_map:
                fp_map[fp] = {
                    "fixed_by_session": session_id,
                    "fixed_by_pr": pr_url,
                    "verified_at": verified_at,
                }
    return fp_map


def aggregate_verification_stats(
    records: list[dict[str, Any]],
) -> dict[str, Any]:
    """Compute aggregate verification metrics across all records."""
    total_verifications = len(records)
    total_fixed = 0
    total_remaining = 0
    total_targeted = 0
    fully_verified = 0
    partial_fixes = 0

    for record in records:
        summary = record.get("summary", {})
        fixed = summary.get("fixed_count", 0)
        targeted = summary.get("total_targeted", 0)
        remaining = summary.get("remaining_count", 0)

        total_fixed += fixed
        total_remaining += remaining
        total_targeted += targeted

        if targeted > 0 and fixed == targeted:
            fully_verified += 1
        elif fixed > 0:
            partial_fixes += 1

    return {
        "total_verifications": total_verifications,
        "total_issues_fixed": total_fixed,
        "total_issues_remaining": total_remaining,
        "total_issues_targeted": total_targeted,
        "fully_verified_prs": fully_verified,
        "partial_fix_prs": partial_fixes,
        "overall_fix_rate": round(
            total_fixed / max(total_targeted, 1) * 100, 1
        ),
    }
