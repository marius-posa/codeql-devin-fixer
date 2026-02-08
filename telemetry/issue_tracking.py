from datetime import datetime


def _parse_ts(ts: str) -> datetime | None:
    if not ts:
        return None
    for fmt in ("%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%dT%H:%M:%S.%fZ", "%Y-%m-%dT%H:%M:%S%z"):
        try:
            return datetime.strptime(ts, fmt)
        except ValueError:
            continue
    return None


def track_issues_across_runs(runs: list[dict]) -> list[dict]:
    if not runs:
        return []

    sorted_runs = sorted(runs, key=lambda r: r.get("timestamp", ""))

    fp_history: dict[str, list[dict]] = {}
    fp_metadata: dict[str, dict] = {}

    runs_per_repo: dict[str, int] = {}
    runs_with_fps_per_repo: dict[str, int] = {}

    for run in sorted_runs:
        repo = run.get("target_repo", "")
        if repo:
            runs_per_repo[repo] = runs_per_repo.get(repo, 0) + 1

        fingerprints = run.get("issue_fingerprints", [])
        if not fingerprints:
            continue

        if repo:
            runs_with_fps_per_repo[repo] = runs_with_fps_per_repo.get(repo, 0) + 1

        for iss in fingerprints:
            fp = iss.get("fingerprint", "")
            if not fp:
                continue
            if fp not in fp_history:
                fp_history[fp] = []
            fp_history[fp].append({
                "run_number": run.get("run_number"),
                "timestamp": run.get("timestamp", ""),
                "issue_id": iss.get("id", ""),
                "target_repo": repo,
            })
            if fp not in fp_metadata:
                fp_metadata[fp] = {
                    "rule_id": iss.get("rule_id", ""),
                    "severity_tier": iss.get("severity_tier", ""),
                    "cwe_family": iss.get("cwe_family", ""),
                    "file": iss.get("file", ""),
                    "start_line": iss.get("start_line", 0),
                    "description": iss.get("description", ""),
                    "resolution": iss.get("resolution", ""),
                    "code_churn": iss.get("code_churn", 0),
                }

    latest_run_per_repo: dict[str, dict] = {}
    for run in sorted_runs:
        repo = run.get("target_repo", "")
        if repo:
            latest_run_per_repo[repo] = run
    latest_fps: set[str] = set()
    for run in latest_run_per_repo.values():
        for iss in run.get("issue_fingerprints", []):
            fp = iss.get("fingerprint", "")
            if fp:
                latest_fps.add(fp)

    result: list[dict] = []
    for fp, appearances in fp_history.items():
        first = appearances[0]
        latest = appearances[-1]
        run_numbers = [a["run_number"] for a in appearances]
        repo = first["target_repo"]

        has_older_runs_without_fps = (
            runs_per_repo.get(repo, 0) > runs_with_fps_per_repo.get(repo, 0)
        )

        if fp in latest_fps:
            if len(appearances) > 1 or has_older_runs_without_fps:
                status = "recurring"
            else:
                status = "new"
        else:
            status = "fixed"

        meta = fp_metadata.get(fp, {})

        fix_duration_hours = None
        if status == "fixed":
            first_ts = _parse_ts(first["timestamp"])
            latest_ts = _parse_ts(latest["timestamp"])
            if first_ts and latest_ts:
                delta = latest_ts - first_ts
                fix_duration_hours = round(delta.total_seconds() / 3600, 1)

        result.append({
            "fingerprint": fp,
            "rule_id": meta.get("rule_id", ""),
            "severity_tier": meta.get("severity_tier", ""),
            "cwe_family": meta.get("cwe_family", ""),
            "file": meta.get("file", ""),
            "start_line": meta.get("start_line", 0),
            "description": meta.get("description", ""),
            "resolution": meta.get("resolution", ""),
            "code_churn": meta.get("code_churn", 0),
            "status": status,
            "first_seen_run": first["run_number"],
            "first_seen_date": first["timestamp"],
            "last_seen_run": latest["run_number"],
            "last_seen_date": latest["timestamp"],
            "target_repo": repo,
            "appearances": len(appearances),
            "run_numbers": run_numbers,
            "latest_issue_id": latest["issue_id"],
            "fix_duration_hours": fix_duration_hours,
        })

    _STATUS_ORDER = {"recurring": 0, "new": 1, "fixed": 2}
    result.sort(key=lambda x: (
        _STATUS_ORDER.get(x["status"], 3),
        x.get("last_seen_date", ""),
    ))
    return result
