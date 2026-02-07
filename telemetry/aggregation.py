def aggregate_sessions(runs: list[dict]) -> list[dict]:
    sessions = []
    for run in runs:
        for s in run.get("sessions", []):
            sessions.append({
                "session_id": s.get("session_id", ""),
                "session_url": s.get("session_url", ""),
                "batch_id": s.get("batch_id"),
                "status": s.get("status", "unknown"),
                "issue_ids": s.get("issue_ids", []),
                "target_repo": run.get("target_repo", ""),
                "fork_url": run.get("fork_url", ""),
                "run_number": run.get("run_number"),
                "run_id": run.get("run_id", ""),
                "run_url": run.get("run_url", ""),
                "run_label": run.get("run_label", ""),
                "timestamp": run.get("timestamp", ""),
                "pr_url": s.get("pr_url", ""),
            })
    return sessions


def aggregate_stats(runs: list[dict], sessions: list[dict], prs: list[dict]) -> dict:
    repos = set()
    total_issues = 0
    severity_agg: dict[str, int] = {}
    category_agg: dict[str, int] = {}

    latest_by_repo: dict[str, dict] = {}
    for run in runs:
        repo = run.get("target_repo", "")
        if repo:
            repos.add(repo)
        total_issues += run.get("issues_found", 0)
        for tier, count in run.get("severity_breakdown", {}).items():
            severity_agg[tier] = severity_agg.get(tier, 0) + count
        for cat, count in run.get("category_breakdown", {}).items():
            category_agg[cat] = category_agg.get(cat, 0) + count
        if repo:
            ts = run.get("timestamp", "")
            prev = latest_by_repo.get(repo)
            if prev is None or ts > prev.get("timestamp", ""):
                latest_by_repo[repo] = run

    latest_issues = sum(
        r.get("issues_found", 0) for r in latest_by_repo.values()
    )
    latest_severity: dict[str, int] = {}
    latest_category: dict[str, int] = {}
    for r in latest_by_repo.values():
        for tier, count in r.get("severity_breakdown", {}).items():
            latest_severity[tier] = latest_severity.get(tier, 0) + count
        for cat, count in r.get("category_breakdown", {}).items():
            latest_category[cat] = latest_category.get(cat, 0) + count

    pr_merged = sum(1 for p in prs if p.get("merged", False))
    pr_open = sum(1 for p in prs if p.get("state") == "open")
    pr_closed = sum(1 for p in prs if p.get("state") == "closed" and not p.get("merged", False))

    sessions_created = len([s for s in sessions if s.get("session_id")])
    sessions_finished = len([s for s in sessions if s.get("status") == "finished"])
    sessions_with_pr = len([s for s in sessions if s.get("pr_url")])

    return {
        "repos_scanned": len(repos),
        "repo_list": sorted(repos),
        "total_runs": len(runs),
        "total_issues": total_issues,
        "latest_issues": latest_issues,
        "latest_severity": latest_severity,
        "latest_category": latest_category,
        "sessions_created": sessions_created,
        "sessions_finished": sessions_finished,
        "sessions_with_pr": sessions_with_pr,
        "prs_total": len(prs),
        "prs_merged": pr_merged,
        "prs_open": pr_open,
        "prs_closed": pr_closed,
        "fix_rate": round(pr_merged / max(len(prs), 1) * 100, 1),
        "severity_breakdown": severity_agg,
        "category_breakdown": category_agg,
    }


def build_repos_dict(runs: list[dict], sessions: list[dict], prs: list[dict]) -> list[dict]:
    repos: dict[str, dict] = {}
    for run in runs:
        repo = run.get("target_repo", "")
        if not repo:
            continue
        if repo not in repos:
            repos[repo] = {
                "repo": repo,
                "fork_url": run.get("fork_url", ""),
                "runs": 0,
                "issues_found": 0,
                "sessions_created": 0,
                "sessions_finished": 0,
                "prs_total": 0,
                "prs_merged": 0,
                "prs_open": 0,
                "severity_breakdown": {},
                "category_breakdown": {},
                "last_run": "",
            }
        r = repos[repo]
        r["runs"] += 1
        r["issues_found"] += run.get("issues_found", 0)
        for tier, count in run.get("severity_breakdown", {}).items():
            r["severity_breakdown"][tier] = r["severity_breakdown"].get(tier, 0) + count
        for cat, count in run.get("category_breakdown", {}).items():
            r["category_breakdown"][cat] = r["category_breakdown"].get(cat, 0) + count
        ts = run.get("timestamp", "")
        if ts > r["last_run"]:
            r["last_run"] = ts
    for s in sessions:
        repo = s.get("target_repo", "")
        if repo in repos:
            repos[repo]["sessions_created"] += 1
            if s.get("status") in ("finished", "stopped"):
                repos[repo]["sessions_finished"] += 1
    for p in prs:
        fork_full = p.get("repo", "")
        matched_repo = ""
        for repo, info in repos.items():
            fork_url = info.get("fork_url", "")
            if fork_full and fork_full in fork_url:
                matched_repo = repo
                break
        if matched_repo:
            repos[matched_repo]["prs_total"] += 1
            if p.get("merged"):
                repos[matched_repo]["prs_merged"] += 1
            elif p.get("state") == "open":
                repos[matched_repo]["prs_open"] += 1
    return sorted(repos.values(), key=lambda r: r["last_run"], reverse=True)
