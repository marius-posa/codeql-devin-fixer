#!/usr/bin/env python3
"""Generate a tracking dashboard from run logs and GitHub API data."""

import json
import os
import re
import sys
from datetime import datetime, timezone
from typing import Any

import requests

DASHBOARD_TEMPLATE = """\
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>CodeQL Devin Fixer Dashboard</title>
<style>
  :root {{
    --bg: #0d1117; --surface: #161b22; --border: #30363d;
    --text: #c9d1d9; --text-muted: #8b949e; --accent: #58a6ff;
    --green: #3fb950; --red: #f85149; --yellow: #d29922; --purple: #bc8cff;
  }}
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Helvetica, Arial, sans-serif;
         background: var(--bg); color: var(--text); padding: 24px; }}
  h1 {{ font-size: 24px; margin-bottom: 8px; }}
  .subtitle {{ color: var(--text-muted); margin-bottom: 24px; font-size: 14px; }}
  .cards {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 16px; margin-bottom: 32px; }}
  .card {{ background: var(--surface); border: 1px solid var(--border); border-radius: 8px; padding: 20px; }}
  .card .label {{ color: var(--text-muted); font-size: 12px; text-transform: uppercase; letter-spacing: 0.5px; }}
  .card .value {{ font-size: 32px; font-weight: 600; margin-top: 4px; }}
  .card .value.green {{ color: var(--green); }}
  .card .value.red {{ color: var(--red); }}
  .card .value.yellow {{ color: var(--yellow); }}
  .card .value.accent {{ color: var(--accent); }}
  .card .value.purple {{ color: var(--purple); }}
  h2 {{ font-size: 18px; margin-bottom: 12px; }}
  table {{ width: 100%; border-collapse: collapse; margin-bottom: 32px; background: var(--surface);
           border: 1px solid var(--border); border-radius: 8px; overflow: hidden; }}
  th {{ background: #1c2128; text-align: left; padding: 10px 12px; font-size: 12px;
       text-transform: uppercase; letter-spacing: 0.5px; color: var(--text-muted); border-bottom: 1px solid var(--border); }}
  td {{ padding: 10px 12px; border-bottom: 1px solid var(--border); font-size: 14px; }}
  tr:last-child td {{ border-bottom: none; }}
  a {{ color: var(--accent); text-decoration: none; }}
  a:hover {{ text-decoration: underline; }}
  .badge {{ display: inline-block; padding: 2px 8px; border-radius: 12px; font-size: 12px; font-weight: 500; }}
  .badge.merged {{ background: rgba(63,185,80,0.15); color: var(--green); }}
  .badge.open {{ background: rgba(88,166,255,0.15); color: var(--accent); }}
  .badge.closed {{ background: rgba(248,81,73,0.15); color: var(--red); }}
  .empty {{ color: var(--text-muted); text-align: center; padding: 40px; }}
</style>
</head>
<body>
<h1>CodeQL Devin Fixer Dashboard</h1>
<p class="subtitle">Generated {generated_at} | Repository: {repo_name}</p>

<div class="cards">
  <div class="card"><div class="label">Action Runs</div><div class="value accent">{total_runs}</div></div>
  <div class="card"><div class="label">Issues Identified</div><div class="value yellow">{total_issues}</div></div>
  <div class="card"><div class="label">Devin Sessions</div><div class="value purple">{total_sessions}</div></div>
  <div class="card"><div class="label">PRs Created</div><div class="value accent">{total_prs}</div></div>
  <div class="card"><div class="label">PRs Merged</div><div class="value green">{prs_merged}</div></div>
  <div class="card"><div class="label">PRs Outstanding</div><div class="value red">{prs_open}</div></div>
</div>

<h2>Run History</h2>
{runs_table}

<h2>Devin Sessions</h2>
{sessions_table}

<h2>Pull Requests</h2>
{prs_table}

</body>
</html>
"""


def fetch_workflow_runs(token: str, owner: str, repo: str) -> list[dict[str, Any]]:
    runs: list[dict[str, Any]] = []
    url = f"https://api.github.com/repos/{owner}/{repo}/actions/runs"
    headers = {"Authorization": f"token {token}", "Accept": "application/vnd.github+json"}
    params: dict[str, Any] = {"per_page": 50}
    resp = requests.get(url, headers=headers, params=params, timeout=30)
    if resp.status_code == 200:
        data = resp.json()
        for r in data.get("workflow_runs", []):
            runs.append({
                "id": r["id"],
                "run_number": r["run_number"],
                "status": r["status"],
                "conclusion": r.get("conclusion", ""),
                "created_at": r["created_at"],
                "html_url": r["html_url"],
                "name": r.get("name", ""),
            })
    return runs


def fetch_codeql_prs(token: str, owner: str, repo: str) -> list[dict[str, Any]]:
    prs: list[dict[str, Any]] = []
    headers = {"Authorization": f"token {token}", "Accept": "application/vnd.github+json"}
    for state in ("open", "closed"):
        url = f"https://api.github.com/repos/{owner}/{repo}/pulls"
        params: dict[str, Any] = {"state": state, "per_page": 100, "sort": "created", "direction": "desc"}
        resp = requests.get(url, headers=headers, params=params, timeout=30)
        if resp.status_code == 200:
            for pr in resp.json():
                title = pr.get("title", "")
                if "fix(" in title.lower() or "codeql" in title.lower() or "cqlf-" in title.lower():
                    issue_ids = re.findall(r"CQLF-[\w-]+", title, re.IGNORECASE)
                    prs.append({
                        "number": pr["number"],
                        "title": title,
                        "state": pr["state"],
                        "merged": pr.get("merged_at") is not None,
                        "created_at": pr["created_at"],
                        "merged_at": pr.get("merged_at", ""),
                        "html_url": pr["html_url"],
                        "issue_ids": issue_ids,
                        "user": pr.get("user", {}).get("login", ""),
                    })
    seen = set()
    unique: list[dict[str, Any]] = []
    for pr in prs:
        if pr["number"] not in seen:
            seen.add(pr["number"])
            unique.append(pr)
    return unique


def load_run_logs(logs_dir: str) -> list[dict[str, Any]]:
    logs: list[dict[str, Any]] = []
    if not os.path.isdir(logs_dir):
        return logs
    for entry in sorted(os.listdir(logs_dir)):
        run_dir = os.path.join(logs_dir, entry)
        if not os.path.isdir(run_dir):
            continue
        run_log_path = os.path.join(run_dir, "run_log.json")
        if os.path.isfile(run_log_path):
            with open(run_log_path) as f:
                log = json.load(f)
            sessions_path = os.path.join(run_dir, "sessions.json")
            if os.path.isfile(sessions_path):
                with open(sessions_path) as f:
                    sessions = json.load(f)
                log["sessions"] = sessions
                log["sessions_count"] = len([s for s in sessions if s.get("status") == "created"])
            else:
                log["sessions"] = []
                log["sessions_count"] = 0
            log["dir_name"] = entry
            logs.append(log)
    return logs


def build_runs_table(run_logs: list[dict[str, Any]], workflow_runs: list[dict[str, Any]]) -> str:
    if not run_logs and not workflow_runs:
        return '<p class="empty">No runs recorded yet.</p>'

    rows = []
    for log in run_logs:
        rows.append(
            f"<tr><td>{log.get('run_label', log.get('dir_name', ''))}</td>"
            f"<td>{log.get('timestamp', '')}</td>"
            f"<td>{log.get('total_filtered', 0)}</td>"
            f"<td>{log.get('total_batches', 0)}</td>"
            f"<td>{log.get('sessions_count', 0)}</td></tr>"
        )

    if not rows:
        for wr in workflow_runs[:20]:
            rows.append(
                f"<tr><td><a href=\"{wr['html_url']}\">{wr['run_number']}</a></td>"
                f"<td>{wr['created_at']}</td>"
                f"<td>-</td><td>-</td><td>-</td></tr>"
            )

    return (
        "<table><thead><tr><th>Run</th><th>Date</th><th>Issues</th>"
        "<th>Batches</th><th>Sessions</th></tr></thead><tbody>"
        + "\n".join(rows)
        + "</tbody></table>"
    )


def build_sessions_table(run_logs: list[dict[str, Any]]) -> str:
    all_sessions = []
    for log in run_logs:
        run_label = log.get("run_label", "")
        for s in log.get("sessions", []):
            all_sessions.append({**s, "run_label": run_label})

    if not all_sessions:
        return '<p class="empty">No sessions recorded yet.</p>'

    rows = []
    for s in all_sessions:
        url = s.get("url", "")
        link = f'<a href="{url}">Open</a>' if url and url != "dry-run" else s.get("status", "")
        rows.append(
            f"<tr><td>{s.get('run_label', '')}</td>"
            f"<td>{s.get('batch_id', '')}</td>"
            f"<td>{link}</td>"
            f"<td>{s.get('status', '')}</td></tr>"
        )

    return (
        "<table><thead><tr><th>Run</th><th>Batch</th>"
        "<th>Session</th><th>Status</th></tr></thead><tbody>"
        + "\n".join(rows)
        + "</tbody></table>"
    )


def build_prs_table(prs: list[dict[str, Any]]) -> str:
    if not prs:
        return '<p class="empty">No CodeQL fix PRs found.</p>'

    rows = []
    for pr in sorted(prs, key=lambda p: p["created_at"], reverse=True):
        if pr["merged"]:
            badge = '<span class="badge merged">Merged</span>'
        elif pr["state"] == "open":
            badge = '<span class="badge open">Open</span>'
        else:
            badge = '<span class="badge closed">Closed</span>'
        ids = ", ".join(pr.get("issue_ids", [])) or "-"
        rows.append(
            f"<tr><td><a href=\"{pr['html_url']}\">#{pr['number']}</a></td>"
            f"<td>{pr['title'][:80]}</td>"
            f"<td>{ids}</td>"
            f"<td>{badge}</td>"
            f"<td>{pr['created_at'][:10]}</td></tr>"
        )

    return (
        "<table><thead><tr><th>PR</th><th>Title</th><th>Issue IDs</th>"
        "<th>Status</th><th>Created</th></tr></thead><tbody>"
        + "\n".join(rows)
        + "</tbody></table>"
    )


def main() -> None:
    token = os.environ.get("GITHUB_TOKEN", "")
    target_repo = os.environ.get("TARGET_REPO", "")
    logs_dir = os.environ.get("LOGS_DIR", "logs")
    output_dir = os.environ.get("DASHBOARD_OUTPUT_DIR", "dashboard")

    if not target_repo:
        print("ERROR: TARGET_REPO is required")
        sys.exit(1)

    target_repo = target_repo.strip().rstrip("/")
    if target_repo.endswith(".git"):
        target_repo = target_repo[:-4]
    m = re.match(r"https://github\.com/([\w.-]+)/([\w.-]+)", target_repo)
    if not m:
        print(f"ERROR: cannot parse repo URL: {target_repo}")
        sys.exit(1)
    owner, repo = m.group(1), m.group(2)
    repo_name = f"{owner}/{repo}"

    run_logs = load_run_logs(logs_dir)

    workflow_runs: list[dict[str, Any]] = []
    prs: list[dict[str, Any]] = []
    if token:
        workflow_runs = fetch_workflow_runs(token, owner, repo)
        prs = fetch_codeql_prs(token, owner, repo)
    else:
        print("WARNING: GITHUB_TOKEN not set; skipping API queries")

    total_runs = len(run_logs) or len(workflow_runs)
    total_issues = sum(log.get("total_filtered", 0) for log in run_logs)
    total_sessions = sum(log.get("sessions_count", 0) for log in run_logs)
    total_prs = len(prs)
    prs_merged = len([p for p in prs if p["merged"]])
    prs_open = len([p for p in prs if p["state"] == "open" and not p["merged"]])

    runs_table = build_runs_table(run_logs, workflow_runs)
    sessions_table = build_sessions_table(run_logs)
    prs_table = build_prs_table(prs)

    generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    html = DASHBOARD_TEMPLATE.format(
        generated_at=generated_at,
        repo_name=repo_name,
        total_runs=total_runs,
        total_issues=total_issues,
        total_sessions=total_sessions,
        total_prs=total_prs,
        prs_merged=prs_merged,
        prs_open=prs_open,
        runs_table=runs_table,
        sessions_table=sessions_table,
        prs_table=prs_table,
    )

    os.makedirs(output_dir, exist_ok=True)
    output_path = os.path.join(output_dir, "index.html")
    with open(output_path, "w") as f:
        f.write(html)
    print(f"Dashboard written to {output_path}")

    summary_path = os.path.join(output_dir, "metrics.json")
    metrics = {
        "generated_at": generated_at,
        "repo": repo_name,
        "total_runs": total_runs,
        "total_issues": total_issues,
        "total_sessions": total_sessions,
        "total_prs": total_prs,
        "prs_merged": prs_merged,
        "prs_open": prs_open,
        "prs_closed_not_merged": total_prs - prs_merged - prs_open,
    }
    with open(summary_path, "w") as f:
        json.dump(metrics, f, indent=2)
    print(f"Metrics written to {summary_path}")

    github_output = os.environ.get("GITHUB_OUTPUT")
    if github_output:
        with open(github_output, "a") as f:
            for k, v in metrics.items():
                f.write(f"dashboard_{k}={v}\n")


if __name__ == "__main__":
    main()
