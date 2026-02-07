#!/usr/bin/env python3
"""Generate a tracking dashboard from run logs and GitHub API data.

This script produces a self-contained HTML dashboard (no external JS/CSS
dependencies) that visualises the performance of the CodeQL Devin Fixer
action across multiple runs.  It pulls data from two sources:

1. **Local run logs** -- JSON files committed to ``logs/run-{label}/`` in the
   target repository by ``persist_logs.py``.  These provide per-run detail
   (issues found, batches created, sessions dispatched).

2. **GitHub API** -- workflow runs and pull requests on the *fork* repository.
   PRs are matched by title pattern (``fix(...)`` or ``CQLF-`` prefix) so that
   only Devin-generated fix PRs are counted.

The dashboard is written to ``<output_dir>/index.html`` alongside a
``metrics.json`` summary that downstream steps can consume.

Environment variables
---------------------
GITHUB_TOKEN : str
    Personal Access Token with ``repo`` scope.  Used to query the GitHub API
    for workflow runs and pull requests.
TARGET_REPO : str
    Full HTTPS URL of the repository being scanned (the fork URL).
LOGS_DIR : str
    Path to the ``logs/`` directory inside the cloned target repo.
DASHBOARD_OUTPUT_DIR : str
    Directory where ``index.html`` and ``metrics.json`` will be written.
"""

import json
import os
import re
import sys
from datetime import datetime, timezone
from typing import Any

import requests

# ---------------------------------------------------------------------------
# HTML template
# ---------------------------------------------------------------------------
# The template uses CSS-only styling (no JavaScript frameworks) so the
# dashboard can be opened as a standalone file or served from GitHub Pages.
# Double-braces ``{{`` / ``}}`` are used to escape Python's str.format().
DASHBOARD_TEMPLATE = """\
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>CodeQL Devin Fixer &ndash; Dashboard</title>
<style>
  :root {{
    --bg: #0d1117; --surface: #161b22; --surface-hover: #1c2128;
    --border: #30363d; --text: #e6edf3; --text-muted: #8b949e;
    --accent: #58a6ff; --green: #3fb950; --red: #f85149;
    --yellow: #d29922; --purple: #bc8cff; --orange: #f0883e;
  }}
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Helvetica, Arial, sans-serif;
    background: var(--bg); color: var(--text); padding: 32px 24px;
    max-width: 1200px; margin: 0 auto; line-height: 1.5;
  }}

  /* ---- Header ---- */
  .header {{ margin-bottom: 32px; }}
  .header h1 {{ font-size: 26px; font-weight: 700; margin-bottom: 4px; }}
  .header h1 span {{ color: var(--accent); }}
  .header .meta {{ color: var(--text-muted); font-size: 13px; display: flex; flex-wrap: wrap; gap: 16px; }}
  .header .meta a {{ color: var(--accent); text-decoration: none; }}
  .header .meta a:hover {{ text-decoration: underline; }}

  /* ---- Metric cards ---- */
  .cards {{
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
    gap: 14px; margin-bottom: 36px;
  }}
  .card {{
    background: var(--surface); border: 1px solid var(--border);
    border-radius: 10px; padding: 18px 16px;
  }}
  .card .label {{
    color: var(--text-muted); font-size: 11px; text-transform: uppercase;
    letter-spacing: 0.6px; margin-bottom: 6px;
  }}
  .card .value {{ font-size: 34px; font-weight: 700; }}
  .card .sub {{ color: var(--text-muted); font-size: 12px; margin-top: 2px; }}
  .green  {{ color: var(--green); }}
  .red    {{ color: var(--red); }}
  .yellow {{ color: var(--yellow); }}
  .accent {{ color: var(--accent); }}
  .purple {{ color: var(--purple); }}
  .orange {{ color: var(--orange); }}

  /* ---- Section headings ---- */
  h2 {{
    font-size: 17px; font-weight: 600; margin: 28px 0 12px;
    padding-bottom: 6px; border-bottom: 1px solid var(--border);
  }}

  /* ---- Bar charts (CSS-only) ---- */
  .bar-chart {{ margin-bottom: 28px; }}
  .bar-row {{
    display: flex; align-items: center; margin-bottom: 6px; font-size: 13px;
  }}
  .bar-row .bar-label {{
    width: 130px; flex-shrink: 0; color: var(--text-muted);
    text-transform: capitalize;
  }}
  .bar-row .bar-track {{
    flex: 1; height: 18px; background: var(--surface); border-radius: 4px;
    overflow: hidden; border: 1px solid var(--border);
  }}
  .bar-row .bar-fill {{
    height: 100%; border-radius: 4px 0 0 4px; transition: width .3s;
  }}
  .bar-row .bar-count {{
    width: 50px; text-align: right; flex-shrink: 0; font-weight: 600;
    font-size: 13px;
  }}

  /* ---- Tables ---- */
  table {{
    width: 100%; border-collapse: collapse; margin-bottom: 32px;
    background: var(--surface); border: 1px solid var(--border);
    border-radius: 10px; overflow: hidden;
  }}
  th {{
    background: var(--surface-hover); text-align: left; padding: 10px 14px;
    font-size: 11px; text-transform: uppercase; letter-spacing: 0.5px;
    color: var(--text-muted); border-bottom: 1px solid var(--border);
  }}
  td {{
    padding: 10px 14px; border-bottom: 1px solid var(--border); font-size: 13px;
  }}
  tr:last-child td {{ border-bottom: none; }}
  tr:hover td {{ background: rgba(88,166,255,0.04); }}
  a {{ color: var(--accent); text-decoration: none; }}
  a:hover {{ text-decoration: underline; }}

  /* ---- Badges ---- */
  .badge {{
    display: inline-block; padding: 2px 10px; border-radius: 12px;
    font-size: 11px; font-weight: 600; letter-spacing: 0.3px;
  }}
  .badge.merged  {{ background: rgba(63,185,80,0.15); color: var(--green); }}
  .badge.open    {{ background: rgba(88,166,255,0.15); color: var(--accent); }}
  .badge.closed  {{ background: rgba(248,81,73,0.15); color: var(--red); }}
  .badge.created {{ background: rgba(188,140,255,0.15); color: var(--purple); }}
  .badge.dry-run {{ background: rgba(139,148,158,0.15); color: var(--text-muted); }}

  .empty {{
    color: var(--text-muted); text-align: center; padding: 40px;
    font-size: 14px;
  }}

  /* ---- Footer ---- */
  .footer {{
    margin-top: 48px; padding-top: 16px; border-top: 1px solid var(--border);
    color: var(--text-muted); font-size: 12px; text-align: center;
  }}
  .footer a {{ color: var(--accent); }}
</style>
</head>
<body>

<!-- Header -->
<div class="header">
  <h1>CodeQL Devin Fixer <span>Dashboard</span></h1>
  <div class="meta">
    <span>Repository: <a href="https://github.com/{repo_name}" target="_blank">{repo_name}</a></span>
    <span>Generated: {generated_at}</span>
    <span>Runs analysed: {total_runs}</span>
  </div>
</div>

<!-- Metric cards -->
<div class="cards">
  <div class="card">
    <div class="label">Action Runs</div>
    <div class="value accent">{total_runs}</div>
    <div class="sub">workflow dispatches</div>
  </div>
  <div class="card">
    <div class="label">Issues Found</div>
    <div class="value yellow">{total_issues}</div>
    <div class="sub">across all runs</div>
  </div>
  <div class="card">
    <div class="label">Devin Sessions</div>
    <div class="value purple">{total_sessions}</div>
    <div class="sub">AI agents dispatched</div>
  </div>
  <div class="card">
    <div class="label">PRs Created</div>
    <div class="value accent">{total_prs}</div>
    <div class="sub">fix pull requests</div>
  </div>
  <div class="card">
    <div class="label">PRs Merged</div>
    <div class="value green">{prs_merged}</div>
    <div class="sub">{merge_rate} merge rate</div>
  </div>
  <div class="card">
    <div class="label">PRs Open</div>
    <div class="value orange">{prs_open}</div>
    <div class="sub">awaiting review</div>
  </div>
  <div class="card">
    <div class="label">PRs Closed</div>
    <div class="value red">{prs_closed}</div>
    <div class="sub">closed without merge</div>
  </div>
</div>

<!-- Severity breakdown -->
<h2>Issues by Severity</h2>
{severity_bars}

<!-- Category breakdown -->
<h2>Issues by Category</h2>
{category_bars}

<!-- Run history -->
<h2>Run History</h2>
{runs_table}

<!-- Devin sessions -->
<h2>Devin Sessions</h2>
{sessions_table}

<!-- Pull requests -->
<h2>Pull Requests</h2>
{prs_table}

<div class="footer">
  Powered by <a href="https://github.com/{action_repo}" target="_blank">CodeQL Devin Fixer</a>
  &middot; Data refreshed every action run
</div>

</body>
</html>
"""


# ---------------------------------------------------------------------------
# GitHub API helpers
# ---------------------------------------------------------------------------

def _gh_headers(token: str) -> dict[str, str]:
    """Return standard GitHub API request headers."""
    h: dict[str, str] = {"Accept": "application/vnd.github+json"}
    if token:
        h["Authorization"] = f"token {token}"
    return h


def fetch_workflow_runs(token: str, owner: str, repo: str) -> list[dict[str, Any]]:
    """Fetch recent workflow runs from the GitHub Actions API.

    Returns a simplified list of run metadata (id, number, status, URL).
    Only the most recent 50 runs are returned to keep the dashboard focused
    on recent activity.
    """
    runs: list[dict[str, Any]] = []
    url = f"https://api.github.com/repos/{owner}/{repo}/actions/runs"
    params: dict[str, Any] = {"per_page": 50}
    try:
        resp = requests.get(url, headers=_gh_headers(token), params=params, timeout=30)
        if resp.status_code == 200:
            for r in resp.json().get("workflow_runs", []):
                runs.append({
                    "id": r["id"],
                    "run_number": r["run_number"],
                    "status": r["status"],
                    "conclusion": r.get("conclusion", ""),
                    "created_at": r["created_at"],
                    "html_url": r["html_url"],
                    "name": r.get("name", ""),
                })
        else:
            print(f"WARNING: workflow runs API returned {resp.status_code}")
    except requests.exceptions.RequestException as exc:
        print(f"WARNING: could not fetch workflow runs: {exc}")
    return runs


def fetch_codeql_prs(token: str, owner: str, repo: str) -> list[dict[str, Any]]:
    """Fetch pull requests that match the CodeQL Devin Fixer naming convention.

    PRs are identified by looking for ``CQLF-`` issue IDs in the title or
    body.  This ensures only PRs created by action-triggered Devin sessions
    are included -- unrelated Devin PRs on the same repo are excluded.
    """
    prs: list[dict[str, Any]] = []
    headers = _gh_headers(token)
    for state in ("open", "closed"):
        url = f"https://api.github.com/repos/{owner}/{repo}/pulls"
        params: dict[str, Any] = {
            "state": state, "per_page": 100,
            "sort": "created", "direction": "desc",
        }
        try:
            resp = requests.get(url, headers=headers, params=params, timeout=30)
            if resp.status_code == 200:
                for pr in resp.json():
                    title = pr.get("title", "")
                    body = pr.get("body", "") or ""
                    combined = title + " " + body
                    if not re.search(r"CQLF-R\d+-\d+", combined, re.IGNORECASE):
                        continue
                    issue_ids = re.findall(r"CQLF-R\d+-\d+", combined, re.IGNORECASE)
                    prs.append({
                        "number": pr["number"],
                        "title": title,
                        "state": pr["state"],
                        "merged": pr.get("merged_at") is not None,
                        "created_at": pr["created_at"],
                        "merged_at": pr.get("merged_at", ""),
                        "html_url": pr["html_url"],
                        "issue_ids": list(dict.fromkeys(issue_ids)),
                        "user": pr.get("user", {}).get("login", ""),
                    })
            else:
                print(f"WARNING: PRs API ({state}) returned {resp.status_code}")
        except requests.exceptions.RequestException as exc:
            print(f"WARNING: could not fetch PRs ({state}): {exc}")

    # Deduplicate (a PR appears in both open+closed queries if state changed)
    seen: set[int] = set()
    unique: list[dict[str, Any]] = []
    for pr in prs:
        if pr["number"] not in seen:
            seen.add(pr["number"])
            unique.append(pr)
    return unique


# ---------------------------------------------------------------------------
# Local log helpers
# ---------------------------------------------------------------------------

def load_run_logs(logs_dir: str) -> list[dict[str, Any]]:
    """Load persisted run logs from ``logs/run-{label}/`` directories.

    Each directory is expected to contain ``run_log.json`` and optionally
    ``sessions.json``.  The function aggregates them into a list sorted by
    directory name (which encodes the timestamp).
    """
    logs: list[dict[str, Any]] = []
    if not os.path.isdir(logs_dir):
        return logs
    for entry in sorted(os.listdir(logs_dir)):
        run_dir = os.path.join(logs_dir, entry)
        if not os.path.isdir(run_dir):
            continue
        run_log_path = os.path.join(run_dir, "run_log.json")
        if not os.path.isfile(run_log_path):
            continue
        with open(run_log_path) as f:
            log = json.load(f)

        # Attach session data if available
        sessions_path = os.path.join(run_dir, "sessions.json")
        if os.path.isfile(sessions_path):
            with open(sessions_path) as f:
                sessions = json.load(f)
            log["sessions"] = sessions
            log["sessions_count"] = len(
                [s for s in sessions if s.get("status") in ("created", "dry-run")]
            )
        else:
            log["sessions"] = []
            log["sessions_count"] = 0

        # Attach issue data for severity/category breakdowns
        issues_path = os.path.join(run_dir, "issues.json")
        if os.path.isfile(issues_path):
            with open(issues_path) as f:
                log["issues_detail"] = json.load(f)
        else:
            log["issues_detail"] = []

        log["dir_name"] = entry
        logs.append(log)
    return logs


# ---------------------------------------------------------------------------
# HTML builders
# ---------------------------------------------------------------------------

def _bar_color(label: str) -> str:
    """Pick a colour for a severity tier or category label."""
    colors = {
        "critical": "var(--red)", "high": "var(--orange)",
        "medium": "var(--yellow)", "low": "var(--accent)",
        "injection": "var(--red)", "xss": "var(--orange)",
        "path-traversal": "var(--yellow)", "ssrf": "var(--purple)",
        "auth": "var(--red)", "crypto": "var(--orange)",
        "info-disclosure": "var(--accent)", "redirect": "var(--yellow)",
        "csrf": "var(--orange)", "regex-dos": "var(--purple)",
        "type-confusion": "var(--red)", "template-injection": "var(--orange)",
        "deserialization": "var(--red)", "prototype-pollution": "var(--purple)",
        "xxe": "var(--orange)",
    }
    return colors.get(label.lower(), "var(--accent)")


def build_bar_chart(data: dict[str, int]) -> str:
    """Render a horizontal bar chart as pure HTML/CSS.

    ``data`` maps label -> count.  The longest bar fills 100% of the track;
    shorter bars are proportional.
    """
    if not data:
        return '<p class="empty">No data available.</p>'
    max_val = max(data.values()) or 1
    rows = []
    for label, count in data.items():
        pct = round(count / max_val * 100)
        color = _bar_color(label)
        rows.append(
            f'<div class="bar-row">'
            f'<span class="bar-label">{label}</span>'
            f'<div class="bar-track"><div class="bar-fill" '
            f'style="width:{pct}%;background:{color}"></div></div>'
            f'<span class="bar-count">{count}</span>'
            f'</div>'
        )
    return '<div class="bar-chart">' + "\n".join(rows) + "</div>"


def build_runs_table(
    run_logs: list[dict[str, Any]],
    workflow_runs: list[dict[str, Any]],
) -> str:
    """Build the Run History HTML table.

    Prefers local run logs (richer data) but falls back to the GitHub Actions
    API if no local logs exist yet (e.g. first run before log persistence
    has been pushed).
    """
    if not run_logs and not workflow_runs:
        return '<p class="empty">No runs recorded yet.</p>'

    rows = []
    for log in reversed(run_logs):
        label = log.get("run_label", log.get("dir_name", ""))
        rows.append(
            f"<tr>"
            f"<td>{label}</td>"
            f"<td>{log.get('timestamp', '')[:10]}</td>"
            f"<td>{log.get('total_filtered', 0)}</td>"
            f"<td>{log.get('total_batches', 0)}</td>"
            f"<td>{log.get('sessions_count', 0)}</td>"
            f"<td>{log.get('severity_threshold', 'low')}</td>"
            f"</tr>"
        )

    # Fallback to GitHub Actions API data when no local logs exist
    if not rows:
        for wr in workflow_runs[:20]:
            conclusion = wr.get("conclusion", "") or wr.get("status", "")
            rows.append(
                f'<tr><td><a href="{wr["html_url"]}">'
                f'Run #{wr["run_number"]}</a></td>'
                f"<td>{wr['created_at'][:10]}</td>"
                f"<td>&ndash;</td><td>&ndash;</td><td>&ndash;</td>"
                f"<td>{conclusion}</td></tr>"
            )

    return (
        "<table><thead><tr>"
        "<th>Run</th><th>Date</th><th>Issues</th>"
        "<th>Batches</th><th>Sessions</th><th>Threshold / Status</th>"
        "</tr></thead><tbody>\n"
        + "\n".join(rows)
        + "\n</tbody></table>"
    )


def build_sessions_table(run_logs: list[dict[str, Any]]) -> str:
    """Build the Devin Sessions HTML table from persisted run logs."""
    all_sessions: list[dict[str, Any]] = []
    for log in run_logs:
        run_label = log.get("run_label", "")
        for s in log.get("sessions", []):
            all_sessions.append({**s, "run_label": run_label})

    if not all_sessions:
        return '<p class="empty">No sessions recorded yet.</p>'

    rows = []
    for s in reversed(all_sessions):
        url = s.get("url", "")
        status = s.get("status", "")
        if url and url != "dry-run":
            link = f'<a href="{url}" target="_blank">{s.get("session_id", "")[:12]}...</a>'
        else:
            link = "&ndash;"
        badge_cls = "created" if status == "created" else "dry-run"
        rows.append(
            f"<tr>"
            f"<td>{s.get('run_label', '')}</td>"
            f"<td>Batch {s.get('batch_id', '')}</td>"
            f"<td>{link}</td>"
            f'<td><span class="badge {badge_cls}">{status}</span></td>'
            f"</tr>"
        )

    return (
        "<table><thead><tr>"
        "<th>Run</th><th>Batch</th><th>Session</th><th>Status</th>"
        "</tr></thead><tbody>\n"
        + "\n".join(rows)
        + "\n</tbody></table>"
    )


def build_prs_table(prs: list[dict[str, Any]]) -> str:
    """Build the Pull Requests HTML table from GitHub API data."""
    if not prs:
        return '<p class="empty">No CodeQL fix PRs found yet.</p>'

    rows = []
    for pr in sorted(prs, key=lambda p: p["created_at"], reverse=True):
        if pr["merged"]:
            badge = '<span class="badge merged">Merged</span>'
        elif pr["state"] == "open":
            badge = '<span class="badge open">Open</span>'
        else:
            badge = '<span class="badge closed">Closed</span>'
        ids = ", ".join(pr.get("issue_ids", [])) or "&ndash;"
        title_short = pr["title"][:80] + ("..." if len(pr["title"]) > 80 else "")
        rows.append(
            f'<tr>'
            f'<td><a href="{pr["html_url"]}" target="_blank">#{pr["number"]}</a></td>'
            f"<td>{title_short}</td>"
            f"<td>{ids}</td>"
            f"<td>{badge}</td>"
            f'<td>{pr["user"]}</td>'
            f'<td>{pr["created_at"][:10]}</td>'
            f"</tr>"
        )

    return (
        "<table><thead><tr>"
        "<th>PR</th><th>Title</th><th>Issue IDs</th>"
        "<th>Status</th><th>Author</th><th>Created</th>"
        "</tr></thead><tbody>\n"
        + "\n".join(rows)
        + "\n</tbody></table>"
    )


# ---------------------------------------------------------------------------
# Aggregation helpers
# ---------------------------------------------------------------------------

def aggregate_severity(run_logs: list[dict[str, Any]]) -> dict[str, int]:
    """Aggregate issue counts by severity tier across all runs."""
    counts: dict[str, int] = {}
    for log in run_logs:
        for issue in log.get("issues_detail", []):
            tier = issue.get("severity_tier", "unknown")
            counts[tier] = counts.get(tier, 0) + 1
    # Sort by severity order so the chart reads critical -> low
    order = ["critical", "high", "medium", "low", "none"]
    return {k: counts[k] for k in order if k in counts}


def aggregate_categories(run_logs: list[dict[str, Any]]) -> dict[str, int]:
    """Aggregate issue counts by CWE family across all runs."""
    counts: dict[str, int] = {}
    for log in run_logs:
        for issue in log.get("issues_detail", []):
            family = issue.get("cwe_family", "other")
            counts[family] = counts.get(family, 0) + 1
    # Sort descending by count for the chart
    return dict(sorted(counts.items(), key=lambda x: -x[1]))


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    token = os.environ.get("GITHUB_TOKEN", "")
    target_repo = os.environ.get("TARGET_REPO", "")
    logs_dir = os.environ.get("LOGS_DIR", "logs")
    output_dir = os.environ.get("DASHBOARD_OUTPUT_DIR", "dashboard")
    action_repo_env = os.environ.get("ACTION_REPO", "")

    if not target_repo:
        print("ERROR: TARGET_REPO is required")
        sys.exit(1)

    target_repo = target_repo.strip().rstrip("/")
    if target_repo.endswith(".git"):
        target_repo = target_repo[:-4]
    if not target_repo.startswith("http://") and not target_repo.startswith("https://"):
        if re.match(r"^[\w.-]+/[\w.-]+$", target_repo):
            target_repo = f"https://github.com/{target_repo}"
    m = re.match(r"https://github\.com/([\w.-]+)/([\w.-]+)", target_repo)
    if not m:
        print(f"ERROR: cannot parse repo URL: {target_repo}")
        sys.exit(1)
    owner, repo = m.group(1), m.group(2)
    repo_name = f"{owner}/{repo}"

    # -- Collect data -------------------------------------------------------
    run_logs = load_run_logs(logs_dir)

    workflow_runs: list[dict[str, Any]] = []
    prs: list[dict[str, Any]] = []
    if token:
        workflow_runs = fetch_workflow_runs(token, owner, repo)
        prs = fetch_codeql_prs(token, owner, repo)
    else:
        print("WARNING: GITHUB_TOKEN not set; skipping API queries")

    # -- Compute metrics ----------------------------------------------------
    total_runs = len(run_logs) or len(workflow_runs)
    total_issues = sum(log.get("total_filtered", 0) for log in run_logs)
    total_sessions = sum(log.get("sessions_count", 0) for log in run_logs)
    total_prs = len(prs)
    prs_merged = len([p for p in prs if p["merged"]])
    prs_open = len([p for p in prs if p["state"] == "open" and not p["merged"]])
    prs_closed = total_prs - prs_merged - prs_open
    merge_rate = (
        f"{round(prs_merged / total_prs * 100)}%" if total_prs > 0 else "N/A"
    )

    # -- Build HTML fragments -----------------------------------------------
    severity_data = aggregate_severity(run_logs)
    category_data = aggregate_categories(run_logs)
    severity_bars = build_bar_chart(severity_data)
    category_bars = build_bar_chart(category_data)
    runs_table = build_runs_table(run_logs, workflow_runs)
    sessions_table = build_sessions_table(run_logs)
    prs_table = build_prs_table(prs)

    generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    # -- Render HTML --------------------------------------------------------
    html = DASHBOARD_TEMPLATE.format(
        generated_at=generated_at,
        repo_name=repo_name,
        action_repo=action_repo_env or repo_name,
        total_runs=total_runs,
        total_issues=total_issues,
        total_sessions=total_sessions,
        total_prs=total_prs,
        prs_merged=prs_merged,
        prs_open=prs_open,
        prs_closed=prs_closed,
        merge_rate=merge_rate,
        severity_bars=severity_bars,
        category_bars=category_bars,
        runs_table=runs_table,
        sessions_table=sessions_table,
        prs_table=prs_table,
    )

    os.makedirs(output_dir, exist_ok=True)
    output_path = os.path.join(output_dir, "index.html")
    with open(output_path, "w") as f:
        f.write(html)
    print(f"Dashboard written to {output_path}")

    # -- Write metrics JSON -------------------------------------------------
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
        "prs_closed_not_merged": prs_closed,
        "merge_rate": merge_rate,
        "severity_breakdown": severity_data,
        "category_breakdown": category_data,
    }
    with open(summary_path, "w") as f:
        json.dump(metrics, f, indent=2)
    print(f"Metrics written to {summary_path}")

    # -- Write GitHub Action outputs ----------------------------------------
    github_output = os.environ.get("GITHUB_OUTPUT")
    if github_output:
        with open(github_output, "a") as f:
            for k, v in metrics.items():
                if isinstance(v, (str, int, float)):
                    f.write(f"dashboard_{k}={v}\n")


if __name__ == "__main__":
    main()
