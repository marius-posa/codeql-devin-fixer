import os
import re
import sqlite3
from urllib.parse import urlparse

import requests

from config import gh_headers


def collect_session_ids(runs: list[dict]) -> set[str]:
    ids: set[str] = set()
    for run in runs:
        for s in run.get("sessions", []):
            sid = s.get("session_id", "")
            if sid and sid != "dry-run":
                clean = sid.replace("devin-", "") if sid.startswith("devin-") else sid
                ids.add(clean)
    return ids


def match_pr_to_session(pr_body: str, session_ids: set[str]) -> str:
    for sid in session_ids:
        if sid in (pr_body or ""):
            return sid
    return ""


def fetch_prs_from_github(runs: list[dict]) -> list[dict]:
    token = os.environ.get("GITHUB_TOKEN", "")
    if not token:
        return []

    search_repos: set[str] = set()
    for run in runs:
        for url_field in ("fork_url", "target_repo"):
            raw_url = run.get(url_field, "")
            parsed = urlparse(raw_url)
            if parsed.hostname == "github.com":
                path = parsed.path.strip("/")
                if path:
                    search_repos.add(path)

    session_ids = collect_session_ids(runs)

    prs: list[dict] = []
    seen_urls: set[str] = set()
    for repo_full in search_repos:
        gh_page = 1
        while True:
            url = (f"https://api.github.com/repos/{repo_full}/pulls"
                   f"?state=all&per_page=100&page={gh_page}")
            try:
                resp = requests.get(url, headers=gh_headers(), timeout=30)
                if resp.status_code != 200:
                    snippet = (resp.text or "").strip().replace("\n", " ")[:200]
                    print(f"WARNING: PRs API returned {resp.status_code} for {repo_full} page {gh_page}: {snippet}")
                    break
                batch = resp.json()
                if not batch:
                    break
                for pr in batch:
                    title = pr.get("title", "")
                    body = pr.get("body", "") or ""
                    html_url = pr.get("html_url", "")
                    user_login = pr.get("user", {}).get("login", "")

                    has_issue_ref_in_title = bool(re.search(r"CQLF-R\d+-\d+", title, re.IGNORECASE))
                    matched_session = match_pr_to_session(title + body, session_ids)

                    if not has_issue_ref_in_title and not matched_session:
                        continue
                    if html_url in seen_urls:
                        continue
                    seen_urls.add(html_url)

                    issue_ids = re.findall(r"CQLF-R\d+-\d+", title, re.IGNORECASE)
                    prs.append({
                        "pr_number": pr.get("number"),
                        "title": title,
                        "html_url": html_url,
                        "state": pr.get("state", ""),
                        "merged": pr.get("merged_at") is not None,
                        "created_at": pr.get("created_at", ""),
                        "repo": repo_full,
                        "issue_ids": list(dict.fromkeys(issue_ids)),
                        "user": user_login,
                        "session_id": matched_session,
                    })
                if len(batch) < 100:
                    break
                gh_page += 1
            except requests.RequestException as exc:
                print(f"ERROR: fetching PRs from GitHub failed: {exc}")
                break
    return prs


def link_prs_to_sessions(
    sessions: list[dict], prs: list[dict],
) -> list[dict]:
    pr_by_session: dict[str, str] = {}
    pr_by_issue: dict[str, str] = {}
    for p in prs:
        sid = p.get("session_id", "")
        if sid:
            pr_by_session[sid] = p.get("html_url", "")
        for iid in p.get("issue_ids", []):
            if iid:
                pr_by_issue[iid] = p.get("html_url", "")

    for s in sessions:
        if s.get("pr_url"):
            continue
        sid = s.get("session_id", "")
        clean = sid.replace("devin-", "") if sid.startswith("devin-") else sid
        if clean in pr_by_session:
            s["pr_url"] = pr_by_session[clean]
            continue
        for iid in s.get("issue_ids", []):
            if iid in pr_by_issue:
                s["pr_url"] = pr_by_issue[iid]
                break
    return sessions


def fetch_prs_from_github_to_db(conn: sqlite3.Connection) -> int:
    from database import upsert_pr, collect_session_ids_from_db, collect_search_repos_from_db

    token = os.environ.get("GITHUB_TOKEN", "")
    if not token:
        return 0

    search_repos = collect_search_repos_from_db(conn)
    session_ids = collect_session_ids_from_db(conn)

    count = 0
    seen_urls: set[str] = set()
    for repo_full in search_repos:
        gh_page = 1
        while True:
            url = (f"https://api.github.com/repos/{repo_full}/pulls"
                   f"?state=all&per_page=100&page={gh_page}")
            try:
                resp = requests.get(url, headers=gh_headers(), timeout=30)
                if resp.status_code != 200:
                    break
                batch = resp.json()
                if not batch:
                    break
                for pr in batch:
                    title = pr.get("title", "")
                    body = pr.get("body", "") or ""
                    html_url = pr.get("html_url", "")

                    has_issue_ref_in_title = bool(re.search(r"CQLF-R\d+-\d+", title, re.IGNORECASE))
                    matched_session = match_pr_to_session(title + body, session_ids)

                    if not has_issue_ref_in_title and not matched_session:
                        continue
                    if html_url in seen_urls:
                        continue
                    seen_urls.add(html_url)

                    issue_ids = re.findall(r"CQLF-R\d+-\d+", title, re.IGNORECASE)
                    pr_data = {
                        "pr_number": pr.get("number"),
                        "title": title,
                        "html_url": html_url,
                        "state": pr.get("state", ""),
                        "merged": pr.get("merged_at") is not None,
                        "created_at": pr.get("created_at", ""),
                        "repo": repo_full,
                        "issue_ids": list(dict.fromkeys(issue_ids)),
                        "user": pr.get("user", {}).get("login", ""),
                        "session_id": matched_session,
                    }
                    upsert_pr(conn, pr_data)
                    count += 1
                if len(batch) < 100:
                    break
                gh_page += 1
            except requests.RequestException:
                break
    return count


def link_prs_to_sessions_db(conn: sqlite3.Connection) -> None:
    from database import query_all_prs, update_session

    all_prs = query_all_prs(conn)
    pr_by_session: dict[str, str] = {}
    pr_by_issue: dict[str, str] = {}
    for p in all_prs:
        sid = p.get("session_id", "")
        if sid:
            pr_by_session[sid] = p.get("html_url", "")
        for iid in p.get("issue_ids", []):
            if iid:
                pr_by_issue[iid] = p.get("html_url", "")

    sessions = conn.execute(
        "SELECT s.id, s.session_id, s.pr_url FROM sessions s WHERE s.pr_url = ''"
    ).fetchall()
    for s in sessions:
        sid = s["session_id"]
        clean = sid.replace("devin-", "") if sid.startswith("devin-") else sid
        pr_url = pr_by_session.get(clean, "")
        if not pr_url:
            iid_rows = conn.execute(
                "SELECT issue_id FROM session_issue_ids WHERE session_id = ?",
                (s["id"],),
            ).fetchall()
            for iid_row in iid_rows:
                if iid_row["issue_id"] in pr_by_issue:
                    pr_url = pr_by_issue[iid_row["issue_id"]]
                    break
        if pr_url:
            update_session(conn, sid, pr_url=pr_url)
