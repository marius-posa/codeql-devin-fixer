#!/usr/bin/env python3
"""Create Devin sessions for each batch of CodeQL issues."""

import json
import os
import re
import sys
import time
import requests


DEVIN_API_BASE = "https://api.devin.ai/v1"

MAX_RETRIES = 3
RETRY_DELAY = 5


def validate_repo_url(url: str) -> str:
    url = url.strip().rstrip("/")
    if url.endswith(".git"):
        url = url[:-4]
    pattern = r"^https://github\.com/[\w.-]+/[\w.-]+$"
    if not re.match(pattern, url):
        print(f"WARNING: repo URL may be invalid: {url}")
    return url


def build_batch_prompt(batch: dict, repo_url: str, default_branch: str) -> str:
    family = batch["cwe_family"]
    tier = batch["severity_tier"]
    issues = batch["issues"]

    file_list = set()
    for issue in issues:
        for loc in issue.get("locations", []):
            if loc.get("file"):
                file_list.add(loc["file"])

    prompt_parts = [
        f"Fix {batch['issue_count']} CodeQL security issue(s) in {repo_url} "
        f"(branch: {default_branch}).",
        "",
        f"Category: {family} | Severity: {tier.upper()} "
        f"(max CVSS: {batch['max_severity_score']})",
        "",
        "Issues to fix:",
        "",
    ]

    for idx, issue in enumerate(issues, 1):
        locs = ", ".join(
            f"{loc['file']}:{loc['start_line']}"
            for loc in issue.get("locations", [])
            if loc.get("file")
        )
        cwes = ", ".join(issue.get("cwes", [])) or "N/A"
        prompt_parts.extend(
            [
                f"### Issue {idx}: {issue['rule_name']} ({issue['rule_id']})",
                f"- Severity: {issue['severity_tier'].upper()} ({issue['severity_score']})",
                f"- CWE: {cwes}",
                f"- Location(s): {locs}",
                f"- Description: {issue['message'][:300]}",
            ]
        )
        if issue.get("rule_description"):
            prompt_parts.append(f"- Rule: {issue['rule_description'][:200]}")
        if issue.get("rule_help"):
            prompt_parts.append(f"- Guidance: {issue['rule_help'][:500]}")
        prompt_parts.append("")

    prompt_parts.extend(
        [
            "Instructions:",
            f"1. Clone {repo_url} and create a new branch from {default_branch}.",
            "2. Fix ALL the issues listed above.",
            "3. Ensure fixes don't break existing functionality.",
            "4. Run existing tests if available to verify.",
            "5. Create a PR with a clear description of what was fixed and why.",
            f"6. Title the PR: 'fix: resolve {family} security issues "
            f"(CodeQL batch {batch['batch_id']})'",
            "",
            "Files to focus on:",
        ]
    )
    for f in sorted(file_list):
        prompt_parts.append(f"- {f}")

    return "\n".join(prompt_parts)


def create_devin_session(
    api_key: str,
    prompt: str,
    batch: dict,
    max_acu: int | None = None,
) -> dict:
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
    }

    tags = [
        "codeql-fix",
        f"severity-{batch['severity_tier']}",
        f"cwe-{batch['cwe_family']}",
        f"batch-{batch['batch_id']}",
    ]

    payload: dict = {
        "prompt": prompt,
        "idempotent": True,
        "tags": tags,
        "title": (
            f"CodeQL Fix: {batch['cwe_family']} "
            f"({batch['severity_tier'].upper()}) - Batch {batch['batch_id']}"
        ),
    }
    if max_acu is not None and max_acu > 0:
        payload["max_acu_limit"] = max_acu

    last_err = None
    for attempt in range(1, MAX_RETRIES + 1):
        try:
            resp = requests.post(
                f"{DEVIN_API_BASE}/sessions",
                headers=headers,
                json=payload,
                timeout=30,
            )
            resp.raise_for_status()
            return resp.json()
        except requests.exceptions.RequestException as e:
            last_err = e
            if attempt < MAX_RETRIES:
                print(f"  Retry {attempt}/{MAX_RETRIES} after error: {e}")
                time.sleep(RETRY_DELAY * attempt)
    raise last_err  # type: ignore[misc]


def check_session_status(api_key: str, session_id: str) -> dict:
    headers = {"Authorization": f"Bearer {api_key}"}
    resp = requests.get(
        f"{DEVIN_API_BASE}/sessions/{session_id}",
        headers=headers,
        timeout=30,
    )
    resp.raise_for_status()
    return resp.json()


def _get_status_enum(payload: dict) -> str:
    return str(payload.get("status_enum") or payload.get("status") or "").lower()


def _get_pr_url(payload: dict) -> str:
    pr = payload.get("pull_request")
    if isinstance(pr, dict):
        return str(pr.get("url") or "")
    if isinstance(payload.get("pull_request"), str):
        return str(payload.get("pull_request"))
    # some responses might expose url at top-level
    return str(payload.get("pr_url") or payload.get("url") or "")


def _is_terminal(status: str) -> bool:
    return status in {
        "finished",
        "blocked",
        "expired",
        "failed",
        "canceled",
        "cancelled",
    }


def poll_sessions(
    api_key: str,
    sessions: list[dict],
    batches: list[dict],
    timeout_sec: int,
    interval_sec: int,
) -> list[dict]:
    by_batch = {b["batch_id"]: b for b in batches}
    outcomes: list[dict] = []

    deadline = time.time() + timeout_sec
    pending = [
        s for s in sessions if s.get("session_id") and s.get("status") == "created"
    ]
    while pending and time.time() < deadline:
        next_pending: list[dict] = []
        for s in pending:
            sid = s["session_id"]
            batch_id = s["batch_id"]
            try:
                data = check_session_status(api_key, sid)
                status = _get_status_enum(data) or "working"
                pr_url = _get_pr_url(data)
                if _is_terminal(status):
                    b = by_batch.get(batch_id, {})
                    outcomes.append(
                        {
                            "batch_id": batch_id,
                            "session_id": sid,
                            "status": status,
                            "pr_url": pr_url,
                            "issues": b.get("issue_count", 0),
                            "cwe_family": b.get("cwe_family", ""),
                            "severity_tier": b.get("severity_tier", ""),
                        }
                    )
                else:
                    next_pending.append(s)
            except requests.exceptions.RequestException as e:
                # network hiccup: keep pending and try later
                print(f"  Poll error for {sid}: {e}")
                next_pending.append(s)

        pending = next_pending
        if pending:
            time.sleep(max(1, interval_sec))

    # mark any still-pending as timed_out
    for s in pending:
        b = by_batch.get(s["batch_id"], {})
        outcomes.append(
            {
                "batch_id": s["batch_id"],
                "session_id": s["session_id"],
                "status": "timed_out",
                "pr_url": "",
                "issues": b.get("issue_count", 0),
                "cwe_family": b.get("cwe_family", ""),
                "severity_tier": b.get("severity_tier", ""),
            }
        )

    return outcomes


def main() -> None:
    batches_path = sys.argv[1] if len(sys.argv) > 1 else "output/batches.json"
    output_dir = sys.argv[2] if len(sys.argv) > 2 else "output"

    api_key = os.environ.get("DEVIN_API_KEY", "")
    repo_url = validate_repo_url(os.environ.get("TARGET_REPO", ""))
    default_branch = os.environ.get("DEFAULT_BRANCH", "main")
    max_acu_str = os.environ.get("MAX_ACU_PER_SESSION", "")
    dry_run = os.environ.get("DRY_RUN", "false").lower() == "true"

    max_acu = int(max_acu_str) if max_acu_str else None

    if not api_key and not dry_run:
        print("ERROR: DEVIN_API_KEY is required (set DRY_RUN=true to skip)")
        sys.exit(1)

    if not repo_url:
        print("ERROR: TARGET_REPO environment variable is required")
        sys.exit(1)

    with open(batches_path) as f:
        batches = json.load(f)

    if not batches:
        print("No batches to process. Exiting.")
        return

    print(f"Processing {len(batches)} batches for {repo_url}")
    print(f"Default branch: {default_branch}")
    print(f"Dry run: {dry_run}")
    print()

    sessions: list[dict] = []

    for batch in batches:
        prompt = build_batch_prompt(batch, repo_url, default_branch)
        batch_id = batch["batch_id"]

        prompt_path = os.path.join(output_dir, f"prompt_batch_{batch_id}.txt")
        with open(prompt_path, "w") as f:
            f.write(prompt)

        print(f"--- Batch {batch_id} ---")
        print(f"  Category: {batch['cwe_family']}")
        print(f"  Severity: {batch['severity_tier'].upper()}")
        print(f"  Issues: {batch['issue_count']}")

        if dry_run:
            print(f"  [DRY RUN] Prompt saved to {prompt_path}")
            sessions.append(
                {
                    "batch_id": batch_id,
                    "session_id": "dry-run",
                    "url": "dry-run",
                    "status": "dry-run",
                }
            )
            continue

        try:
            result = create_devin_session(api_key, prompt, batch, max_acu)
            session_id = result["session_id"]
            url = result["url"]
            print(f"  Session created: {url}")
            sessions.append(
                {
                    "batch_id": batch_id,
                    "session_id": session_id,
                    "url": url,
                    "status": "created",
                }
            )
            time.sleep(2)
        except requests.exceptions.RequestException as e:
            print(f"  ERROR creating session: {e}")
            sessions.append(
                {
                    "batch_id": batch_id,
                    "session_id": "",
                    "url": "",
                    "status": f"error: {e}",
                }
            )

    with open(os.path.join(output_dir, "sessions.json"), "w") as f:
        json.dump(sessions, f, indent=2)

    print("\n" + "=" * 60)
    print("Dispatch Summary")
    print("=" * 60)

    summary_lines = ["\n## Devin Sessions Created\n"]
    summary_lines.append("| Batch | Category | Severity | Session | Status |")
    summary_lines.append("|-------|----------|----------|---------|--------|")

    for s in sessions:
        batch = next(b for b in batches if b["batch_id"] == s["batch_id"])
        link = (
            f"[Open]({s['url']})" if s["url"] and s["url"] != "dry-run" else s["status"]
        )
        summary_lines.append(
            f"| {s['batch_id']} | {batch['cwe_family']} "
            f"| {batch['severity_tier'].upper()} | {link} | {s['status']} |"
        )

    summary = "\n".join(summary_lines)
    print(summary)

    github_summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if github_summary:
        with open(github_summary, "a") as f:
            f.write(summary + "\n")

    github_output = os.environ.get("GITHUB_OUTPUT")
    if github_output:
        with open(github_output, "a") as f:
            session_urls = ",".join(
                s["url"] for s in sessions if s["url"] and s["url"] != "dry-run"
            )
            f.write(f"session_urls={session_urls}\n")
            f.write(
                f"sessions_created={len([s for s in sessions if s['status'] == 'created'])}\n"
            )

    # Optional: wait for sessions and collect outcomes
    wait_flag = os.environ.get("WAIT_FOR_SESSIONS", "false").lower() == "true"
    poll_timeout_min = int(os.environ.get("POLL_TIMEOUT", "60"))
    poll_interval_sec = int(os.environ.get("POLL_INTERVAL", "30"))

    if not dry_run and wait_flag:
        print("\nWaiting for sessions to complete...")
        outcomes = poll_sessions(
            api_key,
            [s for s in sessions if s.get("status") == "created"],
            batches,
            poll_timeout_min * 60,
            poll_interval_sec,
        )
        with open(os.path.join(output_dir, "outcomes.json"), "w") as f:
            json.dump(outcomes, f, indent=2)

        finished = [o for o in outcomes if o["status"] == "finished"]
        with_pr = [o for o in outcomes if o.get("pr_url")]  # regardless of status
        # proxy metric: issues addressed only when finished AND PR exists
        addressed = [
            o for o in outcomes if o["status"] == "finished" and o.get("pr_url")
        ]
        issues_addressed = sum(o.get("issues", 0) for o in addressed)

        outcome_lines = ["\n## Devin Session Outcomes\n"]
        outcome_lines.append("| Batch | Status | PR | Issues | Category | Severity |")
        outcome_lines.append("|-------|--------|----|--------|----------|----------|")
        for o in outcomes:
            pr_link = f"[PR]({o['pr_url']})" if o.get("pr_url") else "-"
            outcome_lines.append(
                f"| {o['batch_id']} | {o['status']} | {pr_link} | {o.get('issues', 0)} | {o.get('cwe_family', '')} | {o.get('severity_tier', '').upper()} |"
            )
        outcome_lines.append("")
        outcome_lines.append(
            f"Sessions finished: {len(finished)} | Sessions with PR: {len(with_pr)} | Issues addressed (proxy): {issues_addressed}\n"
        )
        outcome_summary = "\n".join(outcome_lines)
        print(outcome_summary)

        if github_summary:
            with open(github_summary, "a") as f:
                f.write(outcome_summary + "\n")
        if github_output:
            with open(github_output, "a") as f:
                f.write(f"sessions_finished={len(finished)}\n")
                f.write(f"sessions_with_pr={len(with_pr)}\n")
                f.write(f"issues_addressed={issues_addressed}\n")


if __name__ == "__main__":
    main()
