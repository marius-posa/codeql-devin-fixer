#!/usr/bin/env python3
"""Create Devin sessions for each batch of CodeQL issues.

This script is the bridge between the CodeQL analysis and the Devin AI agent.
For every batch produced by ``parse_sarif.py`` it:

1. **Builds a prompt** -- a structured, Markdown-formatted instruction set
   that tells Devin exactly which issues to fix, where they are, and how to
   name the resulting PR.
2. **Creates a Devin session** via the ``/v1/sessions`` API with idempotency
   enabled and retry logic (3 attempts, exponential back-off) so transient
   network failures don't abort the entire run.
3. **Records session metadata** for the centralized telemetry app to poll
   later (session polling is no longer done within the action itself).

Key design decisions
--------------------
* **Prompt references the fork URL** -- instruction #5 in the prompt
  explicitly tells Devin to create the PR on the fork repo, not upstream.
  This is critical because the user may not own the upstream repo.
* **Idempotent sessions** -- ``idempotent: True`` in the API payload
  prevents duplicate sessions if the action is re-run.
* **Tags for traceability** -- each session is tagged with the batch ID,
  severity tier, CWE family, and individual issue IDs so sessions can be
  filtered and correlated in the Devin dashboard.
* **PR title convention** -- ``fix({issue_ids}): resolve {family} security
  issues`` allows the telemetry app to match PRs by pattern and count
  them automatically.

Environment variables
---------------------
DEVIN_API_KEY : str
    Bearer token for the Devin API (required unless ``DRY_RUN`` is true).
TARGET_REPO : str
    Fork URL passed from ``fork_repo.py`` (via ``SCAN_REPO_URL``).
DEFAULT_BRANCH : str
    Branch to base fixes on (default ``main``).
MAX_ACU_PER_SESSION : str
    Optional ACU cap per session.
DRY_RUN : str
    If ``true``, prompts are generated but no sessions are created.
"""

import json
import os
import re
import sys
import time
import requests


DEVIN_API_BASE = "https://api.devin.ai/v1"

# Retry parameters for transient API failures.  Three attempts with
# linearly increasing back-off (5 s, 10 s, 15 s) covers most blips.
MAX_RETRIES = 3
RETRY_DELAY = 5


def validate_repo_url(url: str) -> str:
    """Sanitise, normalise, and loosely validate a GitHub repository URL.

    Accepts ``owner/repo`` shorthand in addition to full HTTPS URLs.
    """
    url = url.strip().rstrip("/")
    if url.endswith(".git"):
        url = url[:-4]
    if not url.startswith("http://") and not url.startswith("https://"):
        if re.match(r"^[\w.-]+/[\w.-]+$", url):
            url = f"https://github.com/{url}"
    pattern = r"^https://github\.com/[\w.-]+/[\w.-]+$"
    if not re.match(pattern, url):
        print(f"WARNING: repo URL may be invalid: {url}")
    return url


def build_batch_prompt(
    batch: dict, repo_url: str, default_branch: str, is_own_repo: bool = False,
) -> str:
    """Construct a detailed, Markdown-formatted prompt for a Devin session.

    The prompt is structured so Devin has all the context it needs to:
    * identify which files and lines to examine,
    * understand the vulnerability category and severity,
    * create a PR with the correct title and body format.

    When *is_own_repo* is True the target repo belongs to the user (not a
    fork of an upstream project) so the prompt omits the "not the upstream"
    caveat and tells Devin to work directly on the repo.
    """
    family = batch["cwe_family"]
    tier = batch["severity_tier"]
    issues = batch["issues"]

    file_list = set()
    for issue in issues:
        for loc in issue.get("locations", []):
            if loc.get("file"):
                file_list.add(loc["file"])

    issue_ids = [issue.get("id", "") for issue in issues if issue.get("id")]
    ids_str = ", ".join(issue_ids) if issue_ids else "N/A"

    prompt_parts = [
        f"Fix {batch['issue_count']} CodeQL security issue(s) in {repo_url} "
        f"(branch: {default_branch}).",
        "",
        f"Issue IDs: {ids_str}",
        f"Category: {family} | Severity: {tier.upper()} "
        f"(max CVSS: {batch['max_severity_score']})",
        "",
        "Issues to fix:",
        "",
    ]

    for idx, issue in enumerate(issues, 1):
        issue_id = issue.get("id", f"issue-{idx}")
        locs = ", ".join(
            f"{loc['file']}:{loc['start_line']}"
            for loc in issue.get("locations", [])
            if loc.get("file")
        )
        cwes = ", ".join(issue.get("cwes", [])) or "N/A"
        prompt_parts.extend(
            [
                f"### {issue_id}: {issue['rule_name']} ({issue['rule_id']})",
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

    ids_tag = ",".join(issue_ids[:6]) if issue_ids else f"batch-{batch['batch_id']}"
    pr_title = f"fix({ids_tag}): resolve {family} security issues"

    if is_own_repo:
        pr_instruction = (
            f"5. Create a PR on {repo_url} with a clear description "
            "listing each issue ID fixed."
        )
    else:
        pr_instruction = (
            f"5. Create a PR **on the fork repo {repo_url}** (not the "
            "upstream) with a clear description listing each issue ID fixed."
        )

    prompt_parts.extend(
        [
            "Instructions:",
            f"1. Clone {repo_url} and create a new branch from {default_branch}.",
            "2. Fix ALL the issues listed above. Track which issue IDs you are fixing.",
            "3. Ensure fixes don't break existing functionality.",
            "4. Run existing tests if available to verify.",
            pr_instruction,
            f"6. Title the PR exactly: '{pr_title}'",
            f"7. In the PR body, list each issue ID ({ids_str}) and describe the fix applied.",
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
    """POST to the Devin API to create a new fix session with retry logic."""
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
    }

    issue_ids = [iss.get("id", "") for iss in batch.get("issues", []) if iss.get("id")]
    ids_tag = ",".join(issue_ids[:6]) if issue_ids else f"batch-{batch['batch_id']}"

    run_number = os.environ.get("RUN_NUMBER", "")
    run_id = os.environ.get("RUN_ID", "")

    tags = [
        "codeql-fix",
        f"severity-{batch['severity_tier']}",
        f"cwe-{batch['cwe_family']}",
        f"batch-{batch['batch_id']}",
    ]
    if run_number:
        tags.append(f"run-{run_number}")
    if run_id:
        tags.append(f"run-id-{run_id}")
    for iid in issue_ids:
        tags.append(iid)

    payload: dict = {
        "prompt": prompt,
        "idempotent": True,
        "tags": tags,
        "title": (
            f"CodeQL Fix ({ids_tag}): {batch['cwe_family']} "
            f"({batch['severity_tier'].upper()})"
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


def main() -> None:
    batches_path = sys.argv[1] if len(sys.argv) > 1 else "output/batches.json"
    output_dir = sys.argv[2] if len(sys.argv) > 2 else "output"

    api_key = os.environ.get("DEVIN_API_KEY", "")
    repo_url = validate_repo_url(os.environ.get("TARGET_REPO", ""))
    default_branch = os.environ.get("DEFAULT_BRANCH", "main")
    max_acu_str = os.environ.get("MAX_ACU_PER_SESSION", "")
    dry_run = os.environ.get("DRY_RUN", "false").lower() == "true"
    fork_url = os.environ.get("FORK_URL", "")
    is_own_repo = fork_url == repo_url or not fork_url

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
        prompt = build_batch_prompt(batch, repo_url, default_branch, is_own_repo)
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



if __name__ == "__main__":
    main()
