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
from pathlib import PurePosixPath

import requests

try:
    from fix_learning import CWE_FIX_HINTS, FixLearning
    from github_utils import validate_repo_url
    from parse_sarif import BATCHES_SCHEMA_VERSION
    from pipeline_config import PipelineConfig
    from retry_utils import exponential_backoff_delay
except ImportError:
    from scripts.fix_learning import CWE_FIX_HINTS, FixLearning
    from scripts.github_utils import validate_repo_url
    from scripts.parse_sarif import BATCHES_SCHEMA_VERSION
    from scripts.pipeline_config import PipelineConfig
    from scripts.retry_utils import exponential_backoff_delay

DEVIN_API_BASE = "https://api.devin.ai/v1"

MAX_RETRIES = 3

_PROMPT_INJECTION_PATTERNS = re.compile(
    r"(?:ignore\s+(?:all\s+)?(?:previous|above)\s+instructions"
    r"|you\s+are\s+now\s+(?:a|an)\s+"
    r"|system\s*:\s*"
    r"|<\s*/?(?:system|instruction|prompt)\s*>)",
    re.IGNORECASE,
)


def sanitize_prompt_text(text: str, max_length: int = 500) -> str:
    """Sanitize text from SARIF before including it in a Devin prompt.

    Truncates to *max_length*, strips characters that could break Markdown
    formatting, and removes patterns commonly used for prompt injection.
    """
    text = text[:max_length]
    text = _PROMPT_INJECTION_PATTERNS.sub("[REDACTED]", text)
    text = text.replace("```", "'''")
    return text.strip()


def _extract_code_snippet(target_dir: str, file_path: str, start_line: int, context: int = 5) -> str:
    """Read a code snippet from the cloned repo around *start_line*.

    Returns up to *context* lines before and after the target line,
    prefixed with line numbers.  Returns an empty string if the file
    cannot be read.
    """
    full_path = os.path.join(target_dir, file_path)
    if not os.path.isfile(full_path):
        return ""
    try:
        with open(full_path, errors="replace") as fh:
            lines = fh.readlines()
    except OSError:
        return ""
    if not lines or start_line < 1:
        return ""
    begin = max(0, start_line - 1 - context)
    end = min(len(lines), start_line + context)
    snippet_lines: list[str] = []
    for i in range(begin, end):
        marker = ">>>" if i == start_line - 1 else "   "
        snippet_lines.append(f"{marker} {i + 1:4d} | {lines[i].rstrip()}")
    return "\n".join(snippet_lines)


def _find_related_test_files(target_dir: str, source_file: str) -> list[str]:
    """Heuristically find test files related to *source_file*.

    Checks common test file naming conventions:
    * ``test/X.test.ext``, ``tests/X_test.ext``, ``__tests__/X.test.ext``
    * Same directory with ``test_`` prefix or ``.test.`` / ``.spec.`` infix
    """
    if not source_file or not target_dir:
        return []
    p = PurePosixPath(source_file)
    stem = p.stem
    suffix = p.suffix
    parent = str(p.parent)

    candidates: list[str] = []
    patterns = [
        os.path.join(parent, f"test_{stem}{suffix}"),
        os.path.join(parent, f"{stem}_test{suffix}"),
        os.path.join(parent, f"{stem}.test{suffix}"),
        os.path.join(parent, f"{stem}.spec{suffix}"),
        os.path.join("test", parent, f"{stem}.test{suffix}"),
        os.path.join("test", parent, f"{stem}{suffix}"),
        os.path.join("tests", parent, f"{stem}.test{suffix}"),
        os.path.join("tests", parent, f"test_{stem}{suffix}"),
        os.path.join("__tests__", parent, f"{stem}.test{suffix}"),
    ]
    for candidate in patterns:
        full = os.path.join(target_dir, candidate)
        if os.path.isfile(full):
            candidates.append(candidate)
    return candidates


def build_batch_prompt(
    batch: dict,
    repo_url: str,
    default_branch: str,
    is_own_repo: bool = False,
    target_dir: str = "",
    fix_learning: FixLearning | None = None,
) -> str:
    """Construct a detailed, Markdown-formatted prompt for a Devin session.

    The prompt is structured so Devin has all the context it needs to:
    * identify which files and lines to examine,
    * understand the vulnerability category and severity,
    * create a PR with the correct title and body format.

    When *target_dir* is provided, the prompt is enriched with:
    * source code snippets around each issue location,
    * related test file suggestions,
    * CWE-specific fix pattern hints.

    When *fix_learning* is provided, historical fix-rate context is
    included to help Devin understand past success patterns.

    When *is_own_repo* is True the target repo belongs to the user (not a
    fork of an upstream project) so the prompt omits the "not the upstream"
    caveat and tells Devin to work directly on the repo.
    """
    family = batch["cwe_family"]
    tier = batch["severity_tier"]
    issues = batch["issues"]

    file_list: set[str] = set()
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
    ]

    fix_hint = CWE_FIX_HINTS.get(family)
    if fix_hint:
        prompt_parts.extend([f"Fix pattern hint for {family}: {fix_hint}", ""])

    if fix_learning:
        context = fix_learning.prompt_context_for_family(family)
        if context:
            for line in context.split("\n"):
                if line and not line.startswith("Fix pattern hint"):
                    prompt_parts.append(line)
            prompt_parts.append("")

    prompt_parts.extend(["Issues to fix:", ""])

    all_test_files: set[str] = set()

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
                f"- Description: {sanitize_prompt_text(issue['message'], 300)}",
            ]
        )
        if issue.get("rule_description"):
            prompt_parts.append(f"- Rule: {sanitize_prompt_text(issue['rule_description'], 200)}")
        if issue.get("rule_help"):
            prompt_parts.append(f"- Guidance: {sanitize_prompt_text(issue['rule_help'], 500)}")

        if target_dir:
            for loc in issue.get("locations", []):
                f = loc.get("file", "")
                sl = loc.get("start_line", 0)
                if f and sl > 0:
                    snippet = _extract_code_snippet(target_dir, f, sl)
                    if snippet:
                        prompt_parts.append(f"- Code context:\n```\n{snippet}\n```")
                    tests = _find_related_test_files(target_dir, f)
                    all_test_files.update(tests)
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

    if all_test_files:
        prompt_parts.extend(["", "Related test files (review and update if needed):"])
        for tf in sorted(all_test_files):
            prompt_parts.append(f"- {tf}")

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
                delay = exponential_backoff_delay(attempt)
                print(f"  Retry {attempt}/{MAX_RETRIES} after error: {e} "
                      f"(waiting {delay:.1f}s)")
                time.sleep(delay)
    raise last_err  # type: ignore[misc]


def main() -> None:
    batches_path = sys.argv[1] if len(sys.argv) > 1 else "output/batches.json"
    output_dir = sys.argv[2] if len(sys.argv) > 2 else "output"

    cfg = PipelineConfig.from_env()
    api_key = cfg.devin_api_key
    repo_url = validate_repo_url(cfg.target_repo)
    default_branch = cfg.default_branch
    dry_run = cfg.dry_run
    fork_url = cfg.fork_url
    is_own_repo = fork_url == repo_url or not fork_url
    max_acu = cfg.max_acu_per_session
    target_dir = cfg.target_dir
    if target_dir and not os.path.isdir(target_dir):
        print(f"WARNING: TARGET_DIR '{target_dir}' does not exist; code snippets disabled")
        target_dir = ""
    telemetry_dir = cfg.telemetry_dir

    fix_learn: FixLearning | None = None
    if telemetry_dir and os.path.isdir(telemetry_dir):
        fix_learn = FixLearning.from_telemetry_dir(telemetry_dir)
        rates = fix_learn.prioritized_families()
        if rates:
            print("Historical fix rates by CWE family:")
            for fam, rate in rates:
                print(f"  {fam}: {rate * 100:.0f}%")
            print()

    if not api_key and not dry_run:
        print("ERROR: DEVIN_API_KEY is required (set DRY_RUN=true to skip)")
        sys.exit(1)

    if not repo_url:
        print("ERROR: TARGET_REPO environment variable is required")
        sys.exit(1)

    with open(batches_path) as f:
        raw = json.load(f)

    if isinstance(raw, dict) and "schema_version" in raw:
        file_version = raw["schema_version"]
        if file_version != BATCHES_SCHEMA_VERSION:
            print(
                f"ERROR: batches.json schema version '{file_version}' "
                f"does not match expected '{BATCHES_SCHEMA_VERSION}'. "
                "This indicates an incompatible data format."
            )
            sys.exit(1)
        batches = raw.get("batches", [])
    else:
        batches = raw if isinstance(raw, list) else []

    if not batches:
        print("No batches to process. Exiting.")
        return

    if fix_learn:
        skipped_families: list[str] = []
        kept_batches: list[dict] = []
        for batch in batches:
            family = batch["cwe_family"]
            if fix_learn.should_skip_family(family):
                skipped_families.append(family)
            else:
                kept_batches.append(batch)
        if skipped_families:
            print(f"Skipping {len(skipped_families)} batch(es) due to low "
                  f"historical fix rate: {', '.join(set(skipped_families))}")
        batches = kept_batches
        if not batches:
            print("All batches skipped due to low fix rates. Exiting.")
            return

    print(f"Processing {len(batches)} batches for {repo_url}")
    print(f"Default branch: {default_branch}")
    print(f"Dry run: {dry_run}")
    if target_dir:
        print(f"Target dir: {target_dir} (code snippets enabled)")
    print()

    sessions: list[dict] = []

    for batch in batches:
        prompt = build_batch_prompt(
            batch, repo_url, default_branch, is_own_repo,
            target_dir=target_dir, fix_learning=fix_learn,
        )
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

    sessions_failed = len([s for s in sessions if s["status"].startswith("error")])
    sessions_created = len([s for s in sessions if s["status"] == "created"])

    with open(os.path.join(output_dir, "sessions.json"), "w") as f:
        json.dump(sessions, f, indent=2)

    print("\n" + "=" * 60)
    print("Dispatch Summary")
    print("=" * 60)

    if sessions_failed:
        print(f"WARNING: {sessions_failed}/{len(sessions)} session(s) failed to create")

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
            f.write(f"sessions_created={sessions_created}\n")
            f.write(f"sessions_failed={sessions_failed}\n")

    max_failure_rate = cfg.max_failure_rate
    if sessions and not dry_run and sessions_failed > 0:
        actual_rate = (sessions_failed / len(sessions)) * 100
        if actual_rate > max_failure_rate:
            print(
                f"\nERROR: Session failure rate {actual_rate:.0f}% exceeds "
                f"maximum allowed {max_failure_rate}% "
                f"({sessions_failed}/{len(sessions)} failed)"
            )
            sys.exit(1)


if __name__ == "__main__":
    main()
