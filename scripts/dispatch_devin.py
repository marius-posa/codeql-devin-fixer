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

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import time
from pathlib import PurePosixPath
from typing import Any

import requests

try:
    import jinja2
except ImportError:
    jinja2 = None  # type: ignore[assignment]

try:
    from devin_api import (
        DEVIN_API_BASE, MAX_RETRIES, TERMINAL_STATUSES, clean_session_id,
        headers as devin_headers, request_with_retry, upload_attachment,
    )
    from fix_learning import CWE_FIX_HINTS, FixLearning
    from github_utils import validate_repo_url
    from knowledge import build_knowledge_context, store_fix_knowledge
    from logging_config import setup_logging
    from machine_config import resolve_machine_acu
    from parse_sarif import BATCHES_SCHEMA_VERSION
    from pipeline_config import (
        Batch, DispatchSession, PipelineConfig, STRUCTURED_OUTPUT_SCHEMA,
    )
    from playbook_manager import PlaybookManager
    from repo_context import RepoContext, analyze_repo
    from retry_feedback import process_retry_batch
    from retry_utils import exponential_backoff_delay
except ImportError:
    from scripts.devin_api import (
        DEVIN_API_BASE, MAX_RETRIES, TERMINAL_STATUSES, clean_session_id,
        headers as devin_headers, request_with_retry, upload_attachment,
    )
    from scripts.fix_learning import CWE_FIX_HINTS, FixLearning
    from scripts.github_utils import validate_repo_url
    from scripts.knowledge import build_knowledge_context, store_fix_knowledge
    from scripts.logging_config import setup_logging
    from scripts.machine_config import resolve_machine_acu
    from scripts.parse_sarif import BATCHES_SCHEMA_VERSION
    from scripts.pipeline_config import (
        Batch, DispatchSession, PipelineConfig, STRUCTURED_OUTPUT_SCHEMA,
    )
    from scripts.playbook_manager import PlaybookManager
    from scripts.repo_context import RepoContext, analyze_repo
    from scripts.retry_feedback import process_retry_batch
    from scripts.retry_utils import exponential_backoff_delay

logger = setup_logging(__name__)


def _load_prompt_template(template_path: str) -> "jinja2.Template | None":
    """Load a Jinja2 prompt template from a file path.

    Returns ``None`` if the file doesn't exist or Jinja2 isn't available.
    """
    if not template_path:
        return None
    if not os.path.isfile(template_path):
        logger.warning("Prompt template not found: %s", template_path)
        return None
    if jinja2 is None:
        logger.warning("jinja2 not installed; custom templates disabled")
        return None
    with open(template_path) as f:
        env = jinja2.Environment(autoescape=True)
        return env.from_string(f.read())


def _render_template_prompt(
    template: "jinja2.Template",
    batch: dict,
    repo_url: str,
    default_branch: str,
    is_own_repo: bool = False,
    fix_learning: "FixLearning | None" = None,
) -> str:
    """Render a batch prompt using a custom Jinja2 template."""
    family = batch["cwe_family"]
    context = {
        "batch": batch,
        "repo_url": repo_url,
        "default_branch": default_branch,
        "is_own_repo": is_own_repo,
        "family": family,
        "tier": batch["severity_tier"],
        "issues": batch["issues"],
        "issue_count": batch["issue_count"],
        "max_severity_score": batch["max_severity_score"],
        "fix_hint": CWE_FIX_HINTS.get(family, ""),
        "issue_ids": [i.get("id", "") for i in batch["issues"] if i.get("id")],
    }
    if fix_learning:
        context["fix_learning_context"] = fix_learning.prompt_context_for_family(family)
    return template.render(**context)


def _send_session_webhook(
    session_id: str, session_url: str, batch_id: int,
    target_repo: str, run_id: str,
) -> None:
    """Send a session_created webhook if WEBHOOK_URL is configured."""
    webhook_url = os.environ.get("WEBHOOK_URL", "")
    if not webhook_url:
        return
    webhook_secret = os.environ.get("WEBHOOK_SECRET", "")
    try:
        script_dir = os.path.dirname(os.path.abspath(__file__))
        cmd = [
            sys.executable, os.path.join(script_dir, "webhook.py"),
            "--event", "session_created",
            "--target-repo", target_repo,
            "--run-id", run_id,
            "--session-id", session_id,
            "--session-url", session_url,
            "--batch-id", str(batch_id),
        ]
        env = {**os.environ, "WEBHOOK_URL": webhook_url, "WEBHOOK_SECRET": webhook_secret}
        subprocess.run(cmd, env=env, timeout=30, check=False)
    except Exception as e:
        logger.warning("session_created webhook failed: %s", e)

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


def _upload_batch_attachments(
    api_key: str,
    batch: Batch,
    target_dir: str,
    output_dir: str,
) -> list[str]:
    """Upload batch data and source files as Devin attachments.

    Writes a JSON file with the batch issue details and uploads it via
    the ``/v1/attachments`` API.  When *target_dir* is provided, source
    files referenced by the batch are also uploaded.

    Returns a list of ``ATTACHMENT:"<url>"`` lines to include in the prompt.
    Falls back gracefully (returns an empty list) on any upload failure.
    """
    attachment_lines: list[str] = []

    batch_data = {
        "batch_id": batch["batch_id"],
        "cwe_family": batch["cwe_family"],
        "severity_tier": batch["severity_tier"],
        "max_severity_score": batch["max_severity_score"],
        "issue_count": batch["issue_count"],
        "issues": batch["issues"],
    }
    batch_file = os.path.join(output_dir, f"batch_{batch['batch_id']}_data.json")
    try:
        with open(batch_file, "w") as fh:
            json.dump(batch_data, fh, indent=2)
        url = upload_attachment(api_key, batch_file)
        if url:
            attachment_lines.append(f'ATTACHMENT:"{url}"')
            logger.info("  Uploaded batch data as attachment")
    except OSError as exc:
        logger.warning("Failed to write batch data file: %s", exc)

    if target_dir:
        uploaded_files: set[str] = set()
        for issue in batch.get("issues", []):
            for loc in issue.get("locations", []):
                file_path = loc.get("file", "")
                if not file_path or file_path in uploaded_files:
                    continue
                full_path = os.path.join(target_dir, file_path)
                if not os.path.isfile(full_path):
                    continue
                url = upload_attachment(api_key, full_path)
                if url:
                    attachment_lines.append(f'ATTACHMENT:"{url}"')
                    uploaded_files.add(file_path)

    return attachment_lines


def build_batch_prompt(
    batch: Batch,
    repo_url: str,
    default_branch: str,
    is_own_repo: bool = False,
    target_dir: str = "",
    fix_learning: FixLearning | None = None,
    playbook_mgr: PlaybookManager | None = None,
    repo_context: RepoContext | None = None,
    knowledge_context: str = "",
    attachment_lines: list[str] | None = None,
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

    When *playbook_mgr* is provided and a playbook exists for the batch's
    CWE family, structured step-by-step instructions are included in the
    prompt along with a request for Devin to suggest playbook improvements.

    When *is_own_repo* is True the target repo belongs to the user (not a
    fork of an upstream project) so the prompt omits the "not the upstream"
    caveat and tells Devin to work directly on the repo.

    When *repo_context* is provided, dependency, testing framework, and
    code style information is included so Devin can produce fixes that
    conform to the project's tooling and conventions.
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

    cwe_families = batch.get("cwe_families", [family])
    is_cross_family = batch.get("cross_family", False)
    playbooks: list[tuple[str, Any]] = []
    if playbook_mgr:
        for fam in cwe_families:
            pb = playbook_mgr.get_playbook(fam)
            if pb:
                playbooks.append((fam, pb))
    if playbooks:
        for _fam, pb in playbooks:
            prompt_parts.append(playbook_mgr.format_for_prompt(pb))
            prompt_parts.append("")
    else:
        for fam in cwe_families:
            fix_hint = CWE_FIX_HINTS.get(fam)
            if fix_hint:
                prompt_parts.extend([f"Fix pattern hint for {fam}: {fix_hint}", ""])

    if fix_learning:
        for fam in cwe_families:
            context = fix_learning.prompt_context_for_family(fam)
            if context:
                for line in context.split("\n"):
                    if line and not line.startswith("Fix pattern hint"):
                        prompt_parts.append(line)
                prompt_parts.append("")

            file_patterns = sorted(file_list) if file_list else None
            fix_examples = fix_learning.prompt_fix_examples(fam, file_patterns)
            if fix_examples:
                prompt_parts.extend([fix_examples, ""])

    if repo_context and not repo_context.is_empty():
        prompt_parts.extend([repo_context.to_prompt_section(), ""])

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
    families_label = "+".join(cwe_families) if is_cross_family else family
    pr_title = f"fix({ids_tag}): resolve {families_label} security issues"

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

    if playbooks and playbook_mgr:
        for _fam, pb in playbooks:
            prompt_parts.extend(["", playbook_mgr.format_improvement_request(pb)])

    if knowledge_context:
        prompt_parts.append(knowledge_context)

    prompt_parts.extend([
        "",
        "## Structured Output",
        "",
        "You MUST maintain a structured output object throughout this session.",
        "Update it whenever you make meaningful progress.",
        "Use the following JSON schema:",
        "",
        "```json",
        json.dumps(STRUCTURED_OUTPUT_SCHEMA, indent=2),
        "```",
        "",
        "Update the structured output at these key moments:",
        '- When starting analysis: set status to "analyzing", populate issues_attempted',
        '- When fixing issues: set status to "fixing", update issues_fixed as each is resolved',
        '- When running tests: set status to "testing", set tests_passing accordingly',
        '- When creating the PR: set status to "creating_pr", set pull_request_url once created',
        '- When finished: set status to "done", ensure all fields are final',
        '- If blocked: set status to "blocked", populate issues_blocked with id and reason',
        "",
        "Example initial value:",
        "```json",
        json.dumps({
            "status": "analyzing",
            "issues_attempted": issue_ids,
            "issues_fixed": [],
            "issues_blocked": [],
            "pull_request_url": "",
            "files_changed": 0,
            "tests_passing": False,
        }, indent=2),
        "```",
    ])

    if attachment_lines:
        prompt_parts.extend([
            "",
            "## Attached Files",
            "",
            "The following files have been uploaded as attachments for this session.",
            "Browse them for detailed issue data and source context.",
            "",
        ])
        prompt_parts.extend(attachment_lines)

    return "\n".join(prompt_parts)


def create_devin_session(
    api_key: str,
    prompt: str,
    batch: Batch,
    max_acu: int | None = None,
    playbook_id: str = "",
) -> dict:
    """POST to the Devin API to create a new fix session with retry logic."""
    issue_ids = [iss.get("id", "") for iss in batch.get("issues", []) if iss.get("id")]
    ids_tag = ",".join(issue_ids[:6]) if issue_ids else f"batch-{batch['batch_id']}"

    run_number = os.environ.get("RUN_NUMBER", "")
    run_id = os.environ.get("RUN_ID", "")

    cwe_families = batch.get("cwe_families", [batch["cwe_family"]])
    tags = [
        "codeql-fix",
        f"severity-{batch['severity_tier']}",
        f"batch-{batch['batch_id']}",
    ]
    for fam in cwe_families:
        tags.append(f"cwe-{fam}")
    if batch.get("cross_family", False):
        tags.append("cross-family")
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
        "structured_output_schema": STRUCTURED_OUTPUT_SCHEMA,
    }
    if max_acu is not None and max_acu > 0:
        payload["max_acu_limit"] = max_acu
    if playbook_id:
        payload["playbook_id"] = playbook_id

    return request_with_retry("POST", f"{DEVIN_API_BASE}/sessions", api_key, payload)


SEVERITY_ORDER = ["critical", "high", "medium", "low"]


def group_batches_by_wave(batches: list[Batch]) -> list[list[Batch]]:
    """Group batches into waves by severity tier.

    Each wave contains all batches of one severity tier, ordered from
    most severe (critical) to least severe (low).
    """
    tier_map: dict[str, list[Batch]] = {}
    for batch in batches:
        tier = batch.get("severity_tier", "low")
        tier_map.setdefault(tier, []).append(batch)

    waves: list[list[Batch]] = []
    for tier in SEVERITY_ORDER:
        if tier in tier_map:
            waves.append(tier_map[tier])
    leftover = [
        b for b in batches
        if b.get("severity_tier", "low") not in SEVERITY_ORDER
    ]
    if leftover:
        waves.append(leftover)
    return waves


def poll_sessions_until_done(
    api_key: str,
    sessions: list[DispatchSession],
    poll_interval: int = 60,
    timeout: int = 3600,
) -> list[DispatchSession]:
    """Poll Devin sessions until all are finished or timeout is reached."""
    deadline = time.time() + timeout

    while time.time() < deadline:
        pending = [
            s for s in sessions
            if s["status"] not in TERMINAL_STATUSES
            and s["session_id"]
            and s["session_id"] != "dry-run"
        ]
        if not pending:
            break

        for s in pending:
            clean_sid = clean_session_id(s["session_id"])
            try:
                resp = requests.get(
                    f"{DEVIN_API_BASE}/sessions/{clean_sid}",
                    headers=devin_headers(api_key),
                    timeout=15,
                )
                if resp.status_code == 200:
                    data = resp.json()
                    status_str = str(
                        data.get("status_enum")
                        or data.get("status")
                        or "unknown"
                    ).lower()
                    s["status"] = status_str

                    so = data.get("structured_output")
                    if isinstance(so, dict):
                        pr_url = so.get("pull_request_url", "")
                        if pr_url:
                            s["pr_url"] = pr_url
                        s["structured_output"] = so
            except requests.RequestException as exc:
                logger.warning("Failed to poll session %s: %s", s["session_id"], exc)

        time.sleep(poll_interval)

    return sessions


def compute_wave_fix_rate(sessions: list[DispatchSession]) -> float:
    """Compute the fix rate for a completed wave of sessions."""
    finished = [s for s in sessions if s["session_id"] and s["session_id"] != "dry-run"]
    if not finished:
        return 0.0
    succeeded = [s for s in finished if s["status"] == "finished"]
    return len(succeeded) / len(finished)


def dispatch_wave(
    wave_batches: list[Batch],
    api_key: str,
    repo_url: str,
    default_branch: str,
    is_own_repo: bool,
    target_dir: str,
    fix_learn: "FixLearning | None",
    playbook_mgr: "PlaybookManager | None",
    repo_ctx: "RepoContext | None",
    prompt_template: str,
    output_dir: str,
    run_id: str,
    max_acu: int | None,
    dry_run: bool,
    enable_knowledge: bool = False,
    enable_attachments: bool = False,
    machine_type: str = "",
) -> list[DispatchSession]:
    """Dispatch all batches in a single wave, returning session records."""
    sessions: list[DispatchSession] = []
    for batch in wave_batches:
        family = batch["cwe_family"]

        if max_acu is not None or machine_type:
            batch_acu = resolve_machine_acu(
                explicit_max_acu=max_acu,
                machine_type_name=machine_type,
                target_dir=target_dir,
                issue_count=batch.get("issue_count", 1),
                file_count=batch.get("file_count", 0),
                severity_tier=batch.get("severity_tier", "medium"),
                cross_family=batch.get("cross_family", False),
            )
        else:
            batch_acu = max_acu
        if fix_learn and batch_acu:
            batch_acu = fix_learn.compute_acu_budget(family, batch_acu)
        elif fix_learn and not batch_acu:
            batch_acu = fix_learn.compute_acu_budget(family)

        att_lines: list[str] = []
        if enable_attachments and api_key and not dry_run:
            att_lines = _upload_batch_attachments(
                api_key, batch, target_dir, output_dir,
            )

        if prompt_template:
            prompt = _render_template_prompt(
                prompt_template, batch, repo_url, default_branch,
                is_own_repo, fix_learn,
            )
        else:
            kctx = ""
            if enable_knowledge and api_key:
                try:
                    kctx = build_knowledge_context(api_key, family)
                except Exception as exc:
                    logger.warning("Knowledge context fetch failed for %s: %s", family, exc)
            prompt = build_batch_prompt(
                batch, repo_url, default_branch, is_own_repo,
                target_dir=target_dir, fix_learning=fix_learn,
                playbook_mgr=playbook_mgr,
                repo_context=repo_ctx,
                knowledge_context=kctx,
                attachment_lines=att_lines if att_lines else None,
            )
        batch_id = batch["batch_id"]

        prompt_path = os.path.join(output_dir, f"prompt_batch_{batch_id}.txt")
        with open(prompt_path, "w") as f:
            f.write(prompt)

        logger.info("--- Batch %d ---", batch_id)
        logger.info("  Category: %s", family)
        logger.info("  Severity: %s", batch['severity_tier'].upper())
        logger.info("  Issues: %d", batch['issue_count'])
        if batch_acu and batch_acu != max_acu:
            logger.info("  ACU budget: %d (dynamic, base=%s)", batch_acu, max_acu or 'default')

        if dry_run:
            logger.info("  [DRY RUN] Prompt saved to %s", prompt_path)
            sessions.append({
                "batch_id": batch_id,
                "session_id": "dry-run",
                "url": "dry-run",
                "status": "dry-run",
            })
            continue

        playbook_id = ""
        if playbook_mgr:
            playbook_id = playbook_mgr.get_devin_playbook_id(family)

        try:
            result = create_devin_session(api_key, prompt, batch, batch_acu, playbook_id)
            session_id = result["session_id"]
            url = result["url"]
            logger.info("  Session created: %s", url)
            sessions.append({
                "batch_id": batch_id,
                "session_id": session_id,
                "url": url,
                "status": "created",
            })
            _send_session_webhook(session_id, url, batch_id, repo_url, run_id)
            time.sleep(2)
        except requests.exceptions.RequestException as e:
            logger.error("  ERROR creating session: %s", e)
            sessions.append({
                "batch_id": batch_id,
                "session_id": "",
                "url": "",
                "status": f"error: {e}",
            })
    return sessions


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
        logger.warning("TARGET_DIR '%s' does not exist; code snippets disabled", target_dir)
        target_dir = ""
    telemetry_dir = cfg.telemetry_dir
    playbooks_dir = cfg.playbooks_dir

    playbook_mgr: PlaybookManager | None = None
    if playbooks_dir and os.path.isdir(playbooks_dir):
        playbook_mgr = PlaybookManager(playbooks_dir)
        families = playbook_mgr.available_families
        if families:
            logger.info("Loaded playbooks for: %s", ', '.join(families))
        if api_key and families:
            synced = playbook_mgr.sync_to_devin_api(api_key)
            if synced:
                logger.info("Synced %d playbook(s) to Devin API", len(synced))

    fix_learn: FixLearning | None = None
    if telemetry_dir and os.path.isdir(telemetry_dir):
        fix_learn = FixLearning.from_telemetry_dir(telemetry_dir)
        rates = fix_learn.prioritized_families()
        if rates:
            logger.info("Historical fix rates by CWE family:")
            for fam, rate in rates:
                logger.info("  %s: %.0f%%", fam, rate * 100)

    repo_ctx: RepoContext | None = None
    if target_dir:
        repo_ctx = analyze_repo(target_dir)
        if not repo_ctx.is_empty():
            logger.info("Repository context discovered:")
            if repo_ctx.dependencies:
                logger.info("  Dependencies: %s", ', '.join(repo_ctx.dependencies.keys()))
            if repo_ctx.test_frameworks:
                logger.info("  Test frameworks: %s", ', '.join(repo_ctx.test_frameworks))
            if repo_ctx.style_configs:
                logger.info("  Style configs: %s", ', '.join(repo_ctx.style_configs))

    if not api_key and not dry_run:
        logger.error("DEVIN_API_KEY is required (set DRY_RUN=true to skip)")
        sys.exit(1)

    if not repo_url:
        logger.error("TARGET_REPO environment variable is required")
        sys.exit(1)

    with open(batches_path) as f:
        raw = json.load(f)

    if isinstance(raw, dict) and "schema_version" in raw:
        file_version = raw["schema_version"]
        if file_version != BATCHES_SCHEMA_VERSION:
            logger.error(
                "batches.json schema version '%s' does not match expected '%s'. "
                "This indicates an incompatible data format.",
                file_version, BATCHES_SCHEMA_VERSION,
            )
            sys.exit(1)
        batches = raw.get("batches", [])
    else:
        batches = raw if isinstance(raw, list) else []

    if not batches:
        logger.info("No batches to process. Exiting.")
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
            logger.info("Skipping %d batch(es) due to low historical fix rate: %s",
                        len(skipped_families), ', '.join(set(skipped_families)))
        batches = kept_batches
        if not batches:
            logger.info("All batches skipped due to low fix rates. Exiting.")
            return

    template_path = os.environ.get("PROMPT_TEMPLATE", "")
    prompt_template = _load_prompt_template(template_path)
    if prompt_template:
        logger.info("Using custom prompt template: %s", template_path)

    logger.info("Processing %d batches for %s", len(batches), repo_url)
    logger.info("Default branch: %s", default_branch)
    logger.info("Dry run: %s", dry_run)
    if target_dir:
        logger.info("Target dir: %s (code snippets enabled)", target_dir)
    if playbook_mgr:
        logger.info("Playbooks dir: %s", playbooks_dir)

    enable_knowledge = os.environ.get("ENABLE_KNOWLEDGE", "false").lower() == "true"
    enable_retry = os.environ.get("ENABLE_RETRY_FEEDBACK", "false").lower() == "true"
    max_retry_attempts = int(os.environ.get("MAX_RETRY_ATTEMPTS", "2"))
    knowledge_folder_id = os.environ.get("KNOWLEDGE_FOLDER_ID", "") or None
    github_token = os.environ.get("GITHUB_TOKEN", "")

    if enable_knowledge:
        logger.info("Knowledge API enabled")
    if enable_retry:
        logger.info("Retry-with-feedback enabled (max %d attempts)", max_retry_attempts)

    run_id = os.environ.get("RUN_ID", "")
    sessions: list[DispatchSession] = []

    wave_common_kwargs = {
        "api_key": api_key,
        "repo_url": repo_url,
        "default_branch": default_branch,
        "is_own_repo": is_own_repo,
        "target_dir": target_dir,
        "fix_learn": fix_learn,
        "playbook_mgr": playbook_mgr,
        "repo_ctx": repo_ctx,
        "prompt_template": prompt_template,
        "output_dir": output_dir,
        "run_id": run_id,
        "max_acu": max_acu,
        "dry_run": dry_run,
        "enable_knowledge": enable_knowledge,
        "enable_attachments": cfg.enable_attachments,
        "machine_type": cfg.machine_type,
    }

    if cfg.wave_dispatch:
        waves = group_batches_by_wave(batches)
        logger.info("Wave dispatch enabled: %d wave(s)", len(waves))
        for wave_idx, wave_batches in enumerate(waves, 1):
            tier = wave_batches[0].get("severity_tier", "unknown") if wave_batches else "unknown"
            logger.info("\n" + "=" * 60)
            logger.info("Wave %d/%d -- %s (%d batch(es))",
                        wave_idx, len(waves), tier.upper(), len(wave_batches))
            logger.info("=" * 60)

            wave_sessions = dispatch_wave(wave_batches, **wave_common_kwargs)
            sessions.extend(wave_sessions)

            if not dry_run and wave_idx < len(waves):
                logger.info("Polling wave %d sessions (timeout=%ds)...",
                            wave_idx, cfg.wave_timeout)
                poll_sessions_until_done(
                    api_key, wave_sessions,
                    poll_interval=cfg.wave_poll_interval,
                    timeout=cfg.wave_timeout,
                )
                fix_rate = compute_wave_fix_rate(wave_sessions)
                logger.info("Wave %d fix rate: %.0f%%", wave_idx, fix_rate * 100)

                if fix_rate < cfg.wave_fix_rate_threshold:
                    logger.warning(
                        "Fix rate %.0f%% below threshold %.0f%% -- "
                        "stopping dispatch. Manual review recommended.",
                        fix_rate * 100, cfg.wave_fix_rate_threshold * 100,
                    )
                    break
                logger.info("Fix rate meets threshold, proceeding to wave %d...",
                            wave_idx + 1)
    else:
        sessions = dispatch_wave(batches, **wave_common_kwargs)

    sessions_failed = len([s for s in sessions if s["status"].startswith("error")])
    sessions_created = len([s for s in sessions if s["status"] == "created"])

    with open(os.path.join(output_dir, "sessions.json"), "w") as f:
        json.dump(sessions, f, indent=2)

    logger.info("\n" + "=" * 60)
    logger.info("Dispatch Summary")
    logger.info("=" * 60)

    if sessions_failed:
        logger.warning("%d/%d session(s) failed to create", sessions_failed, len(sessions))

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
    logger.info("\n%s", summary)

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

    if enable_knowledge and not dry_run:
        created_sessions = [s for s in sessions if s["status"] == "created"]
        for sess in created_sessions:
            batch = next((b for b in batches if b["batch_id"] == sess["batch_id"]), None)
            if not batch:
                continue
            try:
                store_fix_knowledge(
                    api_key=api_key,
                    cwe_family=batch["cwe_family"],
                    batch_id=sess["batch_id"],
                    pr_url=sess.get("url", ""),
                    diff_summary=(
                        f"Automated fix for {batch['issue_count']} "
                        f"{batch['cwe_family']} issues"
                    ),
                    issue_count=batch["issue_count"],
                    severity_tier=batch.get("severity_tier", "medium"),
                    repo_url=repo_url,
                    parent_folder_id=knowledge_folder_id,
                    github_token=github_token,
                )
                logger.info(
                    "Stored knowledge for batch %s (%s)",
                    sess["batch_id"], batch["cwe_family"],
                )
            except Exception as exc:
                logger.warning(
                    "Failed to store knowledge for batch %s: %s",
                    sess["batch_id"], exc,
                )

    if enable_retry and not dry_run:
        created_sessions = [s for s in sessions if s["status"] == "created"]
        if created_sessions:
            outcomes = [
                {
                    "batch_id": s["batch_id"],
                    "session_id": s["session_id"],
                    "status": s["status"],
                    "pr_url": s.get("url", ""),
                }
                for s in created_sessions
            ]
            prompts: dict[int | str, str] = {}
            for batch in batches:
                bid = batch["batch_id"]
                prompt_path = os.path.join(output_dir, f"prompt_batch_{bid}.txt")
                if os.path.isfile(prompt_path):
                    with open(prompt_path) as pf:
                        prompts[bid] = pf.read()
            try:
                retry_results = process_retry_batch(
                    api_key=api_key,
                    outcomes=outcomes,
                    batches=batches,
                    prompts=prompts,
                    max_retry_attempts=max_retry_attempts,
                    max_acu=max_acu,
                )
                if retry_results:
                    logger.info(
                        "Retry-with-feedback processed %d session(s)",
                        len(retry_results),
                    )
                    retry_path = os.path.join(output_dir, "retry_results.json")
                    with open(retry_path, "w") as rf:
                        json.dump(retry_results, rf, indent=2)
            except Exception as exc:
                logger.warning("Retry-with-feedback failed: %s", exc)

    max_failure_rate = cfg.max_failure_rate
    if sessions and not dry_run and sessions_failed > 0:
        actual_rate = (sessions_failed / len(sessions)) * 100
        if actual_rate > max_failure_rate:
            logger.error(
                "Session failure rate %.0f%% exceeds maximum allowed %.0f%% "
                "(%d/%d failed)",
                actual_rate, max_failure_rate, sessions_failed, len(sessions),
            )
            sys.exit(1)


if __name__ == "__main__":
    main()
