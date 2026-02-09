#!/usr/bin/env python3
"""Retry-with-feedback for Devin sessions using the Send Message API."""

import json
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from devin_api import DEVIN_API_BASE, TERMINAL_STATUSES, request_with_retry

DEFAULT_MAX_RETRY_ATTEMPTS = 2


def send_message(api_key: str, session_id: str, message: str) -> dict:
    return request_with_retry(
        "POST",
        f"{DEVIN_API_BASE}/sessions/{session_id}/message",
        api_key,
        {"message": message},
    )


def get_session(api_key: str, session_id: str) -> dict:
    return request_with_retry(
        "GET",
        f"{DEVIN_API_BASE}/sessions/{session_id}",
        api_key,
    )


def create_session(
    api_key: str,
    prompt: str,
    tags: list[str] | None = None,
    title: str = "",
    max_acu: int | None = None,
) -> dict:
    payload: dict = {
        "prompt": prompt,
        "idempotent": False,
    }
    if tags:
        payload["tags"] = tags
    if title:
        payload["title"] = title
    if max_acu is not None and max_acu > 0:
        payload["max_acu_limit"] = max_acu
    return request_with_retry(
        "POST", f"{DEVIN_API_BASE}/sessions", api_key, payload
    )


def _build_feedback_message(
    verification_results: str,
    remaining_issues: list[dict] | None = None,
) -> str:
    parts = [
        "## Verification Results - Action Required",
        "",
        "The automated verification scan found that some issues were not fully resolved. "
        "Please review and fix the remaining problems.",
        "",
        verification_results,
    ]

    if remaining_issues:
        parts.extend(
            [
                "",
                "### Remaining Issues",
                "",
            ]
        )
        for idx, issue in enumerate(remaining_issues, 1):
            locs = ", ".join(
                f"{loc['file']}:{loc['start_line']}"
                for loc in issue.get("locations", [])
                if loc.get("file")
            )
            parts.append(
                f"{idx}. **{issue.get('rule_id', 'N/A')}** at {locs}: "
                f"{issue.get('message', '')[:200]}"
            )

    parts.extend(
        [
            "",
            "Please update your fix to address these remaining issues, "
            "then push the changes to the existing PR branch.",
        ]
    )
    return "\n".join(parts)


def _build_followup_prompt(
    original_prompt: str,
    verification_results: str,
    previous_pr_url: str = "",
    remaining_issues: list[dict] | None = None,
    attempt_number: int = 2,
) -> str:
    parts = [
        f"## Retry Attempt {attempt_number}: Fix Remaining Issues",
        "",
        "A previous attempt to fix these issues was partially successful. "
        "Some issues remain unresolved after automated verification.",
        "",
    ]

    if previous_pr_url:
        parts.extend(
            [
                f"**Previous PR**: {previous_pr_url}",
                "Review the previous attempt's changes as context for this fix.",
                "",
            ]
        )

    parts.extend(
        [
            "### Verification Results from Previous Attempt",
            "",
            verification_results,
            "",
        ]
    )

    if remaining_issues:
        parts.extend(
            [
                "### Specific Remaining Issues",
                "",
            ]
        )
        for idx, issue in enumerate(remaining_issues, 1):
            locs = ", ".join(
                f"{loc['file']}:{loc['start_line']}"
                for loc in issue.get("locations", [])
                if loc.get("file")
            )
            cwes = ", ".join(issue.get("cwes", [])) or "N/A"
            parts.append(
                f"{idx}. **{issue.get('rule_name', issue.get('rule_id', 'N/A'))}** "
                f"({issue.get('rule_id', '')})"
            )
            parts.append(f"   - CWE: {cwes}")
            parts.append(f"   - Location: {locs}")
            parts.append(f"   - Message: {issue.get('message', '')[:300]}")
            parts.append("")

    parts.extend(
        [
            "### Original Task",
            "",
            original_prompt,
        ]
    )
    return "\n".join(parts)


def retry_with_feedback(
    api_key: str,
    session_id: str,
    batch: dict,
    original_prompt: str,
    verification_results: str,
    remaining_issues: list[dict] | None = None,
    previous_pr_url: str = "",
    attempt_number: int = 1,
    max_retry_attempts: int = DEFAULT_MAX_RETRY_ATTEMPTS,
    max_acu: int | None = None,
) -> dict:
    if attempt_number > max_retry_attempts:
        return {
            "action": "max_retries_exceeded",
            "session_id": session_id,
            "batch_id": batch.get("batch_id", ""),
            "attempt": attempt_number,
            "max_attempts": max_retry_attempts,
        }

    session_data = get_session(api_key, session_id)
    status = str(
        session_data.get("status_enum") or session_data.get("status") or ""
    ).lower()

    if status not in TERMINAL_STATUSES:
        feedback = _build_feedback_message(verification_results, remaining_issues)
        print(
            f"  Sending feedback to active session {session_id} "
            f"(attempt {attempt_number})"
        )
        send_message(api_key, session_id, feedback)
        return {
            "action": "message_sent",
            "session_id": session_id,
            "batch_id": batch.get("batch_id", ""),
            "attempt": attempt_number,
        }

    followup_prompt = _build_followup_prompt(
        original_prompt=original_prompt,
        verification_results=verification_results,
        previous_pr_url=previous_pr_url,
        remaining_issues=remaining_issues,
        attempt_number=attempt_number + 1,
    )

    tags = [
        "codeql-fix",
        "retry",
        f"attempt-{attempt_number + 1}",
        f"cwe-{batch.get('cwe_family', 'other')}",
        f"batch-{batch.get('batch_id', '')}",
        f"original-session-{session_id}",
    ]

    title = (
        f"CodeQL Fix Retry: {batch.get('cwe_family', 'unknown')} "
        f"({batch.get('severity_tier', '').upper()}) - "
        f"Batch {batch.get('batch_id', '')} (Attempt {attempt_number + 1})"
    )

    print(
        f"  Creating follow-up session for terminated session {session_id} "
        f"(attempt {attempt_number + 1})"
    )
    result = create_session(
        api_key=api_key,
        prompt=followup_prompt,
        tags=tags,
        title=title,
        max_acu=max_acu,
    )

    return {
        "action": "followup_created",
        "session_id": result.get("session_id", ""),
        "url": result.get("url", ""),
        "batch_id": batch.get("batch_id", ""),
        "attempt": attempt_number + 1,
        "original_session_id": session_id,
    }


def process_retry_batch(
    api_key: str,
    outcomes: list[dict],
    batches: list[dict],
    prompts: dict[int | str, str],
    verification_data: dict[str, dict] | None = None,
    max_retry_attempts: int = DEFAULT_MAX_RETRY_ATTEMPTS,
    max_acu: int | None = None,
) -> list[dict]:
    by_batch = {b["batch_id"]: b for b in batches}
    retry_results: list[dict] = []

    if not verification_data:
        verification_data = {}

    needs_retry = [
        o
        for o in outcomes
        if o.get("status") in ("finished", "blocked", "failed")
        and o.get("pr_url")
        and o.get("session_id")
    ]

    for outcome in needs_retry:
        batch_id = outcome["batch_id"]
        session_id = outcome["session_id"]
        batch = by_batch.get(batch_id, {})
        original_prompt = prompts.get(batch_id, "")

        v_data = verification_data.get(session_id, {})
        v_results = v_data.get("results", "Verification detected remaining issues.")
        remaining = v_data.get("remaining_issues")

        result = retry_with_feedback(
            api_key=api_key,
            session_id=session_id,
            batch=batch,
            original_prompt=original_prompt,
            verification_results=v_results,
            remaining_issues=remaining,
            previous_pr_url=outcome.get("pr_url", ""),
            attempt_number=int(v_data.get("attempt", 1)),
            max_retry_attempts=max_retry_attempts,
            max_acu=max_acu,
        )
        retry_results.append(result)
        time.sleep(2)

    return retry_results


def main() -> None:
    api_key = os.environ.get("DEVIN_API_KEY", "")
    if not api_key:
        print("ERROR: DEVIN_API_KEY is required")
        return

    action = os.environ.get("RETRY_ACTION", "send_message")

    if action == "send_message":
        session_id = os.environ.get("SESSION_ID", "")
        message = os.environ.get("FEEDBACK_MESSAGE", "")
        if not session_id or not message:
            print("ERROR: SESSION_ID and FEEDBACK_MESSAGE are required")
            return
        result = send_message(api_key, session_id, message)
        print(json.dumps(result, indent=2))

    elif action == "retry":
        session_id = os.environ.get("SESSION_ID", "")
        verification_results = os.environ.get("VERIFICATION_RESULTS", "")
        original_prompt = os.environ.get("ORIGINAL_PROMPT", "")
        pr_url = os.environ.get("PR_URL", "")
        cwe_family = os.environ.get("CWE_FAMILY", "other")
        batch_id = os.environ.get("BATCH_ID", "0")

        if not session_id:
            print("ERROR: SESSION_ID is required")
            return

        batch = {
            "batch_id": batch_id,
            "cwe_family": cwe_family,
            "severity_tier": os.environ.get("SEVERITY_TIER", "medium"),
        }

        result = retry_with_feedback(
            api_key=api_key,
            session_id=session_id,
            batch=batch,
            original_prompt=original_prompt,
            verification_results=verification_results,
            previous_pr_url=pr_url,
            max_retry_attempts=int(
                os.environ.get("MAX_RETRY_ATTEMPTS", str(DEFAULT_MAX_RETRY_ATTEMPTS))
            ),
        )
        print(json.dumps(result, indent=2))
    else:
        print(f"Unknown action: {action}")


if __name__ == "__main__":
    main()
