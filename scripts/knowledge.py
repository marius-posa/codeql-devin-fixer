#!/usr/bin/env python3
"""Devin Knowledge API client for storing and retrieving fix patterns."""

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from devin_api import DEVIN_API_BASE, fetch_pr_diff, request_with_retry

KNOWLEDGE_NAME_PREFIX = "codeql-fix"


def list_knowledge(api_key: str) -> list[dict]:
    data = request_with_retry("GET", f"{DEVIN_API_BASE}/knowledge", api_key)
    if isinstance(data, list):
        return data
    return data.get("items", data.get("knowledge", []))


def create_knowledge(
    api_key: str,
    name: str,
    body: str,
    trigger_description: str,
    pinned_repo: str | None = None,
    parent_folder_id: str | None = None,
) -> dict:
    payload: dict = {
        "name": name,
        "body": body,
        "trigger_description": trigger_description,
    }
    if pinned_repo:
        payload["pinned_repo"] = pinned_repo
    if parent_folder_id:
        payload["parent_folder_id"] = parent_folder_id
    return request_with_retry(
        "POST", f"{DEVIN_API_BASE}/knowledge", api_key, payload
    )


def update_knowledge(
    api_key: str,
    note_id: str,
    name: str | None = None,
    body: str | None = None,
    trigger_description: str | None = None,
) -> dict:
    payload: dict = {}
    if name is not None:
        payload["name"] = name
    if body is not None:
        payload["body"] = body
    if trigger_description is not None:
        payload["trigger_description"] = trigger_description
    return request_with_retry(
        "PUT", f"{DEVIN_API_BASE}/knowledge/{note_id}", api_key, payload
    )


def delete_knowledge(api_key: str, note_id: str) -> dict:
    return request_with_retry(
        "DELETE", f"{DEVIN_API_BASE}/knowledge/{note_id}", api_key
    )


def _make_knowledge_name(cwe_family: str, batch_id: int | str) -> str:
    return f"{KNOWLEDGE_NAME_PREFIX}/{cwe_family}/batch-{batch_id}"


def _classify_fix_pattern(cwe_family: str) -> str:
    patterns: dict[str, str] = {
        "injection": "parameterized queries / input sanitization",
        "xss": "output encoding / content security policy",
        "path-traversal": "path canonicalization / allowlist validation",
        "ssrf": "URL allowlist / network segmentation",
        "deserialization": "safe deserialization / type validation",
        "auth": "authentication / authorization checks",
        "crypto": "strong cryptographic algorithms / secure random",
        "info-disclosure": "error handling / sensitive data redaction",
        "redirect": "URL validation / redirect allowlist",
        "xxe": "XML parser hardening / external entity disable",
        "csrf": "CSRF token validation",
        "prototype-pollution": "object freeze / property validation",
        "regex-dos": "regex complexity limits / RE2 usage",
        "type-confusion": "strict type checking",
        "template-injection": "template sandboxing / input validation",
    }
    return patterns.get(cwe_family, "security fix pattern")


def store_fix_knowledge(
    api_key: str,
    cwe_family: str,
    batch_id: int | str,
    pr_url: str,
    diff_summary: str,
    issue_count: int,
    severity_tier: str,
    repo_url: str = "",
    parent_folder_id: str | None = None,
    github_token: str = "",
) -> dict:
    fix_pattern = _classify_fix_pattern(cwe_family)
    name = _make_knowledge_name(cwe_family, batch_id)

    diff_content = fetch_pr_diff(pr_url, github_token)

    body_parts = [
        f"# Verified Fix: {cwe_family} ({severity_tier.upper()})",
        "",
        f"**Pattern**: {fix_pattern}",
        f"**Issues fixed**: {issue_count}",
        f"**PR**: {pr_url}",
    ]
    if repo_url:
        body_parts.append(f"**Repository**: {repo_url}")
    body_parts.extend(
        [
            "",
            "## Fix Summary",
            "",
            diff_summary,
        ]
    )
    if diff_content:
        body_parts.extend(
            [
                "",
                "## Actual Fix Diff",
                "",
                "```diff",
                diff_content,
                "```",
            ]
        )
    body = "\n".join(body_parts)

    trigger_description = (
        f"When fixing {cwe_family} security issues (CWE family), "
        f"reference this verified fix pattern: {fix_pattern}"
    )

    return create_knowledge(
        api_key=api_key,
        name=name,
        body=body,
        trigger_description=trigger_description,
        pinned_repo=repo_url.replace("https://github.com/", "") if repo_url else None,
        parent_folder_id=parent_folder_id,
    )


def find_knowledge_for_cwe(api_key: str, cwe_family: str) -> list[dict]:
    all_entries = list_knowledge(api_key)
    prefix = f"{KNOWLEDGE_NAME_PREFIX}/{cwe_family}/"
    return [e for e in all_entries if e.get("name", "").startswith(prefix)]


def build_knowledge_context(api_key: str, cwe_family: str) -> str:
    entries = find_knowledge_for_cwe(api_key, cwe_family)
    if not entries:
        return ""

    parts = [
        "",
        "## Reference: Verified Fix Patterns for This Category",
        "",
        f"The following {len(entries)} verified fix(es) for '{cwe_family}' issues "
        "were previously applied successfully. Use them as reference:",
        "",
    ]
    for idx, entry in enumerate(entries, 1):
        parts.append(f"### Reference Fix {idx}: {entry.get('name', 'N/A')}")
        body = entry.get("body", "")
        if len(body) > 2000:
            body = body[:2000] + "\n... (truncated)"
        parts.append(body)
        parts.append("")

    return "\n".join(parts)


def main() -> None:
    api_key = os.environ.get("DEVIN_API_KEY", "")
    if not api_key:
        print("ERROR: DEVIN_API_KEY is required")
        return

    action = os.environ.get("KNOWLEDGE_ACTION", "list")
    if action == "list":
        entries = list_knowledge(api_key)
        print(json.dumps(entries, indent=2))
    elif action == "store":
        result = store_fix_knowledge(
            api_key=api_key,
            cwe_family=os.environ.get("CWE_FAMILY", "other"),
            batch_id=os.environ.get("BATCH_ID", "0"),
            pr_url=os.environ.get("PR_URL", ""),
            diff_summary=os.environ.get("DIFF_SUMMARY", ""),
            issue_count=int(os.environ.get("ISSUE_COUNT", "0")),
            severity_tier=os.environ.get("SEVERITY_TIER", "medium"),
            repo_url=os.environ.get("TARGET_REPO", ""),
            parent_folder_id=os.environ.get("KNOWLEDGE_FOLDER_ID"),
            github_token=os.environ.get("GITHUB_TOKEN", ""),
        )
        print(json.dumps(result, indent=2))
    elif action == "search":
        cwe = os.environ.get("CWE_FAMILY", "other")
        context = build_knowledge_context(api_key, cwe)
        print(context if context else f"No knowledge entries found for {cwe}")
    else:
        print(f"Unknown action: {action}")


if __name__ == "__main__":
    main()
