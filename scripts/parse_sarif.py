#!/usr/bin/env python3
"""Parse CodeQL SARIF output, prioritize by severity, and group into batches."""

import json
import sys
import os
from collections import defaultdict
from typing import Any

SEVERITY_TIERS = {
    "critical": (9.0, 10.0),
    "high": (7.0, 8.9),
    "medium": (4.0, 6.9),
    "low": (0.1, 3.9),
    "none": (0.0, 0.0),
}

SEVERITY_ORDER = ["critical", "high", "medium", "low", "none"]

CWE_FAMILIES = {
    "injection": [
        "cwe-78", "cwe-89", "cwe-94", "cwe-95", "cwe-96",
        "cwe-77", "cwe-917", "cwe-1321",
    ],
    "xss": ["cwe-79", "cwe-80"],
    "path-traversal": ["cwe-22", "cwe-23", "cwe-36"],
    "ssrf": ["cwe-918"],
    "deserialization": ["cwe-502"],
    "auth": ["cwe-287", "cwe-306", "cwe-862", "cwe-863"],
    "crypto": ["cwe-327", "cwe-328", "cwe-330", "cwe-338"],
    "info-disclosure": ["cwe-200", "cwe-209", "cwe-532", "cwe-497"],
    "redirect": ["cwe-601"],
    "xxe": ["cwe-611"],
    "csrf": ["cwe-352"],
    "prototype-pollution": ["cwe-1321"],
    "regex-dos": ["cwe-1333", "cwe-730"],
}


def classify_severity(score: float) -> str:
    for tier, (low, high) in SEVERITY_TIERS.items():
        if low <= score <= high:
            return tier
    return "none"


def extract_cwes(tags: list[str]) -> list[str]:
    cwes = []
    for tag in tags:
        if tag.startswith("external/cwe/"):
            cwes.append(tag.replace("external/cwe/", ""))
    return cwes


def get_cwe_family(cwes: list[str]) -> str:
    for family, members in CWE_FAMILIES.items():
        for cwe in cwes:
            if cwe.lower() in members:
                return family
    return "other"


def parse_sarif(sarif_path: str) -> list[dict[str, Any]]:
    with open(sarif_path) as f:
        sarif = json.load(f)

    issues: list[dict[str, Any]] = []

    for run in sarif.get("runs", []):
        rules_by_id: dict[str, dict[str, Any]] = {}
        tool = run.get("tool", {})
        driver = tool.get("driver", {})
        for rule in driver.get("rules", []):
            rules_by_id[rule["id"]] = rule

        for ext in tool.get("extensions", []):
            for rule in ext.get("rules", []):
                rules_by_id[rule["id"]] = rule

        for result in run.get("results", []):
            rule_id = result.get("ruleId", "")
            rule = rules_by_id.get(rule_id, {})
            props = rule.get("properties", {})
            tags = props.get("tags", [])

            severity_score = 0.0
            raw_severity = props.get("security-severity")
            if raw_severity is not None:
                try:
                    severity_score = float(raw_severity)
                except (ValueError, TypeError):
                    pass

            if severity_score == 0.0 and result.get("level") == "error":
                severity_score = 7.0
            elif severity_score == 0.0 and result.get("level") == "warning":
                severity_score = 4.0

            cwes = extract_cwes(tags)
            cwe_family = get_cwe_family(cwes)
            severity_tier = classify_severity(severity_score)

            locations = []
            for loc in result.get("locations", []):
                phys = loc.get("physicalLocation", {})
                artifact = phys.get("artifactLocation", {})
                region = phys.get("region", {})
                locations.append({
                    "file": artifact.get("uri", ""),
                    "start_line": region.get("startLine", 0),
                    "end_line": region.get("endLine", region.get("startLine", 0)),
                    "start_column": region.get("startColumn", 0),
                })

            message = result.get("message", {}).get("text", "")
            rule_desc = rule.get("shortDescription", {}).get("text", "")
            rule_help = rule.get("help", {}).get("text", "")
            rule_name = rule.get("name", rule_id)

            issues.append({
                "rule_id": rule_id,
                "rule_name": rule_name,
                "rule_description": rule_desc,
                "rule_help": rule_help[:500] if rule_help else "",
                "message": message,
                "severity_score": severity_score,
                "severity_tier": severity_tier,
                "cwes": cwes,
                "cwe_family": cwe_family,
                "locations": locations,
                "level": result.get("level", "warning"),
            })

    return issues


def prioritize_issues(
    issues: list[dict[str, Any]], threshold: str = "low"
) -> list[dict[str, Any]]:
    threshold_idx = SEVERITY_ORDER.index(threshold)
    allowed_tiers = set(SEVERITY_ORDER[: threshold_idx + 1])
    filtered = [i for i in issues if i["severity_tier"] in allowed_tiers]
    filtered.sort(key=lambda x: (-x["severity_score"], x["cwe_family"]))
    return filtered


def batch_issues(
    issues: list[dict[str, Any]], batch_size: int = 5, max_batches: int = 10
) -> list[dict[str, Any]]:
    family_groups: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for issue in issues:
        family_groups[issue["cwe_family"]].append(issue)

    family_severity: dict[str, float] = {}
    for family, group in family_groups.items():
        family_severity[family] = max(i["severity_score"] for i in group)

    sorted_families = sorted(
        family_groups.keys(), key=lambda f: -family_severity[f]
    )

    batches: list[dict[str, Any]] = []
    for family in sorted_families:
        group = family_groups[family]
        for i in range(0, len(group), batch_size):
            if len(batches) >= max_batches:
                break
            chunk = group[i : i + batch_size]
            top_severity = max(c["severity_score"] for c in chunk)
            top_tier = classify_severity(top_severity)
            batches.append({
                "batch_id": len(batches) + 1,
                "cwe_family": family,
                "severity_tier": top_tier,
                "max_severity_score": top_severity,
                "issue_count": len(chunk),
                "issues": chunk,
            })
        if len(batches) >= max_batches:
            break

    batches.sort(key=lambda b: -b["max_severity_score"])
    for idx, batch in enumerate(batches):
        batch["batch_id"] = idx + 1
    return batches


def generate_summary(
    issues: list[dict[str, Any]], batches: list[dict[str, Any]]
) -> str:
    lines = ["# CodeQL Analysis Summary\n"]

    tier_counts: dict[str, int] = defaultdict(int)
    for issue in issues:
        tier_counts[issue["severity_tier"]] += 1

    lines.append("## Issues by Severity\n")
    lines.append("| Severity | Count |")
    lines.append("|----------|-------|")
    for tier in SEVERITY_ORDER:
        count = tier_counts.get(tier, 0)
        if count > 0:
            lines.append(f"| {tier.upper()} | {count} |")
    lines.append(f"| **TOTAL** | **{len(issues)}** |")
    lines.append("")

    family_counts: dict[str, int] = defaultdict(int)
    for issue in issues:
        family_counts[issue["cwe_family"]] += 1

    lines.append("## Issues by Category\n")
    lines.append("| Category | Count |")
    lines.append("|----------|-------|")
    for family, count in sorted(family_counts.items(), key=lambda x: -x[1]):
        lines.append(f"| {family} | {count} |")
    lines.append("")

    lines.append(f"## Batches Created: {len(batches)}\n")
    lines.append("| Batch | Category | Severity | Issues |")
    lines.append("|-------|----------|----------|--------|")
    for batch in batches:
        lines.append(
            f"| {batch['batch_id']} | {batch['cwe_family']} "
            f"| {batch['severity_tier'].upper()} | {batch['issue_count']} |"
        )

    return "\n".join(lines)


def main() -> None:
    sarif_path = sys.argv[1] if len(sys.argv) > 1 else "results.sarif"
    output_dir = sys.argv[2] if len(sys.argv) > 2 else "output"
    batch_size = int(os.environ.get("BATCH_SIZE", "5"))
    max_batches = int(os.environ.get("MAX_SESSIONS", "10"))
    threshold = os.environ.get("SEVERITY_THRESHOLD", "low")

    os.makedirs(output_dir, exist_ok=True)

    print(f"Parsing SARIF file: {sarif_path}")
    issues = parse_sarif(sarif_path)
    print(f"Found {len(issues)} total issues")

    prioritized = prioritize_issues(issues, threshold)
    print(f"After filtering (threshold={threshold}): {len(prioritized)} issues")

    batches = batch_issues(prioritized, batch_size, max_batches)
    print(f"Created {len(batches)} batches")

    with open(os.path.join(output_dir, "issues.json"), "w") as f:
        json.dump(prioritized, f, indent=2)

    with open(os.path.join(output_dir, "batches.json"), "w") as f:
        json.dump(batches, f, indent=2)

    summary = generate_summary(prioritized, batches)
    with open(os.path.join(output_dir, "summary.md"), "w") as f:
        f.write(summary)

    print(summary)

    github_output = os.environ.get("GITHUB_OUTPUT")
    if github_output:
        with open(github_output, "a") as f:
            f.write(f"total_issues={len(prioritized)}\n")
            f.write(f"total_batches={len(batches)}\n")

    github_summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if github_summary:
        with open(github_summary, "a") as f:
            f.write(summary + "\n")


if __name__ == "__main__":
    main()
