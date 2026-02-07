#!/usr/bin/env python3
"""Parse CodeQL SARIF output, prioritize by severity, and group into batches."""

import json
import re
import sys
import os
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any

SEVERITY_TIERS = {
    "critical": (9.0, 10.0),
    "high": (7.0, 8.9),
    "medium": (4.0, 6.9),
    "low": (0.1, 3.9),
    "none": (0.0, 0.0),
}

SEVERITY_ORDER = ["critical", "high", "medium", "low", "none"]

CWE_FAMILIES: dict[str, list[str]] = {
    "injection": [
        "cwe-77",
        "cwe-78",
        "cwe-89",
        "cwe-90",
        "cwe-94",
        "cwe-95",
        "cwe-96",
        "cwe-116",
        "cwe-917",
        "cwe-943",
        "cwe-1321",
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
    "type-confusion": ["cwe-843"],
    "template-injection": ["cwe-73", "cwe-1336"],
}

_CWE_FAMILY_INDEX: dict[str, str] = {}
for _family, _members in CWE_FAMILIES.items():
    for _cwe in _members:
        _CWE_FAMILY_INDEX[_cwe] = _family


def normalize_cwe(cwe: str) -> str:
    m = re.match(r"cwe-0*(\d+)", cwe.lower())
    if m:
        return f"cwe-{m.group(1)}"
    return cwe.lower()


def classify_severity(score: float) -> str:
    for tier, (low, high) in SEVERITY_TIERS.items():
        if low <= score <= high:
            return tier
    return "none"


def extract_cwes(tags: list[str]) -> list[str]:
    cwes = []
    for tag in tags:
        if tag.startswith("external/cwe/"):
            raw = tag.replace("external/cwe/", "")
            cwes.append(normalize_cwe(raw))
    return cwes


def get_cwe_family(cwes: list[str]) -> str:
    for cwe in cwes:
        family = _CWE_FAMILY_INDEX.get(cwe)
        if family:
            return family
    return "other"


def parse_sarif(sarif_path: str) -> list[dict[str, Any]]:
    file_size = os.path.getsize(sarif_path)
    if file_size > 500 * 1024 * 1024:
        print(f"WARNING: SARIF file is very large ({file_size / 1024 / 1024:.0f} MB)")

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
                locations.append(
                    {
                        "file": artifact.get("uri", ""),
                        "start_line": region.get("startLine", 0),
                        "end_line": region.get("endLine", region.get("startLine", 0)),
                        "start_column": region.get("startColumn", 0),
                    }
                )

            message = result.get("message", {}).get("text", "")
            rule_desc = rule.get("shortDescription", {}).get("text", "")
            rule_help = rule.get("help", {}).get("text", "")
            rule_name = rule.get("name", rule_id)

            issues.append(
                {
                    "id": "",
                    "rule_id": rule_id,
                    "rule_name": rule_name,
                    "rule_description": rule_desc,
                    "rule_help": rule_help[:1000] if rule_help else "",
                    "message": message,
                    "severity_score": severity_score,
                    "severity_tier": severity_tier,
                    "cwes": cwes,
                    "cwe_family": cwe_family,
                    "locations": locations,
                    "level": result.get("level", "warning"),
                }
            )

    return issues


def deduplicate_issues(issues: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen: set[str] = set()
    unique: list[dict[str, Any]] = []
    for issue in issues:
        locs = tuple(
            (loc["file"], loc["start_line"]) for loc in issue.get("locations", [])
        )
        key = (issue["rule_id"], locs)
        key_str = str(key)
        if key_str not in seen:
            seen.add(key_str)
            unique.append(issue)
    return unique


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

    sorted_families = sorted(family_groups.keys(), key=lambda f: -family_severity[f])

    batches: list[dict[str, Any]] = []
    for family in sorted_families:
        group = family_groups[family]
        for i in range(0, len(group), batch_size):
            if len(batches) >= max_batches:
                break
            chunk = group[i : i + batch_size]
            files_in_batch = set()
            for issue in chunk:
                for loc in issue.get("locations", []):
                    if loc.get("file"):
                        files_in_batch.add(loc["file"])
            top_severity = max(c["severity_score"] for c in chunk)
            top_tier = classify_severity(top_severity)
            batches.append(
                {
                    "batch_id": len(batches) + 1,
                    "cwe_family": family,
                    "severity_tier": top_tier,
                    "max_severity_score": top_severity,
                    "issue_count": len(chunk),
                    "file_count": len(files_in_batch),
                    "issues": chunk,
                }
            )
        if len(batches) >= max_batches:
            break

    batches.sort(key=lambda b: -b["max_severity_score"])
    for idx, batch in enumerate(batches):
        batch["batch_id"] = idx + 1
    return batches


def generate_summary(
    issues: list[dict[str, Any]],
    batches: list[dict[str, Any]],
    total_raw: int = 0,
    dedup_removed: int = 0,
) -> str:
    lines = ["# CodeQL Analysis Summary\n"]

    if total_raw > 0:
        lines.append(
            f"**Raw issues**: {total_raw} | "
            f"**Deduplicated**: {dedup_removed} removed | "
            f"**After filtering**: {len(issues)}\n"
        )

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
    lines.append("| Batch | Category | Severity | Issues | Files |")
    lines.append("|-------|----------|----------|--------|-------|")
    for batch in batches:
        lines.append(
            f"| {batch['batch_id']} | {batch['cwe_family']} "
            f"| {batch['severity_tier'].upper()} | {batch['issue_count']} "
            f"| {batch.get('file_count', '?')} |"
        )

    return "\n".join(lines)


def assign_issue_ids(
    issues: list[dict[str, Any]], run_number: str = ""
) -> list[dict[str, Any]]:
    prefix = f"R{run_number}-" if run_number else ""
    for idx, issue in enumerate(issues, 1):
        issue["id"] = f"CQLF-{prefix}{idx:04d}"
    return issues


def main() -> None:
    if len(sys.argv) < 2:
        print("Usage: parse_sarif.py <sarif_path_or_dir> <output_dir>")
        sys.exit(1)

    sarif_input = sys.argv[1]
    output_dir = sys.argv[2] if len(sys.argv) > 2 else "output"
    batch_size = int(os.environ.get("BATCH_SIZE", "5"))
    max_batches = int(os.environ.get("MAX_SESSIONS", "10"))
    threshold = os.environ.get("SEVERITY_THRESHOLD", "low")
    run_number = os.environ.get("RUN_NUMBER", "")

    os.makedirs(output_dir, exist_ok=True)

    sarif_files: list[str] = []
    if os.path.isdir(sarif_input):
        for entry in os.listdir(sarif_input):
            if entry.endswith(".sarif"):
                sarif_files.append(os.path.join(sarif_input, entry))
    elif os.path.isfile(sarif_input):
        sarif_files.append(sarif_input)
    else:
        print(f"ERROR: SARIF path not found: {sarif_input}")
        sys.exit(1)

    if not sarif_files:
        print(f"ERROR: No SARIF files found in {sarif_input}")
        sys.exit(1)

    all_issues: list[dict[str, Any]] = []
    for sf in sorted(sarif_files):
        print(f"Parsing SARIF file: {sf}")
        all_issues.extend(parse_sarif(sf))

    total_raw = len(all_issues)
    print(f"Found {total_raw} total issues across {len(sarif_files)} SARIF file(s)")

    all_issues = deduplicate_issues(all_issues)
    dedup_removed = total_raw - len(all_issues)
    if dedup_removed > 0:
        print(f"Removed {dedup_removed} duplicate issues")
    print(f"Unique issues: {len(all_issues)}")

    prioritized = prioritize_issues(all_issues, threshold)
    print(f"After filtering (threshold={threshold}): {len(prioritized)} issues")

    prioritized = assign_issue_ids(prioritized, run_number)

    batches = batch_issues(prioritized, batch_size, max_batches)
    print(f"Created {len(batches)} batches")

    with open(os.path.join(output_dir, "issues.json"), "w") as f:
        json.dump(prioritized, f, indent=2)

    with open(os.path.join(output_dir, "batches.json"), "w") as f:
        json.dump(batches, f, indent=2)

    summary = generate_summary(prioritized, batches, total_raw, dedup_removed)
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

    run_ts = datetime.now(timezone.utc).strftime("%Y-%m-%d-%H%M%S")
    run_label = f"run-{run_number}-{run_ts}" if run_number else f"run-{run_ts}"
    run_log = {
        "run_label": run_label,
        "run_number": run_number,
        "timestamp": run_ts,
        "total_raw": total_raw,
        "dedup_removed": dedup_removed,
        "total_filtered": len(prioritized),
        "total_batches": len(batches),
        "severity_threshold": threshold,
        "batch_size": batch_size,
        "max_batches": max_batches,
    }
    with open(os.path.join(output_dir, "run_log.json"), "w") as f:
        json.dump(run_log, f, indent=2)

    if github_output:
        with open(github_output, "a") as f:
            f.write(f"run_label={run_label}\n")


if __name__ == "__main__":
    main()
