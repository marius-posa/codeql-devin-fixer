#!/usr/bin/env python3
"""Parse CodeQL SARIF output, prioritize by severity, and group into batches.

This script is the analytical core of the pipeline.  It transforms raw SARIF
(Static Analysis Results Interchange Format) output from CodeQL into
actionable, prioritised batches that can be dispatched to Devin sessions.

The processing pipeline is:

1. **Parse** -- extract issues from one or more ``.sarif`` files.
2. **Deduplicate** -- remove findings that share the same rule + location.
3. **Prioritize** -- filter by severity threshold and sort by CVSS score.
4. **Assign IDs** -- give each issue a stable identifier
   (``CQLF-R{run}-{seq}``) so it can be tracked across sessions and PRs.
5. **Batch** -- group related issues by CWE family and chunk them to fit
   within the configured ``batch_size``.  Families are ordered by maximum
   severity so the most critical batches are dispatched first.

Design decisions
----------------
* **CVSS-based severity tiers** -- we map the ``security-severity`` property
  (a CVSS v3 score) to four tiers.  This mirrors how vulnerability scanners
  report risk and aligns with industry norms (NVD, GitHub Advisory).
* **CWE family grouping** -- issues are batched by CWE family rather than
  individual CWE because related weaknesses often share the same remediation
  pattern (e.g. all injection CWEs benefit from parameterised queries).
  Batching by family lets Devin apply a consistent fix strategy.
* **Issue IDs** -- the ``CQLF-R{run}-{seq}`` format encodes the run number
  so IDs are unique across runs.  This makes it easy to trace a PR back to
  the exact action run that identified the issues.

Environment variables
---------------------
BATCH_SIZE : int
    Maximum issues per batch / Devin session (default 5).
MAX_SESSIONS : int
    Maximum number of batches to create (default 10).
SEVERITY_THRESHOLD : str
    Minimum severity tier to include: critical | high | medium | low.
RUN_NUMBER : str
    GitHub Actions run number, used in issue IDs.
"""

import hashlib
import json
import re
import sys
import os
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any

BATCHES_SCHEMA_VERSION = "1.0"
ISSUES_SCHEMA_VERSION = "1.0"

# Severity tiers map CVSS v3 score ranges to human-readable labels.
# These thresholds follow the NVD / GitHub Advisory severity scale so that
# results are consistent with what developers see on github.com.
SEVERITY_TIERS = {
    "critical": (9.0, 10.0),
    "high": (7.0, 8.9),
    "medium": (4.0, 6.9),
    "low": (0.1, 3.9),
    "none": (0.0, 0.0),
}

SEVERITY_ORDER = ["critical", "high", "medium", "low", "none"]

# CWE families group related weakness IDs so that issues sharing a common
# remediation strategy end up in the same batch.  For example, SQL injection
# (CWE-89) and OS command injection (CWE-78) both require input validation /
# parameterised APIs, so they belong to the "injection" family.
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
        "cwe-564",
        "cwe-917",
        "cwe-943",
    ],
    "xss": ["cwe-79", "cwe-80", "cwe-83", "cwe-87"],
    "path-traversal": ["cwe-22", "cwe-23", "cwe-36", "cwe-73", "cwe-99"],
    "ssrf": ["cwe-918"],
    "deserialization": ["cwe-502"],
    "auth": [
        "cwe-287", "cwe-306", "cwe-862", "cwe-863",
        "cwe-284", "cwe-285", "cwe-269", "cwe-732",
    ],
    "crypto": [
        "cwe-327", "cwe-328", "cwe-330", "cwe-338",
        "cwe-326", "cwe-261", "cwe-310", "cwe-295",
        "cwe-347", "cwe-916",
    ],
    "info-disclosure": [
        "cwe-200", "cwe-209", "cwe-532", "cwe-497",
        "cwe-215", "cwe-538", "cwe-359", "cwe-312",
        "cwe-319",
    ],
    "redirect": ["cwe-601"],
    "xxe": ["cwe-611", "cwe-776"],
    "csrf": ["cwe-352"],
    "prototype-pollution": ["cwe-1321"],
    "regex-dos": ["cwe-1333", "cwe-730", "cwe-400", "cwe-185"],
    "type-confusion": ["cwe-843", "cwe-704"],
    "template-injection": ["cwe-1336"],
    "hardcoded-credentials": [
        "cwe-798", "cwe-259", "cwe-321", "cwe-547",
    ],
    "missing-rate-limiting": ["cwe-770", "cwe-799", "cwe-307"],
    "logging": ["cwe-117", "cwe-778", "cwe-223"],
    "zip-slip": ["cwe-59"],
    "xml-injection": ["cwe-91", "cwe-643"],
    "nosql-injection": ["cwe-1286"],
    "session-management": [
        "cwe-384", "cwe-613", "cwe-614", "cwe-1004",
    ],
    "file-upload": ["cwe-434"],
    "race-condition": ["cwe-362", "cwe-367"],
    "memory-safety": [
        "cwe-119", "cwe-120", "cwe-125", "cwe-787",
        "cwe-416", "cwe-476", "cwe-190",
    ],
}

# Reverse index: CWE-ID -> family name for O(1) lookup during parsing.
_CWE_FAMILY_INDEX: dict[str, str] = {}
for _family, _members in CWE_FAMILIES.items():
    for _cwe in _members:
        _CWE_FAMILY_INDEX[_cwe] = _family


def normalize_cwe(cwe: str) -> str:
    """Normalise a CWE identifier to lowercase ``cwe-{number}`` form.

    SARIF tags may include leading zeros (``CWE-079``); this strips them so
    lookups into ``_CWE_FAMILY_INDEX`` are consistent.
    """
    m = re.match(r"cwe-0*(\d+)", cwe.lower())
    if m:
        return f"cwe-{m.group(1)}"
    return cwe.lower()


def classify_severity(score: float) -> str:
    """Map a numeric CVSS score to a severity tier string."""
    for tier, (low, high) in SEVERITY_TIERS.items():
        if low <= score <= high:
            return tier
    return "none"


def extract_cwes(tags: list[str]) -> list[str]:
    """Extract and normalise CWE IDs from SARIF rule tags.

    CodeQL encodes CWEs as ``external/cwe/cwe-79`` in the tags array.
    """
    cwes = []
    for tag in tags:
        if tag.startswith("external/cwe/"):
            raw = tag.replace("external/cwe/", "")
            cwes.append(normalize_cwe(raw))
    return cwes


def get_cwe_family(cwes: list[str]) -> str:
    """Return the family name for the first recognised CWE, or ``'other'``."""
    for cwe in cwes:
        family = _CWE_FAMILY_INDEX.get(cwe)
        if family:
            return family
    return "other"


def validate_sarif(sarif: dict[str, Any], path: str) -> None:
    """Lightweight validation of a SARIF document's required top-level keys.

    Checks that the document has the expected ``version`` and ``$schema``
    fields, and that at least one ``runs`` entry exists.  This catches
    malformed files early instead of silently producing an empty issues
    list.

    Raises
    ------
    ValueError
        If a required key is missing or has an unexpected value.
    """
    if not isinstance(sarif, dict):
        raise ValueError(f"{path}: SARIF root must be a JSON object, got {type(sarif).__name__}")

    version = sarif.get("version")
    if version is None:
        raise ValueError(f"{path}: missing required 'version' field")
    if not version.startswith("2.1"):
        print(f"WARNING: {path}: unexpected SARIF version '{version}' (expected 2.1.x)")

    schema = sarif.get("$schema", "")
    if schema and "sarif" not in schema.lower():
        print(f"WARNING: {path}: '$schema' does not reference a SARIF schema: {schema}")

    runs = sarif.get("runs")
    if runs is None:
        raise ValueError(f"{path}: missing required 'runs' array")
    if not isinstance(runs, list):
        raise ValueError(f"{path}: 'runs' must be a JSON array, got {type(runs).__name__}")


def parse_sarif(sarif_path: str) -> list[dict[str, Any]]:
    """Extract security issues from a single SARIF file.

    Iterates over every ``run`` / ``result`` in the SARIF and enriches each
    finding with severity score, tier, CWE IDs, and source locations.

    If the ``security-severity`` property is absent (some built-in rules
    don't set it), the function falls back to the result ``level`` field:
    ``error`` -> 7.0 (high), ``warning`` -> 4.0 (medium).
    """
    file_size = os.path.getsize(sarif_path)
    if file_size > 500 * 1024 * 1024:
        print(f"WARNING: SARIF file is very large ({file_size / 1024 / 1024:.0f} MB)")

    with open(sarif_path) as f:
        sarif = json.load(f)

    validate_sarif(sarif, sarif_path)

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

            partial_fps = result.get("partialFingerprints", {})

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
                    "partial_fingerprints": partial_fps,
                }
            )

    return issues


def deduplicate_issues(issues: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Remove duplicate findings that share the same rule ID and location(s).

    CodeQL can report the same issue in multiple SARIF runs (e.g. when
    analysing different languages).  Deduplication prevents Devin from
    receiving the same fix request twice.
    """
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
    """Filter issues below *threshold* and sort by descending severity.

    Secondary sort key is ``cwe_family`` so that issues in the same family
    are adjacent, which improves batching efficiency.
    """
    threshold_idx = SEVERITY_ORDER.index(threshold)
    allowed_tiers = set(SEVERITY_ORDER[: threshold_idx + 1])
    filtered = [i for i in issues if i["severity_tier"] in allowed_tiers]
    filtered.sort(key=lambda x: (-x["severity_score"], x["cwe_family"]))
    return filtered


def batch_issues(
    issues: list[dict[str, Any]], batch_size: int = 5, max_batches: int = 10
) -> list[dict[str, Any]]:
    """Group issues into batches by CWE family, capped at *batch_size*.

    Families with the highest max-severity score are processed first so
    that the most critical batches get dispatched before hitting the
    *max_batches* cap.  Within a family, issues are already sorted by
    severity (from ``prioritize_issues``), so each batch contains the
    most severe issues first.
    """
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
    """Generate a Markdown summary for the GitHub Step Summary."""
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


def compute_fingerprint(issue: dict[str, Any]) -> str:
    """Compute a stable fingerprint for an issue across runs.

    Stability hierarchy (most stable first):

    1. **SARIF ``partialFingerprints``** -- CodeQL emits a content-based hash
       that survives line-number shifts.  When available this is the most
       reliable cross-run identifier.
    2. **rule_id + file + message** -- the diagnostic message usually encodes
       enough context (e.g. tainted variable name) to distinguish distinct
       occurrences of the same rule in the same file without relying on line
       numbers.
    3. **rule_id + file + start_line** -- legacy fallback when neither of the
       above is available.
    """
    partial_fps = issue.get("partial_fingerprints", {})
    primary_fp = (
        partial_fps.get("primaryLocationLineHash")
        or partial_fps.get("primaryLocationStartColumnFingerprint")
    )
    if primary_fp:
        raw = f"{issue.get('rule_id', '')}|{primary_fp}"
        return hashlib.sha256(raw.encode()).hexdigest()[:16]

    rule_id = issue.get("rule_id", "")
    locs = issue.get("locations", [])
    file_path = locs[0].get("file", "") if locs else ""
    message = issue.get("message", "")
    if message:
        raw = f"{rule_id}|{file_path}|{message}"
    else:
        start_line = str(locs[0].get("start_line", 0)) if locs else "0"
        raw = f"{rule_id}|{file_path}|{start_line}"
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


def assign_issue_ids(
    issues: list[dict[str, Any]], run_number: str = ""
) -> list[dict[str, Any]]:
    """Assign a unique ID and stable fingerprint to each issue.

    The run-specific ID uses the format ``CQLF-R{run}-{seq}`` so IDs are
    unique across workflow runs.  The fingerprint is stable across runs
    so the same vulnerability can be tracked over time.
    """
    prefix = f"R{run_number}-" if run_number else ""
    for idx, issue in enumerate(issues, 1):
        issue["id"] = f"CQLF-{prefix}{idx:04d}"
        issue["fingerprint"] = compute_fingerprint(issue)
    return issues


def main() -> None:
    if len(sys.argv) < 2:
        print("Usage: parse_sarif.py <sarif_path_or_dir> <output_dir>")
        sys.exit(1)

    sarif_input = sys.argv[1]
    output_dir = sys.argv[2] if len(sys.argv) > 2 else "output"
    batch_size = int(os.environ.get("BATCH_SIZE", "5"))
    max_batches = int(os.environ.get("MAX_SESSIONS", "25"))
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

    issues_envelope = {
        "schema_version": ISSUES_SCHEMA_VERSION,
        "issues": prioritized,
    }
    with open(os.path.join(output_dir, "issues.json"), "w") as f:
        json.dump(issues_envelope, f, indent=2)

    batches_envelope = {
        "schema_version": BATCHES_SCHEMA_VERSION,
        "batches": batches,
    }
    with open(os.path.join(output_dir, "batches.json"), "w") as f:
        json.dump(batches_envelope, f, indent=2)

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
