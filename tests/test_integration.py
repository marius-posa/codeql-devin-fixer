"""Integration tests for the CodeQL Devin Fixer pipeline.

Covers:
- End-to-end SARIF-to-batches pipeline
- Prompt generation verification from known batches
"""

import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from scripts.parse_sarif import (
    parse_sarif,
    deduplicate_issues,
    prioritize_issues,
    batch_issues,
    assign_issue_ids,
)
from scripts.dispatch_devin import build_batch_prompt

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")


class TestSarifToBatchesPipeline:
    def test_valid_sarif_produces_structured_batches(self):
        sarif_path = os.path.join(FIXTURES, "valid.sarif")
        issues = parse_sarif(sarif_path)
        assert len(issues) == 4

        unique = deduplicate_issues(issues)
        assert len(unique) == 4

        filtered = prioritize_issues(unique, "medium")
        assert all(i["severity_tier"] in ("critical", "high", "medium") for i in filtered)

        filtered = assign_issue_ids(filtered, "99")
        assert all(i["id"].startswith("CQLF-R99-") for i in filtered)
        assert all("fingerprint" in i for i in filtered)

        batches = batch_issues(filtered, batch_size=5, max_batches=10)
        assert len(batches) > 0

        for batch in batches:
            assert "batch_id" in batch
            assert "cwe_family" in batch
            assert "severity_tier" in batch
            assert "issues" in batch
            assert batch["issue_count"] == len(batch["issues"])
            assert batch["file_count"] >= 0
            assert isinstance(batch["max_severity_score"], float)

    def test_empty_sarif_produces_empty_batches(self):
        sarif_path = os.path.join(FIXTURES, "empty_runs.sarif")
        issues = parse_sarif(sarif_path)
        assert issues == []
        batches = batch_issues(issues)
        assert batches == []

    def test_missing_fields_sarif_still_parseable(self):
        sarif_path = os.path.join(FIXTURES, "missing_fields.sarif")
        issues = parse_sarif(sarif_path)
        assert len(issues) == 2
        unique = deduplicate_issues(issues)
        filtered = prioritize_issues(unique, "low")
        batches = batch_issues(filtered, batch_size=5, max_batches=10)
        assert isinstance(batches, list)

    def test_multi_run_sarif(self):
        sarif_path = os.path.join(FIXTURES, "multi_run.sarif")
        issues = parse_sarif(sarif_path)
        assert len(issues) == 2

        families = {i["cwe_family"] for i in issues}
        assert "injection" in families
        assert "xss" in families

        batches = batch_issues(issues, batch_size=5, max_batches=10)
        assert len(batches) == 2

    def test_deduplication_across_identical_results(self):
        sarif_path = os.path.join(FIXTURES, "valid.sarif")
        issues = parse_sarif(sarif_path)
        doubled = issues + issues
        unique = deduplicate_issues(doubled)
        assert len(unique) == len(issues)

    def test_pipeline_batch_ordering_by_severity(self):
        sarif_path = os.path.join(FIXTURES, "valid.sarif")
        issues = parse_sarif(sarif_path)
        filtered = prioritize_issues(issues, "low")
        batches = batch_issues(filtered, batch_size=5, max_batches=10)
        scores = [b["max_severity_score"] for b in batches]
        assert scores == sorted(scores, reverse=True)


class TestPromptGenerationIntegration:
    def test_prompt_from_real_batches(self):
        sarif_path = os.path.join(FIXTURES, "valid.sarif")
        issues = parse_sarif(sarif_path)
        filtered = prioritize_issues(issues, "low")
        filtered = assign_issue_ids(filtered, "1")
        batches = batch_issues(filtered, batch_size=5, max_batches=10)

        for batch in batches:
            prompt = build_batch_prompt(
                batch, "https://github.com/test/repo", "main"
            )
            assert "https://github.com/test/repo" in prompt
            assert batch["cwe_family"] in prompt
            assert batch["severity_tier"].upper() in prompt

            for issue in batch["issues"]:
                if issue.get("id"):
                    assert issue["id"] in prompt
                for loc in issue.get("locations", []):
                    if loc.get("file"):
                        assert loc["file"] in prompt

    def test_prompt_pr_title_format(self):
        sarif_path = os.path.join(FIXTURES, "valid.sarif")
        issues = parse_sarif(sarif_path)
        filtered = assign_issue_ids(prioritize_issues(issues, "low"), "1")
        batches = batch_issues(filtered, batch_size=5, max_batches=10)

        for batch in batches:
            prompt = build_batch_prompt(batch, "https://github.com/t/r", "main")
            assert "fix(" in prompt
            assert f"resolve {batch['cwe_family']} security issues" in prompt

    def test_prompt_contains_instructions(self):
        sarif_path = os.path.join(FIXTURES, "valid.sarif")
        issues = parse_sarif(sarif_path)
        filtered = assign_issue_ids(prioritize_issues(issues, "low"), "1")
        batches = batch_issues(filtered, batch_size=5, max_batches=10)

        prompt = build_batch_prompt(batches[0], "https://github.com/t/r", "main")
        assert "Clone" in prompt
        assert "Fix ALL" in prompt
        assert "Create a PR" in prompt
        assert "Run existing tests" in prompt
