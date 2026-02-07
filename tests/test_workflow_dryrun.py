"""Workflow-level dry-run smoke test.

Validates the full pipeline from SARIF parsing through prompt generation
in dry_run mode, without creating any Devin sessions or making API calls.
This simulates what a CI job would do with `dry_run: true`.
"""

import json
import os
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from scripts.parse_sarif import (
    parse_sarif,
    deduplicate_issues,
    prioritize_issues,
    batch_issues,
    assign_issue_ids,
    generate_summary,
)
from scripts.dispatch_devin import build_batch_prompt, validate_repo_url

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")


class TestDryRunSmokeTest:
    """Simulate the full workflow in dry-run mode using fixture SARIF files."""

    def test_full_pipeline_dryrun(self):
        sarif_path = os.path.join(FIXTURES, "valid.sarif")
        repo_url = validate_repo_url("https://github.com/test-org/test-repo")
        default_branch = "main"
        batch_size = 5
        max_batches = 10
        threshold = "low"
        run_number = "99"

        issues = parse_sarif(sarif_path)
        assert len(issues) > 0, "SARIF parsing should find issues"

        unique = deduplicate_issues(issues)
        assert len(unique) > 0, "Deduplication should preserve unique issues"

        filtered = prioritize_issues(unique, threshold)
        assert len(filtered) > 0, "Filtering should pass issues at 'low' threshold"

        filtered = assign_issue_ids(filtered, run_number)
        for issue in filtered:
            assert issue["id"].startswith("CQLF-R99-")
            assert len(issue["fingerprint"]) == 16

        batches = batch_issues(filtered, batch_size, max_batches)
        assert len(batches) > 0, "Batching should create at least one batch"

        summary = generate_summary(filtered, batches, len(issues), len(issues) - len(unique))
        assert "# CodeQL Analysis Summary" in summary
        assert "Batches Created" in summary

        with tempfile.TemporaryDirectory() as output_dir:
            with open(os.path.join(output_dir, "issues.json"), "w") as f:
                json.dump(filtered, f, indent=2)
            with open(os.path.join(output_dir, "batches.json"), "w") as f:
                json.dump(batches, f, indent=2)
            with open(os.path.join(output_dir, "summary.md"), "w") as f:
                f.write(summary)

            with open(os.path.join(output_dir, "issues.json")) as f:
                loaded_issues = json.load(f)
            assert len(loaded_issues) == len(filtered)

            with open(os.path.join(output_dir, "batches.json")) as f:
                loaded_batches = json.load(f)
            assert len(loaded_batches) == len(batches)

            prompts = []
            for batch in batches:
                prompt = build_batch_prompt(batch, repo_url, default_branch)
                prompts.append(prompt)
                prompt_path = os.path.join(output_dir, f"prompt_batch_{batch['batch_id']}.txt")
                with open(prompt_path, "w") as f:
                    f.write(prompt)

            for prompt in prompts:
                assert repo_url in prompt
                assert "fix(" in prompt
                assert "Instructions:" in prompt

            for batch in loaded_batches:
                assert "batch_id" in batch
                assert "cwe_family" in batch
                assert "severity_tier" in batch
                assert "issues" in batch
                assert batch["issue_count"] > 0

    def test_empty_sarif_dryrun(self):
        sarif_path = os.path.join(FIXTURES, "empty_runs.sarif")
        issues = parse_sarif(sarif_path)
        assert issues == []
        batches = batch_issues(issues)
        assert batches == []

    def test_multi_language_dryrun(self):
        sarif_path = os.path.join(FIXTURES, "multi_run.sarif")
        issues = parse_sarif(sarif_path)
        assert len(issues) == 2

        unique = deduplicate_issues(issues)
        filtered = prioritize_issues(unique, "low")
        filtered = assign_issue_ids(filtered, "1")
        batches = batch_issues(filtered, batch_size=5, max_batches=10)

        assert len(batches) >= 1
        families = {b["cwe_family"] for b in batches}
        assert len(families) >= 1

        for batch in batches:
            prompt = build_batch_prompt(
                batch, "https://github.com/test/repo", "main"
            )
            assert len(prompt) > 0
            assert "fix(" in prompt
