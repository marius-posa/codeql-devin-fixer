"""Integration tests for the CodeQL Devin Fixer pipeline.

Covers:
- End-to-end SARIF-to-batches pipeline
- Prompt generation verification from known batches
- Telemetry round-trip (aggregate -> stats -> repos dict)
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

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "telemetry"))
from aggregation import aggregate_sessions, aggregate_stats, build_repos_dict
from issue_tracking import track_issues_across_runs

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


class TestTelemetryRoundTrip:
    def _run(self, num, repo, issues=5, sessions=None, fps=None, ts=None):
        return {
            "run_number": num,
            "run_id": f"id-{num}",
            "target_repo": repo,
            "fork_url": f"https://github.com/me/{repo.split('/')[-1]}",
            "run_url": f"https://github.com/runs/{num}",
            "run_label": f"run-{num}",
            "timestamp": ts or f"2026-01-{num:02d}T00:00:00Z",
            "issues_found": issues,
            "severity_breakdown": {"high": issues},
            "category_breakdown": {"injection": issues},
            "sessions": sessions or [],
            "issue_fingerprints": fps or [],
        }

    def test_full_round_trip(self):
        runs = [
            self._run(1, "owner/repo", issues=10, sessions=[
                {"session_id": "s1", "session_url": "u1", "batch_id": 1,
                 "status": "finished", "issue_ids": ["I1", "I2"], "pr_url": "http://pr1"},
                {"session_id": "s2", "session_url": "u2", "batch_id": 2,
                 "status": "created", "issue_ids": ["I3"], "pr_url": ""},
            ], fps=[
                {"fingerprint": "fp1", "id": "I1", "rule_id": "r1",
                 "severity_tier": "high", "cwe_family": "injection",
                 "file": "a.js", "start_line": 1},
            ]),
            self._run(2, "owner/repo", issues=8, sessions=[
                {"session_id": "s3", "session_url": "u3", "batch_id": 1,
                 "status": "finished", "issue_ids": ["I4"], "pr_url": "http://pr2"},
            ], fps=[
                {"fingerprint": "fp1", "id": "I1b", "rule_id": "r1",
                 "severity_tier": "high", "cwe_family": "injection",
                 "file": "a.js", "start_line": 1},
                {"fingerprint": "fp2", "id": "I5", "rule_id": "r2",
                 "severity_tier": "medium", "cwe_family": "xss",
                 "file": "b.js", "start_line": 5},
            ]),
        ]

        sessions = aggregate_sessions(runs)
        assert len(sessions) == 3
        assert sessions[0]["session_id"] == "s1"

        prs = [
            {"repo": "me/repo", "state": "closed", "merged": True},
            {"repo": "me/repo", "state": "open", "merged": False},
        ]

        stats = aggregate_stats(runs, sessions, prs)
        assert stats["repos_scanned"] == 1
        assert stats["total_issues"] == 18
        assert stats["latest_issues"] == 8
        assert stats["sessions_created"] == 3
        assert stats["sessions_finished"] == 2
        assert stats["prs_merged"] == 1

        repos = build_repos_dict(runs, sessions, prs)
        assert len(repos) == 1
        assert repos[0]["repo"] == "owner/repo"
        assert repos[0]["runs"] == 2

        tracked = track_issues_across_runs(runs)
        assert len(tracked) == 2
        statuses = {t["fingerprint"]: t["status"] for t in tracked}
        assert statuses["fp1"] == "recurring"
        assert statuses["fp2"] == "new"

    def test_telemetry_with_fixed_issue(self):
        fp1 = {"fingerprint": "fp1", "id": "I1", "rule_id": "r1",
               "severity_tier": "high", "cwe_family": "injection",
               "file": "a.js", "start_line": 1}
        runs = [
            self._run(1, "o/r", fps=[fp1], ts="2026-01-01T00:00:01Z"),
            self._run(2, "o/r", fps=[], ts="2026-01-01T00:00:02Z"),
        ]
        tracked = track_issues_across_runs(runs)
        assert len(tracked) == 1
        assert tracked[0]["status"] == "fixed"
